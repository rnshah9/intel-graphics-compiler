/*========================== begin_copyright_notice ============================

Copyright (C) 2017-2021 Intel Corporation

SPDX-License-Identifier: MIT

============================= end_copyright_notice ===========================*/

#include "Compiler/CISACodeGen/VectorProcess.hpp"
#include "Compiler/CISACodeGen/ShaderCodeGen.hpp"
#include "Compiler/CISACodeGen/EmitVISAPass.hpp"
#include "Compiler/IGCPassSupport.h"
#include "common/IGCIRBuilder.h"
#include "common/LLVMWarningsPush.hpp"
#include "llvmWrapper/Support/Alignment.h"
#include "llvmWrapper/IR/DerivedTypes.h"
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/Support/MathExtras.h>
#include "common/LLVMWarningsPop.hpp"
#include "Probe/Assertion.h"

using namespace llvm;
using namespace IGC;
using IGCLLVM::FixedVectorType;

//
// Description of VectorProcess Pass
//   The pass is to do data layout of vector explicitly by inserting bitcasts.
//   These bitcasts have special meaning and cannot be deleted. We insert
//   those bitcasts right before emitting vISA code so that the most codegen
//   passes will not need to special-handle those bitcasts.
//
// As we assume that vector type (in llvm ir) is in a "packed form", which means
// that when we group several workitems (each llvm code is a single workitem)
// into a single thread, the elements of a vector in LLVM IR are no longer
// consecutive in their GRF. For example, given <n x T> v,  its vISA
// variable under SIMD8 (group 8 workitems into a single thread) will be
// laid out as follow (For readability, C variables are used and C's struct
// layout is assumed):
//     struct { T c0, c1, c2, c3, c4, c5, c6, c7 } visaVar[n];
//     where c0, c1, ... c7 represent values for simd lane 0 -- 7,
//     respectively. For example, assume the original workitem 0 is at SIMD
//     lane 0, and its vector v for lane 0 will be
//       visaVar[0].c0, visaVar[1].c0, visaVar[2].c0,...... visaVar[n-1].c0,
//     which are no longer consecutive in visaVar.
//
// This layout is not guaranteed to be efficiently generated by gathers/scatters.
// For example,  <16xi8> can be generated by 16 1-byte byte scattered Reads, each
// read reads 1 byte for every lane;  but <16xi8> can be viewed as <4xi32>. And
// a single gather4 can get entire <4xi32>. Thus, to have an efficient message,
// the original vector could be "re-layout" to a different vector type that can
// be mapped to send message more efficently. But this "re-layout" has cost,
// that is, we will have to generate mov instructions (maybe a lot), as shown
// below:
//    <16xi8> v
//       struct { i8 c0, c1, ..., c7 } visaVar_v[16];
//       Note: this array of struct is required in IGC (referred to as
//             packed form).
//
//    <4xi32> v_as4xi32
//       struct { i32 c0, c1, ..., c7 } visaVar_v_as4xi32[4]; or
//          struct { i8 c0[4], c1[4], ..., c7[4] } visaVar_v_as4xi32[4];
//          note: each element of the array is actually a struct of array!
//       visaVar_v_as4xi32 = gather4 &v
//
//
//    To convert <4xi32> back to <16xi8> (required as packed-form), the
//    following is needed:
//       for(i=0; i < 4; ++i)
//         for(j=0; j < 4; ++j)
//            visaVar_v[i*4 + j].c0 = visaVar_v_as4xi32[i].c0[j];
//            ......
//            visaVar_v[i*4 + j].c7 = visaVar_v_as4xi32[i].c7[j];
//    and this has 4 * 4 * 8 = 128 mov instructions !
//
//
// In order to generate such mov instructions explicitly, we insert bitcast between
// the original vector and one we want to use for load and store, and this bitcast
// basically emits movs similar to the conversion code as shown above.  We call
// this bitcast as re-data-layout. The following is the code generated for this
// explicit bitcast (done by emitVectorBitCast):
//     before:   %v = load <16xi8>* p
//
//     after:    %np = bitcast p to <4 x i32>*
//               %nv = load <4 x i32>* np
//               %v  = bitcast nv to <16 x i8>       <<--- re-data-layout bitcast
//
// Since this could potentially generate a lot of movs (may be optimized away),
// bitcasts are inserted only if it is needed.
//
// ** Note, we guarantee that the size of a vector is either 1, 2 bytes,
// ** or multiple of DW at this point. This is guaranteed by VectorPreProcess
// ** (as <3 x i8> cannot be mapped to a single send message, has to be
// ** splitted. We split <3 x i8> in VectorPreProcess so that we don't have
// ** to worry about splitting vector here).
//
// Given a vector < n x T>, the type of load/store is calculated "conceptually"
// as the following, note that if sizeof(T) is 4 or 8, we normally do not
// need to do conversion at all (but there are exception when load/store is
// is mis-aligned). (Keep in mind that sizeof(T)*n is 1|2|multiple-of-DW.)
//    if (n * sizeof(T) < 4 bytes) {
//      <n x T> ---> S; where S is the scalar type whose size == n * sizeof(T);
//    } else if ( (sizeof(T) != 4 && Using A32 message ) ||
//                (sizeof(T) != 4|8 && Using A64 message) ) {
//
//      <n x T>  -->  <n1 x i64>  : sizeof(T) == 8 && A64 messages; or
//                    <n1 x i32>  : otherwise
//    }
//
// For example,
//  (1)   %1 = load <8 x i16> *p
//        converted into
//          new_p = bitcast p to <4 x i32>*
//          %2    = load <4 x i32> *new_p
//          %1    = bitcast %2 to <8 x i16>
//
//  (2)   %1 = load <4 x i64> *p
//        Using A32, converted into
//          new_p = bitcast p to <8 x i32>*
//          %2 = load <8 x i32> *new_p
//          %1 = bitcast %2 to <4 x i64>
//
//        Using A64, do nothing.
//
namespace
{
    class VectorProcess : public FunctionPass
    {
    public:
        typedef SmallVector<Instruction*, 32> InstWorkVector;

        static char ID; // Pass identification, replacement for typeid
        VectorProcess()
            : FunctionPass(ID)
            , m_DL(nullptr)
            , m_C(nullptr)
            , has_8Byte_A64_BS(true)
            , m_WorkList()
        {
            initializeVectorProcessPass(*PassRegistry::getPassRegistry());
        }
        StringRef getPassName() const override { return "VectorProcess"; }
        bool runOnFunction(Function& F) override;
        void getAnalysisUsage(AnalysisUsage& AU) const override
        {
            AU.setPreservesCFG();
            AU.addRequired<CodeGenContextWrapper>();
        }

    private:
        bool reLayoutLoadStore(Instruction* Inst);
        bool optimizeBitCast(BitCastInst* BC);

    private:
        const DataLayout* m_DL;
        LLVMContext* m_C;
        bool has_8Byte_A64_BS; // true if 8-byte A64 Byte scattered is supported
        InstWorkVector m_WorkList;
    };
}

// Register pass to igc-opt
#define PASS_FLAG "igc-vectorprocess"
#define PASS_DESCRIPTION "Process vector loads/stores for explicit vISA variable layout"
#define PASS_CFG_ONLY false
#define PASS_ANALYSIS false
IGC_INITIALIZE_PASS_BEGIN(VectorProcess, PASS_FLAG, PASS_DESCRIPTION, PASS_CFG_ONLY, PASS_ANALYSIS)
IGC_INITIALIZE_PASS_DEPENDENCY(CodeGenContextWrapper)
IGC_INITIALIZE_PASS_END(VectorProcess, PASS_FLAG, PASS_DESCRIPTION, PASS_CFG_ONLY, PASS_ANALYSIS)

char VectorProcess::ID = 0;

FunctionPass* IGC::createVectorProcessPass()
{
    return new VectorProcess();
}

bool VectorProcess::reLayoutLoadStore(Instruction* Inst)
{
    LoadInst* const LI = dyn_cast<LoadInst>(Inst);
    StoreInst* const SI = dyn_cast<StoreInst>(Inst);
    GenIntrinsicInst* const II = dyn_cast<GenIntrinsicInst>(Inst);

    Value* Ptr = nullptr;
    Type* Ty = nullptr;
    if (nullptr != LI)
    {
        Ptr = LI->getPointerOperand();
        Ty = LI->getType();
    }
    else if (nullptr != SI)
    {
        IGC_ASSERT(0 < SI->getNumOperands());
        IGC_ASSERT(nullptr != SI->getOperand(0));

        Ptr = SI->getPointerOperand();
        Ty = SI->getOperand(0)->getType();
    }
    else
    {
        IGC_ASSERT(nullptr != II);
        IGC_ASSERT(0 < II->getNumOperands());
        IGC_ASSERT(nullptr != II->getOperand(0));

        Ptr = II->getOperand(0);

        if (II->getIntrinsicID() == GenISAIntrinsic::GenISA_ldrawvector_indexed)
        {
            Ty = II->getType();
        }
        else
        {
            IGC_ASSERT(II->getIntrinsicID() == GenISAIntrinsic::GenISA_storerawvector_indexed);
            IGC_ASSERT(2 < II->getNumArgOperands());
            IGC_ASSERT(nullptr != II->getArgOperand(2));

            Ty = II->getArgOperand(2)->getType();
        }
    }

    IGC_ASSERT(nullptr != Ptr);
    IGC_ASSERT(nullptr != Ty);

    IGCLLVM::FixedVectorType* const VTy = dyn_cast<IGCLLVM::FixedVectorType>(Ty);

    // Treat a scalar as 1-element vector
    uint32_t nelts = VTy ? int_cast<uint32_t>(VTy->getNumElements()) : 1;
    Type* eTy = VTy ? VTy->getElementType() : Ty;
    uint32_t eTyBits = int_cast<unsigned int>(m_DL->getTypeSizeInBits(eTy));

    IGC_ASSERT_MESSAGE((eTyBits == 8 || eTyBits == 16 || eTyBits == 32 || eTyBits == 64), "the Size of Vector element must be 8/16/32/64 bits.");

    uint32_t eTyBytes = (eTyBits >> 3);
    uint32_t TBytes = nelts * eTyBytes;  // Total size in bytes

    //
    // Assumption:
    //    1. if the size of vector < 4 bytes, it must be 1 or 2 bytes (never 3);
    //    2. if the size of vector >= 4 bytes, it must be multiple of DW
    // Those 2 assumption are guaranteed by VectorPreProcess.
    //
    // So far, we are using A32 untyped and byte scattered messages,
    // and A64 scattered messages and A64 untyped messages.
    //
    // A32: using DW as the new element type.
    // A64: the new element type will be:
    //        unaligned load/store: DW if no 8-byte A64 byte scattered message
    //                              QW otherwise;
    //        aligned vector of long type:  use QW
    //        others: use DW.
    // For vector whose size is smaller than 4 bytes, they must be converted
    // to a 1-element vector (or scalar) so all elements are read/written with
    // a single message.
    //
    Type* new_eTy;
    uint32_t new_nelts;
    PointerType* PtrTy = cast<PointerType>(Ptr->getType());

    if (TBytes == 1)
    {
        IGC_ASSERT_MESSAGE(nelts == 1, "Internal Error: something wrong");
        return false;
    }
    else if (TBytes == 2 || TBytes == 4)
    {
        if (nelts == 1)
        {
            // No conversion needed.
            return false;
        }
        new_nelts = 1;
        new_eTy = (TBytes == 2) ? Type::getInt16Ty(*m_C)
            : Type::getInt32Ty(*m_C);
    }
    else
    {
        // This handles all the other cases
        CodeGenContext* cgCtx = nullptr;
        cgCtx = getAnalysis<CodeGenContextWrapper>().getCodeGenContext();
        bool useA64 = IGC::isA64Ptr(PtrTy, cgCtx);
        uint32_t align;
        if (LI)
        {
            align = LI->getAlignment();
        }
        else if (SI)
        {
            align = SI->getAlignment();
        }
        else
        {
            align = 1;
        }

        bool useQW = useA64 && ((TBytes % 8) == 0) &&
            ((has_8Byte_A64_BS && align < 4) || (eTyBytes == 8U && align >= 8U));

        if (cgCtx->platform.LSCEnabled())
        {
            // With LSC, want to use QW if element size is 8 bytes.
            useQW = (eTyBytes == 8);
        }

        const uint32_t new_eTyBytes = useQW ? 8 : 4;
        if (eTyBytes == new_eTyBytes)
        {
            // The original vector is already a good one. Skip.
            return false;
        }
        new_eTy = useQW ? Type::getInt64Ty(*m_C) : Type::getInt32Ty(*m_C);
        IGC_ASSERT(new_eTyBytes);
        IGC_ASSERT_MESSAGE((TBytes % new_eTyBytes) == 0, "Wrong new vector size");
        new_nelts = TBytes / new_eTyBytes;
    }

    IGCIRBuilder<> Builder(Inst);
    Type* newVTy;
    if (new_nelts == 1)
    {
        newVTy = new_eTy;
    }
    else
    {
        newVTy = FixedVectorType::get(new_eTy, new_nelts);
    }
    Type* newPtrTy = PointerType::get(newVTy, PtrTy->getPointerAddressSpace());
    Value* newPtr;
    if (IntToPtrInst * i2p = dyn_cast<IntToPtrInst>(Ptr))
    {
        newPtr = Builder.CreateIntToPtr(i2p->getOperand(0), newPtrTy, "IntToPtr2");
    }
    else
    {
        newPtr = Builder.CreateBitCast(Ptr, newPtrTy, "vptrcast");
    }

    if (LI)
    {
        LoadInst* load = Builder.CreateAlignedLoad(newPtr,
            IGCLLVM::getCorrectAlign(LI->getAlignment()),
            LI->isVolatile(),
            "vCastload");
        load->copyMetadata(*LI);

        Value* V = load;

        if (eTy->isPointerTy())
        {
            // cannot bitcast int to ptr; need to use intToptr.
            // First, cast the loaded value to a vector type that is same to
            //        the original vector type with ptr element type replaced
            //        with int-element type.
            // second, IntToPtr cast to the original vector type.
            Type* int_eTy = Type::getIntNTy(*m_C, eTyBits);
            Type* new_intTy = VTy ? FixedVectorType::get(int_eTy, nelts) : int_eTy;
            V = Builder.CreateBitCast(V, new_intTy);
            if (VTy)
            {
                // If we need a vector inttoptr, scalarize it here.
                auto* BC = V;
                V = UndefValue::get(Ty);
                for (unsigned i = 0; i < nelts; i++)
                {
                    auto* EE = Builder.CreateExtractElement(BC, i);
                    auto* ITP = Builder.CreateIntToPtr(EE, eTy);
                    V = Builder.CreateInsertElement(V, ITP, i);
                }
            }
            else
            {
                V = Builder.CreateIntToPtr(V, Ty);
            }
        }
        else
        {
            V = Builder.CreateBitCast(V, Ty);
        }
        LI->replaceAllUsesWith(V);
        LI->eraseFromParent();
    }
    else
        if (SI)
        {
            Value* StoreVal = SI->getValueOperand();
            Value* V;
            if (eTy->isPointerTy())
            {

                // Similar to the load. First, PtrtoInt cast to a new vector,
                // and then bitcast to the stored type.
                Type* int_eTy = Type::getIntNTy(*m_C, eTyBits);
                if (VTy)
                {
                    // If we need a vector inttoptr, scalarize it here.
                    V = UndefValue::get(FixedVectorType::get(int_eTy, nelts));
                    for (unsigned i = 0; i < nelts; i++)
                    {
                        auto* EE = Builder.CreateExtractElement(StoreVal, i);
                        auto* ITP = Builder.CreatePtrToInt(EE, int_eTy);
                        V = Builder.CreateInsertElement(V, ITP, i);
                    }
                }
                else if (isa<IntToPtrInst>(StoreVal) &&
                    cast<IntToPtrInst>(StoreVal)->getOperand(0)->getType() == int_eTy)
                {
                    // Detect case when creating PtrToInt and BitCast instructions
                    // is not needed. This is when store value is created from
                    // a vector with the same type as the target vector type.
                    //
                    // e.g. example from a Vulkan shader with variable pointers:
                    // Before:
                    //     %7 = bitcast <2 x i32> %assembled.vect7 to i64
                    //     %Temp-26.i.VP = inttoptr i64 %7 to i32 addrspace(1179648)*
                    //     store i32 addrspace(1179648)* %Temp-26.i.VP, i32 addrspace(1179648)** %6, align 8
                    // After:
                    //     store <2 x i32> %assembled.vect7, <2 x i32>* %vptrcast, align 8

                    V = cast<IntToPtrInst>(StoreVal)->getOperand(0);
                }
                else
                {
                    V = Builder.CreatePtrToInt(StoreVal, int_eTy);
                }

                if (isa<BitCastInst>(V) &&
                    (cast<BitCastInst>(V)->getOperand(0)->getType() == newVTy))
                {
                    V = cast<BitCastInst>(V)->getOperand(0);
                }
                else
                {
                    V = Builder.CreateBitCast(V, newVTy);
                }
            }
            else
            {
                V = Builder.CreateBitCast(StoreVal, newVTy);
            }
            StoreInst* store = nullptr;
            if (SI->getAlignment() == 0)
            {
                store = Builder.CreateStore(V, newPtr, SI->isVolatile());
            }
            else
            {
                store = Builder.CreateAlignedStore(V, newPtr, IGCLLVM::getAlign(SI->getAlignment()), SI->isVolatile());
            }
            store->copyMetadata(*SI);
            SI->eraseFromParent();
        }
        else if (II->getIntrinsicID() == GenISAIntrinsic::GenISA_ldrawvector_indexed)
        {
            Type* types[] =
            {
                newVTy,
                newPtrTy
            };

            Function* F = GenISAIntrinsic::getDeclaration(
                II->getParent()->getParent()->getParent(),
                GenISAIntrinsic::GenISA_ldrawvector_indexed,
                types);
            Value* V = Builder.CreateCall4(F, newPtr, II->getOperand(1), II->getOperand(2), II->getOperand(3));
            V = Builder.CreateBitCast(V, Ty);

            II->replaceAllUsesWith(V);
            II->eraseFromParent();
        }
        else
        {
            Type* types[] =
            {
                newPtrTy,
                newVTy
            };

            Function* F = GenISAIntrinsic::getDeclaration(
                II->getParent()->getParent()->getParent(),
                GenISAIntrinsic::GenISA_storerawvector_indexed,
                types);
            Value* V = Builder.CreateBitCast(II->getOperand(2), newVTy);
            Builder.CreateCall5(F, newPtr, II->getOperand(1), V, II->getOperand(3), II->getOperand(4));
            II->eraseFromParent();
        }
    return true;
}

bool VectorProcess::optimizeBitCast(BitCastInst* BC)
{
    bool change = false;
    Value* Src = BC->getOperand(0);
    Type* SrcTy = Src->getType();
    Type* Ty = BC->getType();

    if (Ty == SrcTy)
    {
        BC->replaceAllUsesWith(Src);
        return true;
    }

    // Only handle non-pointer bitcast
    if (isa<PointerType>(Ty) || isa<PointerType>(SrcTy))
    {
        return false;
    }

    for (Value::user_iterator UI = BC->user_begin(), UE = BC->user_end();
        UI != UE; ++UI)
    {
        if (BitCastInst * Inst = dyn_cast<BitCastInst>(*UI))
        {
            IRBuilder<> Builder(Inst);
            Type* Ty1 = Inst->getType();
            if (SrcTy == Ty1)
            {
                Inst->replaceAllUsesWith(Src);
            }
            else
            {
                BitCastInst* nBC = (BitCastInst*)Builder.CreateBitCast(Src, Ty1);
                Inst->replaceAllUsesWith(nBC);

                // Add nBC so it will be processed again.
                m_WorkList.push_back(nBC);
            }
            change = true;
        }
    }
    return change;
}

bool VectorProcess::runOnFunction(Function& F)
{
    CodeGenContext* cgCtx = nullptr;
    cgCtx = getAnalysis<CodeGenContextWrapper>().getCodeGenContext();
    bool changed = false;
    m_DL = &F.getParent()->getDataLayout();
    m_C = &F.getContext();
    has_8Byte_A64_BS = cgCtx->platform.has8ByteA64ByteScatteredMessage();

    //  Adjust load/store layout by inserting bitcast.
    //  Those bitcasts should not be optimized away.
    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I)
    {
        Instruction* inst = &*I;
        if (isa<LoadInst>(inst) || isa<StoreInst>(inst))
        {
            m_WorkList.push_back(inst);
        }
        else
            if (GenIntrinsicInst * intrin = dyn_cast<GenIntrinsicInst>(inst))
            {
                if (intrin->getIntrinsicID() == GenISAIntrinsic::GenISA_ldrawvector_indexed ||
                    intrin->getIntrinsicID() == GenISAIntrinsic::GenISA_storerawvector_indexed)
                {
                    m_WorkList.push_back(inst);
                }
            }
    }

    for (unsigned i = 0; i < m_WorkList.size(); ++i)
    {
        if (reLayoutLoadStore(m_WorkList[i]))
        {
            changed = true;
        }
    }
    m_WorkList.clear();

    // To remove unnecessary bitcast
    if (changed)
    {
        for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I)
        {
            Instruction* inst = &*I;
            if (isa<BitCastInst>(inst))
            {
                m_WorkList.push_back(inst);
            }
        }

        bool doclean = false;
        for (unsigned i = 0; i < m_WorkList.size(); ++i)
        {
            if (BitCastInst * Inst = dyn_cast<BitCastInst>(m_WorkList[i]))
            {
                if (optimizeBitCast(Inst))
                {
                    doclean = true;
                }
            }
        }

        while (doclean)
        {
            // Given  b2 = bitcast A,  T2
            //        b1 = bitcast b2, T1
            // we say b1's level is 1, b2's level is 2.
            //
            // This pass, in theory, can have two-level dead bitcasts.
            // Therefore, we expect "while" will take three iterations at most. And
            // WorkList is the set of bitcasts,  which isn't expected to be big.
            doclean = false;
            for (unsigned i = 0; i < m_WorkList.size(); ++i)
            {
                if (m_WorkList[i] && m_WorkList[i]->use_empty())
                {
                    m_WorkList[i]->eraseFromParent();
                    m_WorkList[i] = NULL;
                    doclean = true;
                }
            }
        }

        m_WorkList.clear();
    }
    //DumpLLVMIR(cgCtx, "vectorprocess");
    return changed;
}


//
// getInfo maps vector to the right messages. It assume that a vector
// can be mapped to more than one messages, and those messages may be
// different as long as the message returns exactly the same "packed form"
// of the vector.
//
// getInfo() initializes the array of struct (insts), which specifies
// the number of send instructions (or gathers/scatters visa instructions)
// needed to read/write this vector into vISA variable. The clients will
// access this array of struct directly after getInfo() call.
//
// VectorProcess() will change each vector load and store into a new vector
// load and store that can map exactly to these messages. getInfo() has
// the following agreement with VectorProcess():
//   1) If sizeof(Ty) >= 4 bytes, sizeof(Ty) must be multiple of 4 bytes.
//      And futhermore, the element type of 'Ty' if 'Ty" is a vector type
//      or 'Ty' if 'Ty' is a scalar type, must be either 4 bytes (DW) or
//      8 bytes (QW).
//   2) If sizeof(Ty) < 4 bytes, sizeof(Ty) must be either 1 byte or
//      2 bytes. The sizeof(Ty) cannot be 3 bytes!
// (Note that VectorMessage and VectorProcess must be in sync with regard
//  to this agreetment.)
//
void VectorMessage::getInfo(Type* Ty, uint32_t Align, bool useA32,
    bool forceByteScatteredRW)
{
    VectorType* VTy = dyn_cast<VectorType>(Ty);
    Type* eTy = VTy ? cast<VectorType>(VTy)->getElementType() : Ty;
    unsigned eltSize = m_emitter->GetScalarTypeSizeInRegister(eTy);
    unsigned nElts = VTy ? (unsigned)cast<IGCLLVM::FixedVectorType>(VTy)->getNumElements() : 1;
    // total bytes
    const unsigned TBytes = nElts * eltSize;

    // Per-channel Max Bytes (MB) that can be read/written by a single send inst
    unsigned MB;
    SIMDMode SM = m_emitter->m_currShader->m_SIMDSize;
    bool has_8B_A64_BS =
        m_emitter->m_currShader->m_Platform->has8ByteA64ByteScatteredMessage();
    bool has_8DW_A64_SM =
        m_emitter->m_currShader->m_Platform->has8DWA64ScatteredMessage();

    //
    // Set up default message and the data type of the message
    //
    MESSAGE_KIND defaultKind;
    VISA_Type    defaultDataType;
    if (Align < 4 || TBytes < 4 || forceByteScatteredRW)
    {
        if (forceByteScatteredRW)
        {
            IGC_ASSERT(useA32);
        }
        defaultKind = useA32
            ? MESSAGE_A32_BYTE_SCATTERED_RW
            : MESSAGE_A64_SCATTERED_RW;
        MB = useA32
            ? A32_BYTE_SCATTERED_MAX_BYTES
            : ((has_8B_A64_BS && eltSize == 8)
                ? A64_BYTE_SCATTERED_MAX_BYTES_8B
                : A64_BYTE_SCATTERED_MAX_BYTES);
        defaultDataType = ISA_TYPE_UB;

        // To make sure that vector and message match.
        IGC_ASSERT_MESSAGE((MB == eltSize || (MB > eltSize && nElts == 1)), "Internal Error: mismatch layout for vector");
    }
    else
    {
        defaultKind = useA32
            ? MESSAGE_A32_UNTYPED_SURFACE_RW
            : MESSAGE_A64_SCATTERED_RW;

        MB = useA32
            ? A32_UNTYPED_MAX_BYTES
            : ((has_8DW_A64_SM && SM == SIMDMode::SIMD8)
                ? A64_SCATTERED_MAX_BYTES_8DW_SIMD8
                : A64_SCATTERED_MAX_BYTES_4DW);

        bool allowQWMessage = !useA32 && eltSize == 8 && Align >= 8U;

        defaultDataType = (eltSize == 8) ? ISA_TYPE_UQ : ISA_TYPE_UD;
        //To make sure that send returns the correct layout for vector.
        IGC_ASSERT_MESSAGE((eltSize == 4 /* common */ || allowQWMessage /* A64, QW */), "Internal Error: mismatch layout for vector");
    }

    MESSAGE_KIND kind = defaultKind;
    VISA_Type    dataType = defaultDataType;
    unsigned bytes = TBytes;
    size_t i = 0;
    for (; bytes >= MB; ++i, bytes -= MB)
    {
        IGC_ASSERT(i < (sizeof(insts) / sizeof(*insts)));
        insts[i].startByte = (uint16_t)(TBytes - bytes);
        insts[i].kind = kind;
        insts[i].blkType = dataType;
        insts[i].blkInBytes = (uint16_t)CEncoder::GetCISADataTypeSize(dataType);
        IGC_ASSERT(insts[i].blkInBytes);
        insts[i].numBlks = MB / insts[i].blkInBytes;
    }

    // Process the remaining elements if any. It could have at most
    // two separate sends. For example, assuming the remaining bytes
    // are for <7 x i32> and it is for A64 SIMD8 with align >=4; thus
    // we will need two sends: one for the first <4 x i32> and the
    // second for  the remaining <3 x i32>.
    if (MB == A64_SCATTERED_MAX_BYTES_8DW_SIMD8)
    {   // MB == 32 bytes
        unsigned MB2 = A64_SCATTERED_MAX_BYTES_8DW_SIMD8 / 2; // 16 bytes
        if (bytes > MB2)
        {
            IGC_ASSERT(i < (sizeof(insts) / sizeof(*insts)));
            insts[i].startByte = (uint16_t)(TBytes - bytes);
            insts[i].kind = kind;
            insts[i].blkInBytes = (uint16_t)CEncoder::GetCISADataTypeSize(dataType);
            IGC_ASSERT(insts[i].blkInBytes);
            insts[i].numBlks = MB2 / insts[i].blkInBytes;
            ++i;
            bytes -= MB2;
        }
    }

    if (bytes > 0)
    {
        if (Align >= 4)
        {
            if (!useA32 && eltSize == 4 && bytes == 12)
            {
                kind = MESSAGE_A64_UNTYPED_SURFACE_RW;
            }
        }

        IGC_ASSERT(i < (sizeof(insts) / sizeof(*insts)));
        insts[i].startByte = (uint16_t)(TBytes - bytes);
        insts[i].kind = kind;
        insts[i].blkType = dataType;
        insts[i].blkInBytes = (uint16_t)CEncoder::GetCISADataTypeSize(dataType);
        IGC_ASSERT(insts[i].blkInBytes);
        insts[i].numBlks = (uint16_t)bytes / insts[i].blkInBytes;
        ++i;
    }

    numInsts = i;
    IGC_ASSERT_MESSAGE(numInsts <= VECMESSAGEINFO_MAX_LEN, "Vector's size is too big, increase MAX_VECMESSAGEINFO_LEN to fix it!");
    IGC_ASSERT_MESSAGE(numInsts <= (sizeof(insts) / sizeof(*insts)), "Vector's size is too big, increase MAX_VECMESSAGEINFO_LEN to fix it!");
}

void VectorMessage::getLSCInfo(llvm::Type* Ty, uint32_t Align, CodeGenContext* ctx, bool useA32, bool transpose)
{
    IGC_ASSERT(nullptr != ctx);
    IGC_ASSERT(nullptr != m_emitter);
    IGC_ASSERT(nullptr != m_emitter->m_currShader);

    IGCLLVM::FixedVectorType* VTy = dyn_cast<IGCLLVM::FixedVectorType>(Ty);
    Type* eTy = VTy ? VTy->getContainedType(0) : Ty;
    unsigned eltSize = m_emitter->GetScalarTypeSizeInRegister(eTy);
    unsigned nElts = VTy ? (unsigned)VTy->getNumElements() : 1;
    // total bytes
    const unsigned TBytes = nElts * eltSize;
    char TRANS_VEC_SIZE[8] = { 1, 2, 3, 4, 8, 16, 32, 64 };
    MESSAGE_KIND kind = useA32
        ? MESSAGE_A32_LSC_RW
        : MESSAGE_A64_LSC_RW;

    VISA_Type dataType = GetType(Ty, ctx);
    uint16_t blkInBytes = (uint16_t)CEncoder::GetCISADataTypeSize(dataType);

    // Per-channel Max Bytes (MB) that can be read/written by a single send inst
    const unsigned int numLanesForSIMDSize = numLanes(m_emitter->m_currShader->m_SIMDSize);
    IGC_ASSERT(numLanesForSIMDSize);
    unsigned int MB = (8 * ctx->platform.getGRFSize()) / numLanesForSIMDSize;
    if (Align < 4 || (eltSize == 8 && Align < 8)) {
        MB = eltSize;
    }

    size_t i = 0;
    if (transpose)
    {
        unsigned bytes = TBytes;
        for (int j = 0; j < 8; j++)
        {
            const unsigned int denominator = blkInBytes * TRANS_VEC_SIZE[7 - j];
            IGC_ASSERT(denominator);

            if (bytes % denominator == 0)
            {
                IGC_ASSERT(i < (sizeof(insts) / sizeof(*insts)));
                insts[i].startByte = (uint16_t)(TBytes - bytes);
                insts[i].kind = kind;
                insts[i].blkType = dataType;
                insts[i].blkInBytes = blkInBytes;
                insts[i].numBlks = TRANS_VEC_SIZE[7 - j];
                bytes -= insts[i].numBlks * blkInBytes;
                i++;
                break;
            }
            else //
            {
                if (bytes / denominator != 0)
                {
                    IGC_ASSERT(i < (sizeof(insts) / sizeof(*insts)));
                    insts[i].startByte = (uint16_t)(TBytes - bytes);
                    insts[i].kind = kind;
                    insts[i].blkType = dataType;
                    insts[i].blkInBytes = blkInBytes;
                    insts[i].numBlks = TRANS_VEC_SIZE[7 - j];
                    bytes -= insts[i].numBlks * blkInBytes;
                    i++;
                }  // else j++;
            }
        }
        IGC_ASSERT(bytes == 0);
    }
    else
    {
        unsigned bytes = TBytes;
        for (; bytes >= MB; ++i, bytes -= MB)
        {
            insts[i].startByte = (uint16_t)(TBytes - bytes);
            insts[i].kind = kind;
            insts[i].blkType = dataType;
            insts[i].blkInBytes = (uint16_t)CEncoder::GetCISADataTypeSize(dataType);
            IGC_ASSERT(insts[i].blkInBytes);
            insts[i].numBlks = MB / insts[i].blkInBytes;
        }

        if (bytes > 0)
        {
            insts[i].startByte = (uint16_t)(TBytes - bytes);
            insts[i].kind = kind;
            insts[i].blkType = dataType;
            insts[i].blkInBytes = (uint16_t)CEncoder::GetCISADataTypeSize(dataType);
            IGC_ASSERT(insts[i].blkInBytes);
            insts[i].numBlks = (uint16_t)bytes / insts[i].blkInBytes;
            ++i;
        }
    }

    numInsts = i;
    IGC_ASSERT_MESSAGE(numInsts <= VECMESSAGEINFO_MAX_LEN, "Vector's size is too big, increase MAX_VECMESSAGEINFO_LEN to fix it!");
    IGC_ASSERT_MESSAGE(numInsts <= (sizeof(insts) / sizeof(*insts)), "Vector's size is too big, increase MAX_VECMESSAGEINFO_LEN to fix it!");
}

