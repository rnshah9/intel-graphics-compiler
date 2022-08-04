/*========================== begin_copyright_notice ============================

Copyright (C) 2022 Intel Corporation

SPDX-License-Identifier: MIT

============================= end_copyright_notice ===========================*/

/*========================== begin_copyright_notice ============================

This file is distributed under the University of Illinois Open Source License.
See LICENSE.TXT for details.

============================= end_copyright_notice ===========================*/

// Originated from llvm source lib/IR/Function.cpp
// Function.cpp - Implement the Global object classes

// Implementation of methods declared in InternalIntrinsics/InternalIntrinsics.h

#include "vc/InternalIntrinsics/InternalIntrinsics.h"

#include <llvm/ADT/StringExtras.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/CodeGen/ValueTypes.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/CommandLine.h>

#include "llvmWrapper/IR/DerivedTypes.h"
#include "llvmWrapper/Support/TypeSize.h"

using namespace llvm;
using namespace vc;

namespace vc::InternalIntrinsic {

// get Attributes for InternalIntrinsics, like ReadOnly, ReadNone, etc
AttributeList getAttributes(LLVMContext &C, ID id);

} // namespace vc::InternalIntrinsic

static cl::opt<bool> EnableInternalIntrinsicsCache(
    "enable-internal-intrinsics-cache", cl::init(true), cl::Hidden,
    cl::desc("Enable metadata caching of internal intrinsics"));

// Metadata name for caching
static StringRef InternalIntrinsicMDName{"internal_intrinsic_id"};

namespace {

/// IIT_Info - These are enumerators that describe the entries returned by the
/// getIntrinsicInfoTableEntries function.
///
/// NOTE: This must be kept in synch with the copy in TblGen/IntrinsicEmitter!
enum IIT_Info {
  // Common values should be encoded with 0-15.
  IIT_Done = 0,
  IIT_I1 = 1,
  IIT_I8 = 2,
  IIT_I16 = 3,
  IIT_I32 = 4,
  IIT_I64 = 5,
  IIT_F16 = 6,
  IIT_F32 = 7,
  IIT_F64 = 8,
  IIT_V2 = 9,
  IIT_V4 = 10,
  IIT_V8 = 11,
  IIT_V16 = 12,
  IIT_V32 = 13,
  IIT_PTR = 14,
  IIT_ARG = 15,

  // Values from 16+ are only encodable with the inefficient encoding.
  IIT_V64 = 16,
  IIT_MMX = 17,
  IIT_TOKEN = 18,
  IIT_METADATA = 19,
  IIT_EMPTYSTRUCT = 20,
  IIT_STRUCT2 = 21,
  IIT_STRUCT3 = 22,
  IIT_STRUCT4 = 23,
  IIT_STRUCT5 = 24,
  IIT_EXTEND_ARG = 25,
  IIT_TRUNC_ARG = 26,
  IIT_ANYPTR = 27,
  IIT_V1 = 28,
  IIT_VARARG = 29,
  IIT_HALF_VEC_ARG = 30,
  IIT_SAME_VEC_WIDTH_ARG = 31,
  IIT_PTR_TO_ARG = 32,
  IIT_PTR_TO_ELT = 33,
  IIT_VEC_OF_ANYPTRS_TO_ELT = 34,
  IIT_I128 = 35,
  IIT_V512 = 36,
  IIT_V1024 = 37,
  IIT_STRUCT6 = 38,
  IIT_STRUCT7 = 39,
  IIT_STRUCT8 = 40,
  IIT_F128 = 41
};

} // namespace
// define static const unsigned IIT_Table
// define static const unsigned char IIT_LongEncodingTable
#define GET_INTRINSIC_GENERATOR_GLOBAL
#include "vc/InternalIntrinsics/InternalIntrinsicDescription.gen"
#undef GET_INTRINSIC_GENERATOR_GLOBAL

static void
DecodeIITType(unsigned &NextElt, ArrayRef<unsigned char> Infos,
              SmallVectorImpl<Intrinsic::IITDescriptor> &OutputTable) {
  using namespace Intrinsic;

  IIT_Info Info = IIT_Info(Infos[NextElt++]);
  unsigned StructElts = 2;

  switch (Info) {
  case IIT_Done:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Void, 0));
    return;
  case IIT_VARARG:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::VarArg, 0));
    return;
  case IIT_MMX:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::MMX, 0));
    return;
  case IIT_TOKEN:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Token, 0));
    return;
  case IIT_METADATA:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Metadata, 0));
    return;
  case IIT_F16:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Half, 0));
    return;
  case IIT_F32:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Float, 0));
    return;
  case IIT_F64:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Double, 0));
    return;
  case IIT_F128:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Quad, 0));
    return;
  case IIT_I1:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Integer, 1));
    return;
  case IIT_I8:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Integer, 8));
    return;
  case IIT_I16:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Integer, 16));
    return;
  case IIT_I32:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Integer, 32));
    return;
  case IIT_I64:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Integer, 64));
    return;
  case IIT_I128:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Integer, 128));
    return;
  case IIT_V1:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Vector, 1));
    DecodeIITType(NextElt, Infos, OutputTable);
    return;
  case IIT_V2:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Vector, 2));
    DecodeIITType(NextElt, Infos, OutputTable);
    return;
  case IIT_V4:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Vector, 4));
    DecodeIITType(NextElt, Infos, OutputTable);
    return;
  case IIT_V8:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Vector, 8));
    DecodeIITType(NextElt, Infos, OutputTable);
    return;
  case IIT_V16:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Vector, 16));
    DecodeIITType(NextElt, Infos, OutputTable);
    return;
  case IIT_V32:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Vector, 32));
    DecodeIITType(NextElt, Infos, OutputTable);
    return;
  case IIT_V64:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Vector, 64));
    DecodeIITType(NextElt, Infos, OutputTable);
    return;
  case IIT_V512:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Vector, 512));
    DecodeIITType(NextElt, Infos, OutputTable);
    return;
  case IIT_V1024:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Vector, 1024));
    DecodeIITType(NextElt, Infos, OutputTable);
    return;
  case IIT_PTR:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Pointer, 0));
    DecodeIITType(NextElt, Infos, OutputTable);
    return;
  case IIT_ANYPTR: { // [ANYPTR addrspace, subtype]
    OutputTable.push_back(
        IITDescriptor::get(IITDescriptor::Pointer, Infos[NextElt++]));
    DecodeIITType(NextElt, Infos, OutputTable);
    return;
  }
  case IIT_ARG: {
    unsigned ArgInfo = (NextElt == Infos.size() ? 0 : Infos[NextElt++]);
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Argument, ArgInfo));
    return;
  }
  case IIT_EXTEND_ARG: {
    unsigned ArgInfo = (NextElt == Infos.size() ? 0 : Infos[NextElt++]);
    OutputTable.push_back(
        IITDescriptor::get(IITDescriptor::ExtendArgument, ArgInfo));
    return;
  }
  case IIT_TRUNC_ARG: {
    unsigned ArgInfo = (NextElt == Infos.size() ? 0 : Infos[NextElt++]);
    OutputTable.push_back(
        IITDescriptor::get(IITDescriptor::TruncArgument, ArgInfo));
    return;
  }
  case IIT_HALF_VEC_ARG: {
    unsigned ArgInfo = (NextElt == Infos.size() ? 0 : Infos[NextElt++]);
    OutputTable.push_back(
        IITDescriptor::get(IITDescriptor::HalfVecArgument, ArgInfo));
    return;
  }
  case IIT_SAME_VEC_WIDTH_ARG: {
    unsigned ArgInfo = (NextElt == Infos.size() ? 0 : Infos[NextElt++]);
    OutputTable.push_back(
        IITDescriptor::get(IITDescriptor::SameVecWidthArgument, ArgInfo));
    return;
  }
  case IIT_PTR_TO_ARG: {
    unsigned ArgInfo = (NextElt == Infos.size() ? 0 : Infos[NextElt++]);
    OutputTable.push_back(
        IITDescriptor::get(IITDescriptor::PtrToArgument, ArgInfo));
    return;
  }
  case IIT_PTR_TO_ELT: {
    unsigned ArgInfo = (NextElt == Infos.size() ? 0 : Infos[NextElt++]);
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::PtrToElt, ArgInfo));
    return;
  }
  case IIT_VEC_OF_ANYPTRS_TO_ELT: {
    unsigned short ArgNo = (NextElt == Infos.size() ? 0 : Infos[NextElt++]);
    unsigned short RefNo = (NextElt == Infos.size() ? 0 : Infos[NextElt++]);
    OutputTable.push_back(
        IITDescriptor::get(IITDescriptor::VecOfAnyPtrsToElt, ArgNo, RefNo));
    return;
  }
  case IIT_EMPTYSTRUCT:
    OutputTable.push_back(IITDescriptor::get(IITDescriptor::Struct, 0));
    return;
  case IIT_STRUCT8:
    ++StructElts;
    LLVM_FALLTHROUGH;
  case IIT_STRUCT7:
    ++StructElts;
    LLVM_FALLTHROUGH;
  case IIT_STRUCT6:
    ++StructElts;
    LLVM_FALLTHROUGH;
  case IIT_STRUCT5:
    ++StructElts;
    LLVM_FALLTHROUGH;
  case IIT_STRUCT4:
    ++StructElts;
    LLVM_FALLTHROUGH;
  case IIT_STRUCT3:
    ++StructElts;
    LLVM_FALLTHROUGH;
  case IIT_STRUCT2: {
    OutputTable.push_back(
        IITDescriptor::get(IITDescriptor::Struct, StructElts));

    for (unsigned i = 0; i != StructElts; ++i)
      DecodeIITType(NextElt, Infos, OutputTable);
    return;
  }
  }
  IGC_ASSERT_MESSAGE(0, "unhandled");
}

static Type *DecodeFixedType(ArrayRef<Intrinsic::IITDescriptor> &Infos,
                             ArrayRef<Type *> Tys, LLVMContext &Context) {
  using namespace Intrinsic;

  IITDescriptor D = Infos.front();
  Infos = Infos.slice(1);

  switch (D.Kind) {
  case IITDescriptor::Void:
    return Type::getVoidTy(Context);
  case IITDescriptor::VarArg:
    return Type::getVoidTy(Context);
  case IITDescriptor::MMX:
    return Type::getX86_MMXTy(Context);
  case IITDescriptor::Token:
    return Type::getTokenTy(Context);
  case IITDescriptor::Metadata:
    return Type::getMetadataTy(Context);
  case IITDescriptor::Half:
    return Type::getHalfTy(Context);
  case IITDescriptor::Float:
    return Type::getFloatTy(Context);
  case IITDescriptor::Double:
    return Type::getDoubleTy(Context);
  case IITDescriptor::Quad:
    return Type::getFP128Ty(Context);

  case IITDescriptor::Integer:
    return IntegerType::get(Context, D.Integer_Width);
  case IITDescriptor::Vector:
    return VectorType::get(DecodeFixedType(Infos, Tys, Context),
                           D.Vector_Width);
  case IITDescriptor::Pointer:
    return PointerType::get(DecodeFixedType(Infos, Tys, Context),
                            D.Pointer_AddressSpace);
  case IITDescriptor::Struct: {
    SmallVector<Type *, 8> Elts;
    for (unsigned i = 0, e = D.Struct_NumElements; i != e; ++i)
      Elts.push_back(DecodeFixedType(Infos, Tys, Context));
    return StructType::get(Context, Elts);
  }
  case IITDescriptor::Argument:
    return Tys[D.getArgumentNumber()];
  case IITDescriptor::ExtendArgument: {
    Type *Ty = Tys[D.getArgumentNumber()];
    if (VectorType *VTy = dyn_cast<VectorType>(Ty))
      return VectorType::getExtendedElementVectorType(VTy);

    return IntegerType::get(Context, 2 * cast<IntegerType>(Ty)->getBitWidth());
  }
  case IITDescriptor::TruncArgument: {
    Type *Ty = Tys[D.getArgumentNumber()];
    if (VectorType *VTy = dyn_cast<VectorType>(Ty))
      return VectorType::getTruncatedElementVectorType(VTy);

    IntegerType *ITy = cast<IntegerType>(Ty);
    IGC_ASSERT(ITy->getBitWidth() % 2 == 0);
    return IntegerType::get(Context, ITy->getBitWidth() / 2);
  }
  case IITDescriptor::HalfVecArgument:
    return VectorType::getHalfElementsVectorType(
        cast<VectorType>(Tys[D.getArgumentNumber()]));
  case IITDescriptor::SameVecWidthArgument: {
    Type *EltTy = DecodeFixedType(Infos, Tys, Context);
    Type *Ty = Tys[D.getArgumentNumber()];
    if (IGCLLVM::FixedVectorType *VTy =
            dyn_cast<IGCLLVM::FixedVectorType>(Ty)) {
      return IGCLLVM::FixedVectorType::get(EltTy, VTy->getNumElements());
    }
    IGC_ASSERT_MESSAGE(0, "unhandled");
  }
  case IITDescriptor::PtrToArgument: {
    Type *Ty = Tys[D.getArgumentNumber()];
    return PointerType::getUnqual(Ty);
  }
  case IITDescriptor::PtrToElt: {
    Type *Ty = Tys[D.getArgumentNumber()];
    VectorType *VTy = dyn_cast<VectorType>(Ty);
    if (!VTy)
      IGC_ASSERT_MESSAGE(0, "Expected an argument of Vector Type");
    Type *EltTy = cast<VectorType>(VTy)->getElementType();
    return PointerType::getUnqual(EltTy);
  }
  case IITDescriptor::VecOfAnyPtrsToElt:
    // Return the overloaded type (which determines the pointers address space)
    return Tys[D.getOverloadArgNumber()];
  default:
    break;
  }
  IGC_ASSERT_MESSAGE(0, "unhandled");
  return nullptr;
}

/// getIntrinsicInfoTableEntries - Return the IIT table descriptor for the
/// specified intrinsic into an array of IITDescriptors.
///
static void
getIntrinsicInfoTableEntries(InternalIntrinsic::ID id,
                             SmallVectorImpl<Intrinsic::IITDescriptor> &T) {
  IGC_ASSERT(isInternalIntrinsic(id));

  // transform id
  // from [not_internal_intrinsic; num_internal_intrinsic] to [0, ...]
  unsigned ID = id - InternalIntrinsic::not_internal_intrinsic;
  IGC_ASSERT(ID <= sizeof(IIT_Table) / sizeof(*IIT_Table));

  // Check to see if the intrinsic's type was expressible by the table.
  unsigned TableVal = IIT_Table[ID - 1];

  // Decode the TableVal into an array of IITValues.
  SmallVector<unsigned char, 8> IITValues;
  ArrayRef<unsigned char> IITEntries;
  unsigned NextElt = 0;
  if ((TableVal >> 31) != 0) {
    // This is an offset into the IIT_LongEncodingTable.
    IITEntries = IIT_LongEncodingTable;

    // Strip sentinel bit.
    NextElt = (TableVal << 1) >> 1;
  } else {
    // Decode the TableVal into an array of IITValues.  If the entry was encoded
    // into a single word in the table itself, decode it now.
    do {
      IITValues.push_back(TableVal & 0xF);
      TableVal >>= 4;
    } while (TableVal);

    IITEntries = IITValues;
    NextElt = 0;
  }

  // Okay, decode the table into the output vector of IITDescriptors.
  DecodeIITType(NextElt, IITEntries, T);
  while (NextElt != IITEntries.size() && IITEntries[NextElt] != 0)
    DecodeIITType(NextElt, IITEntries, T);
}

/// Returns a stable mangling for the type specified for use in the name
/// mangling scheme used by 'any' types in intrinsic signatures.  The mangling
/// of named types is simply their name.  Manglings for unnamed types consist
/// of a prefix ('p' for pointers, 'a' for arrays, 'f_' for functions)
/// combined with the mangling of their component types.  A vararg function
/// type will have a suffix of 'vararg'.  Since function types can contain
/// other function types, we close a function type mangling with suffix 'f'
/// which can't be confused with it's prefix.  This ensures we don't have
/// collisions between two unrelated function types. Otherwise, you might
/// parse ffXX as f(fXX) or f(fX)X.  (X is a placeholder for any other type.)
static std::string getMangledTypeStr(Type *Ty) {
  std::string Result;
  if (PointerType *PTyp = dyn_cast<PointerType>(Ty)) {
    Result += "p" + utostr(PTyp->getAddressSpace()) +
              getMangledTypeStr(PTyp->getPointerElementType());
  } else if (ArrayType *ATyp = dyn_cast<ArrayType>(Ty)) {
    Result += "a" + utostr(ATyp->getNumElements()) +
              getMangledTypeStr(ATyp->getElementType());
  } else if (StructType *STyp = dyn_cast<StructType>(Ty)) {
    if (!STyp->isLiteral())
      Result += STyp->getName();
    else {
      Result += "s" + utostr(STyp->getNumElements());
      for (unsigned int i = 0; i < STyp->getNumElements(); i++)
        Result += getMangledTypeStr(STyp->getElementType(i));
    }
  } else if (FunctionType *FT = dyn_cast<FunctionType>(Ty)) {
    Result += "f_" + getMangledTypeStr(FT->getReturnType());
    for (size_t i = 0; i < FT->getNumParams(); i++)
      Result += getMangledTypeStr(FT->getParamType(i));
    if (FT->isVarArg())
      Result += "vararg";
    // Ensure nested function types are distinguishable.
    Result += "f";
  } else if (isa<VectorType>(Ty))
    Result += "v" +
              utostr(cast<IGCLLVM::FixedVectorType>(Ty)->getNumElements()) +
              getMangledTypeStr(cast<VectorType>(Ty)->getElementType());
  else if (Ty)
    Result += EVT::getEVT(Ty).getEVTString();
  return Result;
}

static const char *const InternalIntrinsicNameTable[] = {
    "not_internal_intrinsic",
#define GET_INTRINSIC_NAME_TABLE
#include "vc/InternalIntrinsics/InternalIntrinsicDescription.gen"
#undef GET_INTRINSIC_NAME_TABLE
};

/// Intrinsic::isOverloaded(ID) - Returns true if the intrinsic can be
/// overloaded.
static bool isOverloaded(InternalIntrinsic::ID id) {
  IGC_ASSERT(isInternalIntrinsic(id) && "Invalid intrinsic ID!");
  id = static_cast<InternalIntrinsic::ID>(
      id - InternalIntrinsic::not_internal_intrinsic);
#define GET_INTRINSIC_OVERLOAD_TABLE
#include "vc/InternalIntrinsics/InternalIntrinsicDescription.gen"
#undef GET_INTRINSIC_OVERLOAD_TABLE
}

/// This defines the "getAttributes(ID id)" method.
#define GET_INTRINSIC_ATTRIBUTES
#include "vc/InternalIntrinsics/InternalIntrinsicDescription.gen"
#undef GET_INTRINSIC_ATTRIBUTES

/// Table of per-target intrinsic name tables.
#define GET_INTRINSIC_TARGET_DATA
#include "vc/InternalIntrinsics/InternalIntrinsicDescription.gen"
#undef GET_INTRINSIC_TARGET_DATA

bool InternalIntrinsic::isOverloadedArg(unsigned IntrinID, unsigned ArgNum) {
#define GET_INTRINSIC_OVERLOAD_ARGS_TABLE
#include "vc/InternalIntrinsics/InternalIntrinsicDescription.gen"
#undef GET_INTRINSIC_OVERLOAD_ARGS_TABLE
}

bool InternalIntrinsic::isOverloadedRet(unsigned IntrinID) {
#define GET_INTRINSIC_OVERLOAD_RET_TABLE
#include "vc/InternalIntrinsics/InternalIntrinsicDescription.gen"
#undef GET_INTRINSIC_OVERLOAD_RET_TABLE
}

/// Find the segment of \c IntrinsicNameTable for intrinsics with the same
/// target as \c Name, or the generic table if \c Name is not target specific.
///
/// Returns the relevant slice of \c IntrinsicNameTable
static ArrayRef<const char *> findTargetSubtable(StringRef Name) {

  IGC_ASSERT(Name.startswith("llvm.vc.internal."));

  ArrayRef<IntrinsicTargetInfo> Targets(TargetInfos);
  StringRef Target = "vc.internal";
  auto It = std::lower_bound(Targets.begin(), Targets.end(), Target,
                             [](const IntrinsicTargetInfo &TI,
                                StringRef Target) { return TI.Name < Target; });
  // We've either found the target or just fall back to the generic set, which
  // is always first.
  const auto &TI = It != Targets.end() && It->Name == Target ? *It : Targets[0];
  return makeArrayRef(&InternalIntrinsicNameTable[1] + TI.Offset, TI.Count);
}

static InternalIntrinsic::ID lookupInternalIntrinsicID(StringRef Name) {
  ArrayRef<const char *> NameTable = findTargetSubtable(Name);
  int Idx = Intrinsic::lookupLLVMIntrinsicByName(NameTable, Name);
  if (Idx == -1) {
    return InternalIntrinsic::not_internal_intrinsic;
  }
  IGC_ASSERT(Idx >= 0);

  // Intrinsic IDs correspond to the location in IntrinsicNameTable, but we have
  // an index into a sub-table.
  int Adjust = NameTable.data() - InternalIntrinsicNameTable;
  auto ID = static_cast<InternalIntrinsic::ID>(
      Idx + Adjust + InternalIntrinsic::not_internal_intrinsic);

  [[maybe_unused]] StringRef NameFromNameTable{NameTable[Idx]};

  // If the intrinsic is not overloaded, require an exact match. If it is
  // overloaded, require either exact or prefix match.
  IGC_ASSERT(Name.size() >= NameFromNameTable.size() &&
             "Expected either exact or prefix match");
  IGC_ASSERT(
      (Name.size() == NameFromNameTable.size()) ||
      (isOverloaded(ID) && "Non-overloadable intrinsic was overloaded!"));
  return ID;
}

/// getInternalName(ID) - Return the LLVM name for a Internal intrinsic
static std::string getInternalName(InternalIntrinsic::ID id,
                                   ArrayRef<Type *> Tys) {
  IGC_ASSERT(InternalIntrinsic::isInternalIntrinsic(id) &&
             "Invalid intrinsic ID!");
  IGC_ASSERT(Tys.empty() || (isOverloaded(id) &&
                             "Non-overloadable intrinsic was overloaded!"));
  id = static_cast<InternalIntrinsic::ID>(
      id - InternalIntrinsic::not_internal_intrinsic);
  std::string Result(InternalIntrinsicNameTable[id]);
  for (Type *Ty : Tys) {
    Result += "." + getMangledTypeStr(Ty);
  }
  return Result;
}

/// getInternalType(ID) - Return the function type for an
/// intrinsic.
static FunctionType *getInternalType(LLVMContext &Context,
                                     InternalIntrinsic::ID id,
                                     ArrayRef<Type *> Tys) {
  SmallVector<Intrinsic::IITDescriptor, 8> Table;
  getIntrinsicInfoTableEntries(id, Table);

  ArrayRef<Intrinsic::IITDescriptor> TableRef = Table;
  Type *ResultTy = DecodeFixedType(TableRef, Tys, Context);

  SmallVector<Type *, 8> ArgTys;
  while (!TableRef.empty())
    ArgTys.push_back(DecodeFixedType(TableRef, Tys, Context));

  // DecodeFixedType returns Void for IITDescriptor::Void and
  // IITDescriptor::VarArg If we see void type as the type of the last argument,
  // it is vararg intrinsic
  if (!ArgTys.empty() && ArgTys.back()->isVoidTy()) {
    ArgTys.pop_back();
    return FunctionType::get(ResultTy, ArgTys, true);
  }
  return FunctionType::get(ResultTy, ArgTys, false);
}

/// resetInternalAttributes(F) - recalculates attributes
/// of a CM intrinsic by setting the default values (as per
/// intrinsic definition)
/// adds metadata if EnableInternalIntrinsicsCache
///
/// F is required to be a Internal intrinsic function
static void resetInternalAttributes(Function *F) {

  IGC_ASSERT(F);

  InternalIntrinsic::ID GXID = InternalIntrinsic::getInternalIntrinsicID(F);

  IGC_ASSERT(GXID != InternalIntrinsic::not_internal_intrinsic);

  // Since Function::isIntrinsic() will return true due to llvm. prefix,
  // Module::getOrInsertFunction fails to add the attributes. explicitly adding
  // the attribute to handle this problem. This since is setup on the function
  // declaration, attribute assignment is global and hence this approach
  // suffices.
  F->setAttributes(InternalIntrinsic::getAttributes(F->getContext(), GXID));

  // Cache intrinsic ID in metadata.
  if (EnableInternalIntrinsicsCache &&
      !F->hasMetadata(InternalIntrinsicMDName)) {
    LLVMContext &Ctx = F->getContext();
    auto *Ty = IntegerType::getInt32Ty(Ctx);
    auto *Cached = ConstantInt::get(Ty, GXID);
    auto *MD = MDNode::get(Ctx, {ConstantAsMetadata::get(Cached)});
    F->addMetadata(InternalIntrinsicMDName, *MD);
  }
}

InternalIntrinsic::ID
InternalIntrinsic::getInternalIntrinsicID(const Function *F) {
  IGC_ASSERT(F);
  llvm::StringRef Name = F->getName();
  if (!Name.startswith(getInternalIntrinsicPrefix())) {
    return InternalIntrinsic::not_internal_intrinsic;
  }

  // Check metadata cache.
  if (auto *MD = F->getMetadata(InternalIntrinsicMDName)) {
    IGC_ASSERT(MD->getNumOperands() == 1 && "Invalid intrinsic metadata");
    auto Val = cast<ValueAsMetadata>(MD->getOperand(0))->getValue();
    InternalIntrinsic::ID Id = static_cast<InternalIntrinsic::ID>(
        cast<ConstantInt>(Val)->getZExtValue());

    // we need to check that metadata is correct and can be actually used
    if (isInternalIntrinsic(Id)) {
      const char *NamePrefix =
          InternalIntrinsicNameTable[Id -
                                     InternalIntrinsic::not_internal_intrinsic];
      if (Name.startswith(NamePrefix))
        return Id;
    }
  }

  // Fallback to string lookup.
  auto ID = lookupInternalIntrinsicID(Name);
  IGC_ASSERT(ID != InternalIntrinsic::not_internal_intrinsic &&
             "Intrinsic not found!");
  return ID;
}

Function *InternalIntrinsic::getInternalDeclaration(Module *M,
                                                    InternalIntrinsic::ID id,
                                                    ArrayRef<Type *> Tys) {
  IGC_ASSERT(isInternalNonTrivialIntrinsic(id));
  IGC_ASSERT(Tys.empty() || (isOverloaded(id) &&
                             "Non-overloadable intrinsic was overloaded!"));

  auto InternalName = getInternalName(id, Tys);
  FunctionType *FTy = getInternalType(M->getContext(), id, Tys);
  Function *F = M->getFunction(InternalName);
  if (!F)
    F = Function::Create(FTy, GlobalVariable::ExternalLinkage, InternalName, M);

  resetInternalAttributes(F);
  return F;
}
