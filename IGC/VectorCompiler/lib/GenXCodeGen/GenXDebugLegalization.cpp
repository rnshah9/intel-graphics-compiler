/*========================== begin_copyright_notice ============================

Copyright (C) 2022 Intel Corporation

SPDX-License-Identifier: MIT

============================= end_copyright_notice ===========================*/

//
/// GenXDebugLegalization
/// -----------------
///
/// Modifies incoming metadata to generate valid debug info later on.
///
/// Operation of the pass
/// ^^^^^^^^^^^^^^^^^^^^^
///
/// Remove DW_OP_constu 4/DW_OP_swap/DW_OP_xderef constructs. These are
/// generated by the FE compiler to annotate address space, which is not
/// used (directly) by the debugger.
///
//===----------------------------------------------------------------------===//
#include "GenX.h"
#include "GenXUtil.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"

#define DEBUG_TYPE "GENX_DEBUGLEGALIZATION"

using namespace llvm;
using namespace genx;

namespace {

// GenXDebugLegalization : reduce integer size
class GenXDebugLegalization : public FunctionPass {

public:
  static char ID;
  explicit GenXDebugLegalization() : FunctionPass(ID) { }
  StringRef getPassName() const override { return "GenX debug legalization"; }
  void getAnalysisUsage(AnalysisUsage &AU) const override;
  bool runOnFunction(Function &F) override;

private:
  bool extractAddressClass(Function& F);
  bool Modified;
};

} // end anonymous namespace

char GenXDebugLegalization::ID = 0;
namespace llvm { void initializeGenXDebugLegalizationPass(PassRegistry &); }
INITIALIZE_PASS_BEGIN(GenXDebugLegalization, "GenXDebugLegalization", "GenXDebugLegalization", false, false)
INITIALIZE_PASS_END(GenXDebugLegalization, "GenXDebugLegalization", "GenXDebugLegalization", false, false)

FunctionPass *llvm::createGenXDebugLegalizationPass() {
  initializeGenXDebugLegalizationPass(*PassRegistry::getPassRegistry());
  return new GenXDebugLegalization;
}

void GenXDebugLegalization::getAnalysisUsage(AnalysisUsage &AU) const
{
  AU.setPreservesCFG();
}

// Detect instructions with an address class pattern. Then remove all opcodes of this pattern from
// this instruction's last operand (metadata of DIExpression).
// Pattern: !DIExpression(DW_OP_constu, 4, DW_OP_swap, DW_OP_xderef)
bool GenXDebugLegalization::extractAddressClass(Function& F)
{
  DIBuilder di(*F.getParent());

  for (auto& bb : F) {
    for (auto& pInst : bb) {
      if (auto* DI = dyn_cast<DbgVariableIntrinsic>(&pInst)) {
        const DIExpression* DIExpr = DI->getExpression();
        llvm::SmallVector<uint64_t, 5> newElements;
        for (auto I = DIExpr->expr_op_begin(), E = DIExpr->expr_op_end(); I != E; ++I) {
          if (I->getOp() == dwarf::DW_OP_constu) {
            auto patternI = I;
            if (++patternI != E && patternI->getOp() == dwarf::DW_OP_swap &&
                ++patternI != E && patternI->getOp() == dwarf::DW_OP_xderef) {
              I = patternI;
              continue;
            }
          }
          I->appendToVector(newElements);
        }

        if (newElements.size() < DIExpr->getNumElements()) {
          DIExpression* newDIExpr = di.createExpression(newElements);
#if LLVM_VERSION_MAJOR < 13
          DI->setArgOperand(2, MetadataAsValue::get(newDIExpr->getContext(), newDIExpr));
#else
          DI->setExpression(newDIExpr);
#endif
          Modified = true;
        }
      }
    }
  }
  return Modified;
}

/***********************************************************************
 * GenXDebugLegalization::runOnFunction : process one function to
 *    reduce integer size where possible
 */
bool GenXDebugLegalization::runOnFunction(Function &F)
{
  Modified = false;
  extractAddressClass(F);
  return Modified;
}

