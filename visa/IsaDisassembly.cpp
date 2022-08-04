/*========================== begin_copyright_notice ============================

Copyright (C) 2017-2021 Intel Corporation

SPDX-License-Identifier: MIT

============================= end_copyright_notice ===========================*/

/*
 * ISA IR Disassembler
 *
 * This library is designed to be extremely reusable and general in nature, and as a result
 * the following ISA IR disassembly code primarily uses the following IR and data types:
 *
 * - common_isa_header
 * - kernel_format_t
 * - attribute_info_t
 * - VISA_opnd
 * - vector_opnd
 * - raw_opnd
 * - CISA_INST
 * - std::list<CISA_INST*>
 *
 * and prints them as human readable text to an isaasm file.
 *
 * Use of any other data types should be discussed by several members of the CM jitter team before hand.
 *
 */

#include "IGC/common/StringMacros.hpp"
#include <algorithm>
#include <cstdint>
#include <cctype>
#include <list>
#include <sstream>
#include <string>

#include "visa_igc_common_header.h"
#include "common.h"
#include "Mem_Manager.h"
#include "Common_ISA.h"
#include "Common_ISA_framework.h"
#include "Common_ISA_util.h"
#include "VISADefines.h"
#include "IsaDisassembly.h"
#include "Option.h"
#include "JitterDataStruct.h"
#include "VISABuilderAPIDefinition.h"
#include "PreDefinedVars.h"
#include "VISAKernel.h"
#include "PlatformInfo.h"

using namespace vISA;

/// Output flags.
_THREAD bool g_shortRegionPrint  = false; /// Use shorthand names for common regions.
_THREAD bool g_inlineTypePrint   = false; /// Print the type information with operands.
_THREAD bool g_prettyPrint       = true ; /// Line up the comments.
_THREAD bool g_ignorelocs        = false; /// Ignore printing LOCs.
_THREAD bool g_noinstid          = false; /// Ignore printing instruction id comments.

const char *printAsmName(const print_format_provider_t* header)
{
    for (unsigned i = 0; i < header->getAttrCount(); i++)
    {
        const char* attrName = header->getString(header->getAttr(i)->nameIndex);
        if (Attributes::isAttribute(Attributes::ATTR_OutputAsmPath, attrName))
            return header->getAttr(i)->value.stringVal;
    }

    return "";
}

const char *getGenVarName(int id, const print_format_provider_t& header)
{
    int numPredefined = Get_CISA_PreDefined_Var_Count();
    if (id < numPredefined)
    {
        return getPredefinedVarString(mapExternalToInternalPreDefVar(id));
    }
    else
    {
        MUST_BE_TRUE((id - numPredefined) < (int) header.getVarCount(),
            "invalid vISA general variable id");
        return header.getString(header.getVar(id - numPredefined)->name_index);
    }
}

static std::string printSurfaceName(uint32_t declID)
{
    std::stringstream sstr;
    unsigned numPreDefinedSurf = Get_CISA_PreDefined_Surf_Count();
    if (declID < numPreDefinedSurf)
    {
        sstr << vISAPreDefSurf[declID].name;
    }
    else
    {
        sstr << "T" << declID;
    }

    return sstr.str();
}

std::string printVariableDeclName(
    const print_format_provider_t* header,
    unsigned declID,
    const Options *options,
    Common_ISA_State_Opnd_Class operand_prefix_kind = NOT_A_STATE_OPND)
{
    MUST_BE_TRUE(header, "Argument Exception: argument header is NULL.");
    std::stringstream sstr;

    unsigned numPreDefinedVars = Get_CISA_PreDefined_Var_Count();
    if (operand_prefix_kind == NOT_A_STATE_OPND)
    {
        sstr << getGenVarName(declID, *header);
    }
    else
    {
        switch (operand_prefix_kind)
        {   case STATE_OPND_SURFACE : sstr << printSurfaceName(declID); break;
            case STATE_OPND_SAMPLER : sstr << "S"   << declID; break;
            default                 :
                if (options->getuInt32Option(vISA_PlatformSet) == GENX_NONE)
                {
                    // If platform is not set then dcl instances are
                    // not created causing a crash. So print dcl name
                    // the old way.
                    if (declID < numPreDefinedVars)
                    {
                        sstr << "V" << declID;
                    }
                    else
                    {
                        declID -= numPreDefinedVars;
                        const var_info_t *var = header->getVar(declID);
                        std::string name = header->getString(var->name_index);
                        sstr << name;
                    }
                }
                else
                {

                    if (declID < numPreDefinedVars)
                    {
                        sstr << "V" << declID;
                    }
                    else
                    {
                        G4_Declare* aliasDcl = header->getVar(declID - numPreDefinedVars)->dcl;
                        unsigned int aliasOff = 0;
                        std::string type = TypeSymbol(aliasDcl->getElemType());

                        while (aliasDcl->getAliasDeclare() != NULL)
                        {
                            aliasOff += aliasDcl->getAliasOffset();
                            aliasDcl = aliasDcl->getAliasDeclare();
                        }

                        // aliasDcl is top most dcl with aliasOff
                        // Lets find out declID of aliasDcl
                        for (unsigned int i = 0; i < header->getVarCount(); i++)
                        {
                            if (header->getVar(i)->dcl == aliasDcl)
                            {
                                declID = i + numPreDefinedVars;
                                break;
                            }
                        }

                        sstr << "V"   << declID << "_" << type;
                        if (aliasOff != 0)
                        {
                            sstr << "_" << aliasOff;
                        }
                    }
                }

                break;
        }
    }
    return sstr.str();
}

static std::string printRegion(uint16_t region)
{
    std::stringstream sstr;
    Common_ISA_Region_Val v_stride = (Common_ISA_Region_Val)(region & 0xF);
    Common_ISA_Region_Val width = (Common_ISA_Region_Val)((region >> 4) & 0xF);
    Common_ISA_Region_Val h_stride = (Common_ISA_Region_Val)((region >> 8) & 0xF);

    if (width == REGION_NULL)
    {
        //dst operand, only have horizontal stride
        sstr << "<" << Common_ISA_Get_Region_Value(h_stride) << ">";
    }
    else if (v_stride == REGION_NULL)
    {
        // VxH mode for indirect operand
        sstr << "<" << Common_ISA_Get_Region_Value(width) << "," << Common_ISA_Get_Region_Value(h_stride) << ">";
    }
    else
    {
        if (g_shortRegionPrint                         &&
            0 == Common_ISA_Get_Region_Value(v_stride) &&
            1 == Common_ISA_Get_Region_Value(width)    &&
            0 == Common_ISA_Get_Region_Value(h_stride))
        {
            sstr << ".s";
        }
        else if (g_shortRegionPrint &&
                Common_ISA_Get_Region_Value(v_stride) ==
                Common_ISA_Get_Region_Value(width) &&
                1 == Common_ISA_Get_Region_Value(h_stride))
        {
            sstr << ".v";
        }
        else
        {
            sstr << "<" << Common_ISA_Get_Region_Value(v_stride) << ";" << Common_ISA_Get_Region_Value(width) << "," << Common_ISA_Get_Region_Value(h_stride) << ">";
        }
    }

    return sstr.str();
}

std::string printVectorOperand(
    const print_format_provider_t* header,
    const VISA_opnd* parentOpnd,
    const Options *opt,
    bool showRegion)
{
    std::stringstream sstr;

    auto opnd = parentOpnd->_opnd.v_opnd;
    MUST_BE_TRUE(header, "Argument Exception: argument header is NULL.");

    VISA_Modifier modifier = (VISA_Modifier)((opnd.tag >> 3) & 0x7);

    /// .sat is dumped with the opcode
    if (modifier == MODIFIER_SAT)
        modifier =  MODIFIER_NONE;

    sstr << " ";
    switch (opnd.tag & 0x7)
    {
        case OPERAND_GENERAL:
        {
            sstr << Common_ISA_Get_Modifier_Name(modifier)
                << printVariableDeclName(header, opnd.getOperandIndex(), opt, NOT_A_STATE_OPND);

            if ((!g_shortRegionPrint)                      ||
                (!(opnd.opnd_val.gen_opnd.row_offset == 0 &&
                (((opnd.opnd_val.gen_opnd.col_offset == 0))))))
            {
                sstr << "("
                     << (unsigned)opnd.opnd_val.gen_opnd.row_offset << ","
                     << (unsigned)opnd.opnd_val.gen_opnd.col_offset << ")";
            }

            if (showRegion)
            {
                sstr << printRegion(opnd.opnd_val.gen_opnd.region);
            }

            break;
        }
        case OPERAND_ADDRESS:
        {
            sstr << Common_ISA_Get_Modifier_Name(modifier) << "A" << opnd.opnd_val.addr_opnd.index
                 << "(" << (unsigned)opnd.opnd_val.addr_opnd.offset << ")<"
                 << Get_VISA_Exec_Size((VISA_Exec_Size)(opnd.opnd_val.addr_opnd.width & 0xF)) << ">";
            break;
        }
        case OPERAND_PREDICATE:
        {
            sstr << Common_ISA_Get_Modifier_Name(modifier) << "P" << parentOpnd->convertToPred().getId();
            break;
        }
        case OPERAND_INDIRECT:
        {
            sstr << Common_ISA_Get_Modifier_Name(modifier) << "r[A" << opnd.opnd_val.indirect_opnd.index
                 << "("
                 << (unsigned)opnd.opnd_val.indirect_opnd.addr_offset     << "),"
                 << (short)   opnd.opnd_val.indirect_opnd.indirect_offset << "]" ;
            sstr << printRegion(opnd.opnd_val.indirect_opnd.region);
            VISA_Type type = (VISA_Type)(opnd.opnd_val.indirect_opnd.bit_property & 0xf);
            sstr << ":" << CISATypeTable[type].typeName;
            break;
        }
        case OPERAND_ADDRESSOF:
        {
            sstr << "&" << printVariableDeclName(header, opnd.getOperandIndex(), opt, NOT_A_STATE_OPND);
            if (opnd.opnd_val.addressof_opnd.addr_offset >= 0) {
                sstr << "[" << (((short)opnd.opnd_val.addressof_opnd.addr_offset)) << "]";
            }
            break;
        }
        case OPERAND_IMMEDIATE:
        {
            VISA_Type type = (VISA_Type)(opnd.opnd_val.const_opnd.type & 0xF);
            if (type == ISA_TYPE_DF)
                sstr << "0x" << std::hex <<
                    *((uint64_t*) &opnd.opnd_val.const_opnd._val.dval) <<
                    ":" << CISATypeTable[type].typeName << std::dec;
            else if (type == ISA_TYPE_Q || type == ISA_TYPE_UQ)
                sstr << "0x" << std::hex << opnd.opnd_val.const_opnd._val.lval <<
                        ":" << CISATypeTable[type].typeName << std::dec;
            else
                sstr << "0x" << std::hex << opnd.opnd_val.const_opnd._val.ival <<
                    ":" << CISATypeTable[type].typeName << std::dec;
            break;
        }
        case OPERAND_STATE:
        {
            sstr << printVariableDeclName(header, opnd.getOperandIndex(), opt, (Common_ISA_State_Opnd_Class)opnd.opnd_val.state_opnd.opnd_class)
                 << "(" << (unsigned)opnd.opnd_val.state_opnd.offset << ")";
            break;
        }
        default: ASSERT_USER(false, "Attempted to dump an invalid or unimplemented vector operand type.");
    }

    return sstr.str();
}

std::string printRawOperand(
    const print_format_provider_t* header,
    const raw_opnd& opnd,
    const Options *opt)
{
    MUST_BE_TRUE(header, "Argument Exception: argument header is NULL.");
    std::stringstream sstr;
    sstr << " " << printVariableDeclName(header, opnd.index, opt, NOT_A_STATE_OPND) << "." << opnd.offset;
    return sstr.str();
}

static std::string printOperand(
    const print_format_provider_t* header,
    const CISA_INST* inst,
    unsigned i,
    const Options *opt)
{
    MUST_BE_TRUE(header, "Argument Exception: argument header is NULL.");
    MUST_BE_TRUE(inst  , "Argument Exception: argument inst   is NULL.");
    MUST_BE_TRUE(inst->opnd_count > i, "No such operand, i, for instruction inst.");
    std::stringstream sstr;
    switch (getOperandType(inst, i))
    {
        case CISA_OPND_OTHER:  sstr << (getPrimitiveOperand<unsigned>             (inst, i)); break;
        case CISA_OPND_VECTOR: sstr << printVectorOperand(header, inst->opnd_array[i], opt, true); break;
        case CISA_OPND_RAW:    sstr << printRawOperand   (header, getRawOperand   (inst, i), opt); break;
        default:               MUST_BE_TRUE(false, "Invalid operand type.");
    }
    return sstr.str();
}

static void encodeStringLiteral(std::stringstream &ss, const char *str) {
  ss << '"';
  for (size_t i = 0, slen = strlen(str); i < slen; i++) {
      switch (str[i]) { // unsigned so >0x7F doesn't sign ext.
      case '\a': ss << '\\'; ss << 'a'; break;
      case '\b': ss << '\\'; ss << 'b'; break;
      case 0x1B: ss << '\\'; ss << 'e'; break;
      case '\f': ss << '\\'; ss << 'f'; break;
      case '\n': ss << '\\'; ss << 'n'; break;
      case '\r': ss << '\\'; ss << 'r'; break;
      case '\t': ss << '\\'; ss << 't'; break;
      case '\v': ss << '\\'; ss << 'v'; break;
      //
      case '\'': ss << '\\'; ss << '\''; break;
      case '"':  ss << '\\'; ss << '"'; break;
      //
      case '\\': ss << '\\'; ss << '\\'; break;
      default:
          if (std::isprint((unsigned char)str[i])) {
              ss << str[i];
          } else {
              ss << "\\x" << std::setw(2) << std::setfill('0') << std::hex <<
                  (unsigned)((unsigned char)str[i]);
          }
      }
  }
  ss << '"';
}

// Return true if str matches IDENT: [[:alpha:]_][[:alnum:]_]*
static bool isIdentifier(const char *str) {
  if (str == nullptr || *str == '\0')
      return false;
  if (!std::isalpha((unsigned char)str[0]) && str[0] != '_')
      return false;
  for (size_t i = 1; str[i] != '\0'; i++) {
      if (!std::isalnum((unsigned char)str[i]) && str[i] != '_')
          return false;
  }
  return true;
}

std::string printAttributes(
    const print_format_provider_t* header,
    const int attr_count,
    const attribute_info_t* attrs)
{
    std::stringstream sstr;

    if (attr_count > 0)
    {
        // decl's attr in the form: attr=<attr0, attr1, ...>
        sstr << " attrs={" << printOneAttribute(header, &attrs[0]);
        for (int j = 1; j < attr_count; j++)
        {
            sstr << ", " << printOneAttribute(header, &attrs[j]);
        }
        sstr << "}";
    }

    return sstr.str();
}

std::string printOneAttribute(
    const print_format_provider_t* kernel,
    const attribute_info_t* attr)
{
    std::stringstream sstr;
    const char* attrName = kernel->getString(attr->nameIndex);
    Attributes::ID aID = Attributes::getAttributeID(attrName);
    MUST_BE_TRUE(aID != Attributes::ATTR_INVALID, "Invalid Attribute names!");

    sstr << attrName;
    if (attr->isInt && Attributes::isInt32(aID)) {
        sstr << "=";
        if (Attributes::isAttribute(Attributes::ATTR_Target, attrName)) {
            switch (attr->value.intVal) {
            case VISA_CM: sstr << "\"cm\""; break;
            case VISA_3D: sstr << "\"3d\""; break;
            default:
              sstr << attr->value.intVal;
            }
        } else {
            sstr << attr->value.intVal;
        }
    } else if (Attributes::isCStr(aID) && attr->size > 0) {
        sstr << "=";
        encodeStringLiteral(sstr, attr->value.stringVal);
    }

    return sstr.str();
}

std::string printPredicateDecl(
    const print_format_provider_t* header, unsigned declID)
{
    MUST_BE_TRUE(header, "Argument Exception: argument header is NULL.");
    std::stringstream sstr;

    const pred_info_t* pred = header->getPred(declID);
    sstr << ".decl P"
         << declID + COMMON_ISA_NUM_PREDEFINED_PRED
         << " "
         << "v_type=P "
         << "num_elts=" << pred->num_elements;

    sstr << printAttributes(header, pred->attribute_count, pred->attributes);
    return sstr.str();
}

std::string printAddressDecl(
    const common_isa_header& isaHeader,
    const print_format_provider_t* header,
    unsigned declID)
{
    MUST_BE_TRUE(header, "Argument Exception: argument header is NULL.");
    std::stringstream sstr;

    const addr_info_t* addr = header->getAddr(declID);
    sstr << ".decl A"
         << declID
         << " "
         << "v_type=A "
         << "num_elts=" << addr->num_elements;

    sstr << printAttributes(header, addr->attribute_count, addr->attributes);

    return sstr.str();
}

std::string printSamplerDecl(
    const print_format_provider_t* header, unsigned declID)
{
    MUST_BE_TRUE(header, "Argument Exception: argument header is NULL.");
    std::stringstream sstr;
    const state_info_t* info = header->getSampler(declID);

    sstr << ".decl S" << declID << " v_type=S";
    sstr << " num_elts=" << info->num_elements;
    sstr << " v_name=" << header->getString(info->name_index);
    sstr << printAttributes(header, info->attribute_count, info->attributes);
    return sstr.str();
}

std::string printSurfaceDecl(
    const print_format_provider_t* header,
    unsigned declID,
    unsigned numPredefinedSurfaces)
{
    MUST_BE_TRUE(header, "Argument Exception: argument header is NULL.");
    std::stringstream sstr;
    const state_info_t* info = header->getSurface(declID);

    sstr << ".decl T" << declID + numPredefinedSurfaces << " v_type=T";
    sstr << " num_elts=" << info->num_elements;
    sstr << " v_name=" << header->getString(info->name_index);
    sstr << printAttributes(header, info->attribute_count, info->attributes);
    return sstr.str();
}

std::string printFuncInput(
    const print_format_provider_t* header,
    unsigned declID,
    bool isKernel,
    const Options* options)
{
    MUST_BE_TRUE(header, "Argument Exception: argument header is NULL.");
    std::stringstream sstr;

    const input_info_t* input = header->getInput(declID);
    if (!isKernel)
    {
        sstr << ".parameter " /* function */;
    }
    else if (!input->getImplicitKind())
    {
        sstr << ".input " /* kernel */;
    }
    else
    {
        sstr << input->getImplicitKindString() << " ";
    }

    if (INPUT_GENERAL == input->getInputClass())
    {
        sstr << printVariableDeclName(header, input->index, options);
    }
    else
    {
        const char* Input_Class_String[] = { "V", "S", "T" };
        sstr << Input_Class_String[input->getInputClass()] << input->index;
    }

    if (isKernel)
        sstr << " offset=" << input->offset;

    sstr << " size=" << input->size;

    return sstr.str();
}

// declID is in the range of [0..#user-var], pre-defnied are not included
std::string printVariableDecl(
    const print_format_provider_t* header,
    unsigned declID,
    const Options *options)
{
    MUST_BE_TRUE(header, "Argument Exception: argument header is NULL.");
    std::stringstream sstr;

    const var_info_t* var = header->getVar(declID);
    VISA_Type  isa_type = (VISA_Type)((var->bit_properties) & 0xF);
    VISA_Align align = var->getAlignment();

    unsigned numPreDefinedVars = Get_CISA_PreDefined_Var_Count();
    sstr << ".decl " << printVariableDeclName(header, declID + numPreDefinedVars, options)
        << " v_type=G"
        << " type=" << CISATypeTable[isa_type].typeName
        << " num_elts=" << var->num_elements;

    if (align != ALIGN_UNDEF)
        sstr << " align=" << Common_ISA_Get_Align_Name(align);

    if (var->alias_index)
    {
        sstr << " alias=<";
        sstr << printVariableDeclName(header, var->alias_index, options);
        sstr << ", " << var->alias_offset << ">";
    }

    sstr << printAttributes(header, var->attribute_count, var->attributes);

    return sstr.str();
}

static std::string printExecutionSize(
    uint8_t opcode, uint8_t execSize, uint8_t subOp = 0)
{
    std::stringstream sstr;

    if (hasExecSize((ISA_Opcode)opcode, subOp))
    {
        sstr << "(";
        uint8_t emsk = ((execSize >> 0x4) & 0xF);
        sstr << emask_str[emsk] << ", ";
        sstr << (unsigned) Get_VISA_Exec_Size((VISA_Exec_Size)(execSize & 0xF));
        sstr << ")";
    }

    if (g_shortRegionPrint && !strcmp("(1)", sstr.str().c_str()))
        return "   ";

    return sstr.str();
}

// execution size is formatted differently for scatter/gather/scatter4/gather4/scatter4_typed/gather4_typed
static std::string printExecutionSizeForScatterGather(uint8_t sizeAndMask)
{
    std::stringstream sstr;
    sstr << "(";
    VISA_EMask_Ctrl emask =
        (VISA_EMask_Ctrl)((sizeAndMask >> 0x4) & 0xF);
    sstr << emask_str[emask] << ", ";

    unsigned execSize = 0;
    switch (sizeAndMask & 0x3)
    {
    case 0:
        execSize = 8;
        break;
    case 1:
        execSize = 16;
        break;
    case 2:
        execSize = 1;
        break;
    default:
        ASSERT_USER(false, "illegal execution size for scatter/gather message");
    }
    sstr << execSize;
    sstr << ")";

    return sstr.str();
}

static std::string printPredicate(uint8_t opcode, PredicateOpnd predOpnd)
{
    std::stringstream sstr;

    if (hasPredicate((ISA_Opcode)opcode) && !predOpnd.isNullPred())
    {
        sstr << "(";
        if (predOpnd.isInverse()) sstr << "!";
        sstr << "P" << predOpnd.getId();

        VISA_PREDICATE_CONTROL control = predOpnd.getControl();
        switch (control)
        {
            case PRED_CTRL_ANY:
                sstr << ".any";
                break;
            case PRED_CTRL_ALL:
                sstr << ".all";
                break;
            default:
                break;
        }

        sstr << ") ";
    }

    return sstr.str();
}

static void printAtomicSubOpc(std::stringstream &sstr, uint8_t value)
{
    VISAAtomicOps op = static_cast<VISAAtomicOps>(value & 0x1F);
    sstr << "." << CISAAtomicOpNames[op];

    if ((value >> 5) == 1)
    {
        sstr << ".16";
    }
    else if ((value >> 6) == 1)
    {
        sstr << ".64";
    }
}

static std::string printInstructionSVM(
    const print_format_provider_t* header,
    const CISA_INST* inst,
    const Options *opt)
{
    unsigned i = 0;
    std::stringstream sstr;

    SVMSubOpcode subOpcode = (SVMSubOpcode)getPrimitiveOperand<uint8_t>(inst, i++);

    if ((subOpcode != SVM_BLOCK_LD) && (subOpcode != SVM_BLOCK_ST)) {
        sstr << printPredicate(inst->opcode, inst->pred);
    }

    sstr << "svm_";
    switch (subOpcode)
    {
        case SVM_BLOCK_ST:
        case SVM_BLOCK_LD:
            {
             sstr << "block_" << (subOpcode == SVM_BLOCK_ST ? "st" : "ld");
             uint8_t properties = getPrimitiveOperand<uint8_t>(inst, i++);
             if (properties & 8)
                 sstr << ".unaligned";
             VISA_Oword_Num numOwords = (VISA_Oword_Num) (properties & 0x7);
             sstr << " (" << Get_VISA_Oword_Num(numOwords) << ")";
             break;
            }
        case SVM_GATHER:
        case SVM_SCATTER:
        {
             sstr << (subOpcode == SVM_GATHER ? "gather" : "scatter");
             uint8_t block_size = getPrimitiveOperand<uint8_t>(inst, i++);
             uint8_t num_blocks = getPrimitiveOperand<uint8_t>(inst, i++);
             sstr << "." << Get_Common_ISA_SVM_Block_Size((VISA_SVM_Block_Type)block_size);
             sstr << "." << Get_Common_ISA_SVM_Block_Num((VISA_SVM_Block_Num)num_blocks);
             sstr << " " << printExecutionSize(inst->opcode, inst->execsize, subOpcode);
             break;
        }
        case SVM_ATOMIC:
        {
            sstr << "atomic";
            /// TODO: Need platform information for this to work.

            printAtomicSubOpc(sstr, getPrimitiveOperand<uint8_t>(inst, i++));
            sstr << " " << printExecutionSize(inst->opcode, inst->execsize, subOpcode);
            /// element offset
            sstr << printOperand(header, inst, i++, opt);
            /// DWORD_ATOMIC is weird and has the text version
            /// putting the dst operand before the src operands.
            std::stringstream sstr1;
            /// src0
            sstr1 << printOperand(header, inst, i++, opt);
            /// src1
            sstr1 << printOperand(header, inst, i++, opt);
            /// message operand (src or dst)
            sstr << printOperand(header, inst, i++, opt);
            sstr << sstr1.str();
            break;
        }
        case SVM_GATHER4SCALED:
        case SVM_SCATTER4SCALED:
        {
            sstr << (subOpcode == SVM_GATHER4SCALED ? "gather4scaled" : "scatter4scaled");
            unsigned chMask = getPrimitiveOperand<uint8_t>(inst, i++);
            // scale is ignored (MBZ)
            (void) getPrimitiveOperand<uint16_t>(inst, i++);
            sstr << "." << channel_mask_str[chMask];
            sstr << " " << printExecutionSize(inst->opcode, inst->execsize, subOpcode);
            sstr << printOperand(header, inst, i++, opt);
            sstr << printOperand(header, inst, i++, opt);
            sstr << printOperand(header, inst, i++, opt);
            break;
        }
        default:
             ASSERT_USER(false, "Unimplemented or Illegal SVM Sub Opcode.");
    }

    for (; i < inst->opnd_count; i++)
        sstr << printOperand(header, inst, i, opt);

    return sstr.str();
}

static std::string printInstructionCommon(
    const print_format_provider_t* header,
    const CISA_INST* inst,
    const Options *opt)
{
    ISA_Opcode opcode = (ISA_Opcode)inst->opcode;

    // TODO: Revisit to see if there's a better way to access platform info in
    // this file. Now it should be fine to get platform and PlatformInfo from
    // the option as this is not a performance critical path.
    TARGET_PLATFORM platform =
        static_cast<TARGET_PLATFORM>(opt->getuInt32Option(vISA_PlatformSet));
    const PlatformInfo* platInfo = PlatformInfo::LookupPlatformInfo(platform);
    ASSERT_USER(platInfo != nullptr, "Failed to look up platform");

    std::stringstream sstr;
    sstr << printPredicate(inst->opcode, inst->pred);

    unsigned i = 0;

    /// Print opcode
    if (opcode == ISA_FMINMAX)
    {
        CISA_MIN_MAX_SUB_OPCODE sub_opcode = (CISA_MIN_MAX_SUB_OPCODE)getPrimitiveOperand<uint8_t>(inst, i++);
        sstr << (sub_opcode == CISA_DM_FMIN ? "min" : "max");
    }
    else
    {
        sstr << ISA_Inst_Table[opcode].str;
    }

    if (ISA_Inst_Sync != ISA_Inst_Table[opcode].type)
    {
        unsigned int Count = inst->opnd_count;

        if (ISA_Inst_Compare == ISA_Inst_Table[opcode].type)
        {
            uint8_t relOp = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << (((relOp >> 7) & 0x1) ? "n" : ""); /// INFO: cmpn opcode print support here.
            sstr << "." << Rel_op_str[(unsigned)(relOp & 0x7)];
        }
        else if (opcode == ISA_BFN)
        {
            // print BooleanFuncCtrl right after op name
            sstr << ".x" << std::hex << (uint32_t)(getPrimitiveOperand<uint8_t>(inst, Count-1)) << std::dec;
            // The following shall skip booleanFuncCtrl opnd
            --Count;
        }

        if (ISA_Inst_Arith   == ISA_Inst_Table[opcode].type ||
            ISA_Inst_Mov     == ISA_Inst_Table[opcode].type ||
            ISA_Inst_Logic   == ISA_Inst_Table[opcode].type ||
            ISA_Inst_Address == ISA_Inst_Table[opcode].type ||
            ISA_Inst_Compare == ISA_Inst_Table[opcode].type)
        {
            bool saturate = (((VISA_Modifier)((getVectorOperand(inst, i).tag >> 3) & 0x7)) == MODIFIER_SAT);
            sstr << (saturate ? ".sat" : "");
        }

        sstr << " " << printExecutionSize(inst->opcode, inst->execsize);

        if (opcode == ISA_GOTO)
        {
            uint16_t label_id = getPrimitiveOperand<uint16_t>(inst, i++);
            sstr << " " << header->getString(header->getLabel(label_id)->name_index);
        }

        for (; i < Count; i++)
        {

            if (opcode == ISA_ADDR_ADD && i == 1) /// Only for src0 of addr_add
            {
                const vector_opnd& curOpnd = getVectorOperand(inst, i);

                if (curOpnd.getOperandClass() == OPERAND_ADDRESS)
                {
                    sstr << printVectorOperand(header, inst->opnd_array[i], opt, true);
                }
                else
                {
                    sstr << " " << Common_ISA_Get_Modifier_Name((VISA_Modifier)((curOpnd.tag >> 3) & 0x7));

                    unsigned opnd_index = curOpnd.getOperandIndex();

                    if (curOpnd.getOperandClass() == OPERAND_GENERAL)
                    {
                        uint32_t numPredefined = Get_CISA_PreDefined_Var_Count();
                        VISA_Type type = opnd_index < numPredefined ?
                            getPredefinedVarType(mapExternalToInternalPreDefVar(opnd_index)) :
                            header->getVar(opnd_index - numPredefined)->getType();
                        sstr << "&" << printVariableDeclName(header, opnd_index, opt);
                        int offset =
                            curOpnd.opnd_val.gen_opnd.col_offset * CISATypeTable[type].typeSize +
                            curOpnd.opnd_val.gen_opnd.row_offset * platInfo->numEltPerGRF<Type_UB>();
                        if (offset) {
                            sstr << "[" << offset << "]";
                        }
                    }
                    else if (curOpnd.getOperandClass() == OPERAND_STATE)
                    {
                        auto OpClass = curOpnd.getStateOpClass();
                        sstr << "&" << printVariableDeclName(header, opnd_index, opt, OpClass);
                        int offset =
                            curOpnd.opnd_val.state_opnd.offset * CISATypeTable[ISA_TYPE_D].typeSize;
                        if (offset) {
                            sstr << "[" << offset << "]";
                        }
                    }
                    else
                    {
                        /// TODO: Should we just assert here? Is this allowed?
                        sstr << printOperand(header, inst, i, opt);
                    }
                }
            }
            else
            {
                sstr << printOperand(header, inst, i, opt);
            }
        }
    }
    else
    {
        if (opcode == ISA_FENCE)
        {
            uint8_t mask = getPrimitiveOperand<uint8_t>(inst, i);

            const int SWFenceMask = 0x80;
            if (mask & SWFenceMask)
            {
                sstr << "_sw";
            }
            else
            {

#define BTI_MASK 0x20 // bit 5
                sstr << ((mask & BTI_MASK) ? "_local" : "_global");
                if (mask != 0)
                {
                    sstr << ".";
                    if (mask & 1) sstr << "E";
                    if (mask & (1 << 1)) sstr << "I";
                    if (mask & (1 << 2)) sstr << "S";
                    if (mask & (1 << 3)) sstr << "C";
                    if (mask & (1 << 4)) sstr << "R";
                    if (mask & (1 << 6)) sstr << "L1";
                }
            }
        }
        else if (opcode == ISA_WAIT)
        {
            sstr << printOperand(header, inst, 0, opt);
        }
        else if (opcode == ISA_SBARRIER)
        {
            uint8_t mode = getPrimitiveOperand<uint8_t>(inst, i);
            sstr << (mode ? ".signal" : ".wait");
        }
        else if (opcode == ISA_NBARRIER)
        {
            uint8_t mode = getPrimitiveOperand<uint8_t>(inst, i);
            bool isSignal = mode & 1;
            sstr << (isSignal ? ".signal" : ".wait");
            sstr << printOperand(header, inst, 1, opt);
            if (isSignal)
            {
                sstr << printOperand(header, inst, 2, opt);
            }
        }
    }

    return sstr.str();
}

static std::string printInstructionControlFlow(
    const print_format_provider_t* header,
    const CISA_INST* inst,
    const Options *opt)
{
    const ISA_Opcode opcode = (ISA_Opcode)inst->opcode;
    unsigned i = 0;
    uint16_t label_id  = 0;

    std::stringstream sstr;

    // Subroutine function name may contains "." or "$" generated by llvm when cloning
    // functions. Replace those to underline in visaasm so that it can be accepted by
    // visaasm reader.
    auto replaceInvalidCharToUnderline = [](std::string str) {
        std::replace(str.begin(), str.end(), '.', '_');
        std::replace(str.begin(), str.end(), '$', '_');
        return str;
    };

    if (ISA_SUBROUTINE == opcode || ISA_LABEL == opcode)
    {
        label_id = getPrimitiveOperand<uint16_t>(inst, i++);

        sstr << "\n";
        switch (opcode)
        {
            case ISA_SUBROUTINE:
            {
                 std::stringstream uniqueSuffixSstr; uniqueSuffixSstr << '_' << label_id;
                 std::string       uniqueSuffixStr = uniqueSuffixSstr.str();

                 std::string labelName(header->getString(header->getLabel(label_id)->name_index));

                 auto replacedName = replaceInvalidCharToUnderline(labelName);

                 sstr << ".function ";
                 encodeStringLiteral(sstr, (replacedName + uniqueSuffixStr).c_str());
                 // add a comment to specify the original name if the name change
                 if (replacedName != labelName) {
                     sstr << " /// Original Name: ";
                     encodeStringLiteral(sstr, (labelName + uniqueSuffixStr).c_str());
                 }
                 sstr << "\n\n" << replaceInvalidCharToUnderline(labelName) << uniqueSuffixStr;
                 break;
            }
            case ISA_LABEL:
            {
                 sstr << replaceInvalidCharToUnderline(header->getString(header->getLabel(label_id)->name_index));
                 break;
            }
            default:
                 break;
        }

        sstr << ":";
    }
    else if (opcode == ISA_CALL)
    {
        // Special handlling of CALL to distinguish fc_call from subroutine call
        label_id = getPrimitiveOperand<uint16_t>(inst, i++);

        const label_info_t* lblinfo = header->getLabel(label_id);
        const char* instName = (lblinfo->kind == LABEL_FC ? "fccall" : ISA_Inst_Table[opcode].str);
        sstr << printPredicate(opcode, inst->pred)
             << instName
             << " "
             << printExecutionSize(opcode, inst->execsize)
             << " "
             << replaceInvalidCharToUnderline(header->getString(lblinfo->name_index))
             << "_"
             << label_id;
    }
    else
    {
        sstr << printPredicate(inst->opcode, inst->pred)
             << ISA_Inst_Table[opcode].str
             << " "
             << printExecutionSize(inst->opcode, inst->execsize);

        switch (opcode)
        {
            case ISA_JMP:
            case ISA_GOTO:
            case ISA_FCALL:
            {
                /// label / function id to jump / call to.
                label_id = getPrimitiveOperand<uint16_t>(inst, i++);

                if (opcode == ISA_FCALL)
                {
                    /// function name in string
                    sstr << " " << replaceInvalidCharToUnderline(header->getString(label_id));
                }
                else
                {
                    sstr << " " << replaceInvalidCharToUnderline(header->getString(header->getLabel(label_id)->name_index));
                    if (header->getLabel(label_id)->kind == LABEL_SUBROUTINE)
                        sstr << "_" << label_id;
                }

                if (opcode == ISA_FCALL)
                {
                    /// arg size
                    sstr << " " << getPrimitiveOperand<unsigned>(inst, i++);

                    /// return size
                    sstr << " " << getPrimitiveOperand<unsigned>(inst, i++);
                }

                break;
            }
            case ISA_IFCALL:
            {
                sstr << printOperand(header, inst, i++, opt);
                /// arg size
                sstr << " " << getPrimitiveOperand<unsigned>(inst, i++);
                /// return size
                sstr << " " << getPrimitiveOperand<unsigned>(inst, i++);
                break;
            }
            case ISA_FADDR:
            {
                /// symbol name in string
                const char* sym = header->getString(getPrimitiveOperand<uint16_t>(inst, i++));
                if (isIdentifier(sym)) {
                    sstr << sym;
                } else {
                    encodeStringLiteral(sstr, sym);
                }
                /// dst
                sstr << printOperand(header, inst, i++, opt);
                break;
            }
            case ISA_SWITCHJMP:
            {
                /// skip num_labels
                i++;
                /// index
                sstr << printOperand(header, inst, i++, opt);
                sstr << " (";
                for (bool first = true; i < inst->opnd_count; i++)
                {
                    if (!first) { sstr << ", "; }
                    label_id = getPrimitiveOperand<uint16_t>(inst, i);
                    sstr << header->getString(header->getLabel(label_id)->name_index);
                    if (first) { first = false; }
                }
                sstr << ")";
                break;
            }
            default:
                break; // Prevent gcc warning
        }
    }

    return sstr.str();
}

static std::string printInstructionMisc(
    const print_format_provider_t* header,
    const CISA_INST* inst,
    const Options *opt)
{
    ISA_Opcode opcode = (ISA_Opcode)inst->opcode;
    unsigned i = 0;

    std::stringstream sstr;

    if (opcode == ISA_3D_URB_WRITE)
    {
        sstr << printPredicate(inst->opcode, inst->pred);
    }

    switch (opcode)
    {
        case ISA_FILE:
        {
            uint32_t filename_index = getPrimitiveOperand<uint32_t>(inst, i++);
            sstr << "FILE ";
            encodeStringLiteral(sstr, header->getString(filename_index));
            break;
        }
        case ISA_LOC:
        {
            unsigned line_number = getPrimitiveOperand<unsigned>(inst, i++);
            sstr << "LOC " << line_number;
            break;
        }
        case ISA_RAW_SEND:
        {
            uint8_t modifiers = inst->modifier;
            i++; // skip the modifier
            uint32_t exMsgDesc = getPrimitiveOperand<uint32_t>(inst, i++); //32b
            uint8_t numSrc    = getPrimitiveOperand<uint8_t>(inst, i++);
            uint8_t numDst    = getPrimitiveOperand<uint8_t>(inst, i++);
            std::string opstring = modifiers == 1? "raw_sendc " : "raw_send ";

            sstr << printPredicate(inst->opcode, inst->pred)
                 << opstring.c_str()
                 << printExecutionSize(inst->opcode, inst->execsize)
                 << " "
                 << "0x" << std::hex << (uint32_t)exMsgDesc << std::dec
                 << " "
                 << (unsigned)numSrc
                 << " "
                 << (unsigned)numDst
                 << " ";

            /// desc
            sstr << printOperand(header, inst, i++, opt);

            /// src
            sstr << printOperand(header, inst, i++, opt);

            /// dst
            sstr << printOperand(header, inst, i++, opt);

            break;
        }
        case ISA_RAW_SENDS:
        {
            uint8_t modifiers = inst->modifier;
            i++; // skip the modifier
            uint8_t numSrc0    = getPrimitiveOperand<uint8_t>(inst, i++);
            uint8_t numSrc1    = getPrimitiveOperand<uint8_t>(inst, i++);
            uint8_t numDst     = getPrimitiveOperand<uint8_t>(inst, i++);
            std::string opstring = (modifiers & 0x1) == 1? "raw_sendsc." : "raw_sends.";

            sstr << printPredicate(inst->opcode, inst->pred)
                 << opstring.c_str();

            uint8_t ffid = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << (unsigned)ffid
                << ".";

            if (modifiers & 0x2)
            {
                sstr << "eot.";
            }

            sstr << (unsigned)numSrc0
                 << "."
                 << (unsigned)numSrc1
                 << "."
                 << (unsigned)numDst
                 << " "
                 << printExecutionSize(inst->opcode, inst->execsize)
                 << " ";

            /// exMsgDesc: could be imm or vector
            sstr << printOperand(header, inst, i++, opt);

            /// desc
            sstr << printOperand(header, inst, i++, opt);

            /// src0
            sstr << printOperand(header, inst, i++, opt);

            /// src1
            sstr << printOperand(header, inst, i++, opt);

            /// dst
            sstr << printOperand(header, inst, i++, opt);

            break;
        }
        case ISA_VME_FBR:
        {
             /// My typical pattern of printing these things doesn't work here since
             /// these VME instructions weirdly put the surface as the third operand.
             std::stringstream sstr1;

             /// uni input
             sstr1 << printOperand(header, inst, i++, opt);

             /// fbr input
             sstr1 << printOperand(header, inst, i++, opt);

             uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

             std::stringstream sstr2;

             sstr2 << " T"
                   << (unsigned)surface
                   << " "
                   << sstr1.str();

             sstr << ISA_Inst_Table[opcode].str << " (";

             /// FBRMbMode
             sstr << printOperand(header, inst, i++, opt); sstr << ",";

             /// FBRSubMbShape
             sstr << printOperand(header, inst, i++, opt); sstr << ",";

             /// FBRSubPredMode
             sstr << printOperand(header, inst, i++, opt);

             sstr << ")";

             /// vme output
             sstr2 << printOperand(header, inst, i++, opt);

             sstr << sstr2.str();

             break;
        }
        case ISA_VME_IME:
        {
             uint8_t streamMode = getPrimitiveOperand<uint8_t>(inst, i++);
             uint8_t searchCtrl = getPrimitiveOperand<uint8_t>(inst, i++);

             sstr << ISA_Inst_Table[opcode].str
                  << "(" << (unsigned)streamMode
                  << "," << (unsigned)searchCtrl
                  << ")";

             std::stringstream sstr1;

             /// uni imput
             sstr1 << printOperand(header, inst, i++, opt);

             /// ime input
             sstr1 << printOperand(header, inst, i++, opt);

             uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

             sstr << " T" << (unsigned)surface << " " << sstr1.str();

             /// ref0
             sstr << printOperand(header, inst, i++, opt);

             /// ref1
             sstr << printOperand(header, inst, i++, opt);

             /// cost center
             sstr << printOperand(header, inst, i++, opt);

             /// vme output
             sstr << printOperand(header, inst, i++, opt);

             break;
        }
        case ISA_VME_SIC:
        {
             /// My typical pattern of printing these things doesn't work here since
             /// these VME instructions weirdly put the surface as the third operand.
             std::stringstream sstr1;

             /// uni input
             sstr1 << printOperand(header, inst, i++, opt);

             /// sic input
             sstr1 << printOperand(header, inst, i++, opt);

             uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

             sstr << ISA_Inst_Table[opcode].str
                  << " T"
                  << (unsigned)surface
                  << " "
                  << sstr1.str();

             /// vme output
             sstr << printOperand(header, inst, i++, opt);

             break;
        }
        case ISA_VME_IDM:
        {
             /// My typical pattern of printing these things doesn't work here since
             /// these VME instructions weirdly put the surface as the third operand.
             std::stringstream sstr1;

             /// uni input
             sstr1 << printOperand(header, inst, i++, opt);

             /// sic input
             sstr1 << printOperand(header, inst, i++, opt);

             uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

             sstr << ISA_Inst_Table[opcode].str
                  << " T"
                  << (unsigned)surface
                  << " "
                  << sstr1.str();

             /// vme output
             sstr << printOperand(header, inst, i++, opt);

             break;
        }
        case ISA_3D_URB_WRITE:
        {

            sstr << ISA_Inst_Table[opcode].str;

            sstr << " " << printExecutionSize(inst->opcode, inst->execsize);

            // num out
            sstr << " " << printOperand(header, inst, i++, opt);

            // channel mask
            // FIXME: change the order of channel mask and global offset in vISA binary
            std::string channelMask = printOperand(header, inst, i++, opt);

            // global offset
            sstr << " " << printOperand(header, inst, i++, opt);
            sstr << channelMask;

            // urb handle
            sstr << printOperand(header, inst, i++, opt);

            // per slot offset
            sstr << printOperand(header, inst, i++, opt);

            // vertex data
            sstr << printOperand(header, inst, i++, opt);

            break;
        }
        case ISA_DPAS:
        case ISA_DPASW:
        {
            const VISA_opnd* dpasOpnd = inst->opnd_array[inst->opnd_count-1];
            GenPrecision A, W;
            uint8_t D, C;
            UI32ToDpasInfo(dpasOpnd->_opnd.other_opnd, A, W, D, C);

            sstr << ISA_Inst_Table[opcode].str
                 << "." << toString(W) << "." << toString(A) << "."
                 << (int)D << "." << (int)C;

            sstr << " " << printExecutionSize(inst->opcode, inst->execsize);

            // dst
            sstr << printRawOperand(header, getRawOperand(inst, i++), opt);

            // src0
            sstr << printRawOperand(header, getRawOperand(inst, i++), opt);

            // src1
            sstr << printRawOperand(header, getRawOperand(inst, i++), opt);

            // src2
            sstr << printVectorOperand(header, inst->opnd_array[i++], opt, false);

            break;
        }
        case ISA_LIFETIME:
        {
            uint8_t properties = getPrimitiveOperand<uint8_t>(inst, i++);
            uint32_t varId = getPrimitiveOperand<uint32_t>(inst, i++);

            sstr << ISA_Inst_Table[opcode].str;

            sstr << ".";

            if ((VISAVarLifetime)(properties & 1) == LIFETIME_START)
            {
                sstr << "start ";
            }
            else
            {
                sstr << "end ";
            }

            // Since variable id is in non-standard form, we cannot invoke
            // printOperand directly on it
            unsigned char type = (properties >> 4) & 0x3;
            if (type == OPERAND_GENERAL)
            {
                // General variable
                sstr << printVariableDeclName(header, varId, opt, NOT_A_STATE_OPND);
            }
            else if (type == OPERAND_ADDRESS)
            {
                // Address variable
                sstr << "A" << varId;
            }
            else if (type == OPERAND_PREDICATE)
            {
                // Predicate variable
                sstr << "P" << varId;
            }

            break;
        }
        default:
        {
            ASSERT_USER(0, "Unimplemented or Illegal Misc Opcode.");
        }
    }

    return sstr.str();
}

// For 3D sampler instructions, subOpcode, pixel null mask and CPS LOD
// compensation enable share the same byte:
//
// Bit 0-4: subOpcode
// Bit   5: pixelNullMask
// Bit   6: cpsEnable
//
static VISA3DSamplerOp getSubOpcodeByte(
    const CISA_INST* inst, unsigned i)
{
    uint8_t val = getPrimitiveOperand<uint8_t>(inst, i);
    return VISA3DSamplerOp::extractSamplerOp(val);
}

static std::string printInstructionSampler(
    const print_format_provider_t* header,
    const CISA_INST* inst,
    const Options *opt)
{
    std::stringstream sstr;

    ISA_Opcode opcode = (ISA_Opcode)inst->opcode;

    if (opcode == ISA_3D_SAMPLE || opcode == ISA_3D_LOAD || opcode == ISA_3D_GATHER4)
    {
        sstr << printPredicate(inst->opcode, inst->pred);
    }

    unsigned i = 0;

    switch (opcode)
    {
        case ISA_LOAD:
        case ISA_SAMPLE:
        {
            uint8_t mod     = getPrimitiveOperand<uint8_t>(inst, i++);
            uint8_t sampler = 0;

            if (opcode == ISA_SAMPLE)
                sampler = getPrimitiveOperand<uint8_t>(inst, i++);

            uint8_t surface   = getPrimitiveOperand<uint8_t>(inst, i++);
            uint8_t channel   = (mod    ) & 0xF;
            uint8_t SIMD_mode = (mod >> 4) & 0x3;

            if ((unsigned)SIMD_mode == 0)
            {
                SIMD_mode = 8;
            }
            else if ((unsigned)SIMD_mode == 1)
            {
                SIMD_mode = 16;
            }

            sstr << ISA_Inst_Table[opcode].str
                 << "."
                 << channel_mask_str[channel]
                 << " ("
                 << (unsigned)SIMD_mode
                 << ")";

            if (opcode == ISA_SAMPLE)
                sstr << " S" << (unsigned)sampler;

            sstr << " " << printSurfaceName(surface);

            /// u offset
            sstr << printOperand(header, inst, i++, opt);

            /// v offset
            sstr << printOperand(header, inst, i++, opt);

            /// r offset
            sstr << printOperand(header, inst, i++, opt);

            /// dst
            sstr << printOperand(header, inst, i++, opt);

            break;
        }
        case ISA_3D_SAMPLE:
        {
            // [(P)] SAMPLE_3d[.pixel_null_mask][.cps][.divS].<channels> (exec_size)
            //   [(u_aoffimmi, v_aoffimii, r_aoffimmi)] <sampler> <surface>
            //   <dst> <u> <v> <r> <ai>
            auto subop = getSubOpcodeByte(inst, i++);

            TARGET_PLATFORM platform =
                static_cast<TARGET_PLATFORM>(opt->getuInt32Option(vISA_PlatformSet));
            sstr << getSampleOp3DName(subop.opcode, platform) << ".";
            // Print the pixel null mask if it is enabled.
            if (subop.pixelNullMask)
            {
                sstr << "pixel_null_mask.";
            }
            // Print CPS LOD compensation if it is enabled.
            // The last '.' is for the channels.
            if (subop.cpsEnable)
            {
                sstr << "cps.";
            }
            if (subop.nonUniformSampler)
            {
                sstr << "divS.";
            }

            uint8_t channels = getPrimitiveOperand<uint8_t>(inst, i++);
            if (channels & 0x1) sstr << "R";
            if (channels & 0x2) sstr << "G";
            if (channels & 0x4) sstr << "B";
            if (channels & 0x8) sstr << "A";

            sstr << " " << printExecutionSize(inst->opcode, inst->execsize) << " ";

            sstr << printOperand(header, inst, i++, opt);

            // sampler
            sstr << " S" << printOperand(header, inst, i++, opt);

            // surface
            uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            // dst
            sstr << printOperand(header, inst, i++, opt);

            // skip the param count
            i++;

            while (i < inst->opnd_count)
            {
                sstr << printOperand(header, inst, i++, opt);
            }

            break;
        }
        case ISA_3D_LOAD:
        {
            auto subop = getSubOpcodeByte(inst, i++);

            TARGET_PLATFORM platform =
                static_cast<TARGET_PLATFORM>(opt->getuInt32Option(vISA_PlatformSet));
            sstr << getSampleOp3DName(subop.opcode, platform) << ".";
            // Print the pixel null mask if it is enabled.
            // The last '.' is for the channels.
            if (subop.pixelNullMask)
            {
                sstr << "pixel_null_mask.";
            }

            uint8_t channels = getPrimitiveOperand<uint8_t>(inst, i++);
            if (channels & 0x1) sstr << "R";
            if (channels & 0x2) sstr << "G";
            if (channels & 0x4) sstr << "B";
            if (channels & 0x8) sstr << "A";

            sstr << " " << printExecutionSize(inst->opcode, inst->execsize) << " ";

            sstr << printOperand(header, inst, i++, opt);

            // surface
            uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            // dst
            sstr << printOperand(header, inst, i++, opt);

            // skip the param count
            i++;

            while (i < inst->opnd_count)
            {
                sstr << printOperand(header, inst, i++, opt);
            }

            break;
        }
        case ISA_3D_GATHER4:
        {
            auto subop = getSubOpcodeByte(inst, i++);

            TARGET_PLATFORM platform =
                static_cast<TARGET_PLATFORM>(opt->getuInt32Option(vISA_PlatformSet));
            sstr << getSampleOp3DName(subop.opcode, platform) << ".";
            // Print the pixel null mask if it is enabled.
            // The last '.' is for the channels.
            if (subop.pixelNullMask)
            {
                sstr << "pixel_null_mask.";
            }

            uint8_t channels = getPrimitiveOperand<uint8_t>(inst, i++);
            if (channels == 0x0)
            {
                sstr << "R";
            }
            else if (channels == 0x1)
            {
                sstr << "G";
            }
            else if (channels == 0x2)
            {
                sstr << "B";
            }
            else if (channels == 0x3)
            {
                sstr << "A";
            }
            else
            {
                sstr << "illegal";
            }

            sstr << " " << printExecutionSize(inst->opcode, inst->execsize);

            sstr << printOperand(header, inst, i++, opt);

            // sampler
            sstr << " S" << printOperand(header, inst, i++, opt);

            // surface
            uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            // dst
            sstr << printOperand(header, inst, i++, opt);

            // skip the param count
            i++;

            while (i < inst->opnd_count)
            {
                sstr << printOperand(header, inst, i++, opt);
            }

            break;
        }
        case ISA_3D_INFO:
        {
            VISASampler3DSubOpCode subop = (VISASampler3DSubOpCode)getPrimitiveOperand<uint8_t>(inst, i++);
            TARGET_PLATFORM platform =
                static_cast<TARGET_PLATFORM>(opt->getuInt32Option(vISA_PlatformSet));
            sstr << getSampleOp3DName(subop, platform);
            if (subop == VISA_3D_RESINFO || subop == VISA_3D_SAMPLEINFO)
            {
                // channelMask
                uint8_t channels = getPrimitiveOperand<uint8_t>(inst, i++);
                ChannelMask chMask = ChannelMask::createFromBinary(ISA_3D_INFO, channels);
                sstr << "." << chMask.getString();
            }

            sstr << " " << printExecutionSize(inst->opcode, inst->execsize) << " ";

            // surface
            uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            if (subop == VISA_3D_RESINFO)
            {
                // lod
                sstr << printOperand(header, inst, i++, opt);
            }

            // dst
            sstr << printOperand(header, inst, i++, opt);

            break;
        }
        case ISA_SAMPLE_UNORM:
        {
            uint8_t channel = getPrimitiveOperand<uint8_t>(inst, i++);
            uint8_t sampler = getPrimitiveOperand<uint8_t>(inst, i++);
            uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << ISA_Inst_Table[opcode].str
                << "."
                << channel_mask_str[(channel & 0xf)]
                << "."
                << sampler_channel_output_str[ChannelMask::getChannelOutputFormat(channel)]
                << " S"
                << (unsigned)sampler
                << " " << printSurfaceName(surface);

            /// u offset
            sstr << printOperand(header, inst, i++, opt);

            /// v offset
            sstr << printOperand(header, inst, i++, opt);

            /// deltaU
            sstr << printOperand(header, inst, i++, opt);

            /// deltaV
            sstr << printOperand(header, inst, i++, opt);

            /// dst
            sstr << printOperand(header, inst, i++, opt);

            break;
        }
        case ISA_AVS:
        {
            uint8_t channel = getPrimitiveOperand<uint8_t>(inst, i++);
            uint8_t sampler = getPrimitiveOperand<uint8_t>(inst, i++);
            uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

            sstr << ISA_Inst_Table[opcode].str
                << "."
                << channel_mask_str[channel]
                << " " << printSurfaceName(surface)
                << " S"
                << (unsigned)sampler;

            /// u offset
            sstr << printOperand(header, inst, i++, opt);

            /// v offset
            sstr << printOperand(header, inst, i++, opt);

            /// delta u
            sstr << printOperand(header, inst, i++, opt);

            /// delta v
            sstr << printOperand(header, inst, i++, opt);

            /// u2d
            sstr << printOperand(header, inst, i++, opt);

            /// groupID
            sstr << printOperand(header, inst, i++, opt);

            /// verticalBlockNumber
            sstr << printOperand(header, inst, i++, opt);

            uint8_t cntrl = ((getPrimitiveOperand<uint8_t>(inst, i++)) & 0xF);

            sstr << " "
                 << avs_control_str[cntrl];

            /// v2d
            sstr << printOperand(header, inst, i++, opt);

            uint8_t execMode  =       (getPrimitiveOperand<uint8_t>(inst, i++) & 0xF);

            sstr << " "
                 << avs_exec_mode[execMode];

            // eifbypass
            sstr << printOperand(header, inst, i++, opt);

            /// dst
            sstr << printOperand(header, inst, i++, opt);

            break;
        }
        case ISA_VA:
        {
            ISA_VA_Sub_Opcode subOpcode = (ISA_VA_Sub_Opcode)getPrimitiveOperand<uint8_t>(inst, i++);
            switch (subOpcode)
            {
                case MINMAX_FOPCODE:
                {
                     uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

                     sstr << ISA_Inst_Table[opcode].str
                          << "."
                          << va_sub_names[subOpcode]
                          << " " << printSurfaceName(surface);

                     /// u offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// v offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// mmf mode
                     if (getVectorOperand(inst, i).getOperandClass() == OPERAND_IMMEDIATE)
                     {
                         unsigned val = getVectorOperand(inst, i++).opnd_val.const_opnd._val.ival;
                         sstr << " " << mmf_enable_mode[val];
                     }
                     else
                     {
                        sstr << printOperand(header, inst, i++, opt);
                     }

                     /// dst
                     sstr << printOperand(header, inst, i++, opt);

                     break;
                }
                case MINMAXFILTER_FOPCODE:
                {
                     uint8_t sampler = getPrimitiveOperand<uint8_t>(inst, i++);
                     uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

                     sstr << ISA_Inst_Table[opcode].str
                          << "."
                          << va_sub_names[subOpcode]
                          << " " << printSurfaceName(surface)
                          << " S" << (unsigned)sampler;

                     /// u offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// v offset
                     sstr << printOperand(header, inst, i++, opt);

                     uint8_t cntrl    = ((getPrimitiveOperand<uint8_t>(inst, i++)) & 0xF);
                     uint8_t execMode = ((getPrimitiveOperand<uint8_t>(inst, i++)) & 0xF);

                     sstr << " "
                          << avs_control_str [ cntrl     ]
                          << " "
                          << mmf_exec_mode   [ execMode ];

                     /// mmf mode
                     sstr << printOperand(header, inst, i++, opt);

                     /// dst
                     sstr << printOperand(header, inst, i++, opt);

                     break;
                }
                case BoolCentroid_FOPCODE:
                case Centroid_FOPCODE:
                {
                    uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

                    sstr << ISA_Inst_Table[opcode].str
                        << "."
                        << va_sub_names[subOpcode]
                        << " " << printSurfaceName(surface);

                     /// u offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// v offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// v size
                     sstr << printOperand(header, inst, i++, opt);

                     /// h size
                     if (subOpcode == BoolCentroid_FOPCODE)
                        sstr << printOperand(header, inst, i++, opt);

                     /// dst
                     sstr << printOperand(header, inst, i++, opt);

                     break;
                }
                case Convolve_FOPCODE:
                case Dilate_FOPCODE:
                case ERODE_FOPCODE:
                {
                     uint8_t sampler = getPrimitiveOperand<uint8_t>(inst, i++);
                     uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

                     sstr << ISA_Inst_Table[opcode].str
                          << "."
                          << va_sub_names[subOpcode]
                          << " " << printSurfaceName(surface)
                          << " S" << (unsigned)sampler;

                     /// u offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// v offset
                     sstr << printOperand(header, inst, i++, opt);

                     uint8_t execMode   =  getPrimitiveOperand<uint8_t>(inst, i ) & 0x3;
                     uint8_t regionSize = (getPrimitiveOperand<uint8_t>(inst, i++) & 0xC) >> 0x2;

                     sstr << " "
                          << (Convolve_FOPCODE == subOpcode ?
                              conv_exec_mode [execMode]     :
                              ed_exec_mode   [execMode]   );

                     if (Convolve_FOPCODE == subOpcode)
                         sstr << " " << (regionSize & 0x1 ? "31x31" : "15x15");

                     /// dst
                     sstr << printOperand(header, inst, i++, opt);

                     break;
                }
                default:
                     ASSERT_USER(false, "Invalid VA sub-opcode");
            }

            break;
        }
        case ISA_VA_SKL_PLUS:
        {
            ISA_VA_Sub_Opcode subOpcode = (ISA_VA_Sub_Opcode)getPrimitiveOperand<uint8_t>(inst, i++);
            switch (subOpcode)
            {
                case VA_OP_CODE_LBP_CORRELATION:
                {
                     uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

                     sstr << ISA_Inst_Table[opcode].str
                         << "."
                         << va_sub_names[subOpcode]
                         << " " << printSurfaceName(surface);

                     /// u offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// v offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// disparity
                     sstr << printOperand(header, inst, i++, opt);

                     /// dst
                     sstr << printOperand(header, inst, i++, opt);

                     break;
                }
                case VA_OP_CODE_1PIXEL_CONVOLVE:
                case VA_OP_CODE_1D_CONVOLVE_VERTICAL:
                case VA_OP_CODE_1D_CONVOLVE_HORIZONTAL:
                {
                     uint8_t sampler = getPrimitiveOperand<uint8_t>(inst, i++);
                     uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

                     sstr << ISA_Inst_Table[opcode].str
                         << "."
                         << va_sub_names[subOpcode]
                         << " " << printSurfaceName(surface)
                         << " S" << (unsigned)sampler;

                     /// u offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// v offset
                     sstr << printOperand(header, inst, i++, opt);

                     uint8_t mode = ((getPrimitiveOperand<uint8_t>(inst, i++)) & 0xF);

                     switch (mode & 0x3)
                     {
                         case 0: sstr << " 4x16"; break;
                         case 2: sstr << " 1x16"; break;
                         case 3: sstr << " 1x1";  break;
                     }

                     /// offsets
                     if (subOpcode == VA_OP_CODE_1PIXEL_CONVOLVE)
                         sstr << printOperand(header, inst, i++, opt);

                     /// dst
                     sstr << printOperand(header, inst, i++, opt);

                     break;
                }
                case VA_OP_CODE_LBP_CREATION:
                {
                     uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

                     sstr << ISA_Inst_Table[opcode].str
                         << "."
                         << va_sub_names[subOpcode]
                         << " " << printSurfaceName(surface);

                     /// u offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// v offset
                     sstr << printOperand(header, inst, i++, opt);

                     uint8_t mode = ((getPrimitiveOperand<uint8_t>(inst, i++)) & 0xF);

                     sstr << " " << lbp_creation_mode[(int)mode];

                     /// dst
                     sstr << printOperand(header, inst, i++, opt);

                     break;
                }
                case VA_OP_CODE_FLOOD_FILL:
                {
                     uint8_t is8Connect = getPrimitiveOperand<uint8_t>(inst, i++);

                     sstr << ISA_Inst_Table[opcode].str
                          << "."
                          << va_sub_names[subOpcode]
                          << " " << (is8Connect & 0x1 ? "8_connect" : "4_connect");

                     /// pixel mask h direction
                     sstr << printOperand(header, inst, i++, opt);

                     /// pixel mask v left direction
                     sstr << printOperand(header, inst, i++, opt);

                     /// pixel mask v right direction
                     sstr << printOperand(header, inst, i++, opt);

                     /// loop count
                     sstr << printOperand(header, inst, i++, opt);

                     /// dst
                     sstr << printOperand(header, inst, i++, opt);

                     break;
                }
                case VA_OP_CODE_CORRELATION_SEARCH:
                {
                     uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

                     sstr << ISA_Inst_Table[opcode].str
                         << "."
                         << va_sub_names[subOpcode]
                         << " " << printSurfaceName(surface);

                     /// u offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// v offset
                     sstr << printOperand(header, inst, i++, opt);

                     /// vertical origin
                     sstr << printOperand(header, inst, i++, opt);

                     /// horizontal origin
                     sstr << printOperand(header, inst, i++, opt);

                     /// x direction size
                     sstr << printOperand(header, inst, i++, opt);

                     /// y direction size
                     sstr << printOperand(header, inst, i++, opt);

                     /// x direction search size
                     sstr << printOperand(header, inst, i++, opt);

                     /// y direction search size
                     sstr << printOperand(header, inst, i++, opt);

                     /// dst
                     sstr << printOperand(header, inst, i++, opt);

                     break;
                }
                case ISA_HDC_CONV:
                case ISA_HDC_ERODE:
                case ISA_HDC_DILATE:
                case ISA_HDC_LBPCORRELATION:
                case ISA_HDC_LBPCREATION:
                case ISA_HDC_MMF:
                case ISA_HDC_1PIXELCONV:
                case ISA_HDC_1DCONV_H:
                case ISA_HDC_1DCONV_V:
                {
                        sstr << ISA_Inst_Table[opcode].str
                             << "."
                             << va_sub_names[subOpcode];

                        if (subOpcode != ISA_HDC_LBPCORRELATION &&
                            subOpcode != ISA_HDC_LBPCREATION)
                        {
                            uint8_t sampler = getPrimitiveOperand<uint8_t>(inst, i++);
                            uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);

                            sstr << " " << printSurfaceName(surface)
                                 << " S" << (unsigned)sampler;
                        }
                        else
                        {
                            /// surface
                            uint8_t surface = getPrimitiveOperand<uint8_t>(inst, i++);
                            sstr << " " << printSurfaceName(surface);
                        }

                        /// u offset
                        sstr << printOperand(header, inst, i++, opt);

                        /// v offset
                        sstr << printOperand(header, inst, i++, opt);


                        if (subOpcode == ISA_HDC_CONV ||
                            subOpcode == ISA_HDC_MMF ||
                            subOpcode == ISA_HDC_1PIXELCONV ||
                            subOpcode == ISA_HDC_1DCONV_H ||
                            subOpcode == ISA_HDC_1DCONV_V)
                        {
                            //pixel size
                            uint8_t pixel_size = getPrimitiveOperand<uint8_t>(inst, i++);
                            int isBigKernel = 0;

                            if (subOpcode == ISA_HDC_CONV)
                            {
                                isBigKernel = (pixel_size & (1 << 4));
                                pixel_size = pixel_size & 0xF;
                            }
                            sstr << " " << pixel_size_str[pixel_size];

                            if (subOpcode == ISA_HDC_CONV  && isBigKernel)
                            {
                                sstr << " 31x31";
                            }
                            else if (subOpcode == ISA_HDC_CONV  && !isBigKernel)
                            {
                                sstr << " 15x15";
                            }
                        }

                        if (subOpcode == ISA_HDC_MMF)
                        {
                            //mode
                            uint8_t mode = getPrimitiveOperand<uint8_t>(inst, i++);
                            sstr << " " << mmf_enable_mode[(int)mode];
                        }

                        if (subOpcode == ISA_HDC_LBPCREATION)
                        {
                            //mode
                            uint8_t mode = getPrimitiveOperand<uint8_t>(inst, i++);
                            sstr << " " << lbp_creation_mode[(int)mode];
                        }

                        if (subOpcode == ISA_HDC_LBPCORRELATION)
                        {
                            /// disparity
                            sstr << printOperand(header, inst, i++, opt);
                        }

                        if (subOpcode == ISA_HDC_1PIXELCONV)
                        {
                            /// offsets
                            sstr << printOperand(header, inst, i++, opt);
                        }

                        /// dst surface
                        uint8_t dst_surface = getPrimitiveOperand<uint8_t>(inst, i++);

                        sstr << " " << printSurfaceName(dst_surface);

                        /// x offset
                        sstr << printOperand(header, inst, i++, opt);

                        /// y offset
                        sstr << printOperand(header, inst, i++, opt);
                        break;
                }
                default:
                     ASSERT_USER(false, "Invalid VA sub-opcode");
            }

            break;
        }
        default: ASSERT_USER(false, "illegal opcode for sampler instruction");
    }

    return sstr.str();
}

static std::string printInstructionDataport(
    const print_format_provider_t* header,
    const CISA_INST* inst,
    const Options *opt)
{
    ISA_Opcode opcode = (ISA_Opcode)inst->opcode;
    unsigned i = 0;

    uint8_t surface  = 0;
    uint8_t modifier = 0;
    std::stringstream sstr;

    switch (opcode) {
    default:
        break;
    case ISA_3D_RT_WRITE:
    case ISA_GATHER4_SCALED:
    case ISA_SCATTER4_SCALED:
    case ISA_GATHER_SCALED:
    case ISA_SCATTER_SCALED:
    case ISA_DWORD_ATOMIC:
    case ISA_3D_TYPED_ATOMIC:
    case ISA_QW_GATHER:
    case ISA_QW_SCATTER:
        sstr << printPredicate(inst->opcode, inst->pred);
        break;
    }

    sstr << ISA_Inst_Table[opcode].str;

    switch (opcode)
    {
        case ISA_MEDIA_ST:
        case ISA_MEDIA_LD:
        {
            uint8_t plane        = 0;
            uint8_t block_width  = 0;
            uint8_t block_height = 0;

            if (ISA_MEDIA_LD == opcode || ISA_MEDIA_ST == opcode)
            {
                modifier = getPrimitiveOperand<uint8_t>(inst, i++); //inst->modifier;
            }

            surface = getPrimitiveOperand<uint8_t>(inst, i++);

            if (ISA_MEDIA_LD == opcode || ISA_MEDIA_ST == opcode)
            {
                plane = getPrimitiveOperand<uint8_t>(inst, i++);
            }

            if (opcode == ISA_MEDIA_LD) sstr << "." << media_ld_mod_str[modifier];
            if (opcode == ISA_MEDIA_ST) sstr << "." << media_st_mod_str[modifier];

            sstr << " (";
            block_width = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << (unsigned)block_width;
            sstr << ",";
            block_height = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << (unsigned)block_height;
            sstr << ")";

            sstr << " " << printSurfaceName(surface);
            sstr << " " << (unsigned)plane;

            /// x offset
            sstr << printOperand(header, inst, i++, opt);

            /// y offset
            sstr << printOperand(header, inst, i++, opt);

            /// message operand (src or dst)
            sstr << printOperand(header, inst, i++, opt);

            break;
        }
        case ISA_OWORD_ST:
        case ISA_OWORD_LD:
        case ISA_OWORD_LD_UNALIGNED:
        {
            uint8_t size = getPrimitiveOperand<uint8_t>(inst, i++);
            size = size & 0x7;
            unsigned num_oword = Get_VISA_Oword_Num((VISA_Oword_Num)size);

            if (ISA_OWORD_ST != opcode)
            {
                modifier = getPrimitiveOperand<uint8_t>(inst, i++);
                if (modifier & 0x1) sstr << ".mod";
            }

            sstr << " (" << num_oword << ")";

            surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            /// offset
            sstr << printOperand(header, inst, i++, opt);

            /// message operand (src or dst)
            sstr << printOperand(header, inst, i++, opt);

            break;
        }
        case ISA_GATHER:
        case ISA_SCATTER:
        {
            uint8_t elt_size = 0;
            uint8_t num_elts = 0;

            elt_size = getPrimitiveOperand<uint8_t>(inst, i++);
            elt_size = elt_size & 0x3;
            switch ((GATHER_SCATTER_ELEMENT_SIZE)elt_size)
            {
                case GATHER_SCATTER_BYTE:
                    elt_size = 1;
                    break;
                case GATHER_SCATTER_WORD:
                    elt_size = 2;
                    break;
                case GATHER_SCATTER_DWORD:
                    elt_size = 4;
                    break;
                default:
                    ASSERT_USER(0, "Incorrect element size for Gather/Scatter CISA inst.");
                    break;
            }
            if (ISA_GATHER == opcode)
            {
                modifier = getPrimitiveOperand<uint8_t>(inst, i++);
            }

            num_elts = getPrimitiveOperand<uint8_t>(inst, i++);

            // modifier
            if (ISA_GATHER == opcode && modifier & 0x1)
            {
                sstr << ".mod";
            }

            // num_elts
            sstr << "." << (unsigned)elt_size;

            // execution size
            sstr << " " << printExecutionSizeForScatterGather(num_elts);

            // modifier
            if (ISA_GATHER == opcode && modifier & 0x1)
            {
                sstr << ".mod";
            }

            //surface
            surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            /// global offset
            sstr << printOperand(header, inst, i++, opt);

            /// element offset
            sstr << printOperand(header, inst, i++, opt);

            /// message operand (src or dst)
            sstr << printOperand(header, inst, i++, opt);

            break;
        }
        case ISA_GATHER4_TYPED:
        case ISA_SCATTER4_TYPED:
        {
            ChannelMask chMask = ChannelMask::createFromBinary(opcode,
                    getPrimitiveOperand<uint8_t>(inst, i++));
            sstr << "." << chMask.getString();

            sstr << " " << printExecutionSize(inst->opcode, inst->execsize);

            surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            /// u offset
            sstr << printOperand(header, inst, i++, opt);

            /// v offset
            sstr << printOperand(header, inst, i++, opt);

            /// r offset
            sstr << printOperand(header, inst, i++, opt);

            /// lod
            sstr << printOperand(header, inst, i++, opt);

            /// message operand (src or dst)
            sstr << printOperand(header, inst, i++, opt);

            break;
        }
        case ISA_GATHER4_SCALED:
        case ISA_SCATTER4_SCALED:
        {
            ChannelMask chMask = ChannelMask::createFromBinary(opcode,
                    getPrimitiveOperand<uint8_t>(inst, i++));
            sstr << "." << chMask.getString();

            // ignore scale which must be 0
            (void) getPrimitiveOperand<uint8_t>(inst, i++);

            sstr << " " << printExecutionSize(inst->opcode, inst->execsize);

            /// surface
            surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            /// global offset
            sstr << printOperand(header, inst, i++, opt);

            /// offsets
            sstr << printOperand(header, inst, i++, opt);

            /// src/dst
            sstr << printOperand(header, inst, i++, opt);
            break;
        }
        case ISA_GATHER_SCALED:
        case ISA_SCATTER_SCALED:
        {
            VISA_SVM_Block_Num numBlocks;

            // block size : ignored
            (void)getPrimitiveOperand<uint8_t>(inst, i++);

            numBlocks = static_cast<VISA_SVM_Block_Num>(getPrimitiveOperand<uint8_t>(inst, i++));

            sstr << "." << Get_Common_ISA_SVM_Block_Num(numBlocks);

            sstr << " " << printExecutionSize(inst->opcode, inst->execsize);

            // scale (MBZ) : ignored
            (void)getPrimitiveOperand<uint8_t>(inst, i++);

            /// surface
            surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            /// global offset
            sstr << printOperand(header, inst, i++, opt);

            /// offsets
            sstr << printOperand(header, inst, i++, opt);

            /// src/dst
            sstr << printOperand(header, inst, i++, opt);
            break;
        }
        case ISA_3D_RT_WRITE:
        {
            // mode
            uint16_t mode = getPrimitiveOperand<uint16_t>(inst, i++);
            uint8_t surface;

            if ((mode) != 0)
            {
                sstr << ".";
                if (mode & (0x1 << 2)) sstr << "<RTI>";
                if (mode & (0x1 << 3)) sstr << "<A>";
                if (mode & (0x1 << 4)) sstr << "<O>";
                if (mode & (0x1 << 5)) sstr << "<Z>";
                if (mode & (0x1 << 6)) sstr << "<ST>";
                if (mode & (0x1 << 7)) sstr << "<LRTW>";
                if (mode & (0x1 << 8)) sstr << "<CPS>";
                if (mode & (0x1 << 9)) sstr << "<PS>";
                if (mode & (0x1 << 10)) sstr << "<CM>";
                if (mode & (0x1 << 11)) sstr << "<SI>";
                if (mode & (0x1 << 12)) sstr << "<NULLRT>";
            }

            sstr << " " << printExecutionSize(inst->opcode, inst->execsize);

            // surface
            surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            while (i < inst->opnd_count)
            {
                sstr << printOperand(header, inst, i++, opt);
            }

            break;
        }
        case ISA_DWORD_ATOMIC: {
            printAtomicSubOpc(sstr, getPrimitiveOperand<uint8_t>(inst, i++));
            sstr << " " << printExecutionSize(inst->opcode, inst->execsize);

            /// surface
            surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            /// offsets
            sstr << printOperand(header, inst, i++, opt);

            /// src0
            sstr << printOperand(header, inst, i++, opt);

            /// src1
            sstr << printOperand(header, inst, i++, opt);

            /// dst
            sstr << printOperand(header, inst, i++, opt);
            break;
        }
        case ISA_3D_TYPED_ATOMIC:
        {
            printAtomicSubOpc(sstr, getPrimitiveOperand<uint8_t>(inst, i++));
            sstr << " " << printExecutionSize(inst->opcode, inst->execsize);

            /// surface
            surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            /// u
            sstr << printOperand(header, inst, i++, opt);

            /// v
            sstr << printOperand(header, inst, i++, opt);

            /// r
            sstr << printOperand(header, inst, i++, opt);

            /// lod
            sstr << printOperand(header, inst, i++, opt);

            /// src0
            sstr << printOperand(header, inst, i++, opt);

            /// src1
            sstr << printOperand(header, inst, i++, opt);

            /// dst
            sstr << printOperand(header, inst, i++, opt);
            break;
        }
        case ISA_QW_GATHER:
        case ISA_QW_SCATTER:
        {
            //QW_GATHER/SCATTER.<num_blocks> (<exec_size>) <surface> <offset> <dst>
            VISA_SVM_Block_Num numBlocks;

            numBlocks = static_cast<VISA_SVM_Block_Num>(getPrimitiveOperand<uint8_t>(inst, i++));
            sstr << "." << Get_Common_ISA_SVM_Block_Num(numBlocks);

            sstr << " " << printExecutionSize(inst->opcode, inst->execsize);

            /// surface
            surface = getPrimitiveOperand<uint8_t>(inst, i++);
            sstr << " " << printSurfaceName(surface);

            /// offsets
            sstr << printOperand(header, inst, i++, opt);

            /// src/dst
            sstr << printOperand(header, inst, i++, opt);
            break;
        }

        default:
        {
            ASSERT_USER(false, "Unimplemented or Illegal DataPort Opcode.");
        }
    }

    return sstr.str();
}

class LscInstFormatter {
    ISA_Opcode                         opcode;
    LSC_OP                             subOp;
    LscOpInfo                          opInfo;

    std::stringstream                  ss;
    const print_format_provider_t     *header;
    const CISA_INST                   *inst;
    const Options                     *opts;

    int                                currOpIx = 0;
    bool                               error = false;

public:
    LscInstFormatter(
        ISA_Opcode                     _opcode,
        const print_format_provider_t *_header,
        const CISA_INST               *_inst,
        const Options                 *_opts)
        : opcode(_opcode)
        , header(_header)
        , inst(_inst)
        , opts(_opts)
    {
        if (_opcode == ISA_LSC_FENCE) {
            subOp = LSC_FENCE;
        } else {
            subOp = getNextEnumU8<LSC_OP>();
        }
        opInfo = LscOpInfoGet(subOp);
    }

private:
    template <typename T>
    T getNextEnumU8() {
        return (T)getPrimitive<uint8_t>(currOpIx++);
    }

    template <typename T>
    T getNext() {
        return getPrimitive<T>(currOpIx++);
    }
    template <typename T>
    T getPrimitive(int absOpIx) {
        return getPrimitiveOperand<T>(inst, absOpIx);
    }

    // LSC_TYPED and non-block2d LSC_UNTYPED
    // "next" because it advances the operand pointer
    LSC_DATA_SHAPE getNextDataShape() {
        auto dataSize = getNextEnumU8<LSC_DATA_SIZE>();
        auto dataOrder = getNextEnumU8<LSC_DATA_ORDER>();
        auto dataElems = getNextEnumU8<LSC_DATA_ELEMS>();
        // chmask only valid on LSC_LOAD_QUAD/LSC_STORE_QUAD
        // but retained in the binary format
        int chMask = (int)getNextEnumU8<int>();
        LSC_DATA_SHAPE dataShape { };
        dataShape.size = dataSize;
        dataShape.order = dataOrder;
        if (opInfo.hasChMask()) {
            dataShape.chmask = chMask;
        } else {
            dataShape.elems = dataElems;
        }
        return dataShape;
    }

    void formatBadEnum(int bits) {
        error = true;
        ss << "<<" << std::hex << std::uppercase << bits << "?>>" << std::dec;
    }

    void formatSfid(LSC_SFID sfid) {
        ss << ".";
        switch (sfid) {
        case LSC_UGM:   ss << "ugm";  break;
        case LSC_UGML:  ss << "ugml"; break;
        case LSC_SLM:   ss << "slm";  break;
        case LSC_TGM:   ss << "tgm";  break;
        default: formatBadEnum(sfid); break;
        }
    }

    // custom so we can conditionally print register operand suffixes
    void formatVectorOperand(int opIx) {
        if (getOperandType(inst, opIx) != CISA_OPND_VECTOR) {
            error = true;
            ss << "<<BAD_OPERAND_NOT_VECTOR>>";
        } else {
            const auto &vo = getVectorOperand(inst, opIx);
            switch (vo.tag & 0x7) {
            case OPERAND_IMMEDIATE:
                ss << "0x" << std::uppercase << std::hex <<
                    vo.opnd_val.const_opnd._val.ival << std::dec;
                break;
            case OPERAND_GENERAL:
                ss << printVariableDeclName(
                    header,
                    vo.getOperandIndex(),
                    opts,
                    NOT_A_STATE_OPND);
                if (vo.opnd_val.gen_opnd.row_offset != 0 ||
                  vo.opnd_val.gen_opnd.col_offset != 0)
                {
                    ss  << std::dec << "("
                         << (unsigned)vo.opnd_val.gen_opnd.row_offset << ","
                         << (unsigned)vo.opnd_val.gen_opnd.col_offset << ")";
                }
                break;
            default:
                error = true;
                ss << "<<BAD_OPERAND_VECTOR_KIND>>";
                break;
          }
        }
    }

    void formatRawOperand(int absIx) {
        if (getOperandType(inst, absIx) != CISA_OPND_RAW) {
            error = true;
            ss << "<<BAD_OPERAND_NOT_RAW>>";
        } else {
            const raw_opnd &ro = getRawOperand(inst, absIx);
            ss << printVariableDeclName(header, ro.index, opts, NOT_A_STATE_OPND);
            if (ro.offset != 0) // only suffix offset if non-zero
               ss << "." << std::dec << (int)ro.offset;
        }
    }
    void formatDataOperand(LSC_DATA_SHAPE dataShape, int absIx) {
        formatRawOperand(absIx);
        formatDataShape(dataShape);
    }

    void formatAddrType(LSC_ADDR_TYPE addrType, int absSurfOpIx) {
        switch (addrType) {
        case LSC_ADDR_TYPE_FLAT:  ss << "flat"; break;
        case LSC_ADDR_TYPE_BSS:   ss << "bss"; break;
        case LSC_ADDR_TYPE_SS:    ss << "ss"; break;
        case LSC_ADDR_TYPE_BTI:   ss << "bti"; break;
        case LSC_ADDR_TYPE_ARG:   ss << "arg"; break;
        default: formatBadEnum(addrType); break;
        }
        switch (addrType) {
        case LSC_ADDR_TYPE_BSS:
        case LSC_ADDR_TYPE_SS:
        case LSC_ADDR_TYPE_BTI:
            ss << "(";
            formatVectorOperand(absSurfOpIx);
            ss << ")";
            break;
        default: break;
        }
    }

    void formatAddrSize(LSC_ADDR_SIZE addrSize) {
        ss << ":";
        switch (addrSize) {
        case LSC_ADDR_SIZE_16b: ss << "a16"; break;
        case LSC_ADDR_SIZE_32b: ss << "a32"; break;
        case LSC_ADDR_SIZE_64b: ss << "a64"; break;
        default: formatBadEnum(addrSize); break;
        }
    }

    void formatDataSize(LSC_DATA_SIZE dataSize) {
        ss << ":";
        switch (dataSize) {
        case LSC_DATA_SIZE_8b:      ss << "d8"; break;
        case LSC_DATA_SIZE_16b:     ss << "d16"; break;
        case LSC_DATA_SIZE_32b:     ss << "d32"; break;
        case LSC_DATA_SIZE_64b:     ss << "d64"; break;
        case LSC_DATA_SIZE_8c32b:   ss << "d8c32"; break;
        case LSC_DATA_SIZE_16c32b:  ss << "d16c32"; break;
        case LSC_DATA_SIZE_16c32bH: ss << "d16c32h"; break;
        default: formatBadEnum(dataSize); break;
        }
    }

    void formatChannelMaskSuffix(int chEnMask) {
        ss << ".";
        auto VALID_MASKS =
            LSC_DATA_CHMASK_X |
            LSC_DATA_CHMASK_Y |
            LSC_DATA_CHMASK_Z |
            LSC_DATA_CHMASK_W;
        if (chEnMask & ~VALID_MASKS) {
            formatBadEnum(chEnMask);
        } else {
            if (LSC_DATA_CHMASK_X & chEnMask) {
                ss << "x";
            }
            if (LSC_DATA_CHMASK_Y & chEnMask) {
                ss << "y";
            }
            if (LSC_DATA_CHMASK_Z & chEnMask) {
                ss << "z";
            }
            if (LSC_DATA_CHMASK_W & chEnMask) {
                ss << "w";
            }
        }
    }

    void formatDataElemsSuffix(
        LSC_DATA_ELEMS dataElems,
        LSC_DATA_ORDER dataOrder)
    {
        switch (dataElems) {
        case LSC_DATA_ELEMS_1: break;
        case LSC_DATA_ELEMS_2:  ss << "x2"; break;
        case LSC_DATA_ELEMS_3:  ss << "x3"; break;
        case LSC_DATA_ELEMS_4:  ss << "x4"; break;
        case LSC_DATA_ELEMS_8:  ss << "x8"; break;
        case LSC_DATA_ELEMS_16: ss << "x16"; break;
        case LSC_DATA_ELEMS_32: ss << "x32"; break;
        case LSC_DATA_ELEMS_64: ss << "x64"; break;
        default: formatBadEnum(dataElems); break;
        }
        formatDataOrder(dataOrder);
    }

    void formatDataOrder(LSC_DATA_ORDER dataOrder) {
        switch (dataOrder) {
        case LSC_DATA_ORDER_NONTRANSPOSE: break;
        case LSC_DATA_ORDER_TRANSPOSE: ss << "t"; break;
        default: formatBadEnum(dataOrder); break;
        }
    }

    void formatDataShape(LSC_DATA_SHAPE dataShape) {
        formatDataSize(dataShape.size);
        if (opInfo.hasChMask()) {
            formatChannelMaskSuffix(dataShape.chmask);
        } else {
            formatDataElemsSuffix(dataShape.elems, dataShape.order);
        }
    }
    void formatDataShape2D(LSC_DATA_SHAPE_BLOCK2D dataShape2D) {
        formatDataSize(dataShape2D.size);
        ss << '.';
        if (dataShape2D.blocks != 1) {
          ss << std::dec << dataShape2D.blocks << 'x';
        }
        ss << std::dec << dataShape2D.width << 'x' << dataShape2D.height;
        ss << (dataShape2D.order == LSC_DATA_ORDER_TRANSPOSE ? 't' : 'n');
        ss << (dataShape2D.vnni ? 't' : 'n');
    }

    void formatCacheOpt(LSC_CACHE_OPT val) {
        switch (val) {
        case LSC_CACHING_DEFAULT:        ss << ".df"; break;
        case LSC_CACHING_UNCACHED:       ss << ".uc"; break;
        case LSC_CACHING_CACHED:         ss << ".ca"; break;
        case LSC_CACHING_WRITEBACK:      ss << ".wb"; break;
        case LSC_CACHING_WRITETHROUGH:   ss << ".wt"; break;
        case LSC_CACHING_STREAMING:      ss << ".st"; break;
        case LSC_CACHING_READINVALIDATE: ss << ".ri"; break;
        default: formatBadEnum(val); break;
        }
    }

    void formatCachingOpts() {
        auto l1 = getNextEnumU8<LSC_CACHE_OPT>();
        auto l3 = getNextEnumU8<LSC_CACHE_OPT>();
        bool cachingDefault =
            l1 == LSC_CACHE_OPT::LSC_CACHING_DEFAULT &&
            l3 == LSC_CACHE_OPT::LSC_CACHING_DEFAULT;
        if (!cachingDefault) {
            // only format cache control if it's non-default
            // NOTE: cache control doesn't have meaning on SLM, but should the
            // IR be malformed and accidentally have it, we'll indulge the user
            // (for debugging sake)
            formatCacheOpt(l1); // L1
            formatCacheOpt(l3); // L3
        }
    }

    /////////////////////////////////////////////////////////
    // top-level formatters for each instruction type
    /////////////////////////////////////////////////////////

    void formatFence() {
        //
        ss << "lsc_fence";
        //
        auto lscSfid = getNextEnumU8<LSC_SFID>();
        formatSfid(lscSfid);
        //
        auto fenceOp = getNextEnumU8<LSC_FENCE_OP>();
        switch (fenceOp) {
        case LSC_FENCE_OP_NONE:       ss << ".none";       break;
        case LSC_FENCE_OP_EVICT:      ss << ".evict";      break;
        case LSC_FENCE_OP_INVALIDATE: ss << ".invalidate"; break;
        case LSC_FENCE_OP_DISCARD:    ss << ".discard";    break;
        case LSC_FENCE_OP_CLEAN:      ss << ".clean";      break;
        case LSC_FENCE_OP_FLUSHL3:    ss << ".flushl3";    break;
        case LSC_FENCE_OP_TYPE6:      ss << ".type6";      break;
        default: ss << ".???"; break;
        }
        //
        auto scope = getNextEnumU8<LSC_SCOPE>();
        switch (scope) {
        case LSC_SCOPE_GROUP:  ss << ".group";  break;
        case LSC_SCOPE_LOCAL:  ss << ".local";  break;
        case LSC_SCOPE_TILE:   ss << ".tile";   break;
        case LSC_SCOPE_GPU:    ss << ".gpu";    break;
        case LSC_SCOPE_GPUS:   ss << ".gpus";   break;
        case LSC_SCOPE_SYSREL: ss << ".sysrel"; break;
        case LSC_SCOPE_SYSACQ: ss << ".sysacq"; break;
        default: ss << ".???"; break;
        }
    } // formatFence

    bool isVectorOpV0(const vector_opnd &vo) const {
        return (vo.tag & 0x7) == OPERAND_GENERAL &&
            (vo.opnd_val.gen_opnd.index == 0);
    }

    ///////////////////////////////////////////////////////////////////////////
    // for all but block2d and append counter atomic
    void formatUntypedSimple() {
        //
        ss << opInfo.mnemonic;

        //////////////////
        // sfid (e.g. .ugm, .ugml, or .slm)
        auto sfid = getNextEnumU8<LSC_SFID>();
        formatSfid(sfid);
        //
        //////////////////
        // caching
        formatCachingOpts();

        // execution size and offset
        ss << " " << printExecutionSize(inst->opcode, inst->execsize, subOp);
        //
        auto addrType = getNextEnumU8<LSC_ADDR_TYPE>();
        uint16_t immediateScale = getNext<uint16_t>();
        int32_t immediateOffset = getNext<int32_t>();
        auto addrSize = getNextEnumU8<LSC_ADDR_SIZE>();
        //
        auto dataShape = getNextDataShape();
        //
        ss << "  ";

        // see the table below for operand indices
        auto fmtAddrOperand = [&] () {
            formatAddrType(addrType, currOpIx);
            //
            ss << "[";
            if (immediateScale > 1) {
              ss << "0x" << std::hex << immediateScale << "*";
            }
            formatRawOperand(currOpIx + 2);
            if (immediateOffset != 0) {
                if (immediateOffset < 0) {
                    immediateOffset = -immediateOffset;
                    ss << "-";
                } else {
                    ss << "+";
                }
                ss << "0x" << std::hex << immediateOffset;
            }
            if (opInfo.isStrided()) {
                const vector_opnd &vo = getVectorOperand(inst, currOpIx + 3);
                if (!isVectorOpV0(vo)) {
                    // only non-V0 values
                    ss << ", ";
                    formatVectorOperand(currOpIx + 3);
                }
            }
            ss << "]";
            formatAddrSize(addrSize);
        };

        // parameter order (c.f. IsaDescription.cpp)
        // =============================+===========================
        //  regular                     |  strided
        // =============================+===========================
        //   0 - surface                |  surface
        //   1 - dst       (data read)  |  dst         (data read)
        //   2 - src0      (addr)       |  src0        (addr-base)
        //   3 - src1      (data sent)  |  src0-stride (data sent)
        //   4 - src2      (atomic arg) |  src1        (data sent/atomic)
        //                              |  (src2 doesn't exist in strided)
        // =============================+===========================
        int src1AbsIx = opInfo.isStrided() ? currOpIx + 4 : currOpIx + 3;
        if (opInfo.isLoad()) {
            formatDataOperand(dataShape, currOpIx + 1); // dst
            ss << "  ";
            fmtAddrOperand(); // src0
        } else if (opInfo.isStore()) {
            fmtAddrOperand(); // src0
            ss << "  ";
            formatDataOperand(dataShape, src1AbsIx); // src1
        } else if (opInfo.isAtomic()) {
            formatDataOperand(dataShape, currOpIx + 1); // dst
            ss << "  ";
            fmtAddrOperand(); // src0
            ss << "  ";
            formatRawOperand(src1AbsIx); // src1
            ss << "  ";
            formatRawOperand(src1AbsIx + 1); // src2
        } else {
            MUST_BE_TRUE(false, "must be load or store or atomic");
        }
    } // formatUntypedSimple

    ///////////////////////////////////////////////////////////////////////////
    void formatUntypedBlock2D() {
        ss << opInfo.mnemonic;

        auto sfid = getNextEnumU8<LSC_SFID>();
        formatSfid(sfid);

        formatCachingOpts();

        // execution size and offset
        ss << " " << printExecutionSize(inst->opcode, inst->execsize, subOp);

        //
        LSC_DATA_SHAPE_BLOCK2D dataShape { };
        dataShape.size = getNextEnumU8<LSC_DATA_SIZE>();
        dataShape.order = getNextEnumU8<LSC_DATA_ORDER>();
        dataShape.blocks = (int)getNext<uint8_t>();
        dataShape.width = (int)getNext<uint16_t>();
        dataShape.height = (int)getNext<uint16_t>();
        dataShape.vnni = getNext<uint8_t>() != 0;

        auto formatDataOperand = [&] (int absOpIx) {
            formatRawOperand(absOpIx);
            formatDataShape2D(dataShape);
        };
        ss << "  ";

        ///////////////////////////////////////////////////////
        // The rest of the operands are arranged as follows.
        //   0 - SurfaceBase
        //   1 - SurfaceWidth
        //   2 - SurfaceHeight
        //   3 - SurfacePitch
        //   4 - SurfaceOffsetX
        //   5 - SurfaceOffsetY
        //   6 - DataOperand
        auto fmtAddrOperand = [&] () {
            ss << "flat";
            ss << "[";
            formatVectorOperand(currOpIx + 1);
            ss << ", ";
            formatVectorOperand(currOpIx + 2);
            ss << ", ";
            formatVectorOperand(currOpIx + 3);
            ss << ", ";
            formatVectorOperand(currOpIx + 4);
            ss << ", ";
            formatVectorOperand(currOpIx + 5);
            ss << ", ";
            formatVectorOperand(currOpIx + 6);
            ss << "]";
        };

        if (opInfo.isLoad()) {
            formatDataOperand(currOpIx + 0);
            ss << "  ";
            fmtAddrOperand();
        } else {
            fmtAddrOperand();
            ss << "  ";
            formatDataOperand(currOpIx + 7);
        }
    } // formatUntypedBlock2D

    ///////////////////////////////////////////////////////////////////////////
    void formatUntyped() {
        if (subOp == LSC_LOAD_BLOCK2D || subOp == LSC_STORE_BLOCK2D) {
            formatUntypedBlock2D();
        } else {
            formatUntypedSimple();
        }
    } // formatUntyped

    ///////////////////////////////////////////////////////////////////////////
    void formatTyped() {
        ss << opInfo.mnemonic;

        formatSfid(LSC_TGM);
        //////////////////
        // caching
        formatCachingOpts();

        // execution size and offset
        ss << " " << printExecutionSize(inst->opcode, inst->execsize, subOp);

        auto addrType = getNextEnumU8<LSC_ADDR_TYPE>();
        auto addrSize = getNextEnumU8<LSC_ADDR_SIZE>();
        auto dataShape = getNextDataShape();

        auto fmtAddrOperand = [&] () {
            // 0 dst, 1-4 u/v/r/lod, 5 src1, 6 src2
            formatAddrType(addrType, currOpIx);
            ss << "[";
            for (int i = 0; i < 4; i++) {
                // +2 skip surface and dst
                const raw_opnd &ro = getRawOperand(inst, currOpIx+2+i);
                auto reg =
                    printVariableDeclName(header, ro.index, opts, NOT_A_STATE_OPND);
                if (reg == "V0")
                    break;
                if (i > 0)
                    ss << ", ";
                ss << reg;
            }
            ss << "]";
            formatAddrSize(addrSize);
        };

        ss << "  ";

        // parameter order (cf IsaDescription.cpp)
        //   0 - surface
        //   1 - dst (data read)
        //   2 - src0 U's (addr)
        //   3 - src0 V's (addr)
        //   4 - src0 R's (addr)
        //   5 - src0 LOD's (addr)
        //   6 - src1 (data sent)
        //   7 - src2 (extra data sent for atomic)
        if (opInfo.isLoad()) {
            formatDataOperand(dataShape, currOpIx + 1);
            ss << "  ";
            fmtAddrOperand();
        } else if (opInfo.isStore()) {
            fmtAddrOperand();
            ss << "  ";
            formatDataOperand(dataShape, currOpIx + 6);
        } else if (opInfo.isAtomic()) {
            formatDataOperand(dataShape, currOpIx + 1); // dst write back
            ss << "  ";
            fmtAddrOperand();
            ss << "  ";
            formatRawOperand(currOpIx + 6); // iadd, etc
            ss << "  ";
            formatRawOperand(currOpIx + 7); // for {i,f}cas
        } else {
            error = true;
            MUST_BE_TRUE(false, "printInstructionLscTyped unexpected category");
        }
    } // formatTyped

    // e.g. lsc_read_state_info.tgm  VDATA  bti(0x4)
    void formatTypedRSI() {
        ss << opInfo.mnemonic;

        formatSfid(LSC_TGM);

        // will be default/default (and thus suppressed)
        formatCachingOpts();

        // exec size is implicit
        auto addrType = getNextEnumU8<LSC_ADDR_TYPE>();
        (void)getNextEnumU8<LSC_ADDR_SIZE>();
        (void)getNextDataShape();

        ss << "  ";
        formatRawOperand(currOpIx + 1); // dst
        ss << "  ";
        formatAddrType(addrType, currOpIx);
    }

public:
    // the only public entry point (except the constructor)
    std::string format() {
        ss << printPredicate(inst->opcode, inst->pred);

        if (opcode == ISA_LSC_FENCE) {
            formatFence();
        } else if (opcode == ISA_LSC_UNTYPED) {
            formatUntyped();
        } else if (opcode == ISA_LSC_TYPED) {
            if (opInfo.op == LSC_READ_STATE_INFO) {
                formatTypedRSI();
            } else {
                formatTyped();
            }
        } else {
            MUST_BE_TRUE(false, "invalid LSC op");
        }
        return ss.str();
    }
};


static std::string printInstructionLsc(
    ISA_Opcode opcode,
    const print_format_provider_t* header,
    const CISA_INST* inst,
    const Options *opt)
{
    LscInstFormatter formatter(opcode, header, inst, opt);
    return formatter.format();
}

std::string VISAKernel_format_provider::printKernelHeader(
    const common_isa_header& isaHeader)
{
    std::stringstream sstr;

    bool isKernel = m_kernel->getIsKernel();

    sstr << printBuildVersion(isaHeader) << std::endl;
    sstr << printFunctionDecl(this, isKernel) << std::endl;

    // Print all functions in the same object
    if (isKernel)
    {
        for (unsigned i = 0; i < isaHeader.num_functions; i++)
        {
            sstr << ".funcdecl ";
            encodeStringLiteral(sstr, isaHeader.functions[i].name);
            sstr << "\n";
        }
    }

    auto options = const_cast<VISAKernelImpl*>(m_kernel)->getOptions();

    // Print the predefined variables as comments
    sstr << "\n" << "/// VISA Predefined Variables";
    for (unsigned i = 0; i < Get_CISA_PreDefined_Var_Count(); i++)
    {
        const var_info_t* predefVar = getPredefVar(i);
        if (predefVar->name_index != -1)
        {
            sstr << "\n" << "// .decl V" << i
                << " v_type=G"
                << " v_name=" << getString(predefVar->name_index);
        }
    }
    for (unsigned i = 0; i < Get_CISA_PreDefined_Surf_Count(); i++)
    {
        const state_info_t* predefSurface = getPredefSurface(i);
        if (predefSurface->name_index != -1)
        {
            sstr << "\n" << "// .decl T" << i
                << " v_type=T"
                << " v_name=" << getString(predefSurface->name_index);
        }
    }
    sstr << "\n";

    // emit var decls
    //.decl  V<#> name=<name> type=<type> num_elts=<num_elements> [align=<align>] [alias=(<alias_index>,<alias_offset>)]
    for (unsigned i = 0; i < getVarCount(); i++)
    {
        sstr << "\n" << printVariableDecl(this, i, options);
    }
    // address decls
    for (unsigned i = 0; i < getAddrCount(); i++)
    {
        sstr << "\n" << printAddressDecl(isaHeader, this, i);
    }
    // pred decls
    for (unsigned i = 0; i < getPredCount(); i++)
    {
        // P0 is reserved; starting from P1 if there is predicate decl
        sstr << "\n" << printPredicateDecl(this, i);
    }
    // sampler
    for (unsigned i = 0; i < getSamplerCount(); i++)
    {
        sstr << "\n" << printSamplerDecl(this, i);
    }
    // surface
    unsigned numPreDefinedSurfs = Get_CISA_PreDefined_Surf_Count();
    for (unsigned i = 0; i < getSurfaceCount(); i++)
    {
        sstr << "\n" << printSurfaceDecl(this, i, numPreDefinedSurfs);
    }
    // inputs to kernel
    for (unsigned i = 0; i < getInputCount(); i++)
    {
        sstr << "\n" << printFuncInput(this, i, isKernel, options);
    }

    bool isTargetSet = false;
    for (unsigned i = 0; i < getAttrCount(); i++)
    {
        const char* attrName = getString(getAttr(i)->nameIndex);
        if (Attributes::isAttribute(Attributes::ATTR_OutputAsmPath, attrName)) {
            // treat this as a transient property and skip it
            // this simplifies diffs in shader dump debugging
            // if you want to set an explicit name from the command line,
            // then use the appropriate option to set this attribute
            continue;
        }
        if (Attributes::isAttribute(Attributes::ATTR_Target, attrName)) {
            isTargetSet = true;
        }
        sstr << "\n.kernel_attr " << printOneAttribute(this, getAttr(i));
    }
    if (!isTargetSet)
    {
        const char* attrName = Attributes::getAttributeName(Attributes::ATTR_Target);
        sstr << "\n" << ".kernel_attr " << attrName << "=";
        switch (options->getTarget()) {
        case VISA_CM: sstr << "\"cm\""; break;
        case VISA_3D: sstr << "\"3d\""; break;
        default:
            MUST_BE_TRUE(false, "Invalid kernel target attribute.");
            break;
        }
    }

    return sstr.str();
}

std::string printFunctionDecl(const print_format_provider_t* header, bool isKernel)
{
    std::stringstream sstr;
    std::string name = header->getString(header->getNameIndex());
    std::replace_if(name.begin(), name.end(), [](char c) { return c == '.'; }, ' ');

    sstr << (!isKernel ? ".global_function " : ".kernel ");
    encodeStringLiteral(sstr, name.c_str());
    return sstr.str();
}

std::string printBuildVersion(const common_isa_header& isaHeader)
{
    std::stringstream sstr;
    sstr << ".version " << (int)(isaHeader.major_version) << "." << (int)(isaHeader.minor_version);
    return sstr.str();
}

std::string printInstruction(
    const print_format_provider_t* header,
    const CISA_INST* instruction,
    const Options *opt)
{
    std::stringstream sstr;

    ISA_Opcode opcode = (ISA_Opcode)instruction->opcode;
    if (opcode != ISA_LOC || !g_ignorelocs)
    {
        if (opcode != ISA_LABEL)
        {
            sstr << "    ";
        }

        switch (ISA_Inst_Table[opcode].type)
        {
            case ISA_Inst_Mov:
            case ISA_Inst_Sync:
            case ISA_Inst_Arith:
            case ISA_Inst_Logic:
            case ISA_Inst_Compare:
            case ISA_Inst_Address:
            case ISA_Inst_SIMD_Flow: sstr << printInstructionCommon      (header, instruction, opt); break;
            case ISA_Inst_SVM:       sstr << printInstructionSVM         (header, instruction, opt); break;
            case ISA_Inst_Flow:      sstr << printInstructionControlFlow (header, instruction, opt); break;
            case ISA_Inst_Misc:      sstr << printInstructionMisc        (header, instruction, opt); break;
            case ISA_Inst_Sampler:   sstr << printInstructionSampler     (header, instruction, opt); break;
            case ISA_Inst_Data_Port: sstr << printInstructionDataport    (header, instruction, opt); break;
            case ISA_Inst_LSC:       sstr << printInstructionLsc         (opcode, header, instruction, opt); break;
            default:
            {
                sstr << "Illegal or unimplemented CISA instruction (opcode, type): ("
                     << opcode << ", " << ISA_Inst_Table[opcode].type << ").";
                MUST_BE_TRUE(false, sstr.str());
            }
        }

        switch (opcode)
        {
            case ISA_LOC:
            case ISA_SUBROUTINE:
            case ISA_FILE:
            case ISA_LABEL: break;
            default:
            {
                std::stringstream sstr2;
                if (g_prettyPrint)
                for (int i = 0; i < (int)80 - (int)sstr.str().length(); i++)
                    sstr2 << ' ';
                if (!g_noinstid)
                    sstr << sstr2.str() << " /// $" << instruction->id;
            }
        }
    }
    else
    {
        sstr << "";
    }

    return sstr.str();
}
