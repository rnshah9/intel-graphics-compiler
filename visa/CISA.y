/*========================== begin_copyright_notice ============================

Copyright (C) 2017-2021 Intel Corporation

SPDX-License-Identifier: MIT

============================= end_copyright_notice ===========================*/

%{
#include <stdio.h>
#include <math.h>
#include <string>
#include <vector>

#include "visa_igc_common_header.h"
#include "Common_ISA.h"
#include "Common_ISA_util.h"
#include "Common_ISA_framework.h"
#include "JitterDataStruct.h"
#include "VISAKernel.h"

static int lscCheckExecSize(
    CISA_IR_Builder* pBuilder,
    LSC_SFID sfid,
    LSC_OP op,
    LSC_DATA_ORDER data_order,
    int exec_size);

//VISA_Type variable_declaration_and_type_check(char *var, Common_ISA_Var_Class type);
void CISAerror(CISA_IR_Builder* builder, char const* msg);
int yylex(CISA_IR_Builder *pBuilder);
extern int CISAlineno;


static bool ParseAlign(CISA_IR_Builder* pBuilder, const char *sym, VISA_Align &value);
static VISA_Align AlignBytesToVisaAlignment(int bytes);
static int DataTypeSizeOf(VISA_Type type);
static bool ParseEMask(const char* sym, VISA_EMask_Ctrl &emask);




//
// check if the cond is true.
// if cond is false, then print errorMessage (syntax error) and YYABORT
#define MUST_HOLD(cond, errorMessage) \
  {if (!(cond)) {pBuilder->RecordParseError(CISAlineno, errorMessage); YYABORT;}}
#define PARSE_ERROR_AT(LINE,...)\
  {pBuilder->RecordParseError(LINE, __VA_ARGS__); YYABORT;}
#define PARSE_ERROR(...)\
    PARSE_ERROR_AT(CISAlineno, __VA_ARGS__)

// Use this to wrap API calls that return false, nullptr, or 0 on failure
// It's assumed that the API call reported the parse error
#define ABORT_ON_FAIL(X) \
    do \
        if (!(X)) \
            YYABORT;\
    while (0)
#define TRACE(S) \
    do { \
      if (CISAout && pBuilder->debugParse()) \
          fprintf(CISAout, "line %d: %s", CISAlineno, S); \
    } while (0)

std::deque<const char*> switchLabels;
char * switch_label_array[32];
std::vector<VISA_opnd*> RTRWOperandsVec;
int num_parameters;

VISA_RawOpnd* rawOperandArray[16];

// global var for non-kernel attribute option.
// The var needs to be cleared before each use.
std::vector<attr_gen_struct*> AttrOptVar;

#ifdef _MSC_VER
#pragma warning(disable:4065; disable:4267)
#endif

%}

%param {CISA_IR_Builder* pBuilder}

//////////////////////////////////////////////////////////////////////////
// This asserts that the parser is (nearly?) free of shift-reduce and reduce-reduce
// conflicts.  This is usually pretty easy to keep at the moment.
//   FIXME: c.f. CmpInstruction:
%expect 1

%define parse.error verbose

%union
{
    int64_t                intval;
    double                 fltval;

    struct strlitbuf_struct {
        char      decoded[4096];
        size_t    len;
    } strlit;
    char *                 string;

    VISA_Type              type;
    ISA_Opcode             opcode;
    bool                   sat;

    VISA_Cond_Mod          cond_mod;

    VISA_opnd *            pred_reg;
    VISA_PREDICATE_STATE   pred_sign;
    VISA_PREDICATE_CONTROL pred_ctrl;

    // to tell call is fc_call or subroutine call
    struct call_sub_or_fc {
        ISA_Opcode opcode;
        bool       is_fccall;
    } cisa_call;

    struct {
        VISA_Modifier mod;
    } src_mod;

    struct {
        unsigned int v_stride;
        unsigned int h_stride;
        unsigned int width;
    } cisa_region;

    struct {
        int                row;
        int                elem;
    } offset;

    struct {
        Common_ISA_Operand_Class type;
        VISA_opnd * cisa_gen_opnd;
    } genOperand;

    struct {
        char * var_name;
        VISA_opnd * cisa_gen_opnd;
        unsigned char streamMode;
        unsigned char searchCtrl;
    } vmeOpndIvb;

    struct {
        VISA_opnd * cisa_fbrMbMode_opnd;
        VISA_opnd * cisa_fbrSubMbShape_opnd;
        VISA_opnd * cisa_fbrSubPredMode_opnd;
    } vmeOpndFbr;

    struct {
        int            row;
        int            elem;
        int            immOff;
        VISA_opnd *    cisa_gen_opnd;
        CISA_GEN_VAR * cisa_decl;
    } regAccess;

    struct {
        char *             aliasname;
        int                offset;
    } alias;

    VISA_opnd * RawVar;

    struct {
        Common_ISA_State_Opnd type;
        unsigned char offset;
        VISA_opnd * cisa_gen_opnd;
    } StateVar;

    struct {
        VISA_EMask_Ctrl emask;
        int exec_size;
    } emask_exec_size;

    struct attr_gen_struct*  pattr_gen;

    struct dpas_info_struct {
        ISA_Opcode    opcode;
        GenPrecision  src2Precision;
        GenPrecision  src1Precision;
        uint8_t       depth;
        uint8_t       count;
    } dpas_info;

    struct bfn_op_struct {
        uint8_t func_ctrl;
    } bfn_info;

    ///////////////////////////////////////////////////////////////////////////
    // Support for LSC instructions
    LSC_OP                  lsc_subOpcode;
    ISA_Opcode              lsc_opcode;
    LSC_CACHE_OPTS          lsc_caching_opts;
    LSC_CACHE_OPT           lsc_caching_opt; // for lexer to parser
    LSC_FENCE_OP            lsc_fence_op;
    LSC_SCOPE               lsc_scope;
    LSC_SFID                lsc_sfid;

    struct {
        VISA_opnd              *reg;
        LSC_DATA_SHAPE          shape;
    } lsc_data_operand;
    LSC_DATA_SHAPE            lsc_data_shape;
    struct {
        VISA_opnd              *reg;
        LSC_DATA_SHAPE_BLOCK2D  shape2D;
    } lsc_data_operand2d;
    LSC_DATA_SHAPE_BLOCK2D    lsc_data_shape2d;

    struct {
        VISA_opnd               *surface;
        // for UNTYPED
        //  simple:  regs[0] = reg addr
        //  strided: regs[0] = base; regs[1] = strided
        //  block2d: regs = {surfBase,surfWidth,surfHeight,surfPitch,surfX,surfY}
        //
        // for TYPED: {U, V, R, LOD}
        // for TYPED block2d: regs = {BlockStartX, BlockStartY}
        VISA_opnd               *regs[6];
        LSC_ADDR                 addr;
    } lsc_addr_operand;
    LSC_ADDR_SIZE              lsc_addr_size;
    LSC_ADDR_TYPE              lsc_addr_type;
    VISA_opnd                 *lsc_addr_surface_ident; // vec. opnd imm or reg
    struct lsc_addr_model_struct {
        LSC_ADDR_TYPE          type;
        VISA_opnd             *surface; // can be imm or reg
    } lsc_addr_model;

    // Align Support in Declaration
    VISA_Align             align;

    VISAAtomicOps          atomic_op;
    VISASampler3DSubOpCode sample3DOp;

    MEDIA_LD_mod           media_mode;
    bool                   oword_mod;
    VISAChannelMask        s_channel; // Cannot use ChannelMask here as it's a member of union where non-trivial constructor is not allowed.
    CHANNEL_OUTPUT_FORMAT  s_channel_output;
    VISA_EMask_Ctrl        emask;
    OutputFormatControl    cntrl;
    AVSExecMode            execMode;
    unsigned char          fence_options;

    // Pixel null mask for sampler instructions.
    bool                   pixel_null_mask;

    // CPS LOD compensation enable for 3d sample.
    bool                   cps;
    bool                   non_uniform_sampler;
    bool                   flag;

    CISA_GEN_VAR*          vISADecl;
} // end of possible token types

%start Listing

%type <intval> ScopeStart


%token <align>     ALIGN_KEYWORD
%token <atomic_op> ATOMIC_SUB_OP

// directives
%token          DIRECTIVE_DECL        // .decl
%token          DIRECTIVE_FUNC        // .function
%token          DIRECTIVE_FUNCDECL    // .funcdecl
%token          DIRECTIVE_GLOBAL_FUNC // .global_function
%token <string> DIRECTIVE_IMPLICIT    // .implicit*
%token          DIRECTIVE_INPUT       // .input
%token          DIRECTIVE_KERNEL      // .kernel
%token          DIRECTIVE_KERNEL_ATTR // .kernel_attr
%token          DIRECTIVE_PARAMETER   // .parameter
%token          DIRECTIVE_VERSION     // .verions

// tokens to support .decl and .input
%token ALIAS_EQ             // .decl ... alias=...
%token ALIGN_EQ             // .decl ... align=...
%token ATTR_EQ              // .decl ... attr=...
%token OFFSET_EQ
%token NUM_ELTS_EQ
%token V_NAME_EQ
%token SIZE_EQ
%token V_TYPE_EQ_G // v_type=G
%token V_TYPE_EQ_P
%token V_TYPE_EQ_A
%token V_TYPE_EQ_S
%token V_TYPE_EQ_T


%token CPS                   // .cps
%token NON_UNIFORM_SAMPLER  // .divS
%token PIXEL_NULL_MASK      // .pixel_null_mask
%token RAW_SENDC_STRING     // raw_sendc
%token RAW_SENDSC_EOT_STRING // raw_sendsc_eot
%token RAW_SENDSC_STRING    // raw_sendsc
%token RAW_SENDS_EOT_STRING // raw_sends_eot
%token RAW_SENDS_STRING     // raw_sends
%token RAW_SEND_STRING      // raw_send
%token SAT                  // .sat
%token SRCMOD_ABS           // (abs)
%token SRCMOD_NEG           // (-)
%token SRCMOD_NEGABS        // (-abs)
%token SRCMOD_NOT           // (~)
%token BFN_OP
%token DPAS_OP
%token BF_CVT_OP
%token <opcode> NBARRIER_SIGNAL
%token <opcode> NBARRIER_WAIT
%token <type>   ITYPE
%token <type>   DECL_DATA_TYPE
%token <type>   DFTYPE         // :df
%token <type>   FTYPE          // :f
%token <type>   HFTYPE         // :hf
%token <type>   VTYPE          // :v and vf
%token <cond_mod> COND_MOD     // .ne .ge ...

%token LANGLE          // <
%token RANGLE          // >
%token LBRACK          // [
%token RBRACK          // ]
%token IND_LBRACK      // r[
%token LPAREN          // (
%token RPAREN          // )
%token LBRACE          // {
%token RBRACE          // }

%token DOT             // .
%token COMMA           // ,
%token SEMI            // ;
%token COLON           // :
%token SLASH           // /
%token PERCENT         // %
%token EQUALS          // =
%token PLUS            // +
%token MINUS           // -
%token TIMES           // *
%token AMP             // &
%token CIRC            // ^
%token PIPE            // |
%token TILDE           // ~
%token BANG            // !
%token QUESTION        // ?
%token LEQ             // relational operators
%token GEQ
%token EQ
%token NEQ
%token SHL             // shift operators
%token SHRS
%token SHRZ

%token <string> LABEL

%token <string> IDENT         // an identifier of some sort
%token <string> BUILTIN_NULL  // %null
%token <string> BUILTIN       // other builtins e.g. %r0, %cr0, ...
%token <string> STRING_LIT

%token NEWLINE


%token <string>            RTWRITE_OPTION
%token <media_mode>        MEDIA_MODE
%token <oword_mod>         OWORD_MODIFIER
%token <s_channel>         SAMPLER_CHANNEL
%token <s_channel_output>  CHANNEL_OUTPUT
%token <execMode>          EXECMODE
%token <cntrl>             CNTRL
%token <fence_options>     FENCE_OPTIONS;

// Instruction opcode tokens
%token <opcode> ADDR_ADD_OP
%token <opcode> UNARY_LOGIC_OP
%token <opcode> BINARY_LOGIC_OP
%token <opcode> TERNARY_LOGIC_OP
%token <opcode> QUATERNARY_LOGIC_OP

%token <opcode> SEL_OP
%token <opcode> MIN_OP
%token <opcode> MAX_OP
%token <opcode> ANTI_TRIG_OP
%token <opcode> MATH2_OP
%token <opcode> MATH3_OP
%token <opcode> ARITH2_OP
%token <opcode> ARITH3_OP
%token <opcode> ARITH4_OP
%token <opcode> ARITH4_OP2
%token <opcode> CMP_OP
%token <opcode> SVM_OP
%token <opcode> SVM_SCATTER_OP
%token <opcode> SVM_GATHER4SCALED_OP
%token <opcode> SVM_SCATTER4SCALED_OP
%token <opcode> SVM_ATOMIC_OP
%token <opcode> OWORD_OP
%token <opcode> MEDIA_OP
%token <opcode> SCATTER_OP
%token <opcode> SCATTER_TYPED_OP
%token <opcode> SCATTER_SCALED_OP
%token <opcode> SCATTER4_SCALED_OP
%token <opcode> BARRIER_OP
%token <opcode> SBARRIER_SIGNAL
%token <opcode> SBARRIER_WAIT
%token <opcode> DWORD_ATOMIC_OP
%token <opcode> TYPED_ATOMIC_OP
%token <opcode> SAMPLE_OP
%token <opcode> SAMPLE_UNORM_OP
%token <opcode> VME_IME_OP
%token <opcode> VME_SIC_OP
%token <opcode> VME_FBR_OP
%token <opcode> BRANCH_OP
%token <opcode> RET_OP
%token <opcode> IFCALL
%token <opcode> FCALL
%token <opcode> FADDR
%token <opcode> SWITCHJMP_OP
%token <opcode> MOVS_OP
%token <opcode> SETP_OP
%token <opcode> MOV_OP
%token <opcode> FILE_OP
%token <opcode> LOC_OP
%token <opcode> CACHE_FLUSH_OP
%token <opcode> WAIT_OP
%token <opcode> FENCE_GLOBAL_OP
%token <opcode> FENCE_LOCAL_OP
%token <opcode> FENCE_SW_OP
%token <opcode> YIELD_OP
%token <sample3DOp> SAMPLE_3D_OP
%token <sample3DOp> LOAD_3D_OP
%token <sample3DOp> SAMPLE4_3D_OP
%token <opcode> RESINFO_OP_3D
%token <opcode> SAMPLEINFO_OP_3D
%token <opcode> RTWRITE_OP_3D
%token <opcode> URBWRITE_OP_3D
%token <opcode> LIFETIME_START_OP
%token <opcode> LIFETIME_END_OP
%token <opcode> AVS_OP
%token <cisa_call> CALL_OP

%type <string> RTWriteModeOpt

%type <intval> SwitchLabels
%type <intval> RTWriteOperands

%type <pred_reg>   Predicate
%type <pred_sign>  PredSign
%type <pred_ctrl>  PredCtrlOpt
%token <pred_ctrl> PRED_CNTL   // .any or .all


%type <string> IdentOrStringLit
%type <string> Var
%type <string> VarNonNull

%type <intval> MediaInstructionPlaneID
%type <intval> SIMDMode
%type <intval> DstRegion


%token <fltval> F32_LIT  // single-precision floating point value
%token <fltval> F64_LIT  // double-precision floating point value
%token <intval> DEC_LIT  // decimal (base 10) literal
%token <intval> HEX_LIT  // hexadecimal literal (e.g. 0x123)

%type <intval> IntExp
%type <intval> IntExpCond
%type <intval> IntExpAND
%type <intval> IntExpXOR
%type <intval> IntExpOR
%type <intval> IntExpCmp
%type <intval> IntExpRel
%type <intval> IntExpNRA
%type <intval> IntExpShift
%type <intval> IntExpAdd
%type <intval> IntExpMul
%type <intval> IntExpUnr
%type <intval> IntExpPrim

%token BUILTIN_SIZEOF
%token BUILTIN_DISPATCH_SIMD_SIZE

%type <intval> ElemNum
%type <intval> InputOffset
%type <intval> InputSize
%type <string> VNameEqOpt

%type <cond_mod> ConditionalModifier

%type <genOperand> SrcGeneralOperand
%type <genOperand> SrcImmOperand
%type <fltval>     FloatLit
%type <fltval>     DoubleFloatLit
%type <genOperand> SrcIndirectOperand
%type <genOperand> SrcAddrOperand
%type <genOperand> SrcAddrOfOperand
%type <regAccess>  AddrOfVar

// the scheme here is:
//   G - general;           e.g. VAR(0,2)
//   I - indirect           e.g. r[A0(0),0]<0;1,0>:f
//   IMM - immediate        e.g. 0x123:d or 3.141:f
//   A - address register   e.g. A(1)
//   AO - address of        e.g. &V127+0x10
%type <genOperand> VecSrcOperand_G
%type <genOperand> VecSrcOperand_G_A
%type <genOperand> VecSrcOperand_G_A_AO
%type <genOperand> VecSrcOperand_G_IMM
%type <genOperand> VecSrcOperand_G_IMM_AO
%type <genOperand> VecSrcOperand_G_I_IMM
%type <genOperand> VecSrcOperand_G_I_IMM_A
%type <genOperand> VecSrcOperand_G_I_IMM_A_AO
%type <genOperand> VecDstOperand_A
%type <genOperand> VecDstOperand_G
%type <genOperand> VecDstOperand_G_I
%type <genOperand> VecSrcOpndSimple
%type <genOperand> DstGeneralOperand
%type <genOperand> DstAddrOperand
%type <genOperand> DstIndirectOperand

%type <cisa_region> SrcRegionDirect
%type <cisa_region> SrcRegionIndirect

%type <regAccess>    IndirectVarAccess
%type <offset>       TwoDimOffset
%type <vISADecl>     PredVar
%type <regAccess>    AddrVarAccess
%type <regAccess>    AddrVarAccessWithWidth
// %type <vISADecl>     AddrVar

%type <vmeOpndIvb> VMEOpndIME
%type <vmeOpndFbr> VMEOpndFBR

%type <align>               Align
%type <align>               AlignAttrOpt
%type <emask_exec_size>     ExecSize
%type <intval>              ExecSizeInt
%type <type>                DataType
%type <type>                DataTypeIntOrVector
%type <src_mod>             SrcModifier
%type <sat>                 SatModOpt
%type <alias>               AliasAttrOpt
%type <oword_mod>           OwordModifier
%type <StateVar>            DstStateOperand
%type <StateVar>            SrcStateOperand
%type <RawVar>              RawOperand
%type <RawVar>              RawOperandNonNull
%type <intval>              RawOperandOffsetSuffix
%type <intval>              RawOperandArray
%type <pixel_null_mask>     PixelNullMaskEnableOpt
%type <cps>                 CPSEnableOpt
%type <non_uniform_sampler> NonUniformSamplerEnableOpt
%type <pattr_gen>           OneAttr
%type <intval>              AttrOpt
%type <intval>              GenAttrOpt
%type <flag>                Atomic16Opt
%type <intval>              AtomicBitwidthOpt
%type <dpas_info>           DPAS_OP
%type <bfn_info>            BFN_OP
%token <opcode>             QW_SCATTER_OP
// elements to support new LSC instructions
//
// cache options
%type  <lsc_caching_opts>      LscCacheOpts
%token <lsc_caching_opt>       LSC_CACHING_OPT
%type <RawVar>                 LscPayloadReg
%type <RawVar>                 LscPayloadNonNullReg
// address syntax; e.g. bss(S2)[V12]:a64
%type <lsc_addr_model>         LscAddrModelOpt
%type <lsc_addr_model>         LscRegAddrModel
%type <lsc_addr_operand>       LscUntypedAddrOperand
%type <lsc_addr_operand>       LscUntypedStridedAddrOperand
%type <lsc_addr_operand>       LscUntypedBlock2dAddrOperand
%type <lsc_addr_operand>       LscTypedAddrOperand
%token <lsc_addr_size>         LSC_ADDR_SIZE_TK
%type <lsc_addr_type>          LscRegAddrModelKind
%type <intval>                 LscAddrImmOffsetOpt
%type <intval>                 LscAddrImmScaleOpt
%type <lsc_addr_surface_ident> LscVectorOpRegOrImm
%type <lsc_addr_surface_ident> LscVectorOpReg
%type <lsc_addr_surface_ident> LscVectorOpImm

// data syntax; e.g. V13:u32x4t
%type <lsc_data_operand>       LscDataOperand
%type <lsc_data_operand2d>     LscDataOperand2D
%token <lsc_data_shape>        LSC_DATA_SHAPE_TK
%token <lsc_data_shape>        LSC_DATA_SHAPE_TK_CHMASK
%token <lsc_data_shape2d>      LSC_DATA_SHAPE_TK_BLOCK2D
//
%token                         LSC_AM_FLAT
%token                         LSC_AM_BTI
%token                         LSC_AM_BSS
%token                         LSC_AM_SS
%token                         LSC_AM_ARG
//
%token <lsc_fence_op>          LSC_FENCE_OP_TYPE
%token <lsc_scope>             LSC_FENCE_SCOPE
//
%type  <lsc_sfid>              LscSfid
%token <lsc_sfid>              LSC_SFID_UNTYPED_TOKEN
%token <lsc_sfid>              LSC_SFID_TYPED_TOKEN
////////////////////////////////////////////////////////
// specific LSC ops
//
// load*/store*/atomic* are all subops of LSC_TYPED and LSC_UNTYPED.
// We infer which parent op based on the grammar (LSC_SFID).
%token <lsc_subOpcode>         LSC_LOAD_MNEMONIC
%token <lsc_subOpcode>         LSC_LOAD_STRIDED_MNEMONIC
%token <lsc_subOpcode>         LSC_LOAD_BLOCK2D_MNEMONIC
%token <lsc_subOpcode>         LSC_STORE_MNEMONIC
%token <lsc_subOpcode>         LSC_STORE_STRIDED_MNEMONIC
%token <lsc_subOpcode>         LSC_STORE_BLOCK2D_MNEMONIC
%token <lsc_subOpcode>         LSC_ATOMIC_MNEMONIC
%token <lsc_subOpcode>         LSC_READ_STATE_INFO_MNEMONIC
// fence is a top-level op (not a subop)
%token <lsc_opcode>            LSC_FENCE_MNEMONIC
%token <opcode>                FCVT_OP



%%
Listing: NewlinesOpt ListingHeader NewlinesOpt Statements NewlinesOpt {
        TRACE("** Listing Complete\n");
        pBuilder->CISA_post_file_parse();
    }

ListingHeader: DirectiveVersion

Statements: Statements Newlines Statement | Statement

Newlines: Newlines NEWLINE | NEWLINE
NewlinesOpt: %empty | Newlines

Statement:
      DirectiveDecl
    | DirectiveKernel
    | DirectiveGlobalFunction
    | DirectiveImplicitInput
    | DirectiveInput
    | DirectiveParameter
    | DirectiveFunc
    | DirectiveAttr
    | Instruction
    | Label
    | Scope


// ------------- Scope -------------
Scope:
      ScopeStart NewlinesOpt                        ScopeEnd
    | ScopeStart NewlinesOpt Statements NewlinesOpt ScopeEnd
    | ScopeStart error {
        PARSE_ERROR_AT((int)$1, "unclosed scope");
    }
ScopeStart:
    LBRACE {
        pBuilder->CISA_push_decl_scope();
        $$ = CISAlineno;
    }
ScopeEnd: RBRACE {pBuilder->CISA_pop_decl_scope();}

// ------------- an identifier or string literal -------------
IdentOrStringLit: IDENT | STRING_LIT;

// ---------------------------------------------------------------------
// ------------------------- directives --------------------------------
// ---------------------------------------------------------------------

// ----- .kernel ------
DirectiveKernel: DIRECTIVE_KERNEL IdentOrStringLit
    {
        VISAKernel *cisa_kernel = NULL;
        pBuilder->AddKernel(cisa_kernel, $2);
    }


// ----- .global_function ------
DirectiveGlobalFunction: DIRECTIVE_GLOBAL_FUNC IdentOrStringLit
  {
      VISAFunction *cisa_kernel = NULL;
      pBuilder->AddFunction(cisa_kernel, $2);
  }


// ----- .version ------
DirectiveVersion : DIRECTIVE_VERSION DEC_LIT DOT DEC_LIT
   {
       pBuilder->CISA_IR_setVersion((unsigned char)$2, (unsigned char)$4);
   }

// ----- .decl -----
DirectiveDecl:
      DeclVariable
    | DeclAddress
    | DeclPredicate
    | DeclSampler
    | DeclSurface
    | DeclFunction

DeclFunction: DIRECTIVE_FUNCDECL STRING_LIT
    {
        // do nothing as it's informational only
    }

DeclVariable:
    //     1         2         3           4             5        6        7            8          9
    DIRECTIVE_DECL IDENT V_TYPE_EQ_G DECL_DATA_TYPE NUM_ELTS_EQ IntExp AlignAttrOpt AliasAttrOpt GenAttrOpt
    {
       ABORT_ON_FAIL(pBuilder->CISA_general_variable_decl(
           $2, (unsigned int)$6, $4, $7, $8.aliasname, $8.offset, AttrOptVar, CISAlineno));
       AttrOptVar.clear();
    }

               //     1       2        3         4         5        6
DeclAddress: DIRECTIVE_DECL IDENT V_TYPE_EQ_A NUM_ELTS_EQ IntExp GenAttrOpt
   {
       ABORT_ON_FAIL(
           pBuilder->CISA_addr_variable_decl($2, (unsigned int)$5, ISA_TYPE_UW, AttrOptVar, CISAlineno));
       AttrOptVar.clear();
   }

               //     1         2         3        4          5       6
DeclPredicate: DIRECTIVE_DECL IDENT V_TYPE_EQ_P NUM_ELTS_EQ IntExp GenAttrOpt
   {
       ABORT_ON_FAIL(pBuilder->CISA_predicate_variable_decl($2, (unsigned int)$5, AttrOptVar, CISAlineno));
       AttrOptVar.clear();
   }

               //     1       2         3       4          5         6          7
DeclSampler: DIRECTIVE_DECL IDENT V_TYPE_EQ_S NUM_ELTS_EQ IntExp VNameEqOpt GenAttrOpt
   {
       ABORT_ON_FAIL(pBuilder->CISA_sampler_variable_decl($2, (int)$5, $6, CISAlineno));
   }
VNameEqOpt: %empty  {$$ = "";} | V_NAME_EQ IDENT {$$ = $2;};

               //     1       2         3          4         5         6          7
DeclSurface: DIRECTIVE_DECL IDENT V_TYPE_EQ_T  NUM_ELTS_EQ IntExp  VNameEqOpt GenAttrOpt
   {
       ABORT_ON_FAIL(pBuilder->CISA_surface_variable_decl($2, (int)$5, $6, AttrOptVar, CISAlineno));
       AttrOptVar.clear();
   }

// ----- .input ------
DirectiveInput:
    DIRECTIVE_INPUT IDENT InputOffset InputSize
    {
        ABORT_ON_FAIL(pBuilder->CISA_input_directive($2, (short)$3, (unsigned short)$4, CISAlineno));
    }
    |
    DIRECTIVE_INPUT IDENT InputOffset
    {
        int64_t size = 0;
        ABORT_ON_FAIL(pBuilder->CISA_eval_sizeof_decl(CISAlineno, $2, size));
        MUST_HOLD(size < 0x10000, "declaration size is too large");
        ABORT_ON_FAIL(pBuilder->CISA_input_directive($2, (short)$3, (unsigned short)size, CISAlineno));
    }

///////////////////////////////////////////////////////////
// ----- .implicit* inputs ------
DirectiveImplicitInput:
    //  1                2        3        4        5
    DIRECTIVE_IMPLICIT IDENT InputOffset InputSize GenAttrOpt
    {
        ABORT_ON_FAIL(pBuilder->CISA_implicit_input_directive(
            $1, $2, (short)$3, (unsigned short)$4, CISAlineno));
    }
    |
    //  1                2        3           4
    DIRECTIVE_IMPLICIT IDENT InputOffset  GenAttrOpt
    {
        int64_t size = 0;
        ABORT_ON_FAIL(pBuilder->CISA_eval_sizeof_decl(CISAlineno, $2, size));
        MUST_HOLD(size < 0x10000, "declaration size is too large");
        ABORT_ON_FAIL(pBuilder->CISA_input_directive($2, (short)$3, (unsigned short)size, CISAlineno));
    }

InputOffset: %empty {$$ = 0;} | OFFSET_EQ IntExp {$$ = $2;}
InputSize: SIZE_EQ IntExp {$$ = $2;}

///////////////////////////////////////////////////////////
// ----- .parameter ------

DirectiveParameter:
    //      1            2       3        4
    DIRECTIVE_PARAMETER IDENT InputSize GenAttrOpt {
        ABORT_ON_FAIL(pBuilder->CISA_input_directive($2, 0, (unsigned short)$3, CISAlineno));
    }
// ----- .attribute ------

DirectiveAttr:
    DIRECTIVE_KERNEL_ATTR IDENT EQUALS STRING_LIT {
        ABORT_ON_FAIL(pBuilder->CISA_attr_directive($2, $4, CISAlineno));
    }
    |
    DIRECTIVE_KERNEL_ATTR IDENT EQUALS IntExp {
        ABORT_ON_FAIL(pBuilder->CISA_attr_directiveNum($2, (uint32_t)$4, CISAlineno));
    }
    |
    DIRECTIVE_KERNEL_ATTR IDENT {
        ABORT_ON_FAIL(pBuilder->CISA_attr_directive($2, nullptr, CISAlineno));
    }
    |
    DIRECTIVE_KERNEL_ATTR IDENT EQUALS {
        ABORT_ON_FAIL(pBuilder->CISA_attr_directive($2, nullptr, CISAlineno));
    }

// ----- .function -----
DirectiveFunc: DIRECTIVE_FUNC IdentOrStringLit
    {
        ABORT_ON_FAIL(pBuilder->CISA_function_directive($2, CISAlineno));
    }


AlignAttrOpt: %empty {$$ = ALIGN_BYTE;} | Align
Align:
    ALIGN_EQ ALIGN_KEYWORD { // 2GRF, 32word, ...
        $$ = $2;
    }
    |
    ALIGN_EQ IDENT { // e.g. byte, word, dword, qword, GRF, GRFx2
       if (!ParseAlign(pBuilder, $2, $$)) {
           PARSE_ERROR($2, ": invalid align value");
       }
    }
    |
    ALIGN_EQ IntExp {
        // e.g. %sizeof(GRF) or %sizeof(DECL)
        $$ = AlignBytesToVisaAlignment((int)$2);
        if ($$ == ALIGN_UNDEF) {
            PARSE_ERROR("invalid align size (must be 1, 2, 4, 8, ..., 128)");
        }
    }
    |
    ALIGN_EQ error {
        PARSE_ERROR("syntax error in align attribute");
    }


AliasAttrOpt:
    %empty
    {
       $$.aliasname = NULL;
       $$.offset = 0;
    }
    | ALIAS_EQ LANGLE Var COMMA IntExpNRA RANGLE
    {
       $$.aliasname = $3;
       $$.offset = (int)$5;
    }
    | ALIAS_EQ LANGLE error
    {
       PARSE_ERROR("syntax error in alias attribute");
    }

OneAttr:
    IDENT EQUALS IntExpNRA
    {
      $$ = pBuilder->CISA_Create_Attr($1, $3, nullptr);
    }
    | IDENT EQUALS STRING_LIT
    {
      $$ = pBuilder->CISA_Create_Attr($1, 0, $3);
    }
    | IDENT
    {
      $$ = pBuilder->CISA_Create_Attr($1, 0, nullptr);
    }

AttrOpt:
    AttrOpt COMMA OneAttr
    {
      AttrOptVar.push_back($3);
    }
    |
    OneAttr
    {
      AttrOptVar.push_back($1);
    }

GenAttrOpt:
    %empty
    {
        $$ = 0;
    }
    | ATTR_EQ LBRACE AttrOpt RBRACE
    {
        $$ = 1;
    }

// ----------------------------------------------------------
// --------------- Instructions -----------------------------
// ----------------------------------------------------------

Instruction:
          LogicInstruction
        | SvmInstruction
        | UnaryLogicInstruction
        | MathInstruction_2OPND
        | MathInstruction_3OPND
        | ArithInstruction_2OPND
        | ArithInstruction_3OPND
        | ArithInstruction_4OPND
        | AntiTrigInstruction
        | AddrAddInstruction
        | CmpInstruction
        | MediaInstruction
        | OwordInstruction
        | ScatterInstruction
        | ScatterTypedInstruction
        | ScatterScaledInstruction
        | Scatter4ScaledInstruction
        | SynchronizationInstruction
        | BranchInstruction
        | DwordAtomicInstruction
        | TypedAtomicInstruction
        | SampleInstruction
        | SampleUnormInstruction
        | VMEInstruction
        | AVSInstruction
        | MovsInstruction
        | MovInstruction
        | SelInstruction
        | MinInstruction
        | MaxInstruction
        | SetpInstruction
        | FILE
        | LOC
        | RawSendInstruction
        | RawSendsInstruction
        | Sample3dInstruction
        | Load3dInstruction
        | Gather43dInstruction
        | ResInfo3dInstruction
        | SampleInfo3dInstruction
        | RTWriteInstruction
        | URBWriteInstruction
        | LifetimeStartInst
        | LifetimeEndInst
        | NullaryInstruction
        | DpasInstruction
        | BfnInstruction
        | QwScatterInstruction
        | BF_CvtInstruction
        | LscInstruction
        | FCvtInstruction


Label: LABEL {pBuilder->CISA_create_label($1, CISAlineno);}


LogicInstruction:
    Predicate BINARY_LOGIC_OP SatModOpt  ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_logic_instruction($1, $2, $3, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, NULL, NULL, CISAlineno);
    }
    |
    Predicate BINARY_LOGIC_OP SatModOpt  ExecSize PredVar           PredVar               PredVar
    {
        pBuilder->CISA_create_logic_instruction($2, $4.emask, $4.exec_size, $5, $6, $7, CISAlineno);
    }
    |
    Predicate TERNARY_LOGIC_OP SatModOpt  ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_logic_instruction($1, $2, $3, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, $8.cisa_gen_opnd, NULL, CISAlineno);
    }
    |
    Predicate QUATERNARY_LOGIC_OP SatModOpt  ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_logic_instruction($1, $2, $3, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, $8.cisa_gen_opnd, $9.cisa_gen_opnd, CISAlineno);
    }


UnaryLogicInstruction:
    Predicate UNARY_LOGIC_OP SatModOpt  ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_logic_instruction($1, $2, $3, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, NULL, NULL, NULL, CISAlineno);
    }
    |
    Predicate UNARY_LOGIC_OP SatModOpt  ExecSize PredVar           PredVar
    {
        pBuilder->CISA_create_logic_instruction($2, $4.emask, $4.exec_size,
            $5, $6, NULL, CISAlineno);
    }

MathInstruction_2OPND:
    Predicate MATH2_OP SatModOpt ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_math_instruction($1, $2, $3, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, NULL, CISAlineno);
    }

MathInstruction_3OPND:
    Predicate MATH3_OP SatModOpt ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_math_instruction($1, $2, $3, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, CISAlineno);
    }

ArithInstruction_2OPND:
    Predicate ARITH2_OP SatModOpt ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_arith_instruction($1, $2, $3, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, NULL, NULL, CISAlineno);
    }

ArithInstruction_3OPND:
    Predicate ARITH3_OP SatModOpt ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM
    {
        MUST_HOLD(!(($2 == ISA_LINE) && ($6.type == OPERAND_IMMEDIATE || $6.type == OPERAND_INDIRECT)),
            "wrong type of src0 operand");
        pBuilder->CISA_create_arith_instruction(
            $1, $2, $3, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, NULL, CISAlineno);
    }


ArithInstruction_4OPND:
     //  1         2         3        4             5                    6                    7                     8
     Predicate ARITH4_OP SatModOpt ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM  VecSrcOperand_G_I_IMM
     {
         pBuilder->CISA_create_arith_instruction($1, $2, $3, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, $8.cisa_gen_opnd, CISAlineno);
     }
     //  1          2                      3           4                   5                   6                   7
     |
     Predicate ARITH4_OP2             ExecSize VecDstOperand_G_I VecDstOperand_G_I VecSrcOperand_G_I_IMM  VecSrcOperand_G_I_IMM
     {
        pBuilder->CISA_create_arith_instruction2($1, $2, $3.emask, $3.exec_size,
            $4.cisa_gen_opnd, $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, CISAlineno);
     }


DpasInstruction:
    // 1       2          3           4           5            6
    DPAS_OP ExecSize  RawOperand  RawOperand  RawOperand VecSrcOpndSimple
    {
        pBuilder->CISA_create_dpas_instruction(
            $1.opcode, $2.emask, $2.exec_size,
            $3, $4, $5, $6.cisa_gen_opnd,
            $1.src2Precision, $1.src1Precision, $1.depth, $1.count, CISAlineno);
    }

BfnInstruction:
    // 1      2         3         4           5                 6                      7                       8
    Predicate BFN_OP SatModOpt ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM  VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_bfn_instruction($1, $2.func_ctrl , $3, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, $8.cisa_gen_opnd, CISAlineno);
    }
//                        1           2        3     4       5      6      7         8
QwScatterInstruction: Predicate QW_SCATTER_OP DOT DEC_LIT ExecSize Var RawOperand RawOperand
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_qword_scatter_instruction(
            $2, $1, $5.emask, $5.exec_size, (uint32_t)$4, $6, $7, $8, CISAlineno));
    }

               //    1         2           3              4
BF_CvtInstruction: BF_CVT_OP ExecSize VecDstOperand_G VecSrcOperand_G_IMM
    {
        pBuilder->CISA_create_bf_cvt_instruction($2.emask, $2.exec_size, $3.cisa_gen_opnd, $4.cisa_gen_opnd, CISAlineno);
    }

               //   1        2            3            4
FCvtInstruction: FCVT_OP ExecSize VecDstOperand_G VecSrcOperand_G_IMM
    {
        pBuilder->CISA_create_fcvt_instruction($2.emask, $2.exec_size, $3.cisa_gen_opnd, $4.cisa_gen_opnd, CISAlineno);
    }

                     //  1            2           3            4             5                6
AntiTrigInstruction: Predicate ANTI_TRIG_OP SatModOpt ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_invtri_inst($1, $2, $3, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, CISAlineno);
    }


AddrAddInstruction:
     //  1         2           3              4                    5
    ADDR_ADD_OP ExecSize VecDstOperand_A VecSrcOperand_G_A_AO VecSrcOperand_G_IMM_AO
    {
        // a grammatically problematic instruction
        //   addr_add (M1_NM, 1) A0(0)<1> &V127 - 0x10...
        //                                        ^^^^ next operand or V127 offset
        pBuilder->CISA_create_address_instruction($1, $2.emask, $2.exec_size,
            $3.cisa_gen_opnd, $4.cisa_gen_opnd, $5.cisa_gen_opnd, CISAlineno);
    }

                //   1      2        3          4
SetpInstruction: SETP_OP ExecSize PredVar VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_setp_instruction(
            $1, $2.emask, $2.exec_size, $3, $4.cisa_gen_opnd, CISAlineno);
    }

                //   1       2       3         4          5                   6                   7
SelInstruction: Predicate SEL_OP SatModOpt ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_sel_instruction($2, $3, $1, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, CISAlineno);
    }

                //   1      2        3        4           5                   6                   7
MinInstruction: Predicate MIN_OP SatModOpt ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_fminmax_instruction(0, ISA_FMINMAX, $3, $1, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, CISAlineno);
    }

MaxInstruction:
    //   1      2         3       4          5                   6                     7
    Predicate MAX_OP SatModOpt ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_fminmax_instruction(
            1, ISA_FMINMAX, $3, $1, $4.emask, $4.exec_size,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, CISAlineno);
    }

MovInstruction:
    //  1       2       3          4         5                   6
    Predicate MOV_OP SatModOpt ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM_A_AO
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_mov_instruction(
            $1, $2, $4.emask, $4.exec_size, $3,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, CISAlineno));
    }
    |
    Predicate MOV_OP SatModOpt ExecSize VecDstOperand_A VecSrcOperand_G_I_IMM_A_AO
    {
        pBuilder->CISA_create_mov_instruction(
            $1, $2, $4.emask, $4.exec_size, $3,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, CISAlineno);
    }
    |
    Predicate MOV_OP SatModOpt ExecSize VecDstOperand_G_I PredVar
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_mov_instruction($5.cisa_gen_opnd, $6, CISAlineno));
    }

MovsInstruction:
    MOVS_OP ExecSize DstStateOperand SrcStateOperand
    {
        pBuilder->CISA_create_movs_instruction($2.emask, ISA_MOVS, $2.exec_size,
            $3.cisa_gen_opnd, $4.cisa_gen_opnd, CISAlineno);
    }
    |
    MOVS_OP ExecSize VecDstOperand_G SrcStateOperand
    {
        pBuilder->CISA_create_movs_instruction($2.emask, ISA_MOVS, $2.exec_size,
            $3.cisa_gen_opnd, $4.cisa_gen_opnd, CISAlineno);
    }
    |
    MOVS_OP ExecSize DstStateOperand VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_movs_instruction($2.emask, ISA_MOVS, $2.exec_size,
            $3.cisa_gen_opnd, $4.cisa_gen_opnd, CISAlineno);
    }


CmpInstruction:
    // FIXME: S/R conflict
    // DstGeneralOperand: Var . TwoDimOffset DstRegion
    //                  | Var . DstRegion
    // PredVar: Var .
    //
    // Given: ExecSize VAR with lookahead LPAREN
    // we cannot decide if we should shift LPAREN (we're looking at a DstOperand paren)
    // or reduce IDENT to PredVar

    // 1          2               3       4                       5                     6
    CMP_OP ConditionalModifier ExecSize PredVar           VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM
    {
        pBuilder->CISA_create_cmp_instruction($2, $3.emask, $3.exec_size,
            $4, $5.cisa_gen_opnd, $6.cisa_gen_opnd, CISAlineno);
    }
    |
    //    1        2              3          4                   5                     6
    CMP_OP ConditionalModifier ExecSize VecDstOperand_G_I VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM
    {
        // NOTE: predication not permitted.  Apparently the vISA API doesn't allow for predicated compares
        pBuilder->CISA_create_cmp_instruction(
            $2, ISA_CMP, $3.emask, $3.exec_size,
            $4.cisa_gen_opnd, $5.cisa_gen_opnd, $6.cisa_gen_opnd, CISAlineno);
    }

MediaInstruction:
    // 1       2          3           4              5                    6                    7                  8
    MEDIA_OP MEDIA_MODE TwoDimOffset Var MediaInstructionPlaneID VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM  RawOperand
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_media_instruction(
            $1, $2, $3.row, $3.elem, (int)$5, $4,
            $6.cisa_gen_opnd, $7.cisa_gen_opnd, $8, CISAlineno));
    }
    |
    // 1       2          3           4                  5                    6                    7
    MEDIA_OP MEDIA_MODE TwoDimOffset Var         VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM  RawOperand
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_media_instruction(
            $1, $2, $3.row, $3.elem, (int)0, $4,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7, CISAlineno));
    }

MediaInstructionPlaneID: DEC_LIT {
        MUST_HOLD($1 <= 0xF, "PlaneID must less than 0xF");
        $$ = $1;
    }

ScatterInstruction:
    //  1          2        3        4         5          6                7           8
    SCATTER_OP ElemNum ExecSize OwordModifier Var VecSrcOperand_G_I_IMM RawOperand RawOperand
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_scatter_instruction(
            $1, (int)$2, $3.emask, $3.exec_size, $4, $5,
            $6.cisa_gen_opnd, $7, $8, CISAlineno));
    }

ScatterTypedInstruction:
    //  1             2                 3             4       5         6           7             8           9            10
    Predicate   SCATTER_TYPED_OP  SAMPLER_CHANNEL  ExecSize  Var    RawOperand   RawOperand   RawOperand  RawOperand    RawOperand
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_scatter4_typed_instruction(
            $2, $1, ChannelMask::createFromAPI($3), $4.emask, $4.exec_size, $5,
            $6, $7, $8, $9, $10, CISAlineno));
    }

Scatter4ScaledInstruction:
    //  1           2               3                4      5          6                 7         8
    Predicate SCATTER4_SCALED_OP SAMPLER_CHANNEL  ExecSize Var VecSrcOperand_G_I_IMM RawOperand RawOperand
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_scatter4_scaled_instruction(
            $2, $1, $4.emask, $4.exec_size, ChannelMask::createFromAPI($3), $5,
            $6.cisa_gen_opnd, $7, $8, CISAlineno));
    }

ScatterScaledInstruction:
    // 1           2             3    4        5      6       7                   8          9
    Predicate SCATTER_SCALED_OP DOT DEC_LIT ExecSize Var VecSrcOperand_G_I_IMM RawOperand RawOperand
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_scatter_scaled_instruction(
            $2, $1, $5.emask, $5.exec_size, (uint32_t) $4, $6,
            $7.cisa_gen_opnd, $8, $9, CISAlineno));
    }

SynchronizationInstruction:
    BARRIER_OP {
        pBuilder->CISA_create_sync_instruction($1, CISAlineno);
    }
    | SBARRIER_SIGNAL {
        pBuilder->CISA_create_sbarrier_instruction(true, CISAlineno);
    }
    | SBARRIER_WAIT {
        pBuilder->CISA_create_sbarrier_instruction(false, CISAlineno);
    }
    | NBARRIER_SIGNAL VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM {
        pBuilder->CISA_create_nbarrier(false, $2.cisa_gen_opnd, $3.cisa_gen_opnd, CISAlineno);
    }
    | NBARRIER_WAIT VecSrcOperand_G_I_IMM {
        pBuilder->CISA_create_nbarrier(true, $2.cisa_gen_opnd, NULL, CISAlineno);
    }

//                      1         2               3             4           5         6     7          8          9          10
DwordAtomicInstruction: Predicate DWORD_ATOMIC_OP ATOMIC_SUB_OP Atomic16Opt ExecSize Var RawOperand RawOperand RawOperand RawOperand
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_dword_atomic_instruction(
            $1, $3, $4, $5.emask, $5.exec_size, $6, $7, $8, $9, $10, CISAlineno));
    }

//                      1         2               3             4           5        6   7          8          9          10         11         12         13
TypedAtomicInstruction: Predicate TYPED_ATOMIC_OP ATOMIC_SUB_OP Atomic16Opt ExecSize Var RawOperand RawOperand RawOperand RawOperand RawOperand RawOperand RawOperand
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_typed_atomic_instruction(
            $1, $3, $4, $5.emask, $5.exec_size, $6,
            $7, $8, $9, $10, $11, $12, $13, CISAlineno));
    }

Atomic16Opt:
      %empty {$$ = false;}
    | DOT DEC_LIT { // .16
        MUST_HOLD(($2 == 16), "only supports 16");
        $$ = true;
    }

                 //            1               2               3        4   5             6                   7                      8                   9                10
SampleUnormInstruction: SAMPLE_UNORM_OP SAMPLER_CHANNEL CHANNEL_OUTPUT Var Var VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM RawOperand
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_sampleunorm_instruction(
            $1, ChannelMask::createFromAPI($2), $3, $4, $5,
            $6.cisa_gen_opnd, $7.cisa_gen_opnd, $8.cisa_gen_opnd, $9.cisa_gen_opnd, $10, CISAlineno));
    }

SampleInstruction:
    // 1            2            3      4   5      6          7          8          9
    SAMPLE_OP SAMPLER_CHANNEL SIMDMode Var Var RawOperand RawOperand RawOperand RawOperand
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_sample_instruction(
            $1, ChannelMask::createFromAPI($2), (int)$3, $4, $5,
            $6, $7, $8, $9, CISAlineno));
    }
   |
   // 1             2          3       4     5           6         7           8
   SAMPLE_OP SAMPLER_CHANNEL SIMDMode Var RawOperand RawOperand RawOperand RawOperand
   {
       ABORT_ON_FAIL(pBuilder->CISA_create_sample_instruction(
           $1, ChannelMask::createFromAPI($2), (int)$3, "", $4,
           $5, $6, $7, $8, CISAlineno));
   }

Sample3dInstruction: Sample3DInstruction

           //        1         2            3                      4            5                          6               7        8                     9   10  11
Sample3DInstruction: Predicate SAMPLE_3D_OP PixelNullMaskEnableOpt CPSEnableOpt NonUniformSamplerEnableOpt SAMPLER_CHANNEL ExecSize VecSrcOperand_G_I_IMM Var Var RawOperand
           //        12
                     RawOperandArray
   {
       const bool success = pBuilder->create3DSampleInstruction(
           $1, $2, $3, $4, $5, ChannelMask::createFromAPI($6),
           $7.emask, $7.exec_size, $8.cisa_gen_opnd, $9, $10,
           $11, (unsigned int)$12, rawOperandArray, CISAlineno);

    ABORT_ON_FAIL(success);
   }




CPSEnableOpt: %empty {$$ = false;} | CPS  {$$ = true;}

NonUniformSamplerEnableOpt: %empty {$$ = false;} | NON_UNIFORM_SAMPLER {$$ = true;}

           //      1         2          3                      4               5        6                     7   8
Load3dInstruction: Predicate LOAD_3D_OP PixelNullMaskEnableOpt SAMPLER_CHANNEL ExecSize VecSrcOperand_G_I_IMM Var RawOperand
           //      9
                   RawOperandArray
   {
       const bool success = pBuilder->create3DLoadInstruction(
           $1, $2, $3, ChannelMask::createFromAPI($4),
           $5.emask, $5.exec_size, $6.cisa_gen_opnd, $7,
           $8, (unsigned int)$9, rawOperandArray, CISAlineno);

    ABORT_ON_FAIL(success);
   }

Gather43dInstruction: Gather43DInstruction

           //         1         2             3                      4               5        6                     7   8   9
Gather43DInstruction: Predicate SAMPLE4_3D_OP PixelNullMaskEnableOpt SAMPLER_CHANNEL ExecSize VecSrcOperand_G_I_IMM Var Var RawOperand
           //      10
                   RawOperandArray
   {
       const bool success = pBuilder->createSample4Instruction(
          $1, $2, $3, ChannelMask::createFromAPI($4), $5.emask, $5.exec_size,
          $6.cisa_gen_opnd, $7, $8,
          $9, (unsigned int)$10, rawOperandArray, CISAlineno);

    ABORT_ON_FAIL(success);
   }


PixelNullMaskEnableOpt: %empty {$$ = false;} | PIXEL_NULL_MASK {$$ = true;}

            //          1                   2              3           4           5              6
ResInfo3dInstruction: RESINFO_OP_3D   SAMPLER_CHANNEL  ExecSize       Var     RawOperand      RawOperand
   {
        ABORT_ON_FAIL(pBuilder->CISA_create_info_3d_instruction(
            VISA_3D_RESINFO, $3.emask, $3.exec_size,
            ChannelMask::createFromAPI($2), $4, $5, $6, CISAlineno));
   }

           //               1                    2              3         4          5
SampleInfo3dInstruction: SAMPLEINFO_OP_3D   SAMPLER_CHANNEL  ExecSize    Var     RawOperand
   {
        ABORT_ON_FAIL(pBuilder->CISA_create_info_3d_instruction(
            VISA_3D_SAMPLEINFO, $3.emask, $3.exec_size,
            ChannelMask::createFromAPI($2), $4, NULL, $5, CISAlineno));
   }

RTWriteOperands:
    %empty
    {
    }
    | RTWriteOperands VecSrcOperand_G_IMM
    {
        RTRWOperandsVec.push_back($2.cisa_gen_opnd);
    }
    | RTWriteOperands RawOperand
    {
        RTRWOperandsVec.push_back($2);
    }

RTWriteInstruction: RTWInstruction

            //      1            2                3                 4           5     6
RTWInstruction: Predicate    RTWRITE_OP_3D    RTWriteModeOpt    ExecSize    Var
              RTWriteOperands
   {
       bool result = pBuilder->CISA_create_rtwrite_3d_instruction(
           $1, $3, $4.emask, (unsigned int)$4.exec_size, $5,
           RTRWOperandsVec, CISAlineno);
       RTRWOperandsVec.clear();
       if (!result)
           YYABORT; // already reported
   }


RTWriteModeOpt: %empty {$$ = 0;} | RTWRITE_OPTION


            //          1            2                3           4         5           6           7           8          9
URBWriteInstruction: Predicate  URBWRITE_OP_3D    ExecSize    DEC_LIT    DEC_LIT    RawOperand  RawOperand  RawOperand  RawOperand
    {
        pBuilder->CISA_create_urb_write_3d_instruction(
            $1, $3.emask, (unsigned int)$3.exec_size, (unsigned int)$4, (unsigned int)$5,
            $6, $7, $8, $9, CISAlineno);
    }

            //      1         2         3   4          5                       6                   7                     8                     9                     10                    11              12        13                 14               15           16
AVSInstruction: AVS_OP SAMPLER_CHANNEL Var Var VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM VecSrcOperand_G_I_IMM CNTRL VecSrcOperand_G_I_IMM EXECMODE VecSrcOperand_G_I_IMM RawOperand
    {
        pBuilder->CISA_create_avs_instruction(
            ChannelMask::createFromAPI($2), $3, $4,
            $5.cisa_gen_opnd, $6.cisa_gen_opnd, $7.cisa_gen_opnd, $8.cisa_gen_opnd,
            $9.cisa_gen_opnd, $10.cisa_gen_opnd, $11.cisa_gen_opnd, $12, $13.cisa_gen_opnd,
            $14, $15.cisa_gen_opnd, $16, CISAlineno);
    }


VMEInstruction:
      //     1          2     3       4         5           6         7           8         9
       VME_IME_OP VMEOpndIME Var RawOperand RawOperand  RawOperand RawOperand RawOperand RawOperand
   {
       //     1 - OP
       //     2 - StreamMode, SearchCtrl
       //     3 - Surface
       //     4 - UNIInput
       //     5 - IMEInput
       //     6 - ref0
       //     7 - ref1
       //     8 - CostCenter
       //     9 - Output
        ABORT_ON_FAIL(pBuilder->CISA_create_vme_ime_instruction(
            $1, $2.streamMode, $2.searchCtrl, $4, $5, $3, $6, $7, $8, $9, CISAlineno));
   }
   |
    //    1    2      3           4          5
   VME_SIC_OP Var RawOperand RawOperand  RawOperand
   {
        ABORT_ON_FAIL(pBuilder->CISA_create_vme_sic_instruction($1, $3, $4, $2, $5, CISAlineno));
   }
   |
   //    1          2     3      4          5         6
   VME_FBR_OP VMEOpndFBR Var RawOperand RawOperand RawOperand
   {
        //    1 - OP
        //    2 - FBRMdMode, FBRSubMbShape, FBRSubPredMode
        //    3 - surface
        //    4 - UNIInput
        //    5 - FBRInput
        //    6 - output
        ABORT_ON_FAIL(pBuilder->CISA_create_vme_fbr_instruction($1, $4, $5, $3,
            $2.cisa_fbrMbMode_opnd, $2.cisa_fbrSubMbShape_opnd, $2.cisa_fbrSubPredMode_opnd, $6, CISAlineno));
    }

                 //    1         2          3       4            5               6
OwordInstruction: OWORD_OP OwordModifier ExecSize Var VecSrcOperand_G_I_IMM RawOperand
    {
        ABORT_ON_FAIL(
            pBuilder->CISA_create_oword_instruction($1, $2, $3.exec_size, $4, $5.cisa_gen_opnd, $6, CISAlineno));
    }

SvmInstruction:
    //     2        3                     4
    SVM_OP ExecSize VecSrcOperand_G_I_IMM RawOperand
    {
        bool aligned = false;
        pBuilder->CISA_create_svm_block_instruction((SVMSubOpcode)$1, $2.exec_size, aligned,
            $3.cisa_gen_opnd, $4, CISAlineno);
    }
    //     1          2         3     4     5     6        7          8        9
    | Predicate SVM_SCATTER_OP DOT DEC_LIT DOT DEC_LIT ExecSize RawOperand RawOperand
    {
        pBuilder->CISA_create_svm_scatter_instruction($1, (SVMSubOpcode)$2, $7.emask, $7.exec_size,
            (unsigned int)$4, (unsigned int)$6, $8, $9, CISAlineno);
    }
    // 1        2             3             4                 5        6          7          8          9
    | Predicate SVM_ATOMIC_OP ATOMIC_SUB_OP AtomicBitwidthOpt ExecSize RawOperand RawOperand RawOperand RawOperand
    {
        pBuilder->CISA_create_svm_atomic_instruction($1, $5.emask, $5.exec_size, $3, (unsigned short)$4,
            $6, $8, $9, $7, CISAlineno);
    }
    //   1                    2               3          4           5                 6          7
    | Predicate SVM_GATHER4SCALED_OP SAMPLER_CHANNEL ExecSize VecSrcOperand_G_I_IMM RawOperand RawOperand
    {
        pBuilder->CISA_create_svm_gather4_scaled($1, $4.emask, $4.exec_size, ChannelMask::createFromAPI($3),
            $5.cisa_gen_opnd, $6, $7, CISAlineno);
    }
    //   1                  2               3            4            5                  6          7
    | Predicate SVM_SCATTER4SCALED_OP SAMPLER_CHANNEL ExecSize VecSrcOperand_G_I_IMM RawOperand RawOperand
    {
        pBuilder->CISA_create_svm_scatter4_scaled($1, $4.emask, $4.exec_size, ChannelMask::createFromAPI($3),
            $5.cisa_gen_opnd, $6, $7, CISAlineno);
    }

AtomicBitwidthOpt:
      %empty {$$ = 32;}
    | DOT DEC_LIT {
        MUST_HOLD($2 == 16 || $2 == 32 || $2 == 64, "only supports 16 or 64");
        $$ = $2;
    }

////////////////////////////////////////////////
// LSC_LOAD - Load/Store Controller Instructions
LscInstruction:
  // untyped loads
    LscUntypedLoad
  | LscUntypedStridedLoad
  | LscUntypedBlock2dLoad
  // untyped stores
  | LscUntypedStore
  | LscUntypedStridedStore
  | LscUntypedBlock2dStore
  // untyped atomics
  | LscUntypedAtomic
  //
  // typed*
  | LscTypedLoad
  | LscTypedStore
  | LscTypedAtomic
  | LscTypedReadStateInfo
  //
  | LscFence

//
// EXAMPLES:
// FLAT (stateless):
//     lsc_load.ugm   V53:u32  flat[V52]:a64
//     lsc_load.slm   V53:u32  flat[V52]:a32
//
// FLAT with immediate offset  (32b with x2 elems per addr)
//     lsc_load.ugm   V53:u32x2  flat[V52+0x100]:a64
//
// BTI:
//     lsc_load.ugm   V53:u32  bti(0x10)[V52]:a32
//     lsc_load.ugml  V53:u32  bti(V10.2)[V52]:a32
//
// SS:
//     lsc_load.ugm   V53:u64   ss(0x200)[V52+0x100]:a16
// BSS:
//     lsc_load.ugm   V53:u8x8  bss(V10)[V52+0x100]:a16
//
LscUntypedLoad:
//  1          2                  3                       4             5
    Predicate  LSC_LOAD_MNEMONIC  LSC_SFID_UNTYPED_TOKEN  LscCacheOpts  ExecSize
//  6                  7
    LscDataOperand  LscUntypedAddrOperand
    {
        $5.exec_size =
            lscCheckExecSize(pBuilder, $3, $2, $6.shape.order, $5.exec_size);
        pBuilder->CISA_create_lsc_untyped_inst(
            $1,  // predicate
            $2,  // subop
            $3,  // sfid
            $4,  // caching settings
            Get_VISA_Exec_Size_From_Raw_Size($5.exec_size),
            $5.emask,
            $7.addr,     // address
            $6.shape,    // data
            $7.surface,  // surface
            $6.reg,      // dst
            $7.regs[0],  // src0
            nullptr,     // src1
            nullptr,     // src2
            CISAlineno);
    }

//
// EXAMPLES:
// FLAT (stateless):
//     lsc_load_strided.ugm   V53:u32  flat[V52]:a64
//     lsc_load_strided.ugm   V53:u32  flat[V52, 32]:a32
//     lsc_load_strided.ugm   V53:u32  flat[4*V52+16, 32]:a32
LscUntypedStridedLoad:
//  1          2                          3                       4             5
    Predicate  LSC_LOAD_STRIDED_MNEMONIC  LSC_SFID_UNTYPED_TOKEN  LscCacheOpts  ExecSize
//  6               7
    LscDataOperand  LscUntypedStridedAddrOperand
    {
        $5.exec_size =
            lscCheckExecSize(pBuilder, $3, $2, $6.shape.order, $5.exec_size);
        pBuilder->CISA_create_lsc_untyped_strided_inst(
            $1,  // predicate
            $2,  // subop
            $3,  // sfid
            $4,  // caching settings
            Get_VISA_Exec_Size_From_Raw_Size($5.exec_size),
            $5.emask,
            $7.addr,     // address
            $6.shape,    // data
            $7.surface,  // surface
            $6.reg,      // dst
            $7.regs[0],  // src0 base
            $7.regs[1],  // src0 stride
            nullptr,     // src1
            CISAlineno);
    }

//
// EXAMPLES:
// FLAT (stateless):
// lsc_load_block2d.ugm   V53:u8.2x32x32  flat[V_BASE,V_SWIDTH,V_SHEIGHT,V_SPITCH,V_X,V_Y]
LscUntypedBlock2dLoad:
//  1          2                           3                       4             5
    Predicate  LSC_LOAD_BLOCK2D_MNEMONIC  LSC_SFID_UNTYPED_TOKEN  LscCacheOpts  ExecSize
//  6                 7
    LscDataOperand2D  LscUntypedBlock2dAddrOperand
    {
        $5.exec_size =
            lscCheckExecSize(pBuilder, $3, $2, $6.shape2D.order, $5.exec_size);
        pBuilder->CISA_create_lsc_untyped_block2d_inst(
            $1,  // predicate
            $2,  // subop
            $3,  // sfid
            $4,  // caching settings
            Get_VISA_Exec_Size_From_Raw_Size($5.exec_size),
            $5.emask,
            $6.shape2D,  // data shape
            $6.reg,      // dst
            $7.regs,     // src0 surface info / addrs
            nullptr,     // src1
            CISAlineno);
    }

//
// EXAMPLE:
//     lsc_store.ugm    flat[V52]:a64      V53:u32
LscUntypedStore:
//  1          2                   3                       4             5
    Predicate  LSC_STORE_MNEMONIC  LSC_SFID_UNTYPED_TOKEN  LscCacheOpts  ExecSize
//  6                      7
    LscUntypedAddrOperand  LscDataOperand
    {
        $5.exec_size =
            lscCheckExecSize(pBuilder, $3, $2, $7.shape.order, $5.exec_size);
        pBuilder->CISA_create_lsc_untyped_inst(
            $1,  // predicate
            $2,  // subop
            $3,  // SFID
            $4,  // caching settings
            Get_VISA_Exec_Size_From_Raw_Size($5.exec_size),
            $5.emask,
            $6.addr,     // address
            $7.shape,    // data
            $6.surface,  // surface
            nullptr,     // dst
            $6.regs[0],  // src0
            $7.reg,      // src1
            nullptr,     // src2
            CISAlineno);
    }
LscUntypedStridedStore:
//  1          2                           3                       4             5
    Predicate  LSC_STORE_STRIDED_MNEMONIC  LSC_SFID_UNTYPED_TOKEN  LscCacheOpts  ExecSize
//  6                             7
    LscUntypedStridedAddrOperand  LscDataOperand
    {
        $5.exec_size =
            lscCheckExecSize(pBuilder, $3, $2, $7.shape.order, $5.exec_size);
        pBuilder->CISA_create_lsc_untyped_strided_inst(
            $1,  // predicate
            $2,  // subop
            $3,  // SFID
            $4,  // caching settings
            Get_VISA_Exec_Size_From_Raw_Size($5.exec_size),
            $5.emask,
            $6.addr,     // address
            $7.shape,    // data
            $6.surface,  // surface
            nullptr,     // dst
            $6.regs[0],  // src0 base
            $6.regs[1],  // src0 stride
            $7.reg,      // src1
            CISAlineno);
    }

// EXAMPLES
//     lsc_store_block2d.ugm   flat[V_BASE,V_X,V_Y,V_PITCH,V_HEIGHT,VBLOCK_X,VBLOCK_Y,32,4]   V53:u64
LscUntypedBlock2dStore:
//  1          2                           3                       4             5
    Predicate  LSC_STORE_BLOCK2D_MNEMONIC  LSC_SFID_UNTYPED_TOKEN  LscCacheOpts  ExecSize
//  6                            7
    LscUntypedBlock2dAddrOperand LscDataOperand2D
    {
        $5.exec_size =
            lscCheckExecSize(pBuilder, $3, $2, $7.shape2D.order, $5.exec_size);
        pBuilder->CISA_create_lsc_untyped_block2d_inst(
            $1,  // predicate
            $2,  // subop
            $3,  // sfid
            $4,  // caching settings
            Get_VISA_Exec_Size_From_Raw_Size($5.exec_size),
            $5.emask,
            $7.shape2D,  // data2d
            nullptr,     // dst
            $6.regs,     // src0 addrs
            $7.reg,      // src1
            CISAlineno);
    }

// EXAMPLES:
//     lsc_atomic_iinc.ugm   VRESULT:u32  flat[VADDR]:a64       V0     V0
//     lsc_atomic_iinc.ugml  VRESULT:u32  flat[VADDR]:a64       V0     V0
//     lsc_atomic_iadd.slm   VRESULT:u32  flat[VADDR+0x10]:a32  VSRC1  V0
LscUntypedAtomic:
//  1         2                    3                       4             5
    Predicate LSC_ATOMIC_MNEMONIC  LSC_SFID_UNTYPED_TOKEN  LscCacheOpts  ExecSize
//  6               7                      8              9
    LscDataOperand  LscUntypedAddrOperand  LscPayloadReg  LscPayloadReg
    {
        $5.exec_size =
            lscCheckExecSize(pBuilder, $3, $2, $6.shape.order, $5.exec_size);
        pBuilder->CISA_create_lsc_untyped_inst(
            $1,  // predicate
            $2,                // op
            $3,                // sfid
            $4,                // caching settings
            Get_VISA_Exec_Size_From_Raw_Size($5.exec_size),
            $5.emask,
            $7.addr,     // address info
            $6.shape,    // data type
            $7.surface,  // surface
            $6.reg,      // dst data
            $7.regs[0],  // src0 addr
            $8,          // src1 data
            $9,          // src2 data (for icas/fcas)
            CISAlineno);
    }

//
// EXAMPLES:
// SS using only U:
//     lsc_load_quad.tgm   V60:u32.x     ss(T6)[V52]:a32
// BSS using U and V:
//     lsc_load_quad.tgm   V60:u32.xyzw  bss(V10)[V52,V53]:a32
// BSS using U, V, R, and LOD:
//     lsc_load_quad.tgm   V60:u32.xz    bss(V10)[V52,V53,V54,V55]:a32
//
LscTypedLoad:
//  1          2                  3                     4             5
    Predicate  LSC_LOAD_MNEMONIC  LSC_SFID_TYPED_TOKEN  LscCacheOpts  ExecSize
//  6               7
    LscDataOperand  LscTypedAddrOperand
    {
        if ($2 != LSC_LOAD_QUAD) {
            PARSE_ERROR("unsupported load operation for .tgm");
        }
        $5.exec_size =
            lscCheckExecSize(pBuilder, $3, $2, $6.shape.order, $5.exec_size);
        pBuilder->CISA_create_lsc_typed_inst(
            $1,  // predicate
            $2,  // subop
            $3,  // sfid
            $4,  // caching settings
            Get_VISA_Exec_Size_From_Raw_Size($5.exec_size),
            $5.emask,
            $7.addr.type,  // address model
            $7.addr.size,  // address size
            $6.shape,    // data type
            $7.surface,  // surface
            $6.reg,      // dst data
            $7.regs[0],  // src0_u
            $7.regs[1],  // src0_v
            $7.regs[2],  // src0_r
            $7.regs[3],  // src0_lod
            nullptr,     // src1 data
            nullptr,     // src2 data
            CISAlineno);
    }
//
// EXAMPLES:
// SS using only U:
//     lsc_store_quad.tgm   V60:u32.x     ss(T6)[V52]:a32
// BSS using U and V:
//     lsc_store_quad.tgm   V60:u32.xyzw  bss(V10)[V52,V53]:a32
// BSS using U, V, R, and LOD:
//     lsc_store_quad.tgm   V60:u32.xz    bss(V10)[V52,V53,V54,V55]:a32
//
LscTypedStore:
//  1          2                   3                     4             5
    Predicate  LSC_STORE_MNEMONIC  LSC_SFID_TYPED_TOKEN  LscCacheOpts  ExecSize
//  6                    7
    LscTypedAddrOperand  LscDataOperand
    {
        if ($2 != LSC_STORE_QUAD) {
            PARSE_ERROR("unsupported store operation for .tgm");
        }
        $5.exec_size =
            lscCheckExecSize(pBuilder, $3, $2, $7.shape.order, $5.exec_size);
        pBuilder->CISA_create_lsc_typed_inst(
            $1,  // predicate
            $2,  // subop
            $3,  // sfid
            $4,  // caching settings
            Get_VISA_Exec_Size_From_Raw_Size($5.exec_size),
            $5.emask,
            $6.addr.type,  // address model
            $6.addr.size,  // address size
            $7.shape,    // data type
            $6.surface,  // surface
            nullptr,     // dst
            $6.regs[0],  // src0_u
            $6.regs[1],  // src0_v
            $6.regs[2],  // src0_r
            $6.regs[3],  // src0_lod
            $7.reg,      // src1 data
            nullptr,     // src2 data
            CISAlineno);
    }
//
// EXAMPLES:
// SS using only U:
//     lsc_atomic_iinc.tgm   ss(T6)[V52]:a32        V0:u32.x      V0  V0
// BSS using U and V:
//     lsc_atomic_iadd.tgm   bss(V10)[V52,V53]:a32  V60:u32.xyzw  V0  V70
// BSS using U, V, R, and LOD:
//     lsc_atomic_icas.tgm   bss(V10)[V52,V53,V54,V55]:a32  V60:u32.xz  V61 V70
//
LscTypedAtomic:
//  1          2                    3                     4             5
    Predicate  LSC_ATOMIC_MNEMONIC  LSC_SFID_TYPED_TOKEN  LscCacheOpts  ExecSize
//  6               7                    8              9
    LscDataOperand  LscTypedAddrOperand  LscPayloadReg  LscPayloadReg
    {
        $5.exec_size =
            lscCheckExecSize(pBuilder, $3, $2, $6.shape.order, $5.exec_size);
        pBuilder->CISA_create_lsc_typed_inst(
            $1,  // predicate
            $2,  // subop
            $3,  // sfid
            $4,  // caching settings
            Get_VISA_Exec_Size_From_Raw_Size($5.exec_size),
            $5.emask,
            $7.addr.type, // address model
            $7.addr.size,  // address size
            $6.shape,    // data type
            $7.surface,  // surface
            $6.reg,      // dst data
            $7.regs[0],  // src0 addrs u
            $7.regs[1],  // src0 addrs v
            $7.regs[2],  // src0 addrs r
            $7.regs[3],  // src0 addrs lod
            $8,          // src1 data
            $9,          // src2 data
            CISAlineno);
    }

// EXAMPLE:
//   lsc_read_state_info.tgm  VDATA  bti(0x4)
LscTypedReadStateInfo:
// 1          2                             3
   Predicate  LSC_READ_STATE_INFO_MNEMONIC  LSC_SFID_TYPED_TOKEN
// 4              5
   LscPayloadReg  LscRegAddrModel
   {
        LSC_CACHE_OPTS caching{LSC_CACHING_DEFAULT,LSC_CACHING_DEFAULT};
        LSC_DATA_SHAPE dataShape{LSC_DATA_SIZE_32b,LSC_DATA_ORDER_NONTRANSPOSE};
        dataShape.elems = LSC_DATA_ELEMS_1;
        pBuilder->CISA_create_lsc_typed_inst(
            $1,              // predicate
            $2,              // subop
            $3,              // sfid
            caching,         // caching settings
            EXEC_SIZE_1,
            vISA_EMASK_M1_NM,
            $5.type,           // address model
            LSC_ADDR_SIZE_32b, // address size
            dataShape,         // data type
            $5.surface,        // surface
            $4,                // dst data
            nullptr,           // src0 addrs u
            nullptr,           // src0 addrs v
            nullptr,           // src0 addrs r
            nullptr,           // src0 addrs lod
            nullptr,           // src1 data
            nullptr,           // src2 data
            CISAlineno);
   }

// EXAMPLES:
//    lsc_fence.ugm.evict.gpu   // evicts all caches up to the GPU level
//    lsc_fence.slm.flush.group // flushes cache up to the thread-group level
//    lsc_fence.tgm.flush.local // typed global memory flush to the local unit
//
LscFence:
//  1                   2        3                  4
    LSC_FENCE_MNEMONIC  LscSfid  LSC_FENCE_OP_TYPE  LSC_FENCE_SCOPE
    {
        pBuilder->CISA_create_lsc_fence($2, $3, $4, CISAlineno);
    }

LscSfid: LSC_SFID_UNTYPED_TOKEN | LSC_SFID_TYPED_TOKEN

LscCacheOpts:
    %empty                          {$$ = {LSC_CACHING_DEFAULT,LSC_CACHING_DEFAULT};}
  | LSC_CACHING_OPT                 {$$ = {$1,LSC_CACHING_DEFAULT};}
  | LSC_CACHING_OPT LSC_CACHING_OPT {$$ = {$1,$2};}

LscUntypedAddrOperand:
//  1               2      3                  4
    LscAddrModelOpt LBRACK LscAddrImmScaleOpt LscPayloadNonNullReg
//    5                    6             7
      LscAddrImmOffsetOpt  RBRACK LSC_ADDR_SIZE_TK
    {
        $$ = {$1.surface,{$4},{$1.type,(int)$3,(int)$5,$7}};
    }

LscUntypedStridedAddrOperand:
//  1               2      3                  4
    LscAddrModelOpt LBRACK LscAddrImmScaleOpt LscPayloadNonNullReg
//    5                    6     7                   8      9
      LscAddrImmOffsetOpt  COMMA LscVectorOpRegOrImm RBRACK LSC_ADDR_SIZE_TK
    {
        $$ = {$1.surface,{$4,$7},{$1.type,(int)$3,(int)$5,$9}};
    }
    | LscUntypedAddrOperand {
        $$ = $1;
        $$.regs[1] = nullptr;
    }

// e.g. flat[VBASE(0,0),VSWIDTH(1,0),VSHEIGHT(1,0),VPITCH(1,0),VX(0,4),VY(0,5)]
LscUntypedBlock2dAddrOperand:
//  1            2
    LSC_AM_FLAT  LBRACK
//            3 (surfaceAddr)
              LscVectorOpReg
//      4     5 (surfaceWidth)
        COMMA LscVectorOpRegOrImm
//      6     7 (surfaceHeight)
        COMMA LscVectorOpRegOrImm
//      8     9 (surfacePitch)
        COMMA LscVectorOpRegOrImm
//      10    11 (baseX)
        COMMA LscVectorOpRegOrImm
//      12    13 (baseY)
        COMMA LscVectorOpRegOrImm
//      14
        RBRACK
    {
        $$ = {nullptr,{$3,$5,$7,$9,$11,$13},{LSC_ADDR_TYPE_FLAT,1,0,LSC_ADDR_SIZE_64b}};
    }

LscTypedAddrOperand:
//
// just U
//  1               2
    LscRegAddrModel LBRACK
//    3
      LscPayloadNonNullReg
//    4      5
      RBRACK LSC_ADDR_SIZE_TK
    {
        $$ = {$1.surface,{$3},{$1.type,1,0,$5}};
    }
//
// U, V
//  1               2
  | LscRegAddrModel LBRACK
//  3                    4     5
    LscPayloadNonNullReg COMMA LscPayloadNonNullReg
//    6             7
      RBRACK LSC_ADDR_SIZE_TK
    {
        $$ = {$1.surface,{$3,$5},{$1.type,1,0,$7}};
    }
//
// U, V, R
//  1               2
  | LscRegAddrModel LBRACK
//  3                    4     5                    6     7
    LscPayloadNonNullReg COMMA LscPayloadNonNullReg COMMA LscPayloadNonNullReg
//    8             9
      RBRACK LSC_ADDR_SIZE_TK
    {
        $$ = {$1.surface,{$3,$5,$7},{$1.type,1,0,$9}};
    }
//
// U, V, R, LOD
//  1               2
  | LscRegAddrModel LBRACK
//  3                    4     5                    6     7                    8     9
    LscPayloadNonNullReg COMMA LscPayloadNonNullReg COMMA LscPayloadNonNullReg COMMA LscPayloadNonNullReg
//    10            11
      RBRACK LSC_ADDR_SIZE_TK
    {
        $$ = {$1.surface,{$3,$5,$7,$9},{$1.type,1,0,$11}};
    }

// Enables stuff like
// [VADDR + 4*0x100 - 32]
// [VADDR - (32 + 4*0x100)]
LscAddrImmOffsetOpt:
    %empty           {$$ =   0;}
  | PLUS  IntExpAdd  {$$ =  $2;}
  | MINUS IntExpPrim {$$ = -$2;}
  ;

// e.g. [4*%sizeof(GRF)*VADDR + ...]
//       ^
// Note: we can't allow
LscAddrImmScaleOpt:
    %empty            {$$ = 1;}
    | IntExpMul TIMES {$$ = $1;}

LscAddrModelOpt:
    %empty       {$$ = {LSC_ADDR_TYPE_FLAT,nullptr};}
  | LSC_AM_FLAT  {$$ = {LSC_ADDR_TYPE_FLAT,nullptr};}
  | LSC_AM_ARG   {$$ = {LSC_ADDR_TYPE_ARG,nullptr};}
  | LscRegAddrModel

LscRegAddrModel:
    // address models that take a reg parameter
    LscRegAddrModelKind  LPAREN  LscVectorOpRegOrImm  RPAREN {
        $$ = {$1,$3};
    }

LscRegAddrModelKind:
    LSC_AM_BSS {$$ = LSC_ADDR_TYPE_BSS;}
  | LSC_AM_SS  {$$ = LSC_ADDR_TYPE_SS;}
  | LSC_AM_BTI {$$ = LSC_ADDR_TYPE_BTI;}

LscVectorOpRegOrImm: LscVectorOpReg | LscVectorOpImm

LscVectorOpImm:
    IntExp {
        $$ = pBuilder->CISA_create_immed($1,ISA_TYPE_UD, CISAlineno);
    }

LscVectorOpReg:
    Var {
        ABORT_ON_FAIL($$ = pBuilder->CISA_create_gen_src_operand(
            $1,
            0, 1, 0, // region
            0, 0, // row and col offset
            MODIFIER_NONE, CISAlineno));
    }
    |
    Var DOT DEC_LIT {
        ABORT_ON_FAIL($$ = pBuilder->CISA_create_gen_src_operand(
            $1,
            0, 1, 0, // region
            0, (unsigned char)$3, // row and col offset
            MODIFIER_NONE, CISAlineno));
    }
    |
    Var LPAREN IntExp COMMA IntExp RPAREN {
        MUST_HOLD($3 <= 255 || $3 >= 0, "row is out of bounds");
        MUST_HOLD($5 <= 255 || $5 >= 0, "col is out of bounds");
        $$ = pBuilder->CISA_create_gen_src_operand(
            $1,
            0, 1, 0,
            (unsigned char)$3, (unsigned char)$5, // row and col offset
            MODIFIER_NONE, CISAlineno);
        if ($$ == nullptr) {
            PARSE_ERROR("cannot find surface variable");
        }
    }

LscDataOperand:
    LscPayloadReg  LSC_DATA_SHAPE_TK {
        $$ = {$1,$2};
    }
    |
    LscPayloadReg  LSC_DATA_SHAPE_TK_CHMASK {
        $$ = {$1,$2};
    }

LscDataOperand2D:
   // 1             2
    LscPayloadReg LSC_DATA_SHAPE_TK_BLOCK2D {
        $$ = {$1,$2};
    }

LscPayloadReg:
    RawOperand
    |
    // TODO: remove this rule once RawOperand handles no-suffix case
    Var {
        ABORT_ON_FAIL($$ = pBuilder->CISA_create_RAW_operand($1, 0, CISAlineno));
    }
LscPayloadNonNullReg:
    RawOperandNonNull
    |
    // TODO: remove this rule once RawOperand handles no-suffix case
    VarNonNull {
        ABORT_ON_FAIL($$ = pBuilder->CISA_create_RAW_operand($1, 0, CISAlineno));
    }

SwitchLabels:
    %empty
    {
    }
    | COMMA SwitchLabels
    {
    }
    | IDENT SwitchLabels
    {
        // parse rule means we see last label first
        switchLabels.push_front($1);
    }

                   // 1        2         3          4
BranchInstruction: Predicate BRANCH_OP ExecSize IdentOrStringLit
    {
        pBuilder->CISA_create_branch_instruction($1, $2, $3.emask, $3.exec_size, $4, false, CISAlineno);
    }
    | Predicate CALL_OP ExecSize IdentOrStringLit
    {
        pBuilder->CISA_create_branch_instruction($1, $2.opcode, $3.emask, $3.exec_size, $4, $2.is_fccall, CISAlineno);
    }
    | Predicate RET_OP ExecSize
    {
        pBuilder->CISA_Create_Ret($1, $2, $3.emask, $3.exec_size, CISAlineno);
    }
    | SWITCHJMP_OP ExecSize VecSrcOperand_G_I_IMM LPAREN SwitchLabels RPAREN
    {
        pBuilder->CISA_create_switch_instruction($1, $2.exec_size, $3.cisa_gen_opnd, switchLabels, CISAlineno);
        switchLabels.clear();
    }
    //  1          2         3     4       5       6
    | Predicate  FCALL   ExecSize IDENT  DEC_LIT DEC_LIT
    {
        pBuilder->CISA_create_fcall_instruction($1, $2, $3.emask, $3.exec_size, $4, (unsigned)$5, (unsigned)$6, CISAlineno);
    }
    // 1           2       3       4                    5       6
    | Predicate IFCALL ExecSize VecSrcOperand_G_I_IMM DEC_LIT DEC_LIT
    {
        pBuilder->CISA_create_ifcall_instruction(
        $1, $3.emask, $3.exec_size,
        $4.cisa_gen_opnd, (unsigned)$5, (unsigned)$6, CISAlineno);
    }
    // 1      2                3
    | FADDR  IdentOrStringLit VecDstOperand_G_I
    {
        pBuilder->CISA_create_faddr_instruction($2, $3.cisa_gen_opnd, CISAlineno);
    }

FILE: FILE_OP STRING_LIT
    {
        pBuilder->CISA_create_FILE_instruction($1, $2, CISAlineno);
    }

LOC: LOC_OP DEC_LIT
    {
        pBuilder->CISA_create_LOC_instruction($1, (unsigned)$2, CISAlineno);
    }
RawSendInstruction:
    //    1             2            3       4      5       6           7                8         9
    Predicate  RAW_SEND_STRING  ExecSize HEX_LIT DEC_LIT DEC_LIT VecSrcOperand_G_IMM RawOperand RawOperand
    {
        pBuilder->CISA_create_raw_send_instruction(ISA_RAW_SEND, false, $3.emask, $3.exec_size, $1,
            (unsigned)$4, (unsigned char)$5, (unsigned char)$6, $7.cisa_gen_opnd, $8, $9, CISAlineno);
    }
    |
    //    1             2           3       4        5       6          7               8           9
    Predicate  RAW_SENDC_STRING  ExecSize HEX_LIT DEC_LIT DEC_LIT VecSrcOperand_G_IMM RawOperand RawOperand
    {
        pBuilder->CISA_create_raw_send_instruction(ISA_RAW_SEND, true, $3.emask, $3.exec_size, $1,
            (unsigned)$4, (unsigned char)$5, (unsigned char)$6, $7.cisa_gen_opnd, $8, $9, CISAlineno);
    }

        //            1                      2
LifetimeStartInst: LIFETIME_START_OP        IDENT
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_lifetime_inst((unsigned char)0, $2, CISAlineno));
    }

        //            1                      2
LifetimeEndInst:  LIFETIME_END_OP           IDENT
    {
        ABORT_ON_FAIL(pBuilder->CISA_create_lifetime_inst((unsigned char)1, $2, CISAlineno));
    }
RawSendsInstruction:
    //    1             2         3        4       5      6          7              8                  9               10         11        12
    Predicate RAW_SENDS_STRING ElemNum ElemNum  ElemNum ElemNum ExecSize VecSrcOperand_G_IMM   VecSrcOperand_G_IMM RawOperand RawOperand RawOperand
    {
        pBuilder->CISA_create_raw_sends_instruction(
            ISA_RAW_SENDS, false, false, $7.emask, $7.exec_size, $1, $8.cisa_gen_opnd,
            (unsigned char)$3, (unsigned char)$4, (unsigned char)$5, (unsigned char)$6,
            $9.cisa_gen_opnd, $10, $11, $12, CISAlineno);
    }
    //    1             2               3        4       5      6          7              8                  9               10         11        12
    | Predicate RAW_SENDS_EOT_STRING ElemNum ElemNum  ElemNum ElemNum ExecSize VecSrcOperand_G_IMM   VecSrcOperand_G_IMM RawOperand RawOperand RawOperand
    {
        pBuilder->CISA_create_raw_sends_instruction(
            ISA_RAW_SENDS, false, true, $7.emask, $7.exec_size, $1, $8.cisa_gen_opnd,
            (unsigned char)$3, (unsigned char)$4, (unsigned char)$5, (unsigned char)$6,
            $9.cisa_gen_opnd, $10, $11, $12, CISAlineno);
    }
    //    1             2              3       4       5        6        7                         8             9          10        11
    | Predicate  RAW_SENDSC_STRING  ElemNum ElemNum ElemNum ExecSize VecSrcOperand_G_IMM VecSrcOperand_G_IMM RawOperand RawOperand RawOperand
    {
        pBuilder->CISA_create_raw_sends_instruction(
            ISA_RAW_SENDS, true, false, $6.emask, $6.exec_size, $1, $7.cisa_gen_opnd,
            0, (unsigned char)$3, (unsigned char)$4, (unsigned char)$5,
            $8.cisa_gen_opnd, $9, $10, $11, CISAlineno);
    }
    //    1             2                  3       4       5        6        7                         8             9          10        11
    | Predicate  RAW_SENDSC_EOT_STRING  ElemNum ElemNum ElemNum ExecSize VecSrcOperand_G_IMM VecSrcOperand_G_IMM RawOperand RawOperand RawOperand
    {
        pBuilder->CISA_create_raw_sends_instruction(
            ISA_RAW_SENDS, true, true, $6.emask, $6.exec_size, $1, $7.cisa_gen_opnd,
            0, (unsigned char)$3, (unsigned char)$4, (unsigned char)$5,
            $8.cisa_gen_opnd, $9, $10, $11, CISAlineno);
    }

NullaryInstruction:
    CACHE_FLUSH_OP
    {
        pBuilder->CISA_create_NO_OPND_instruction($1, CISAlineno);
    }
    |
    WAIT_OP VecSrcOperand_G_IMM
    {
        pBuilder->CISA_create_wait_instruction($2.cisa_gen_opnd, CISAlineno);
    }
    |
    YIELD_OP
    {
        pBuilder->CISA_create_yield_instruction($1, CISAlineno);
    }
    |
    FENCE_GLOBAL_OP
    {
        pBuilder->CISA_create_fence_instruction($1, 0x0, CISAlineno);
    }
    |
    FENCE_GLOBAL_OP FENCE_OPTIONS
    {
        pBuilder->CISA_create_fence_instruction($1, $2, CISAlineno);
    }
    |
    FENCE_LOCAL_OP
    {
        pBuilder->CISA_create_fence_instruction($1, 0x20, CISAlineno);
    }
    |
    FENCE_LOCAL_OP FENCE_OPTIONS
    {
        pBuilder->CISA_create_fence_instruction($1, $2 | 0x20, CISAlineno);
    }
    |
    FENCE_SW_OP
    {
        pBuilder->CISA_create_fence_instruction($1, 0x80, CISAlineno);
    }

OwordModifier: %empty {$$ = false;} | OWORD_MODIFIER;


// ------ predicate and saturation and source modifiers ------

Predicate:
    %empty
    {
        $$ = NULL;
    }
    |
    LPAREN PredSign PredVar PredCtrlOpt RPAREN
    {
        $$ = pBuilder->CISA_create_predicate_operand($3, $2, $4, CISAlineno);
    }

PredSign: %empty {$$ = PredState_NO_INVERSE;} | BANG {$$ = PredState_INVERSE;}

PredCtrlOpt: %empty {$$ = PRED_CTRL_NON;} | PRED_CNTL


SatModOpt: %empty {$$ = false;} | SAT {$$ = true;}

SrcModifier:
      SRCMOD_NEG    {$$.mod = MODIFIER_NEG;}
    | SRCMOD_ABS    {$$.mod = MODIFIER_ABS;}
    | SRCMOD_NEGABS {$$.mod = MODIFIER_NEG_ABS;}
    | SRCMOD_NOT    {$$.mod = MODIFIER_NOT;}

ConditionalModifier: %empty {$$ = ISA_CMP_UNDEF;} | COND_MOD;

// ------ operands groups ------

// ------ DST -----------
VecDstOperand_A: DstAddrOperand    {$$ = $1; $$.type = OPERAND_ADDRESS;}
VecDstOperand_G: DstGeneralOperand {$$ = $1; $$.type = OPERAND_GENERAL;}
VecDstOperand_G_I:
      DstGeneralOperand    {$$ = $1; $$.type = OPERAND_GENERAL;}
    | DstIndirectOperand   {$$ = $1; $$.type = OPERAND_INDIRECT;}

// ------ SRC -----------
VecSrcOperand_G_I_IMM_A_AO:
      VecSrcOperand_G_I_IMM_A
    | SrcAddrOfOperand     {$$ = $1; $$.type = OPERAND_ADDRESSOF;}

VecSrcOperand_G_I_IMM_A:
      VecSrcOperand_G_I_IMM
    | SrcAddrOperand       {$$ = $1; $$.type = OPERAND_ADDRESS;}

VecSrcOperand_G_I_IMM:
      VecSrcOperand_G
    | SrcIndirectOperand   {$$ = $1; $$.type = OPERAND_INDIRECT;}
    | SrcImmOperand        {$$ = $1; $$.type = OPERAND_IMMEDIATE;}

VecSrcOperand_G_IMM:
      VecSrcOperand_G
    | SrcImmOperand       {$$ = $1; $$.type = OPERAND_IMMEDIATE;}

VecSrcOperand_G_IMM_AO:
      VecSrcOperand_G
    | SrcImmOperand       {$$ = $1; $$.type = OPERAND_IMMEDIATE;}
    | SrcAddrOfOperand    {$$ = $1; $$.type = OPERAND_ADDRESSOF;}

VecSrcOperand_G_A:
      VecSrcOperand_G
    | SrcAddrOperand      {$$ = $1; $$.type = OPERAND_ADDRESS;}

VecSrcOperand_G_A_AO:
      VecSrcOperand_G_A
    | SrcAddrOfOperand    {$$ = $1; $$.type = OPERAND_ADDRESS;}

VecSrcOperand_G: SrcGeneralOperand {$$ = $1; $$.type = OPERAND_GENERAL;}

VecSrcOpndSimple: Var TwoDimOffset
    {
        // simple vector operand with no modifier that has an
        // implicit src region = <1,1,0>
        $$.type = OPERAND_GENERAL;
        ABORT_ON_FAIL($$.cisa_gen_opnd = pBuilder->CISA_create_gen_src_operand(
            $1, 1, 1, 0, $2.row, $2.elem, MODIFIER_NONE, CISAlineno));
    }

         //   1         2         3      4          5
VMEOpndIME: LPAREN DEC_LIT COMMA DEC_LIT RPAREN
    {
        $$.streamMode = (unsigned char)$2;
        $$.searchCtrl = (unsigned char)$4;
    }

         //   1            2                3             4             5           6             7
VMEOpndFBR: LPAREN VecSrcOperand_G_I_IMM COMMA VecSrcOperand_G_I_IMM COMMA VecSrcOperand_G_I_IMM RPAREN
    {
        $$.cisa_fbrMbMode_opnd = $2.cisa_gen_opnd;
        $$.cisa_fbrSubMbShape_opnd = $4.cisa_gen_opnd;
        $$.cisa_fbrSubPredMode_opnd = $6.cisa_gen_opnd;
    }

SrcStateOperand:
  Var LPAREN IntExp RPAREN
    {
        MUST_HOLD($3 < 0x100, "offset out of bounds");
        $$.offset = (unsigned char)$3;
        ABORT_ON_FAIL($$.cisa_gen_opnd = pBuilder->CISA_create_state_operand($1, (unsigned char)$3, CISAlineno, false));
    }

DstStateOperand:
  Var LPAREN IntExp RPAREN
    {
        MUST_HOLD($3 < 0x100, "offset out of bounds");
        $$.offset = (unsigned char)$3;
        ABORT_ON_FAIL($$.cisa_gen_opnd = pBuilder->CISA_create_state_operand($1, (unsigned char)$3, CISAlineno, true));
    }

///////////////////////////////////////////////////////////////////////////////
// ------------ Operands ------------

// ------  Raw Operands -----
// EXAMPLES:
//   VDATA.12   // raw operand with offset
//   VDATA.(%sizeof X / 2)
//   %null.0
// TODO: these cases (see below for needed fixes)
//   VDATA      // implicitly VDATA.0
//   %null
RawOperand:
    RawOperandNonNull
    |
//
// conflicts SampleInstruction: has a ... (Var Var | Var) ... part
//  also RTWriteOperand, DSRTWriteInstruction
// those instructions need to parse proper operands
//
//    BUILTIN_NULL
//    {
//        $$ = pBuilder->CISA_create_RAW_NULL_operand(CISAlineno); // can't fail
//    }
//    |
    BUILTIN_NULL DOT DEC_LIT
    {
        MUST_HOLD($3 == 0, "%null must have 0 as offset");
        $$ = pBuilder->CISA_create_RAW_NULL_operand(CISAlineno); // can't fail
    }

RawOperandNonNull:
    VarNonNull RawOperandOffsetSuffix
    {
        ABORT_ON_FAIL($$ = pBuilder->CISA_create_RAW_operand($1, (unsigned short)$2, CISAlineno));
    }
// TODO: see RawOperand: BUILTIN_NULL issues (same here)
//    |
//    VarNonNull
//    {
//        ABORT_ON_FAIL($$ = pBuilder->CISA_create_RAW_operand($1, 0, CISAlineno));
//    }

RawOperandOffsetSuffix:
    DOT DEC_LIT {
        MUST_HOLD($2 <= 0x10000, "offset out of bounds");
        $$ = $2;
    }
    |
    DOT LPAREN IntExp RPAREN {
        MUST_HOLD($3 <= 0x10000, "offset out of bounds");
        $$ = $3;
    }


RawOperandArray:
    %empty
    {
        $$ = 0;
    }
    |
    RawOperandArray RawOperand
    {
        rawOperandArray[$1++] = (VISA_RawOpnd*)$2;
        $$ = $1;
    }


// ------  Dst Operands -----
DstAddrOperand: AddrVarAccessWithWidth
    {
        ABORT_ON_FAIL($$.cisa_gen_opnd =
          pBuilder->CISA_set_address_operand(
            $1.cisa_decl, $1.elem, $1.row, true, CISAlineno));
    }

DstGeneralOperand:
    Var TwoDimOffset DstRegion
    {
        ABORT_ON_FAIL($$.cisa_gen_opnd = pBuilder->CISA_dst_general_operand(
            $1, $2.row, $2.elem, (unsigned short)$3, CISAlineno));
    }
    |
    Var DstRegion {
        ABORT_ON_FAIL($$.cisa_gen_opnd = pBuilder->CISA_dst_general_operand(
            $1, 0, 0, (unsigned short)$2, CISAlineno));
    }

DstIndirectOperand: IndirectVarAccess DstRegion DataType
    {
        ABORT_ON_FAIL($$.cisa_gen_opnd = pBuilder->CISA_create_indirect_dst(
            $1.cisa_decl, MODIFIER_NONE, $1.row, $1.elem, $1.immOff, (unsigned short)$2, $3, CISAlineno));
    }


//  ------  Src Operands --------------

SrcAddrOfOperand:
    // This is a problem because any instruction that allows an operand that includes
    // an SrcAddrOf operand followed by a SrcImm operand will create a problem.
    //
    // For example, given the stream for a pair of sources where one is an
    // ADDR_OF and the other is an IMM:
    //     &V127 - 16 - 32:d
    // We don' tknow if that should be read as:
    //       SRC[i]     SRC[i+1]
    // 1.  &V127-16    -32:d
    //   OR
    // 2.  &V127       -16-32:d
    //
    AddrOfVar {
         $$.cisa_gen_opnd = pBuilder->CISA_set_address_expression($1.cisa_decl, 0, CISAlineno);
    }
    |
    AddrOfVar LBRACK IntExp RBRACK {
         MUST_HOLD((short)$3 == $3, "variable address offset is too large");
         $$.cisa_gen_opnd = pBuilder->CISA_set_address_expression($1.cisa_decl, (short)$3, CISAlineno);
    }

AddrOfVar:
    AMP Var {
        // Both GENERAL_VAR and SURFACE_VAR are addressable
        $$.cisa_decl = pBuilder->CISA_find_decl($2);
        if ($$.cisa_decl == nullptr)
            PARSE_ERROR("unbound variable");
        $$.row = 0;
        $$.elem = 0;
    }


SrcAddrOperand: AddrVarAccessWithWidth
    {
        ABORT_ON_FAIL($$.cisa_gen_opnd =
            pBuilder->CISA_set_address_operand(
                $1.cisa_decl, $1.elem, $1.row, false, CISAlineno));
    }

SrcGeneralOperand:
                Var TwoDimOffset SrcRegionDirect
    {
        ABORT_ON_FAIL($$.cisa_gen_opnd =
            pBuilder->CISA_create_gen_src_operand(
                $1, $3.v_stride, $3.width, $3.h_stride, $2.row, $2.elem, MODIFIER_NONE, CISAlineno));
    }
    |
    SrcModifier Var TwoDimOffset SrcRegionDirect
    {
        ABORT_ON_FAIL($$.cisa_gen_opnd =
            pBuilder->CISA_create_gen_src_operand(
                $2, $4.v_stride, $4.width, $4.h_stride, $3.row, $3.elem, $1.mod, CISAlineno));
    }

SrcImmOperand:
    ////////////////
    // Integral
    IntExpUnr DataTypeIntOrVector
    {
        $$.cisa_gen_opnd = pBuilder->CISA_create_immed($1, $2, CISAlineno);
    }
    ////////////////
    // FP16
    | HEX_LIT HFTYPE {
        MUST_HOLD($1 < 0x10000, "literal too large for half float");
        $$.cisa_gen_opnd = pBuilder->CISA_create_immed(
            (unsigned short)$1, ISA_TYPE_HF, CISAlineno);
    }
    ////////////////
    // FP32
    |       FloatLit
    {
        $$.cisa_gen_opnd = pBuilder->CISA_create_float_immed($1, ISA_TYPE_F, CISAlineno);
    }
    | MINUS FloatLit {
        $$.cisa_gen_opnd = pBuilder->CISA_create_float_immed(-$2, ISA_TYPE_F, CISAlineno);
    }
    ////////////////
    // FP64
    |       DoubleFloatLit
    {
        $$.cisa_gen_opnd = pBuilder->CISA_create_float_immed($1, ISA_TYPE_DF, CISAlineno);
    }
    | MINUS DoubleFloatLit
    {
        $$.cisa_gen_opnd = pBuilder->CISA_create_float_immed(-$2, ISA_TYPE_DF, CISAlineno);
    }

FloatLit:
     F32_LIT
   | DEC_LIT FTYPE
   {
        // "1:f" means 1.4e-45
        int number = (int)$1;
        float *fp = (float *)&number;
        $$ = *fp;
   }
   | HEX_LIT FTYPE  // e.g. 0x3f800000:f
   {
        int number = (int)$1;
        float *fp = (float *)&number;
        $$ = *fp;
   }

DoubleFloatLit:
     F64_LIT
   | DEC_LIT DFTYPE {
        // "1:df" means 5e-324
        int64_t number = $1;
        double *fp = (double *)&number;
        $$ = *fp;
   }
   | HEX_LIT DFTYPE {
        // to support 0x7ff0000000000000:df
        int64_t number = $1;
        double *fp = (double *)&number;
        $$ = *fp;
   }



SrcIndirectOperand:
                IndirectVarAccess SrcRegionIndirect DataType
    {
        ABORT_ON_FAIL($$.cisa_gen_opnd =
            pBuilder->CISA_create_indirect(
                $1.cisa_decl, MODIFIER_NONE, $1.row, $1.elem, $1.immOff,
                $2.v_stride, $2.width, $2.h_stride, $3, CISAlineno));
    }
    |
    SrcModifier IndirectVarAccess SrcRegionIndirect DataType
    {
        ABORT_ON_FAIL($$.cisa_gen_opnd =
            pBuilder->CISA_create_indirect(
                $2.cisa_decl, $1.mod, $2.row, $2.elem, $2.immOff,
                $3.v_stride, $3.width, $3.h_stride, $4, CISAlineno));
    }

// -------- regions -----------
DstRegion: LANGLE IntExpNRA RANGLE    // <HorzStride>
    {
        MUST_HOLD(($2 == 0 || $2 == 1 || $2 == 2 || $2 == 4),
             "Dst HorzStride must be 0, 1, 2, or 4");
        $$ = $2;
    }


SrcRegionDirect:
    // <VertStride;Width,HorzStride>
    // FIXME: Using > as a closing delimiter is ambiguous with a > operator
    //  <1;2,4 > ...
    //         ^ ambiguity
    //  <1;2,4 > :ud
    //         ^ ambiguity
    //  <1;2,4 > x ? 1 : 0>:ud
    //         ^ ambiguity
    //   (see the note on AliasAttrOpt)
    LANGLE IntExp SEMI IntExp COMMA IntExpNRA RANGLE
    {
        MUST_HOLD(($2 == 0 || $2 == 1 || $2 == 2 || $2 == 4 || $2 == 8 || $2 == 16 || $2 == 32),
                 "Src Region VertStride must be 0, 1, 2, 4, 8, 16, or 32");
        MUST_HOLD(($4 == 0 || $4 == 1 || $4 == 2 || $4 == 4 || $4 == 8 || $4 == 16),
                 "Src Region Width must be 0, 1, 2, 4, 8 or 16");
        MUST_HOLD(($6 == 0 || $6 == 1 || $6 == 2 || $6 == 4),
                 "Src Region HorzStride must be 0, 1, 2, or 4");
        $$.v_stride = (unsigned)$2;
        $$.width = (unsigned)$4;
        $$.h_stride = (unsigned)$6;
    }

SrcRegionIndirect:
    SrcRegionDirect
    |
//    LANGLE IntExp COMMA IntExpNRA RANGLE   // <Width,HorzStride>
    LANGLE IntExp COMMA DEC_LIT RANGLE   // <Width,HorzStride>
    {
        MUST_HOLD(($2 == 0 || $2 == 1 || $2 == 2 || $2 == 4 || $2 == 8 || $2 == 16),
                 "Width must be 0, 1, 2, 4, 8 or 16");
        MUST_HOLD(($4 == 0 || $4 == 1 || $4 == 2 || $4 == 4),
                 "HorzStride must be 0, 1, 2, or 4");
        $$.v_stride = -1;
        $$.width = (unsigned)$2;
        $$.h_stride = (unsigned)$4;
    }
    |
    LANGLE IntExpNRA RANGLE   // <HorzStride>
    {
        MUST_HOLD(($2 == 0 || $2 == 1 || $2 == 2 || $2 == 4),
             "HorzStride must be 0, 1, 2, or 4");
        $$.v_stride = -1;
        $$.width = -1;
        $$.h_stride = (unsigned)$2;
    }


IndirectVarAccess:
    IND_LBRACK AddrVarAccess COMMA IntExp RBRACK {
        $$ = $2;
        $$.immOff = (int)$4;
    }
    |
    IND_LBRACK AddrVarAccess              RBRACK {
          $$ = $2;
          $$.immOff = 0;
    }

TwoDimOffset: LPAREN IntExp COMMA IntExp RPAREN {
        MUST_HOLD($2 >= 0, "row (register) offset must be positive");
        $$.row = (int)$2;
        MUST_HOLD($4 >= 0 && $4 <= 0xFFFF, "sub-register offset out of bounds");
        $$.elem = (int)$4;
    }

PredVar:
    Var {
        $$ = pBuilder->CISA_find_decl($1);
        if ($$ == nullptr)
            PARSE_ERROR($1, ": undefined predicate variable");
        if ($$->type != PREDICATE_VAR)
            PARSE_ERROR($1, ": not a predicate variable");
    }

AddrVarAccess:
    Var LPAREN IntExp RPAREN {
        $$.cisa_decl = pBuilder->CISA_find_decl($1);
        if ($$.cisa_decl == nullptr) {
            PARSE_ERROR($1, ": unbound variable");
        } else if ($$.cisa_decl->type != ADDRESS_VAR) {
            PARSE_ERROR($1, ": not an address variable");
        }
        $$.row = 1;
        $$.elem = (int)$3;
    }

AddrVarAccessWithWidth:
    Var LPAREN IntExp RPAREN LANGLE IntExpNRA RANGLE {
        $$.cisa_decl = pBuilder->CISA_find_decl($1);
        if ($$.cisa_decl == nullptr) {
            PARSE_ERROR($1, ": unbound variable");
        } else if ($$.cisa_decl->type != ADDRESS_VAR) {
            PARSE_ERROR($1, ": not an address variable");
        }
        $$.row = (int)$6;
        $$.elem = (int)$3;
    }


// -----------register size ------------------------------
SIMDMode:
    %empty {$$ = 0;}
    |
    LPAREN DEC_LIT RPAREN
    {
       MUST_HOLD(($2 == 8 || $2 == 16 || $2 == 32),
                 "SIMD mode can only be 8, 16, or 32");
       $$ = $2;
    }



// ----------- Execution size --------------

ElemNum: DOT DEC_LIT
    {
        $$ = $2;
    }

ExecSize:
//    %empty
//    {
//        $$.exec_size = UNDEFINED_EXEC_SIZE;
//        $$.emask = vISA_EMASK_M1;
//    }
//    |
    LPAREN ExecSizeInt RPAREN
    {
        $$.emask = vISA_EMASK_M1;
        $$.exec_size = (int)$2;
    }
    |
    LPAREN Var COMMA ExecSizeInt RPAREN
    {
        if (!ParseEMask($2, $$.emask)) {
            PARSE_ERROR("invalid execution offset info");
        }
        $$.exec_size = (int)$4;
    }

ExecSizeInt: DEC_LIT
    {
        if ($1 != 1 && $1 != 2 && $1 != 4 && $1 != 8 && $1 != 16 && $1 != 32) {
            PARSE_ERROR("invalid execution size");
        }
        $$ = (unsigned short)$1;
    }

// ------ imm values -----------------------------------
Var: VarNonNull | BUILTIN_NULL
VarNonNull: IDENT | BUILTIN


IntExp: IntExpCond
IntExpCond:
      IntExpAND QUESTION IntExpAND COLON IntExpCond {$$ = $1 ? $3 : $5;}
    | IntExpAND
IntExpAND:
      IntExpAND AMP  IntExpXOR {$$ = $1 & $3;}
    | IntExpXOR
IntExpXOR:
      IntExpXOR CIRC  IntExpOR {$$ = $1 ^ $3;}
    | IntExpOR
IntExpOR:
      IntExpOR  PIPE  IntExpCmp {$$ = $1 | $3;}
    | IntExpCmp
IntExpCmp:
      IntExpRel EQ   IntExpRel {$$ = $1 == $3;}
    | IntExpRel NEQ  IntExpRel {$$ = $1 != $3;}
    | IntExpRel
IntExpRel:
      IntExpNRA LANGLE IntExpNRA {$$ = $1 < $3;}
    | IntExpNRA RANGLE IntExpNRA {$$ = $1 > $3;}
    | IntExpNRA LEQ    IntExpNRA {$$ = $1 <= $3;}
    | IntExpNRA GEQ    IntExpNRA {$$ = $1 >= $3;}
    | IntExpNRA

// In all cases where RANGLE follows an int expression we must start
// expression parsing at a higher precedence than relational operators
//
// e.g. .decl ... alias=<%r0,IntExp>
//                           ^^^^^^
//  ...  DST<4;1,IntExp>   SRC<4;1,IntExp>
//               ^^^^^^            ^^^^^^
// e.g given ... alias=<%r0, 3 > ...
//                             ^ we don't know if we are looking at
//               alias=<%r0, 3 > x ? 0x10 : 20> // end
//  or
//               alias=<%r0, 3 > // end
//
// In practice, the user can use parentheses to force precedence
// when needed.  99.9999% of the users will never need this.
IntExpNRA: IntExpShift

IntExpShift:
      IntExpAdd SHL  IntExpAdd {$$ = $1 << $3;}
    | IntExpAdd SHRS IntExpAdd {$$ = (int64_t)$1 >> (int)$3;}
    | IntExpAdd SHRZ IntExpAdd {$$ = (int64_t)((uint64_t)$1 >> (uint64_t)$3);}
    | IntExpAdd
IntExpAdd:
      IntExpAdd PLUS  IntExpMul {$$ = $1 + $3;}
    | IntExpAdd MINUS IntExpMul {$$ = $1 - $3;}
    | IntExpMul
IntExpMul:
      IntExpMul TIMES IntExpUnr {$$ = $1 * $3;}
    | IntExpMul SLASH IntExpUnr {
            if ($3 == 0)
                PARSE_ERROR("division by 0");
            $$ = $1 / $3;
        }
    | IntExpMul PERCENT IntExpUnr {
            if ($3 == 0)
                PARSE_ERROR("division by 0");
            $$ = $1 % $3;
        }
    | IntExpUnr
IntExpUnr:
      MINUS IntExpUnr {$$ = -$2;}
    | TILDE IntExpUnr {$$ = ~$2;}
    | BANG  IntExpUnr {$$ = !($2);}
    | IntExpPrim

IntExpPrim:
      // A literal
      DEC_LIT
    | HEX_LIT
      // a grouping (1 + 2)
    | LPAREN IntExp RPAREN {$$ = $2;}
    //
    //  %sizeof V0034
    //  %sizeof GRF  << matches GRF size (unless someone declares a GRF variable)
    | BUILTIN_SIZEOF IDENT {
        $$ = 0;
        ABORT_ON_FAIL(pBuilder->CISA_eval_sizeof_decl(CISAlineno, $2, $$));
    }
    | BUILTIN_SIZEOF LPAREN IDENT RPAREN {
        // TODO: %AlignOf(...), %Max(..)
        $$ = 0;
        ABORT_ON_FAIL(pBuilder->CISA_eval_sizeof_decl(CISAlineno, $3, $$));
    }
    // a built-in constant
    | BUILTIN_DISPATCH_SIMD_SIZE {
        // e.g. %DispatchSimdSize
        // N.B. %sizeof happens above
        $$ = 0;
        ABORT_ON_FAIL(pBuilder->CISA_lookup_builtin_constant(CISAlineno, "%DispatchSimd", $$));
    }


// ------ data types ------------------------------------
DataType: DataTypeIntOrVector
        | DFTYPE
        | FTYPE
        | HFTYPE
DataTypeIntOrVector:
          ITYPE
        | VTYPE


%%
///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//                        Utility Functions                                  //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

void CISAerror(CISA_IR_Builder* pBuilder, char const *s)
{
    pBuilder->RecordParseError(CISAlineno, s);
}

static bool ParseAlign(CISA_IR_Builder* pBuilder, const char *sym, VISA_Align &value)
{
    if (strcmp(sym, "byte") == 0) {
        value = ALIGN_BYTE;
    } else if (strcmp(sym, "word") == 0) {
        value = ALIGN_WORD;
    } else if (strcmp(sym, "dword") == 0) {
        value = ALIGN_DWORD;
    } else if (strcmp(sym, "qword") == 0) {
        value = ALIGN_QWORD;
    } else if (strcmp(sym, "oword") == 0) {
        value = ALIGN_OWORD;
    } else if (strcmp(sym, "GRF") == 0) {
        value = ALIGN_GRF;
    } else if (strcmp(sym, "GRFx2") == 0 || strcmp(sym, "2GRF") == 0) {
        value = ALIGN_2_GRF;
    } else if (strcmp(sym, "hword") == 0) {
        value = ALIGN_HWORD;
    } else if (strcmp(sym, "wordx32") == 0) {
        value = ALIGN_32WORD;
    } else if (strcmp(sym, "wordx64") == 0) {
        value = ALIGN_64WORD;
    } else {
        value = ALIGN_UNDEF;
        return false;
    }
    return true;
}


static VISA_Align AlignBytesToVisaAlignment(int bytes)
{
    VISA_Align val = ALIGN_UNDEF;
    switch (bytes) {
    case 1:   val = ALIGN_BYTE; break;
    case 2:   val = ALIGN_WORD; break;
    case 4:   val = ALIGN_DWORD; break;
    case 8:   val = ALIGN_QWORD; break;
    case 16:  val = ALIGN_OWORD; break;
    case 32:  val = ALIGN_HWORD; break;
    case 64:  val = ALIGN_32WORD; break;
    case 128: val = ALIGN_64WORD; break;
    default:  val = ALIGN_UNDEF; break;
    }
    return val;
}



static bool ParseEMask(
    const char* sym,
    VISA_EMask_Ctrl &emask)
{
    if (strcmp(sym, "NoMask") == 0) {
        emask = vISA_EMASK_M1_NM;
        return true;
    }
    for (int i = 0; i < vISA_NUM_EMASK +1; i++)
    {
        if (!strcmp(emask_str[i], sym))
        {
            emask = (VISA_EMask_Ctrl)i;
            return true;
        }
    }

    emask = vISA_NUM_EMASK;
    return false;
}

static int lscCheckExecSize(
    CISA_IR_Builder* pBuilder,
    LSC_SFID sfid,
    LSC_OP op,
    LSC_DATA_ORDER data_order,
    int exec_size)
{
    int is_vector_op =
        op != LSC_LOAD_BLOCK2D &&
        op != LSC_STORE_BLOCK2D;
        // other ops like LSC_LOAD_SURFACE_INFO may be SIMD1
    if (op == LSC_READ_STATE_INFO) {
        exec_size = 1;
    } else if (data_order == LSC_DATA_ORDER_NONTRANSPOSE && is_vector_op) {
        if (exec_size == UNDEFINED_EXEC_SIZE) {
            if (pBuilder->getPlatform() == Xe_DG2) // for DG2 typed is 8, untyped is 16
                exec_size = sfid == LSC_TGM ? 8 : 16;
            else if (pBuilder->getPlatform() >= Xe_PVC) // on PVC typed is 16, untyped is 32
                exec_size = sfid == LSC_TGM ? 16 : 32;
            else
                exec_size = 32; // the world is finally sane
        }
    } else {
        // block and transpose get SIMD by default
        if (exec_size == UNDEFINED_EXEC_SIZE) {
           exec_size = 1; // transpose is implicitly 1 if needed
        }
    }
    return exec_size;
}
