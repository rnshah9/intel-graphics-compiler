/*========================== begin_copyright_notice ============================

Copyright (C) 2021 Intel Corporation

SPDX-License-Identifier: MIT

============================= end_copyright_notice ===========================*/

#include "IGC/common/StringMacros.hpp"
#include "G4_IR.hpp"
#include "BuildIR.h"

#include <sstream>
#include <iomanip>

using namespace vISA;


///////////////////////////////////////////////////////////////////////////////
// LdSt data type support
// MsgOp
std::string vISA::ToSymbol(MsgOp op)
{
    switch (op) {
    case MsgOp::LOAD:         return "load";
    case MsgOp::LOAD_QUAD:    return "load_quad";
    case MsgOp::LOAD_STRIDED: return "load_strided";
    case MsgOp::LOAD_BLOCK2D: return "load_block2d";
    case MsgOp::STORE:         return "store";
    case MsgOp::STORE_QUAD:    return "store_quad";
    case MsgOp::STORE_STRIDED: return "store_strided";
    case MsgOp::STORE_BLOCK2D: return "store_block2d";
    // general atomics
    case MsgOp::ATOMIC_LOAD:   return "atomic_load";
    case MsgOp::ATOMIC_STORE:  return "atomic_store";
    // floating point
    case MsgOp::ATOMIC_FADD:   return "atomic_fadd";
    case MsgOp::ATOMIC_FSUB:   return "atomic_fsub";
    case MsgOp::ATOMIC_FMIN:   return "atomic_fmin";
    case MsgOp::ATOMIC_FMAX:   return "atomic_fmax";
    case MsgOp::ATOMIC_FCAS:   return "atomic_fcas";
    // integer
    case MsgOp::ATOMIC_IINC:   return "atomic_iinc";
    case MsgOp::ATOMIC_IDEC:   return "atomic_idec";
    case MsgOp::ATOMIC_IADD:   return "atomic_iadd";
    case MsgOp::ATOMIC_ISUB:   return "atomic_isub";
    case MsgOp::ATOMIC_ICAS:   return "atomic_icas";
    case MsgOp::ATOMIC_SMIN:   return "atomic_smin";
    case MsgOp::ATOMIC_SMAX:   return "atomic_smax";
    case MsgOp::ATOMIC_UMIN:   return "atomic_umin";
    case MsgOp::ATOMIC_UMAX:   return "atomic_umax";
    // integer bitwise
    case MsgOp::ATOMIC_AND:    return "atomic_and";
    case MsgOp::ATOMIC_XOR:    return "atomic_xor";
    case MsgOp::ATOMIC_OR:     return "atomic_or";
    case MsgOp::EOT:           return "eot";
    case MsgOp::FENCE:         return "fence";
    case MsgOp::BARRIER:       return "barrier";
    case MsgOp::NBARRIER:      return "named_barrier";
    default:
        break;
    }
    return "???";
}

MsgOp vISA::ConvertSamplerOpToMsgOp (VISASampler3DSubOpCode op) {
    switch (op) {
        case VISASampler3DSubOpCode::VISA_3D_SAMPLE:
            return MsgOp::SAMPLE;
        case VISASampler3DSubOpCode::VISA_3D_SAMPLE_B:
            return MsgOp::SAMPLE_B;
        case VISASampler3DSubOpCode::VISA_3D_SAMPLE_L:
            return MsgOp::SAMPLE_L;
        case VISASampler3DSubOpCode::VISA_3D_SAMPLE_C:
            return MsgOp::SAMPLE_C;
        case VISASampler3DSubOpCode::VISA_3D_SAMPLE_D:
            return MsgOp::SAMPLE_D;
        case VISASampler3DSubOpCode::VISA_3D_SAMPLE_B_C:
            return MsgOp::SAMPLE_B_C;
        case VISASampler3DSubOpCode::VISA_3D_SAMPLE_L_C:
            return MsgOp::SAMPLE_L_C;
        case VISASampler3DSubOpCode::VISA_3D_GATHER4:
            return MsgOp::GATHER4;
        case VISASampler3DSubOpCode::VISA_3D_GATHER4_C:
            return MsgOp::GATHER4_C;
        case VISASampler3DSubOpCode::VISA_3D_SAMPLE_D_C:
            return MsgOp::SAMPLE_D_C;
        case VISASampler3DSubOpCode::VISA_3D_SAMPLE_LZ:
            return MsgOp::SAMPLE_LZ;
        case VISASampler3DSubOpCode::VISA_3D_SAMPLE_C_LZ:
            return MsgOp::SAMPLE_C_LZ;
        default:
            return MsgOp::INVALID;
    }
}

MsgOp vISA::ConvertLSCOpToMsgOp(LSC_OP op) {
    switch(op) {
        case LSC_OP::LSC_LOAD:
            return MsgOp::LOAD;
        case LSC_OP::LSC_LOAD_STRIDED:
            return MsgOp::LOAD_STRIDED;
        case LSC_OP::LSC_LOAD_QUAD:
            return MsgOp::LOAD_QUAD;
        case LSC_OP::LSC_LOAD_BLOCK2D:
            return MsgOp::LOAD_BLOCK2D;
        case LSC_OP::LSC_STORE:
            return MsgOp::STORE;
        case LSC_OP::LSC_STORE_STRIDED:
            return MsgOp::STORE_STRIDED;
        case LSC_OP::LSC_STORE_QUAD:
            return MsgOp::STORE_QUAD;
        case LSC_OP::LSC_STORE_BLOCK2D:
            return MsgOp::STORE_BLOCK2D;
        case LSC_OP::LSC_ATOMIC_IINC:
            return MsgOp::ATOMIC_IINC;
        case LSC_OP::LSC_ATOMIC_IDEC:
            return MsgOp::ATOMIC_IDEC;
        case LSC_OP::LSC_ATOMIC_LOAD:
            return MsgOp::ATOMIC_LOAD;
        case LSC_OP::LSC_ATOMIC_STORE:
            return MsgOp::ATOMIC_STORE;
        case LSC_OP::LSC_ATOMIC_IADD:
            return MsgOp::ATOMIC_IADD;
        case LSC_OP::LSC_ATOMIC_ISUB:
            return MsgOp::ATOMIC_ISUB;
        case LSC_OP::LSC_ATOMIC_ICAS:
            return MsgOp::ATOMIC_ICAS;
        case LSC_OP::LSC_ATOMIC_FADD:
            return MsgOp::ATOMIC_FADD;
        case LSC_OP::LSC_ATOMIC_FSUB:
            return MsgOp::ATOMIC_FSUB;
        case LSC_OP::LSC_ATOMIC_FMIN:
            return MsgOp::ATOMIC_FMIN;
        case LSC_OP::LSC_ATOMIC_FMAX:
            return MsgOp::ATOMIC_FMAX;
        case LSC_OP::LSC_ATOMIC_FCAS:
            return MsgOp::ATOMIC_FCAS;
        case LSC_OP::LSC_ATOMIC_AND:
            return MsgOp::ATOMIC_AND;
        case LSC_OP::LSC_ATOMIC_XOR:
            return MsgOp::ATOMIC_XOR;
        case LSC_OP::LSC_ATOMIC_OR:
            return MsgOp::ATOMIC_OR;
        case LSC_OP::LSC_FENCE:
            return MsgOp::FENCE;
        default:
            return MsgOp::INVALID;
    }
}

uint32_t vISA::GetRenderTargetMsgOpEncoding(MsgOp m) {
    switch(m) {
        case MsgOp::RTREAD: return 2;
        case MsgOp::RTWRITE: return 6;
        case MsgOp::RTDSWRITE: return 5;
        default: MUST_BE_TRUE(false, "Invalid msg op");
    }
    return 0;
}

uint32_t vISA::GetSamplerMsgOpEncoding(MsgOp m) {
    switch(m) {
        case MsgOp::SAMPLE: return 0;
        case MsgOp::SAMPLE_B: return 1;
        case MsgOp::SAMPLE_L: return 2;
        case MsgOp::SAMPLE_C: return 3;
        case MsgOp::SAMPLE_D: return 4;
        case MsgOp::SAMPLE_B_C: return 5;
        case MsgOp::SAMPLE_L_C: return 6;
        case MsgOp::SAMPLE_D_C: return 20;
        case MsgOp::SAMPLE_LZ: return 24;
        case MsgOp::SAMPLE_C_LZ: return 25;
        case MsgOp::GATHER4: return 8;
        case MsgOp::GATHER4_C: return 16;
        default: MUST_BE_TRUE(false, "Invalid msg op");
    }
    return 0;
}

uint32_t vISA::GetMsgOpEncoding(MsgOp m) {
    switch(m) {
        case MsgOp::LOAD: return 0;
        case MsgOp::LOAD_QUAD: return 2;
        case MsgOp::LOAD_BLOCK2D: return 3;
        case MsgOp::STORE: return 4;
        case MsgOp::STORE_QUAD: return 6;
        case MsgOp::STORE_BLOCK2D: return 7;
        case MsgOp::ATOMIC_IINC: return 8;
        case MsgOp::ATOMIC_IDEC: return 9;
        case MsgOp::ATOMIC_LOAD: return 10;
        case MsgOp::ATOMIC_STORE: return 11;
        case MsgOp::ATOMIC_IADD: return 12;
        case MsgOp::ATOMIC_ISUB: return 13;
        case MsgOp::ATOMIC_SMIN: return 14;
        case MsgOp::ATOMIC_SMAX: return 15;
        case MsgOp::ATOMIC_UMIN: return 16;
        case MsgOp::ATOMIC_UMAX: return 17;
        case MsgOp::ATOMIC_CAS: return 18;
        case MsgOp::ATOMIC_FADD: return 19;
        case MsgOp::ATOMIC_FSUB: return 20;
        case MsgOp::ATOMIC_FMIN: return 21;
        case MsgOp::ATOMIC_FMAX: return 22;
        case MsgOp::ATOMIC_FCAS: return 23;
        case MsgOp::ATOMIC_AND: return 24;
        case MsgOp::ATOMIC_XOR: return 25;
        case MsgOp::ATOMIC_OR: return 26;
        case MsgOp::READ_STATE_INFO: return 30;
        case MsgOp::FENCE:     return 31;
        //
        case MsgOp::EOT:      return 0x0;
        case MsgOp::BARRIER:  return 0x4;
        case MsgOp::NBARRIER: return 0x5;
        // TODO: other ops
        default: MUST_BE_TRUE(false, "Invalid msg op");
    }
    return 0;
}

// data size
std::string vISA::ToSymbol(DataSize d) {
    switch(d)
    {
        case DataSize::INVALID: return "invalid data size";
        case DataSize::D8: return "8b";
        case DataSize::D16: return "16b";
        case DataSize::D32: return "32b";
        case DataSize::D64: return "64b";
        case DataSize::D8U32: return "8b zero extended to 32b";
        case DataSize::D16U32: return "16b zero extended to 32b";
        default: return "?";
    }
}

DataSize vISA::ConvertLSCDataSize(LSC_DATA_SIZE ds) {
    switch(ds) {
        case LSC_DATA_SIZE_8b: return DataSize::D8;
        case LSC_DATA_SIZE_16b: return DataSize::D16;
        case LSC_DATA_SIZE_32b: return DataSize::D32;
        case LSC_DATA_SIZE_64b: return DataSize::D64;
        case LSC_DATA_SIZE_8c32b: return DataSize::D8U32;
        case LSC_DATA_SIZE_16c32b: return DataSize::D16U32;
        default: MUST_BE_TRUE(false, "invalid data size");
    }
    return DataSize::INVALID;
}

uint32_t vISA::GetDataSizeEncoding(DataSize ds) {
    switch(ds) {
        case DataSize::D8: return 0;
        case DataSize::D16: return 1;
        case DataSize::D32: return 2;
        case DataSize::D64: return 3;
        case DataSize::D8U32: return 4;
        case DataSize::D16U32: return 5;
        default: MUST_BE_TRUE(false, "invalid data size");
    }
    return 0;
}

size_t vISA::GetDataSizeInBytes(DataSize ds) {
    switch(ds) {
    case DataSize::D8: return 1;
    case DataSize::D16: return 2;
    case DataSize::D32: return 4;
    case DataSize::D64: return 8;
    case DataSize::D8U32: return 4;
    case DataSize::D16U32: return 4;
    default: MUST_BE_TRUE(false, "invalid encoding");
    }
    return 0;
}

// data order
std::string vISA::ToSymbol(DataOrder d) {
    switch(d) {
    case DataOrder::INVALID: return "invalid data order";
    case DataOrder::NONTRANSPOSE: return "non transpose";
    case DataOrder::TRANSPOSE: return "transpose";
        default: return "?";
    }
}

DataOrder vISA::ConvertLSCDataOrder(LSC_DATA_ORDER dord) {
    switch(dord) {
        case LSC_DATA_ORDER_NONTRANSPOSE: return DataOrder::NONTRANSPOSE;
        case LSC_DATA_ORDER_TRANSPOSE: return DataOrder::TRANSPOSE;
        default: MUST_BE_TRUE(false, "invalid data order");
    }
    return DataOrder::INVALID;
}

uint32_t vISA::GetDataOrderEncoding(DataOrder dord) {
    switch(dord) {
        case DataOrder::NONTRANSPOSE: return 0;
        case DataOrder::TRANSPOSE: return 1;
        default: MUST_BE_TRUE(false, "invalid data order");
    }
    return 0;
}

// data elems
std::string vISA::ToSymbol(VecElems v) {
    switch(v) {
    case VecElems::V1: return "vector length 1";
    case VecElems::V2: return "vector length 2";
    case VecElems::V3: return "vector length 3";
    case VecElems::V4: return "vector length 4";
    case VecElems::V8: return "vector length 8";
    case VecElems::V16: return "vector length 16";
    case VecElems::V32: return "vector length 32";
    case VecElems::V64: return "vector length 64";
    default: return "?";
    }
}

VecElems vISA::ConvertLSCDataElems(LSC_DATA_ELEMS de) {
    switch(de) {
    case LSC_DATA_ELEMS_1: return VecElems::V1;
    case LSC_DATA_ELEMS_2: return VecElems::V2;
    case LSC_DATA_ELEMS_3: return VecElems::V3;
    case LSC_DATA_ELEMS_4: return VecElems::V4;
    case LSC_DATA_ELEMS_8: return VecElems::V8;
    case LSC_DATA_ELEMS_16: return VecElems::V16;
    case LSC_DATA_ELEMS_32: return VecElems::V32;
    case LSC_DATA_ELEMS_64: return VecElems::V64;
    default: MUST_BE_TRUE(false, "number of data elements");
    }
    return VecElems::INVALID;
}

uint32_t vISA::GetVecElemsEncoding(VecElems ve) {
    switch(ve) {
    case VecElems::V1: return 0;
    case VecElems::V2: return 1;
    case VecElems::V3: return 2;
    case VecElems::V4: return 3;
    case VecElems::V8: return 4;
    case VecElems::V16: return 5;
    case VecElems::V32: return 6;
    case VecElems::V64: return 7;
    default: MUST_BE_TRUE(false, "invalid vector elements");
    }
    return 0;
}

size_t vISA::GetNumVecElems(VecElems ve) {
    switch(ve) {
    case VecElems::V1: return 1;
    case VecElems::V2: return 2;
    case VecElems::V3: return 3;
    case VecElems::V4: return 4;
    case VecElems::V8: return 8;
    case VecElems::V16: return 16;
    case VecElems::V32: return 32;
    case VecElems::V64: return 64;
    default: MUST_BE_TRUE(false, "invalid encoding");
    }
    return 0;
}

// data chmask
size_t vISA::GetNumVecElemsQuad(int chMask) {
    size_t vecElems = 0;
    if (chMask & DataChMask::X) vecElems++;
    if (chMask & DataChMask::Y) vecElems++;
    if (chMask & DataChMask::Z) vecElems++;
    if (chMask & DataChMask::W) vecElems++;

    return vecElems;
}

// Addr size type
std::string vISA::ToSymbol(AddrSizeType a) {
    switch (a)
    {
    case AddrSizeType::FLAT_A64_A32: return "flat_a64_a32";
    case AddrSizeType::FLAT_A64_A64: return "flat_a64_a64";
    case AddrSizeType::STATEFUL_A32: return "stateful_a32";
    case AddrSizeType::FLAT_A32_A32: return "flat_a32_a32";
    case AddrSizeType::GLOBAL_A32_A32: return "global_a32_a32";
    case AddrSizeType::LOCAL_A32_A32: return "local_a32_a32";
    default: return "?";
    }
}

AddrSizeType vISA::ConvertLSCAddrSizeType(LSC_ADDR_SIZE a) {
    // TODO: This function may need an additional argument -- LSC_ADDR_TYPE
    // TODO: expand the cases
    switch(a) {
    case LSC_ADDR_SIZE_32b: return AddrSizeType::FLAT_A64_A32;
    case LSC_ADDR_SIZE_64b: return AddrSizeType::FLAT_A64_A64;
    default: MUST_BE_TRUE(false, "address size");
    }
    return AddrSizeType::INVALID;
}

uint32_t vISA::GetAddrSizeTypeEncoding(AddrSizeType a) {
    switch(a) {
    case AddrSizeType::FLAT_A32_A32:
    case AddrSizeType::GLOBAL_A32_A32:
    case AddrSizeType::FLAT_A64_A32:
        return 0;
    case AddrSizeType::LOCAL_A32_A32:
    case AddrSizeType::FLAT_A64_A64:
        return 1;
    case AddrSizeType::STATEFUL_A32:
        return 2;
    default: MUST_BE_TRUE(false, "invalid address size type");
    }
    return 0;
}

// caching
std::string vISA::ToSymbol(Caching c)
{
    switch (c)
    {
    case Caching::CA: return ".ca";
    case Caching::DF: return ".df";
    case Caching::RI: return ".ri";
    case Caching::ST: return ".st";
    case Caching::WB: return ".wb";
    case Caching::WT: return ".wt";
    case Caching::UC: return ".uc";
    default: return "?";
    }
}

std::string vISA::ToSymbol(Caching l1, Caching l3)
{
    if (l1 == Caching::DF && l3 == Caching::DF)
        return "";
    else
        return ToSymbol(l1) + ToSymbol(l3);
}

Caching vISA::ConvertLSCCacheOpt(LSC_CACHE_OPT co) {
    switch(co) {
    case LSC_CACHING_DEFAULT: return Caching::DF;
    case LSC_CACHING_UNCACHED: return Caching::UC;
    case LSC_CACHING_CACHED: return Caching::CA;
    case LSC_CACHING_WRITEBACK: return Caching::WB;
    case LSC_CACHING_WRITETHROUGH: return Caching::WT;
    case LSC_CACHING_STREAMING: return Caching::ST;
    case LSC_CACHING_READINVALIDATE: return Caching::RI;
    default: MUST_BE_TRUE(false, "invalid caching");
    }
    return Caching::INVALID;
}

std::pair<Caching, Caching> vISA::ConvertLSCCacheOpts(LSC_CACHE_OPT col1,
                        LSC_CACHE_OPT col3) {

    return std::make_pair(ConvertLSCCacheOpt(col1), ConvertLSCCacheOpt(col3));
}

int ElemsPerAddr::getCount() const
{
    if (!isChannelMask())
        return count;
    return
        ((int(channels) & int(Chs::X)) ? 1 : 0) +
        ((int(channels) & int(Chs::Y)) ? 1 : 0) +
        ((int(channels) & int(Chs::Z)) ? 1 : 0) +
        ((int(channels) & int(Chs::W)) ? 1 : 0);
}

ElemsPerAddr::Chs ElemsPerAddr::getMask() const
{
    MUST_BE_TRUE(isChannelMask(), "must be a channel mask vector");
    return channels;
}

std::string ElemsPerAddr::str() const
{
    if (isChannelMask()) {
        if (channels == Chs::INVALID)
            return ".?";
        // e.g. .xyz
        std::string s = ".";
        if (int(channels) & int(Chs::X))
            s += 'x';
        if (int(channels) & int(Chs::Y))
            s += 'y';
        if (int(channels) & int(Chs::Z))
            s += 'z';
        if (int(channels) & int(Chs::W))
            s += 'w';
        return s;
    } else {
        // e.g. x4 (note absence of a dot)
        return "x" + std::to_string(count);
    }
}

///////////////////////////////////////////////////////////////////////////////
// G4_SendDesc implementations
///////////////////////////////////////////////////////////////////////////////
static inline int roundUpToGrf(int bytes, int grfSize) {
    return g4::alignUp(grfSize, bytes) / grfSize;
}

size_t G4_SendDesc::getSrc0LenRegs() const {
    return roundUpToGrf(getSrc0LenBytes(), irb.getGRFSize());
}

size_t G4_SendDesc::getDstLenRegs() const {
    return roundUpToGrf(getDstLenBytes(), irb.getGRFSize());
}

size_t G4_SendDesc::getSrc1LenRegs() const {
    return roundUpToGrf(getSrc1LenBytes(), irb.getGRFSize());
}

bool G4_SendDesc::isHDC() const
{
    auto funcID = getSFID();
    return
        funcID == SFID::DP_DC0 ||
        funcID == SFID::DP_DC1 ||
        funcID == SFID::DP_DC2 ||
        funcID == SFID::DP_CC;
}

bool G4_SendDesc::isLSC() const
{
    switch (getSFID()) {
    case SFID::UGM:
    case SFID::UGML:
    case SFID::TGM:
    case SFID::SLM:
        return true;
    default:
        break;
    }
    return false;
}

///////////////////////////////////////////////////////////////////////////////
// G4_SendDescLdSt implementations
///////////////////////////////////////////////////////////////////////////////
G4_SendDescLdSt::G4_SendDescLdSt(
    SFID sfid,
    MsgOp _op,
    G4_ExecSize _execSize,
    //
    // addr params
    AddrType at, int _addrBits, int _addrDims,
    //
    // data params
    int elemBitsMem, int elemBitsReg, int elemsPerAddr,
    LdStOrder _order,
    //
    // ext info
    Caching _l1, Caching _l3,
    G4_Operand *surf,
    ImmOff _immOff,
    LdStAttrs _attrs,
    const IR_Builder& builder)
    : G4_SendDesc(G4_SendDesc::Kind::INVALID, sfid, _execSize, builder),
    op(_op),
    //
    addrType(at), addrBits(_addrBits), addrDims(_addrDims),
    //
    elemBitsMem(elemBitsMem), elemBitsReg(elemBitsReg),
    elemPerAddr(elemsPerAddr), order(_order),
    l1(_l1), l3(_l3),
    surface(surf), immOff(_immOff),
    attrs(_attrs)
{
}

static size_t toExecSlots(const G4_SendDescLdSt &d, TARGET_PLATFORM platform)
{
    int minExecSize = 8;
    if (platform >= TARGET_PLATFORM::Xe_PVC)
        minExecSize = 16;
    MUST_BE_TRUE(false, "TODO: needs to deal with half size LSC messages");
    MUST_BE_TRUE(false, "TODO: need to deal with varying typed message sizes");
    // e.g. deal with
    //   SIMD4 typed ...
    //   SIMD4 untyped...
    // (or we make the descriptor creator just pass the right exec size in)
    int execSlots = std::max((int)d.getExecSize(), minExecSize);
    return (size_t)execSlots;
}

size_t G4_SendDescLdSt::getSrc0LenBytes() const
{
    if (overrideSrc0LengthBytesValue >= 0) {
        return (size_t)overrideSrc0LengthBytesValue;
    }
    switch (op) {
    case MsgOp::LOAD_STRIDED:
    case MsgOp::STORE_STRIDED:
        return 8 + 4;  // address field is 64b (even for A32) + pitch is 32b
    case MsgOp::LOAD_BLOCK2D:
    case MsgOp::STORE_BLOCK2D:
        // [243:0] ~ 256b = 32B
        return 32;
    default:
        break; // fallthrough to other logic
    }
    if (order == LdStOrder::SCALAR) {
        // transpose messages send one address only
        return elemPerAddr / 8;
    } else {
        MUST_BE_TRUE(false, "TODO: needs to deal with half HDC gunk");
        MUST_BE_TRUE(false, "TODO: needs to deal with addrDims");
        int execSlots = std::max((int)execSize, 16);
        return (size_t)(execSlots * elemPerAddr / 8);
    }
}

size_t G4_SendDescLdSt::getSrc1LenBytes() const
{
    if (overrideSrc1LengthBytesValue >= 0) {
        return (size_t)overrideSrc1LengthBytesValue;
    }
    if (order == LdStOrder::SCALAR) {
        // transpose messages send one address only
        return elemPerAddr / 8;
    } else {
        return toExecSlots(*this, irb.getPlatform()) * elemBitsReg;
    }
    MUST_BE_TRUE(false, "TODO: compute data bytes sent");
    return (size_t)-1;
}

size_t G4_SendDescLdSt::getDstLenBytes() const
{
    if (overrideDstLengthBytesValue >= 0) {
        return (size_t)overrideDstLengthBytesValue;
    }
    MUST_BE_TRUE(false, "TODO: compute bytes received");
    return (size_t)-1;
}
void G4_SendDescLdSt::setCaching(Caching _l1, Caching _l3)
{
    l1 = _l1;
    l3 = _l3;
}
bool G4_SendDescLdSt::isSLM() const
{
    if (getSFID() == SFID::SLM)
        return true;
    MUST_BE_TRUE(!isHDC(), "HDC SLM not supported (yet)");
    return false;
}

SendAccess G4_SendDescLdSt::getAccessType() const
{
    if ((int(op) & int(MSGOP_BUFFER_LOAD_GROUP)) != 0)
        return SendAccess::READ_ONLY;
    else if ((int(op) & int(MSGOP_BUFFER_STORE_GROUP)) != 0)
        return SendAccess::WRITE_ONLY;
    else if ((int(op) & int(MSGOP_BUFFER_ATOMIC_GROUP)) != 0)
        return hasAttrs(LdStAttrs::ATOMIC_RETURN) ?
        SendAccess::READ_WRITE : SendAccess::WRITE_ONLY;

    MUST_BE_TRUE(false, "unsupported op group");
    return SendAccess::INVALID;
}

bool G4_SendDescLdSt::isAtomic() const
{
    return (int(op) & int(MSGOP_BUFFER_ATOMIC_GROUP)) != 0;
}

bool G4_SendDescLdSt::isTyped() const
{
    if (getSFID() == SFID::TGM)
        return true;
    return false;
}

static std::string ToSymbol(vISA::SFID sfid)
{
    switch (sfid) {
    case SFID::UGM:  return ".ugm";
    case SFID::UGML: return ".ugml";
    case SFID::SLM:  return ".slm";
    case SFID::TGM:  return ".tgm";
        // these aren't necessarily supported yet
    case SFID::DP_DC0:  return ".dc0";
    case SFID::DP_DC1:  return ".dc1";
    case SFID::DP_DC2:  return ".dc2";
    case SFID::DP_CC: return ".dcro";
    case SFID::URB:  return ".urb";
        // others not needed
    default: break;
    }
    return ".?";
}

static std::string ToSymbolDataSize(int reg, int mem)
{
    if (reg == mem)
        return "d" + std::to_string(reg);
    return "d" + std::to_string(mem) + "a" + std::to_string(reg) ;
}

static std::string ToSymbol(AddrType at)
{
    switch (at) {
    case AddrType::FLAT: return "";
    case AddrType::BSS:  return "bss";
    case AddrType::SS:   return "ss";
    case AddrType::BTI:  return "bti";
    default: break;
    }
    return "?";
}

static void GetMnemonicPart(std::ostream &os, const G4_SendDescLdSt &m)
{
    os << ToSymbol(m.op);
    os << "." << ::ToSymbol(m.getSFID());
    os << "." << ToSymbolDataSize(m.elemBitsReg, m.elemBitsReg);
    os << ".a" << std::to_string(m.addrBits);
    os << ToSymbol(m.l1, m.l3);
}

std::string G4_SendDescLdSt::str() const
{
    std::stringstream ss;
    str(ss);
    return ss.str();
}

void G4_SendDescLdSt::str(std::ostream &os) const
{
    auto fmtHex =
        [] (int64_t x) {
        std::stringstream ss;
        ss << "0x" << std::hex << std::uppercase << x;
        return ss.str();
    };

    GetMnemonicPart(os, *this);
    os << " ";
    os << ::ToSymbol(addrType);
    if (addrType != AddrType::FLAT) {
        os << "[";
        if (const G4_Operand *surf = getSurface()) {
            if (surf->isImm()) {
                os << fmtHex(surf->asImm()->getImm());
            } else if (surf->isA0() ){
                os << "a0.?"; // how to find subreg
            } else {
                os << "A?";
            }
        } else {
            os << "???";
        }
        os << "]";
    }
}


///////////////////////////////////////////////////////////////////////////////
// G4_SendDescRaw implementations
///////////////////////////////////////////////////////////////////////////////
G4_SendDescRaw::G4_SendDescRaw(
    uint32_t fCtrl, uint32_t regs2rcv,
    uint32_t regs2snd, SFID fID, uint16_t extMsgLen,
    uint32_t extFCtrl, SendAccess access,
    G4_Operand *bti, G4_Operand *sti,
    const IR_Builder& builder)
    : G4_SendDesc(G4_SendDesc::Kind::RAW, fID, builder)
{
    // All unnamed bits should be passed with those control bits.
    // Otherwise, need to be set individually.
    desc.value = fCtrl;

    desc.layout.rspLength = regs2rcv;
    desc.layout.msgLength = regs2snd;

    extDesc.value = 0;
    extDesc.layout.funcID = SFIDtoInt(fID);
    extDesc.layout.extMsgLength = extMsgLen;
    extDesc.layout.extFuncCtrl = extFCtrl;

    src1Len = extMsgLen; // [10:6]
    eotAfterMessage = false; // [5]
    sfid = fID;

    accessType = access;
    funcCtrlValid = true;

    m_bti = bti;
    m_sti = sti;

    if (m_bti && m_bti->isImm())
    {
        setBindingTableIdx((unsigned)m_bti->asImm()->getInt());
    }
    if (m_sti && m_sti->isImm())
    {
        desc.value |= (((unsigned)m_sti->asImm()->getInt()) << 8); // [11:8]
    }

    uint32_t totalMaxLength = builder.getMaxSendMessageLength();
    MUST_BE_TRUE(extDesc.layout.extMsgLength + desc.layout.msgLength < totalMaxLength,
        "combined message length may not exceed the maximum");
}

G4_SendDescRaw::G4_SendDescRaw(
    uint32_t descBits, uint32_t extDescBits,
    SendAccess access,
    G4_Operand *bti,
    G4_Operand *sti,
    const IR_Builder& builder)
    : G4_SendDesc(G4_SendDesc::Kind::RAW,
        intToSFID(extDescBits & 0xF, builder.getPlatform()), builder), // [3:0]
    accessType(access), m_sti(sti), m_bti(bti), funcCtrlValid(true)
{
    desc.value = descBits;
    extDesc.value = extDescBits;
    src1Len = (extDescBits >> 6) & 0x1F; // [10:6]
    eotAfterMessage = extDesc.layout.eot; // [5]


    if (bti && bti->isImm())
    {
        setBindingTableIdx((unsigned)bti->asImm()->getInt());
    }
    if (sti && sti->isImm())
    {
        desc.value |= (((unsigned)m_sti->asImm()->getInt()) << 8); // [11:8]
    }
}

G4_SendDescRaw::G4_SendDescRaw(
    SFID _sfid,
    uint32_t _desc,
    uint32_t _extDesc,
    int _src1Len,
    SendAccess access,
    G4_Operand* bti,
    bool isValidFuncCtrl,
    const IR_Builder& builder)
    : G4_SendDescRaw(_sfid, _desc, _extDesc, _src1Len, access, bti,
                     g4::SIMD_UNDEFINED, isValidFuncCtrl, builder)
{}

G4_SendDescRaw::G4_SendDescRaw(
    SFID _sfid,
    uint32_t _desc,
    uint32_t _extDesc,
    int _src1Len,
    SendAccess access,
    G4_Operand *bti,
    G4_ExecSize execSize,
    bool isValidFuncCtrl,
    const IR_Builder& builder)
    : G4_SendDesc(G4_SendDesc::Kind::RAW, _sfid, execSize, builder),
    accessType(access), m_sti(nullptr), m_bti(bti), funcCtrlValid(isValidFuncCtrl)
{
    isLscDescriptor =
        _sfid == SFID::UGM || _sfid == SFID::UGML ||
        _sfid == SFID::SLM || _sfid == SFID::TGM;

    if (!isLscDescriptor && bti && bti->isImm()) {
        setBindingTableIdx((unsigned)bti->asImm()->getInt());
    }
    // ensure ExDesc[10:6] also holds src1Len
    // see the note above (other constructor) about DG2 descriptors and
    // ExDesc[10:6]
    _extDesc |= ((_src1Len & 0x1F) << 6);
    desc.value = _desc;
    extDesc.value = _extDesc;
    src1Len = _src1Len;
    eotAfterMessage = false;
}

uint32_t G4_SendDescRaw::getHdcMessageType() const
{
    MUST_BE_TRUE(isHDC(),"not an HDC message");
    return (desc.value >> 14) & 0x1F;
}

LSC_ADDR_TYPE G4_SendDescRaw::getLscAddrType() const
{
    MUST_BE_TRUE(isLscOp(), "must be LSC op");
    const int LSC_ADDR_TYPE_OFFSET = 29;
    const uint32_t LSC_ADDR_TYPE_MASK = 0x3;
    const uint32_t rawDescBits = getDesc();
    auto addrTypeBits = ((rawDescBits >> LSC_ADDR_TYPE_OFFSET) & LSC_ADDR_TYPE_MASK);
    return LSC_ADDR_TYPE(addrTypeBits + 1);
}

int G4_SendDescRaw::getLscAddrSizeBytes() const
{
    MUST_BE_TRUE(isLscOp(), "must be LSC op");
    auto op = getLscOp();
    switch (op) {
    case LSC_LOAD:
    case LSC_LOAD_STRIDED:
    case LSC_LOAD_QUAD:
    case LSC_STORE:
    case LSC_STORE_STRIDED:
    case LSC_STORE_QUAD:
        break;
    case LSC_LOAD_BLOCK2D:
    case LSC_STORE_BLOCK2D:
        return getSFID() == SFID::TGM ? 4 : 8;
    default:
        if (op < LSC_ATOMIC_IINC && op > LSC_ATOMIC_XOR) {
            return 0;
        }
    }
    // it's a good op with an AddrType field in [8:7]
    switch ((getDesc() >> 7) & 0x3) {
    case 1: return 2;
    case 2: return 4;
    case 3: return 8;
    default: break;
    }
    return 0;
}

LSC_DATA_ORDER G4_SendDescRaw::getLscDataOrder() const
{
    MUST_BE_TRUE(isLscOp(), "must be LSC op");
    auto op = getLscOp();
    if (op == LSC_LOAD_QUAD || op == LSC_STORE_QUAD)
        return LSC_DATA_ORDER_NONTRANSPOSE;
    if ((getDesc() >> 15) & 0x1) {
        return LSC_DATA_ORDER_TRANSPOSE;
    } else {
        return LSC_DATA_ORDER_NONTRANSPOSE;
    }
}


bool G4_SendDescRaw::setEOT() {
    eotAfterMessage = true;

    if (isLscOp())
        return true;

    extDesc.layout.eot = true; // for ancient platforms/encoders
    return true;
}

static bool isHdcIntAtomicMessage(SFID funcID, uint16_t msgType, const IR_Builder& irb)
{
    if (funcID != SFID::DP_DC1)
        return false;

    if (msgType == DC1_UNTYPED_ATOMIC || msgType == DC1_A64_ATOMIC)
    {
        return true;
    }
    if (irb.getPlatform() >= GENX_SKL)
    {
        if (msgType == DC1_TYPED_ATOMIC)
            return true;
    }
    if (irb.getPlatformGeneration() >= PlatformGen::XE)
    {
        if (msgType == DC1_TYPED_HALF_INTEGER_ATOMIC ||
            msgType == DC1_TYPED_HALF_COUNTER_ATOMIC ||
            msgType == DC1_UNTYPED_HALF_INTEGER_ATOMIC ||
            msgType == DC1_A64_UNTYPED_HALF_INTEGER_ATOMIC)
            return true;
    }
    return false;
}

static bool isHdcFloatAtomicMessage(SFID funcID, uint16_t msgType, const IR_Builder& irb)
{
    if (funcID != SFID::DP_DC1)
        return false;

    if (irb.getPlatform() >= GENX_SKL)
    {
        if (msgType == DC1_UNTYPED_FLOAT_ATOMIC ||
            msgType == DC1_A64_UNTYPED_FLOAT_ATOMIC)
            return true;
    }
    if (irb.getPlatformGeneration() >= PlatformGen::XE)
    {
        if (msgType == DC1_UNTYPED_HALF_FLOAT_ATOMIC ||
            msgType == DC1_A64_UNTYPED_HALF_FLOAT_ATOMIC)
            return true;
    }
    return false;
}

bool G4_SendDescRaw::isAtomicMessage() const
{
    if (isLscOp() &&
        (desc.value & 0x3F) >= LSC_ATOMIC_IINC &&
        (desc.value & 0x3F) <= LSC_ATOMIC_XOR)
    {
        return true;
    }

    auto funcID = getSFID();
    if (!isHDC())
        return false; // guard getMessageType() on SFID without a message type
    uint16_t msgType = getHdcMessageType();
    return isHdcIntAtomicMessage(funcID, msgType, irb) ||
        isHdcFloatAtomicMessage(funcID, msgType, irb);
}

uint16_t G4_SendDescRaw::getHdcAtomicOp() const
{
    MUST_BE_TRUE(isHDC(), "must be HDC message");
    MUST_BE_TRUE(isAtomicMessage(), "getting atomicOp from non-atomic message!");
    uint32_t funcCtrl = getFuncCtrl();
    if (isHdcIntAtomicMessage(getSFID(), getHdcMessageType(), irb))
    {
        // bits: 11:8
        return (uint16_t)((funcCtrl >> 8) & 0xF);
    }

    // must be float Atomic
    // bits: 10:8
    return (int16_t)((funcCtrl >> 8) & 0x7);
}

bool G4_SendDescRaw::isSLMMessage() const
{
    if (getSFID() == SFID::DP_DC2)
    {
        uint32_t msgType = getHdcMessageType();
        if ((msgType == DC2_UNTYPED_SURFACE_WRITE || msgType == DC2_BYTE_SCATTERED_WRITE) &&
            (getFuncCtrl() & 0x80))
        {
            return true;
        }
    }

    if (getSFID() == SFID::DP_DC2 ||
        getSFID() == SFID::DP_DC1 ||
        getSFID() == SFID::DP_DC0)
    {
        if ((getDesc() & 0xFF) == SLMIndex)
        {
            return true;
        }
    }

    if (m_bti && m_bti->isImm() && m_bti->asImm()->getInt() == SLMIndex)
    {
        return true;
    }

    return getSFID() == SFID::SLM;
}


uint16_t G4_SendDescRaw::ResponseLength() const
{
    // the loadblock2DArray message may return up to 32 GRF.
    // Since we don't have enough bits to encode 32, block2d creates an exception where 31 means 31 or 32 (HW detects).
    // SW must know the actual size is 32 for data-flow/RA/SWSB to function correctly though.
    // fortunately it doesn't look like 31 is a valid value for this message, we just treat 31 as 32
    bool isLoadBlock2DArray = isLscOp() && getLscOp() == LSC_LOAD_BLOCK2D;
    if (desc.layout.rspLength == 31 && isLoadBlock2DArray)
    {
        return 32;
    }
    return desc.layout.rspLength;
}


bool G4_SendDescRaw::isHeaderPresent() const {
    if (isLscOp())
        return false;

    return desc.layout.headerPresent == 1;
}

void G4_SendDescRaw::setHeaderPresent(bool val)
{
    MUST_BE_TRUE(!isLscOp(), "LSC ops don't have headers");
    desc.layout.headerPresent = val;
}

void G4_SendDescRaw::setBindingTableIdx(unsigned idx)
{
    if (isLscOp()) {
        extDesc.value |= (idx << 24);
        return;
    }
    desc.value |= idx;
}

uint32_t G4_SendDescRaw::getSamplerMessageType() const
{
    MUST_BE_TRUE(isSampler(), "wrong descriptor type for method");
    return (getFuncCtrl() >> 12) & 0x1f;
}

bool G4_SendDescRaw::is16BitInput() const
{
    MUST_BE_TRUE(!isLscOp(), "wrong descriptor type for method");
    // TODO: could use this for LSC messages too potentially
    return desc.layout.simdMode2 == 1;
}

bool G4_SendDescRaw::is16BitReturn() const
{
    MUST_BE_TRUE(!isLscOp(), "wrong descriptor type for method");
    return desc.layout.returnFormat == 1;
}

bool G4_SendDescRaw::isByteScatterRW() const
{
    auto funcID = getSFID();
    switch (funcID) {
    case SFID::DP_DC0:
        switch (getHdcMessageType()) {
        case DC_BYTE_SCATTERED_READ:
        case DC_BYTE_SCATTERED_WRITE:
            return true;
        default:
            break;
        }
        break;
    case SFID::DP_DC1:
        switch (getHdcMessageType()) {
        case DC1_A64_SCATTERED_READ:
        case DC1_A64_SCATTERED_WRITE:
            return (getElemSize() == 1);
        default:
            break;
        }
        break;
    case SFID::DP_DC2:
        switch (getHdcMessageType()) {
        case DC2_A64_SCATTERED_READ:
        case DC2_A64_SCATTERED_WRITE:
            return (getElemSize() == 1);
        case DC2_BYTE_SCATTERED_READ:
        case DC2_BYTE_SCATTERED_WRITE:
            return true;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return false;
}

bool G4_SendDescRaw::isDWScatterRW() const
{
    auto funcID = getSFID();
    switch (funcID) {
    case SFID::DP_DC0:
        switch (getHdcMessageType()) {
        case DC_DWORD_SCATTERED_READ:
        case DC_DWORD_SCATTERED_WRITE:
            return true;
        default:
            break;
        }
        break;
    case SFID::DP_DC1:
        switch (getHdcMessageType()) {
        case DC1_A64_SCATTERED_READ:
        case DC1_A64_SCATTERED_WRITE:
            return (getElemSize() == 4);
        default:
            break;
        }
        break;
    case SFID::DP_DC2:
        switch (getHdcMessageType()) {
        case DC2_A64_SCATTERED_READ:
        case DC2_A64_SCATTERED_WRITE:
            return (getElemSize() == 4);
        default:
            break;
        }
        break;
    default:
        break;
    }
    return false;
}

bool G4_SendDescRaw::isQWScatterRW() const
{
    auto funcID = getSFID();
    switch (funcID) {
    case SFID::DP_DC0:
        switch (getHdcMessageType()) {
        case DC_QWORD_SCATTERED_READ:
        case DC_QWORD_SCATTERED_WRITE:
            return true;
        default:
            break;
        }
        break;
    case SFID::DP_DC1:
        switch (getHdcMessageType()) {
        case DC1_A64_SCATTERED_READ:
        case DC1_A64_SCATTERED_WRITE:
            return (getElemSize() == 8);
        default:
            break;
        }
        break;
    case SFID::DP_DC2:
        switch (getHdcMessageType()) {
        case DC2_A64_SCATTERED_READ:
        case DC2_A64_SCATTERED_WRITE:
            return (getElemSize() == 8);
        default:
            break;
        }
        break;
    default:
        break;
    }
    return false;
}

bool G4_SendDescRaw::isUntypedRW() const
{
    auto funcID = getSFID();
    switch (funcID) {
    case SFID::DP_DC1:
        switch (getHdcMessageType()) {
        case DC1_UNTYPED_SURFACE_READ:
        case DC1_UNTYPED_SURFACE_WRITE:
        case DC1_A64_UNTYPED_SURFACE_READ:
        case DC1_A64_UNTYPED_SURFACE_WRITE:
            return true;
        default:
            break;
        }
        break;
    case SFID::DP_DC2:
        switch (getHdcMessageType()) {
        case DC2_UNTYPED_SURFACE_READ:
        case DC2_UNTYPED_SURFACE_WRITE:
        case DC2_A64_UNTYPED_SURFACE_READ:
        case DC2_A64_UNTYPED_SURFACE_WRITE:
            return true;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return false;
}

bool G4_SendDescRaw::isA64Message() const
{
    if (!isHDC()) {
        return false;
    }

    uint32_t msgType = getHdcMessageType();
    auto funcID = getSFID();
    switch (funcID) {
    case SFID::DP_DC1:
    {
        switch (msgType) {
        default:
            break;
        case DC1_A64_SCATTERED_READ:
        case DC1_A64_UNTYPED_SURFACE_READ:
        case DC1_A64_ATOMIC:
        case DC1_A64_BLOCK_READ :
        case DC1_A64_BLOCK_WRITE:
        case DC1_A64_UNTYPED_SURFACE_WRITE:
        case DC1_A64_SCATTERED_WRITE:
        case DC1_A64_UNTYPED_FLOAT_ATOMIC:
        case DC1_A64_UNTYPED_HALF_INTEGER_ATOMIC:
        case DC1_A64_UNTYPED_HALF_FLOAT_ATOMIC:
            return true;
        }
        break;
    }
    case SFID::DP_DC2 :
    {
        switch (msgType) {
        default:
            break;
        case DC2_A64_SCATTERED_READ:
        case DC2_A64_UNTYPED_SURFACE_READ:
        case DC2_A64_UNTYPED_SURFACE_WRITE:
        case DC2_A64_SCATTERED_WRITE:
            return true;
        }
        break;
    }
    default:
        break;
    }
    return false;
}

static int getNumEnabledChannels(uint32_t chDisableBits)
{
    switch (chDisableBits)
    {
    case 0x7:
    case 0xB:
    case 0xD:
    case 0xE: return 1;
    case 0x3:
    case 0x5:
    case 0x6:
    case 0x9:
    case 0xA:
    case 0xC: return 2;
    case 0x1:
    case 0x2:
    case 0x4:
    case 0x8: return 3;
    case 0x0: return 4;
    case 0xF: return 0;
    default: MUST_BE_TRUE(false, "Illegal Channel Mask Number");
    }
    return 0;
}

#define MSG_BLOCK_SIZE_OFFSET   8
unsigned G4_SendDescRaw::getEnabledChannelNum() const
{
    // TODO: should further scope this to typed/untyped
    MUST_BE_TRUE(isHDC(), "message does not have field ChannelEnable");
    uint32_t funcCtrl = getFuncCtrl();
    return getNumEnabledChannels((funcCtrl >> MSG_BLOCK_SIZE_OFFSET) & 0xF);
}

unsigned G4_SendDescRaw::getElemsPerAddr() const
{
    if (isHDC()) {
        uint32_t funcCtrl = getFuncCtrl();

        const int MSG_BLOCK_NUMBER_OFFSET = 10;
        funcCtrl = (funcCtrl >> MSG_BLOCK_NUMBER_OFFSET) & 0x3;
        switch (funcCtrl)
        {
        case SVM_BLOCK_NUM_1: return 1;
        case SVM_BLOCK_NUM_2: return 2;
        case SVM_BLOCK_NUM_4: return 4;
        case SVM_BLOCK_NUM_8: return 8;
        default: MUST_BE_TRUE(false, "Illegal SVM block number (should be 1, 2, 4, or 8).");
        }
    } else if (isLSC()) {
        auto op = getLscOp();
        switch (op) {
        case LSC_STORE_QUAD:
        case LSC_LOAD_QUAD:
        {
            int elems = 0;
            auto cmask = (getDesc() >> 14) & 0xF;
            for (int i = 0; i < 4; i++, cmask >>= 1) {
                elems += (cmask & 1);
            }
            break;
        }
        case LSC_LOAD:
        case LSC_LOAD_STRIDED:
        case LSC_STORE:
        case LSC_STORE_STRIDED:
            // bits [14:12] are the vector size
            switch ((getDesc() >> 14) & 0x7) {
            case 0: return 1;
            case 1: return 2;
            case 2: return 3;
            case 3: return 4;
            case 4: return 8;
            case 5: return 16;
            case 6: return 32;
            case 7: return 64;
            }
            break;
        case LSC_LOAD_BLOCK2D:
        case LSC_STORE_BLOCK2D:
            // unsupported
            return 0;
        default:
            if (op >= LSC_ATOMIC_IINC && op <= LSC_ATOMIC_XOR) {
                return 1; // atomics are always 1
            } else {
                return 0;
            }
        }
        return 1;
    } // TODO: others e.g. sampler
    return 0;
}

unsigned G4_SendDescRaw::getElemSize() const
{
    if (isHDC()) {
        // FIXME: this should be checking for DC1 (SVM? only???)
        // Move HDC decode logic from Augmentation to here
        uint32_t funcCtrl = getFuncCtrl();

        funcCtrl =  (funcCtrl >> MSG_BLOCK_SIZE_OFFSET) & 0x3;
        switch (funcCtrl)
        {
        case SVM_BLOCK_TYPE_BYTE: return 1;
        case SVM_BLOCK_TYPE_DWORD: return 4;
        case SVM_BLOCK_TYPE_QWORD: return 8;
        default: MUST_BE_TRUE(false, "Illegal SVM block size (should be 1, 4, or 8).");
        }
        return 0;
    } else if (isLSC()) {
        if (getSFID() == SFID::TGM)
            return 4; // typed always accesses 4B
        // UGM, SLM, or something else untyped
        auto op = getLscOp();
        switch (op) {
        case LSC_LOAD:
        case LSC_LOAD_STRIDED:
        case LSC_LOAD_QUAD:
        case LSC_LOAD_BLOCK2D:
        case LSC_STORE:
        case LSC_STORE_STRIDED:
        case LSC_STORE_QUAD:
        case LSC_STORE_BLOCK2D:
            break; // supported
        default:
            if (op < LSC_ATOMIC_IINC && op > LSC_ATOMIC_XOR) {
                MUST_BE_TRUE(false, "unexpected receiver (unsupported descriptor type) ==> fix this");
                return 0;
            } // else supported
        }
        // []
        switch ((getDesc() >> 9) & 0x7) {
        case 0: return 1; // d8 (block2d only)
        case 1: return 2; // d16 (block2d only)
        case 3: return 8; // d64
        default: return 2; // d32, d8u32, ... all 32b in register file
        }
    } else if (getSFID() == SFID::SAMPLER) {
        return is16BitReturn() ? 2 : 4;
    // TODO: render target
    // TODO: other unsupported things like barrier and fence should just return 0 without asserting?
    } else {
        MUST_BE_TRUE(false, "unexpected receiver (unsupported descriptor type) ==> fix this");
        return 0;
    }
}

bool G4_SendDescRaw::isOwordLoad() const
{
    if (!isHDC()) {
        return false;
    }
    uint32_t funcCtrl = getFuncCtrl();
    auto funcID = getSFID();
    static int DC0_MSG_TYPE_OFFSET = 14;
    static int DC1_MSG_SUBTYPE_OFFSET = 12; // [31:12]
    uint16_t msgType = (funcCtrl >> DC0_MSG_TYPE_OFFSET) & 0x1F;
    uint16_t dc1MsgSubType = (funcCtrl >> DC1_MSG_SUBTYPE_OFFSET) & 0x3;
    // bits [18:14] are message type
    // (included 18 because that is set for scratch)
    static const uint32_t MSD0R_OWAB  = 0x0; // DC0
    static const uint32_t MSD0R_OWB   = 0x0; // DC0
    static const uint32_t MSD_CC_OWAB = 0x1; // DC_CC
    static const uint32_t MSD_CC_OWB = 0x0; // DC_CC
    static const uint32_t MSD1R_A64_OWB = 0x14; // DC1 A64 [13:12] == 1
    static const uint32_t MSD1R_A64_OWAB = 0x14; // DC1 A64 [13:12] == 0
    bool isDc0Owb = funcID == SFID::DP_DC0 && (msgType == MSD0R_OWAB || msgType == MSD0R_OWB);
    bool isCcOwb = funcID == SFID::DP_CC && (msgType == MSD_CC_OWAB || msgType == MSD_CC_OWB);
    bool isDc1A64Owb =
        funcID == SFID::DP_DC1 && (msgType == MSD1R_A64_OWB) &&
        // st==2, 3 don't have mappings that I can find, but just to be
        // safe force 0 or 1 (which are unalgined vs aligned)
        (dc1MsgSubType == 0 || dc1MsgSubType == 1);
    return isDc0Owb || isCcOwb || isDc1A64Owb;
}

unsigned G4_SendDescRaw::getOwordsAccessed() const
{
    MUST_BE_TRUE(isOwordLoad(), "must be OWord message");
    // This encoding holds for the DP_DC0, DP_CC, and DP_DC1 (A64 block)
    // element count.
    auto owEnc = (getFuncCtrl() >> 8) & 0x7; // Desc[10:8] is OW count
    if (owEnc == 0) {
        return 1; // OW1L (low half of GRF)
    } else if (owEnc == 1) {
        // for OW1H (high half of GRF): treat as full 32B
        // (this control probably isn't ever be used and was removed in Xe)
        return 1;
    } else {
        // 2 = OW2, 3 == OW4, 4 == OW8, 5 == OW16
        return 2 << (owEnc - 2);
    }
}

bool G4_SendDescRaw::isHdcTypedSurfaceWrite() const
{
    return isHDC() && getHdcMessageType() == DC1_TYPED_SURFACE_WRITE;
}

std::string G4_SendDescRaw::getDescription() const
{
    // Return plain text string of type of msg, ie "oword read", "oword write",
    // "media rd", etc.
    const G4_SendDescRaw* msgDesc = this;
    unsigned int category;

    switch (msgDesc->getSFID())
    {
    case SFID::SAMPLER: return "sampler";
    case SFID::GATEWAY: return "gateway";
    case SFID::DP_DC2:
        switch (getHdcMessageType())
        {
        case DC2_UNTYPED_SURFACE_READ: return "scaled untyped surface read";
        case DC2_A64_SCATTERED_READ: return "scaled A64 scatter read";
        case DC2_A64_UNTYPED_SURFACE_READ: return "scaled A64 untyped surface read";
        case DC2_BYTE_SCATTERED_READ: return "scaled byte scattered read";
        case DC2_UNTYPED_SURFACE_WRITE: return "scaled untyped surface write";
        case DC2_A64_UNTYPED_SURFACE_WRITE: return "scaled A64 untyped surface write";
        case DC2_A64_SCATTERED_WRITE: return "scaled A64 scattered write";
        case DC2_BYTE_SCATTERED_WRITE: return "scaled byte scattede write";
        default: return "unrecognized DC2 message";
        }
    case SFID::DP_WRITE:
        switch ((getFuncCtrl() >> 14) & 0x1F)
        {
        case 0xc: return "render target write";
        case 0xd: return "render target read";
        default: return "unrecognized RT message";
        }
        break;
    case SFID::URB: return "urb";
    case SFID::SPAWNER: return "thread spawner";
    case SFID::VME: return "vme";
    case SFID::DP_CC:
        switch (getHdcMessageType())
        {
        case 0x0: return "oword block read";
        case 0x1: return "unaligned oword block read";
        case 0x2: return "oword dual block read";
        case 0x3: return "dword scattered read";
        default: return "unrecognized DCC message";
        }
    case SFID::DP_DC0:
        category = (msgDesc->getFuncCtrl() >> 18) & 0x1;
        if (category == 0)
        {
            // legacy data port
            bool hword = (msgDesc->getFuncCtrl() >> 13) & 0x1;
            switch (getHdcMessageType())
            {
            case 0x0: return hword ? "hword block read" : "oword block read";
            case 0x1: return hword ? "hword aligned block read" : "unaligned oword block read";
            case 0x2: return "oword dual block read";
            case 0x3: return "dword scattered read";
            case 0x4: return "byte scattered read";
            case 0x7: return "memory fence";
            case 0x8: return hword ? "hword block write" : "oword block write";
            case 0x9: return "hword aligned block write";
            case 0xa: return "oword dual block write";
            case 0xb: return "dword scattered write";
            case 0xc: return "byte scattered write";
            case 0x5: return "qword gather";
            case 0xd: return "qword scatter";
            default: return "unrecognized DC0 message";
            }
        }
        else
        {
            // scratch
            int bits = (msgDesc->getFuncCtrl() >> 17) & 0x1;

            if (bits == 0)
                return "scratch read";
            else
                return "scratch write";
        }
        break;
    case SFID::DP_PI: return "dp_pi";
    case SFID::DP_DC1:
        switch (getHdcMessageType())
        {
        case 0x0: return "transpose read";
        case 0x1: return "untyped surface read";
        case 0x2: return "untyped atomic operation";
        case 0x3: return "untyped atomic operation simd4x2";
        case 0x4: return "media block read";
        case 0x5: return "typed surface read";
        case 0x6: return "typed atomic operation";
        case 0x7: return "typed atomic operation simd4x2";
        case 0x8: return "untyped atomic float add";
        case 0x9: return "untyped surface write";
        case 0xa: return "media block write (non-iecp)";
        case 0xb: return "atomic counter operation";
        case 0xc: return "atomic counter operation simd4x2";
        case 0xd: return "typed surface write";
        case 0x10: return "a64 gathering read";
        case 0x11: return "a64 untyped surface read";
        case 0x12: return "a64 untyped atomic operation";
        case 0x13: return "a64 untyped atomic operation simd4x2";
        case 0x14: return "a64 block read";
        case 0x15: return "a64 block write";
        case 0x18: return "a64 untyped atomic float add";
        case 0x19: return "a64 untyped surface write";
        case 0x1a: return "a64 scattered write";
        default: return "unrecognized DC1 message";
        }
        break;
    case SFID::CRE: return "cre";
    case SFID::SLM:
    case SFID::TGM:
    case SFID::UGM:
    case SFID::UGML:
    {
        LscOpInfo opInfo { };
        if (LscOpInfoFind((LSC_OP)(desc.value & 0x3F), opInfo)) { // Desc[5:0]
            return opInfo.mnemonic;
        } else {
            const char* invalid = "lsc (invalid operation)";
            return invalid;
        }
    }
    default: return "--";
    }
    return NULL;
}

size_t G4_SendDescRaw::getSrc0LenBytes() const
{
    return MessageLength() * (size_t)irb.getGRFSize();
}

size_t G4_SendDescRaw::getDstLenBytes() const
{
    if (isScratchRW()) {
        return 32 * getScratchRWSize(); // HWords
    } else if (isOwordLoad()) {
        return 16 * getOwordsAccessed(); // OWords
#if 0
    // Due to VMIT-9224, comment this out!
    // Use macro fo easy testing.
    } else if (isByteScatterRW() && isDataPortRead()) {
        assert(getExecSize() != g4::SIMD_UNDEFINED);
        uint16_t nbytes = getElemsPerAddr();
        // assume 4 at least
        nbytes = (nbytes >= 4 ? nbytes : 4);
        size_t sz = nbytes * getExecSize();
        return sz;
    } else if (isDWScatterRW() && isDataPortRead()) {
        assert(getExecSize() != g4::SIMD_UNDEFINED);
        size_t sz = 4 * getElemsPerAddr() * getExecSize();
        return sz;
    } else if (isQWScatterRW() && isDataPortRead()) {
        assert(getExecSize() != g4::SIMD_UNDEFINED);
        size_t sz = 8 * getElemsPerAddr() * getExecSize();
        return sz;
    } else if (isUntypedRW() && isDataPortRead()) {
        assert(getExecSize() != g4::SIMD_UNDEFINED);
        size_t sz = 4 * getEnabledChannelNum() * getExecSize();
        return sz;
#endif
    } else {
        // fallback to the raw GRF count
        return ResponseLength() * (size_t)irb.getGRFSize();
    }
}

size_t G4_SendDescRaw::getSrc1LenBytes() const
{
    if (isLscDescriptor) {
        return src1Len * irb.getGRFSize();
    }
    if (isScratchRW()) {
        return 32 * getScratchRWSize(); // HWords
    }
    // we could support OW store here, but no one seems to need that and
    // we are phasing this class out; so ignore it for now

    return extMessageLength() * (size_t)irb.getGRFSize();
}

bool G4_SendDescRaw::isFence() const
{
    if (isLscOp())
        return (desc.value & 0x3F) == LSC_FENCE;

    SFID sfid = getSFID();
    unsigned FC = getFuncCtrl();

    // Memory Fence
    if (sfid == SFID::DP_DC0 && ((FC >> 14) & 0x1F) == DC_MEMORY_FENCE)
    {
        return true;
    }

    // Sampler cache flush
    if (sfid == SFID::SAMPLER && ((FC >> 12) & 0x1F) == 0x1F)
    {
        return true;
    }

    return false;
}
bool G4_SendDescRaw::isBarrier() const
{
    auto funcID = getSFID();
    uint32_t funcCtrl = getFuncCtrl();
    return funcID == SFID::GATEWAY && (funcCtrl & 0xFF) == 0x4;
}


std::optional<ImmOff> G4_SendDescRaw::getOffset() const
{
    if (isLscOp()) {
    } else if (isScratchRW()) {
        // HWord scratch message
        return ImmOff(getScratchRWOffset() * 32);
    }
    return std::nullopt;
}

static Caching cachingToG4(LSC_CACHE_OPT co)
{
    switch (co) {
    case LSC_CACHING_DEFAULT:        return Caching::DF;
    case LSC_CACHING_CACHED:         return Caching::CA;
    case LSC_CACHING_READINVALIDATE: return Caching::RI;
    case LSC_CACHING_WRITEBACK:      return Caching::WB;
    case LSC_CACHING_UNCACHED:       return Caching::UC;
    case LSC_CACHING_STREAMING:      return Caching::ST;
    case LSC_CACHING_WRITETHROUGH:   return Caching::WT;
    default: break;
    }
    return Caching::INVALID;
}

// decode caching from Desc[19:17]
static std::pair<Caching,Caching> decodeCaching3(
    bool isLoad, uint32_t descBits)
{
    auto mk = [&](Caching l1IfLd, Caching l3IfLd,
        Caching l1IfStAt, Caching l3IfStAt)
    {
        return isLoad ?
            std::make_pair(l1IfLd, l3IfLd) :
            std::make_pair(l1IfStAt, l3IfStAt);
    };

    // Decode caching field from in [19:17]
    uint32_t ccBits = (descBits >> 17) & 0x7;
    switch (ccBits) {
    case 0: return mk(
        Caching::DF, Caching::DF,
        Caching::DF, Caching::DF);
    case 1: return mk(
        Caching::UC, Caching::UC,
        Caching::UC, Caching::UC);
    case 2: return mk(
        Caching::UC, Caching::CA,
        Caching::UC, Caching::WB);
    case 3: return mk(
        Caching::CA, Caching::UC,
        Caching::WT, Caching::UC);
    case 4: return mk(
        Caching::CA, Caching::CA,
        Caching::WT, Caching::WB);
    case 5: return mk(
        Caching::ST, Caching::UC,
        Caching::ST, Caching::UC);
    case 6: return mk(
        Caching::ST, Caching::CA,
        Caching::ST, Caching::WB);
    case 7: return mk(
        Caching::RI, Caching::CA,
        Caching::WB, Caching::WB);
    }
    return std::make_pair(Caching::INVALID,Caching::INVALID);
}


std::pair<Caching,Caching> G4_SendDescRaw::getCaching() const {
    if (!isLscOp()) {
        return std::make_pair(Caching::INVALID, Caching::INVALID);
    }
    const auto opInfo = LscOpInfoGet(getLscOp());
    if (opInfo.isOther()) {
        return std::make_pair(Caching::INVALID, Caching::INVALID);
    }

    auto ccPair =
        decodeCaching3(opInfo.isLoad(), getDesc());
    MUST_BE_TRUE(
        ccPair.first != Caching::INVALID &&
        ccPair.second != Caching::INVALID,
        "unexpected invalid caching options (corrupt descriptor?)");
    return ccPair;
}


static LSC_CACHE_OPT toVisaCachingOpt(Caching c) {
    switch (c) {
    case Caching::DF: return LSC_CACHING_DEFAULT;
    case Caching::UC: return LSC_CACHING_UNCACHED;
    case Caching::CA: return LSC_CACHING_CACHED;
    case Caching::WB: return LSC_CACHING_WRITEBACK;
    case Caching::WT: return LSC_CACHING_WRITETHROUGH;
    case Caching::ST: return LSC_CACHING_STREAMING;
    case Caching::RI: return LSC_CACHING_READINVALIDATE;
    default:
        MUST_BE_TRUE(false, "invalid cache option");
        return (LSC_CACHE_OPT)-1;
    }
}

void G4_SendDescRaw::setCaching(Caching l1, Caching l3)
{
    if (!isLscOp()) {
        MUST_BE_TRUE(
            (l1 == Caching::INVALID && l3 == Caching::INVALID) ||
            (l1 == Caching::DF && l3 == Caching::DF),
            "invalid caching options for platform*SFID");
    }
    const auto opInfo = LscOpInfoGet(getLscOp());
    MUST_BE_TRUE(!opInfo.isOther(), "invalid LSC message kind for caching op");
    LSC_CACHE_OPTS visaCopts { };
    visaCopts.l1 = toVisaCachingOpt(l1);
    visaCopts.l3 = toVisaCachingOpt(l3);

    uint32_t cacheEnc = 0;
    uint32_t fieldMask = (0x7 << 17);
    bool isBits17_19 = true;
    bool success =
        LscTryEncodeCacheOpts(opInfo, visaCopts, cacheEnc, isBits17_19);
    MUST_BE_TRUE(success, "failed to set caching options");
    desc.value &= ~fieldMask;
    desc.value |= cacheEnc;
}

static bool isDc1OpTyped(uint32_t desc)
{
    uint32_t mty = (desc >> 14) & 0x1F;
    switch (mty) {
    case DC1_TYPED_SURFACE_WRITE:
    case DC1_TYPED_SURFACE_READ:
    case DC1_TYPED_ATOMIC:
    case DC1_TYPED_HALF_INTEGER_ATOMIC:
        return true;
    default:
        break;
    }
    return false;
}

bool G4_SendDescRaw::isTyped() const
{
    return getSFID() == SFID::DP_DC1 && isDc1OpTyped(getDesc());
}

