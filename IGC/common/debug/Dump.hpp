/*========================== begin_copyright_notice ============================

Copyright (C) 2017-2021 Intel Corporation

SPDX-License-Identifier: MIT

============================= end_copyright_notice ===========================*/

#pragma once

#include "common/Types.hpp"

#include "AdaptorCommon/customApi.hpp"
#include "Compiler/CodeGenPublicEnums.h"

#include <iStdLib/utility.h>

#include "common/LLVMWarningsPush.hpp"
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/Module.h>
#include <llvm/ADT/Optional.h>
#include <llvm/Pass.h>
#include "common/LLVMWarningsPop.hpp"
#include "AdaptorCommon/API/igc.h"

#include <string>
#include <vector>
#include <stdarg.h>
#include <mutex>

// Forward declarations
struct D3D10DDIARG_SIGNATURE_ENTRY;
struct D3D10DDIARG_STAGE_IO_SIGNATURES;
struct D3D11DDIARG_TESSELLATION_IO_SIGNATURES;
namespace IGC { class CodeGenContext; }

namespace USC
{
    struct ShaderD3D;
    struct SPixelShaderNOS;
    struct SVertexShaderNOS;
}

namespace IGC
{
class CShader;
namespace Debug
{
const char* GetShaderTypeAcronym(ShaderType shaderType);

/*************************************************************************************************\
 *  Generic
 */

class DumpName
{
public:
    explicit DumpName(std::string const& dumpName);
    DumpName();

    //Needs to be static so that all objects of the class share it and public so that all derived classes have access to it.
    static std::mutex hashMapLock;
    static unsigned int shaderNum;

    DumpName ShaderName(std::string const& name) const;
    DumpName Type(ShaderType type) const;
    DumpName Extension(std::string const& extension) const;
    DumpName StagedInfo(void const* context) const;
    DumpName SIMDSize(SIMDMode width) const;
    DumpName DispatchMode(ShaderDispatchMode mode) const;
    DumpName Hash(ShaderHash hash) const;
    DumpName PostFix(std::string const& postfixStr) const;
    DumpName Pass(std::string const& name, llvm::Optional<uint32_t> index = llvm::Optional<uint32_t>()) const;
    DumpName PSPhase(PixelShaderPhaseType phase) const;
    DumpName Retry(unsigned retryId) const;
    std::string str() const;
    std::string overridePath() const;
    std::string RelativePath() const;
    std::string AbsolutePath(OutputFolderName folder) const;
    std::string GetKernelName() const;
    bool allow() const;

private:
    class CPassDescriptor
    {
    public:
        std::string               m_name;
        llvm::Optional<unsigned int>    m_index;
    };

    llvm::Optional<std::string>         m_dumpName;
    llvm::Optional<std::string>         m_shaderName;
    llvm::Optional<ShaderType>          m_type;
    llvm::Optional<PixelShaderPhaseType> m_psPhase;
    llvm::Optional<std::string>         m_extension;
    llvm::Optional<SIMDMode>            m_simdWidth;
    llvm::Optional<CG_FLAG_t>           m_cgFlag;
    llvm::Optional<ShaderDispatchMode>  m_ShaderMode;
    llvm::Optional<ShaderHash>          m_hash;
    llvm::Optional<std::string>         m_postfixStr;
    llvm::Optional<CPassDescriptor>     m_pass;
    llvm::Optional<unsigned>            m_retryId;
};

/// return the name of the file to dump
std::string GetDumpName(const CShader* pProgram, const char* ext);

/// return the name of the file to dump
DumpName GetDumpNameObj(const CShader* pProgram, const char* ext);

/// return the name of the file to dump for llvm IR
DumpName GetLLDumpName(IGC::CodeGenContext* pContext, const char* dumpName);

class Dump
{
public:
    Dump( DumpName const& dumpName, DumpType type );
    virtual ~Dump();

    llvm::raw_ostream& stream() const;

    void flush();

    template<typename T>
    llvm::raw_ostream& operator<< ( T const& val ) const
    {
        stream() << val;
        return stream();
    }

private:
    std::string                        m_string;
    const DumpName                     m_name;
    std::unique_ptr<llvm::raw_ostream> m_pStream;
    llvm::raw_ostream*                 m_pStringStream;
    const DumpType                     m_type;
    bool                               m_ClearFile;
};

// Common implementation of the flush pass
template<typename PassT>
class CommonFlushDumpPass : public PassT
{
public:

    CommonFlushDumpPass(Dump& dump, char& pid) : PassT(pid), m_Dump(dump) {}

    void getAnalysisUsage(llvm::AnalysisUsage& AU) const override
    {
        AU.setPreservesAll();
    }

    llvm::StringRef getPassName() const override
    {
        return "Flush Dump";
    }

protected:
    Dump& m_Dump;
};

class ModuleFlushDumpPass : public CommonFlushDumpPass<llvm::ModulePass>
{
public:
    static char ID;

    ModuleFlushDumpPass(Dump& dump) : CommonFlushDumpPass(dump, ID) {}

    bool runOnModule(llvm::Module&) override
    {
        m_Dump.flush();
        return false;
    }
};

class FunctionFlushDumpPass : public CommonFlushDumpPass<llvm::FunctionPass>
{
public:
    static char ID;

    FunctionFlushDumpPass(Dump& dump) : CommonFlushDumpPass(dump, ID) {}

    bool runOnFunction(llvm::Function&) override
    {
        m_Dump.flush();
        return false;
    }
};

void DumpLLVMIRText(
    llvm::Module*             pModule,
    const DumpName&           dumpName,
    llvm::AssemblyAnnotationWriter*  optionalAnnotationWriter = nullptr);

int PrintDebugMsgV(
    const Dump* dump,
    const char* fmt,
    va_list ap);

void PrintDebugMsg(
    const Dump* dump,
    const char* fmt,
    ...);


inline FILE* OpenDumpFile(
    const char* fileNamePrefix,
    const char* fileNameExt,
    const ShaderHash& hash,
    const char* flag)
{
    std::string name =
        IGC::Debug::DumpName(fileNamePrefix)
        .Hash(hash)
        .Extension(fileNameExt)
        .str();
    FILE* fp = fopen(name.c_str(), flag);
    return fp;
}

ShaderHash ShaderHashOCL(const UINT* pShaderCode, size_t size);

ShaderHash ShaderHashOGL(QWORD glslHash, QWORD nosHash);

} // namespace Debug
} // namespace IGC
