// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN 1

// apparently we need this if we're implementing an SSP
// to stop the functions from being declared dllimport
#define _NO_KSECDD_IMPORT_

#include <windows.h>
#include <security.h>

#include <stdio.h>
#include <stdlib.h>

extern "C"
SECURITY_STATUS SEC_ENTRY myEnumerateSecurityPackagesW(
    unsigned long *pcPackages,
    PSecPkgInfoW  *ppPackageInfo
) {
    printf("[testssp] EnumerateSecurityPackagesW called\n");
    *pcPackages = 1;

    // If function A uses 'new Foo' and function B uses 'new Bar[42]',
    // and SSPI says the results of both A and B can be freed with FreeContextBuffer,
    // there would be no implementation of FreeContextBuffer that would work
    // in both cases (delete vs delete[]). Therefore we need to use plain C
    // malloc/free when FreeContextBuffer is involved.
    SecPkgInfoW* packages = (SecPkgInfoW*)malloc(sizeof(SecPkgInfo) * 1);
    packages[0].fCapabilities = SECPKG_FLAG_PRIVACY | SECPKG_FLAG_CLIENT_ONLY | SECPKG_FLAG_STREAM;
    packages[0].wVersion = 1;
    packages[0].wRPCID = SECPKG_ID_NONE;
    packages[0].cbMaxToken = 16384; // ??
    // make it easy to hex edit an executable to use this instead of Microsoft's
    packages[0].Name = L"Mycrosoft Unified Security Protocol Provider";
    packages[0].Comment = L"Doesn't work yet";
    *ppPackageInfo = packages;

    return SEC_E_OK;
}

extern "C"
SECURITY_STATUS SEC_ENTRY myFreeContextBuffer(PVOID pvContextBuffer)
{
    printf("[testssp] FreeContextBuffer(%p)\n", pvContextBuffer);
    free(pvContextBuffer);
    return SEC_E_OK;
}

class SSPCredentials {
public:
    static const UINT32 MAGIC = 0x5cb2715c;

    SSPCredentials();
    CredHandle toHandle() const;
    static SSPCredentials* fromHandle(PCredHandle handle);

private:
    // non-copyable
    SSPCredentials(const SSPCredentials&) = delete;
    SSPCredentials& operator=(const SSPCredentials&) = delete;
};
CredHandle SSPCredentials::toHandle() const {
    return { MAGIC, reinterpret_cast<UINT_PTR>(this) };
}
SSPCredentials* SSPCredentials::fromHandle(PCredHandle handle) {
    if (handle->dwLower == MAGIC) {
        return reinterpret_cast<SSPCredentials*>(handle->dwUpper);
    } else {
        return nullptr;
    }
}
SSPCredentials::SSPCredentials() {
    ;
}

class SSPContext {
public:
    static const UINT32 MAGIC = 0xbe80c313;

    SSPContext();
    CtxtHandle toHandle() const;
    static SSPContext* fromHandle(PCtxtHandle handle);

private:
    // non-copyable
    SSPContext(const SSPContext&) = delete;
    SSPContext& operator=(const SSPContext&) = delete;
};
CtxtHandle SSPContext::toHandle() const {
    return { MAGIC, reinterpret_cast<UINT_PTR>(this) };
}
SSPContext* SSPContext::fromHandle(PCtxtHandle handle) {
    if (handle->dwLower == MAGIC) {
        return reinterpret_cast<SSPContext*>(handle->dwUpper);
    } else {
        return nullptr;
    }
}
SSPContext::SSPContext() {
    ;
}

extern "C"
SECURITY_STATUS SEC_ENTRY myAcquireCredentialsHandleW(
    _In_opt_  SEC_WCHAR*     pszPrincipal,
    _In_      SEC_WCHAR*     pszPackage,
    _In_      unsigned long  fCredentialUse,
    _In_opt_  void*          pvLogonID,
    _In_opt_  void*          pAuthData,
    _In_opt_  SEC_GET_KEY_FN pGetKeyFn,
    _In_opt_  void*          pvGetKeyArgument,
    _Out_     PCredHandle    phCredential,
    _Out_opt_ PTimeStamp     ptsExpiry
) {
    printf("principal '%ls' package '%ls' credentialuse %lu logonid %p authdata %p getkeyfn %p getkeyarg %p pcredential %p pexpiry %p\n", pszPrincipal, pszPackage, fCredentialUse, pvLogonID, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
    SSPCredentials* cred = new SSPCredentials();
    *phCredential = cred->toHandle();

    return SEC_E_OK;
}

extern "C"
SECURITY_STATUS SEC_ENTRY myFreeCredentialsHandle(PCredHandle phCredential)
{
    printf("[testssp] FreeCredentialsHandle(%p)\n", phCredential);
    auto* cred = SSPCredentials::fromHandle(phCredential);
    if (cred) {
        delete cred;
        return SEC_E_OK;
    } else {
        return SEC_E_INVALID_HANDLE;
    }
}

extern "C"
SECURITY_STATUS SEC_ENTRY myInitializeSecurityContextW(
    _In_opt_    PCredHandle    phCredential,
    _In_opt_    PCtxtHandle    phContext,
    _In_opt_    SEC_WCHAR*     pszTargetName,
    _In_        unsigned long  fContextReq,
    _In_        unsigned long  Reserved1,
    _In_        unsigned long  TargetDataRep,
    _In_opt_    PSecBufferDesc pInput,
    _In_        unsigned long  Reserved2,
    _Inout_opt_ PCtxtHandle    phNewContext,
    _Inout_opt_ PSecBufferDesc pOutput,
    _Out_       unsigned long* pfContextAttr,
    _Out_opt_   PTimeStamp     ptsExpiry
) {
    printf("[testssp] InitializeSecurityContext credential '%p' (%p) pcontext '%p' target name '%ls' contextReq 0x%x targetdatarep %u pInput (%d buffers), pnewcontext %p, pOutput (%d buffers), pContextAttr %p pexpiry %p\n",
        phCredential, phCredential ? phCredential->dwUpper : 0, phContext, pszTargetName, fContextReq, TargetDataRep, pInput->cBuffers, phNewContext, pOutput->cBuffers, pfContextAttr, ptsExpiry);
    if (!phContext) {
        SSPContext* ctx = new SSPContext();
        *phNewContext = ctx->toHandle();
        return SEC_E_OK;
    }
    return SEC_E_INTERNAL_ERROR;
}

extern "C"
SECURITY_STATUS SEC_ENTRY myDeleteSecurityContext(
    PCtxtHandle phContext
) {
    printf("[testssp] DeleteSecurityContext(%p)\n", phContext);
    auto* ctx = SSPContext::fromHandle(phContext);
    if (ctx) {
        delete ctx;
        return SEC_E_OK;
    }
    else {
        return SEC_E_INVALID_HANDLE;
    }
}


SecurityFunctionTableW g_functionTable = {
    SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION, // dwVersion
    &myEnumerateSecurityPackagesW, // EnumerateSecurityPackagesW
    nullptr, // QueryCredentialsAttributesW
    &myAcquireCredentialsHandleW, // AcquireCredentialsHandleW
    &myFreeCredentialsHandle, // FreeCredentialsHandle
    nullptr, // Reserved2
    &myInitializeSecurityContextW, // InitializeSecurityContextW
    nullptr, // AcceptSecurityContext
    nullptr, // CompleteAuthToken
    &myDeleteSecurityContext, // DeleteSecurityContext
    nullptr, // ApplyControlToken
    nullptr, // QueryContextAttributesW
    nullptr, // ImpersonateSecurityContext
    nullptr, // RevertSecurityContext
    nullptr, // MakeSignature
    nullptr, // VerifySignature
    &myFreeContextBuffer, // FreeContextBuffer
    nullptr, // QuerySecurityPackageInfoW
    nullptr, // Reserved3
    nullptr, // Reserved4
    nullptr, // ExportSecurityContext
    nullptr, // ImportSecurityContextW
    nullptr, // AddCredentialsW
    nullptr, // Reserved8
    nullptr, // QuerySecurityContextToken
    nullptr, // EncryptMessage
    nullptr  // DecryptMessage
};

extern "C"
PSecurityFunctionTableW SEC_ENTRY InitSecurityInterfaceW() {
    printf("[testssp] InitSecurityInterface called\n");
    return &g_functionTable;
}
