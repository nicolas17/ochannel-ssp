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

#include <openssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>

void dumpBufferDesc(PSecBufferDesc desc) {
    static const char* typeMap[] = {
        "EMPTY", // 0
        "DATA", // 1
        "TOKEN", // 2
        "PKG_PARAMS", // 3
        "MISSING", // 4
        "EXTRA", // 5
        "STREAM_TRAILER", // 6
        "STREAM_HEADER", // 7
        "NEGOTIATION_INFO", // 8
        "PADDING", // 9
        "STREAM", // 10
        "MECHLIST", // 11
        "MECHLIST_SIGNATURE", // 12
        "TARGET", // 13
        "CHANNEL_BINDINGS", // 14
        "CHANGE_PASS_RESPONSE", // 15
        "TARGET_HOST", // 16
        "ALERT", // 17
        "APPLICATION_PROTOCOLS", // 18
        "SRTP_PROTECTION_PROFILES", // 19
        "SRTP_MASTER_KEY_IDENTIFIER", // 20
        "TOKEN_BINDING", // 21
        "PRESHARED_KEY", // 22
        "PRESHARED_KEY_IDENTITY", // 23
        "DTLS_MTU" // 24
    };
    if (!desc) {
        printf("BufferDesc* is null\n");
        return;
    }
    printf("BufferDesc with %d buffers\n", desc->cBuffers);
    for (int i = 0; i < desc->cBuffers; ++i) {
        const char* typeStr = "??";
        unsigned long typeNum = desc->pBuffers[i].BufferType;
        if (typeNum >= 0 && typeNum <= 24) {
            typeStr = typeMap[typeNum];
        }
        printf(" Buffer[%d]: type %s (%d), size %u\n", i, typeStr, typeNum, desc->pBuffers[i].cbBuffer);
    }
    printf("End BufferDesc\n");
}

// A note on memory allocation:
// If function A uses 'new Foo' and function B uses 'new Bar[42]',
// and SSPI says the results of both A and B are freed with FreeContextBuffer,
// there would be no implementation of FreeContextBuffer that would work
// in both cases (delete vs delete[]). Therefore we would need to use plain C
// malloc/free when FreeContextBuffer is involved.
//
// However, it looks like Windows's global FreeContextBuffer doesn't actually
// call the security package's funcTable->FreeContextBuffer, it just calls
// LocalFree(). In retrospect that makes sense, FreeContextBuffer doesn't have
// enough information to know what package it has to forward the call to.
//
// In the particular case of EnumerateSecurityPackages, Windows does call the
// package's funcTable->FreeContextBuffer to release the SecPkgInfo. For
// consistency, and in case future Windows versions ever do make FreeContextBuffer
// call the package's implementation, we have to use LocalAlloc instead of malloc.

extern "C"
SECURITY_STATUS SEC_ENTRY myEnumerateSecurityPackagesW(
    unsigned long *pcPackages,
    PSecPkgInfoW  *ppPackageInfo
) {
    printf("[testssp] EnumerateSecurityPackagesW called\n");
    *pcPackages = 1;

    SecPkgInfoW* packages = (SecPkgInfoW*)LocalAlloc(0, sizeof(SecPkgInfo) * 1);
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
    LocalFree(pvContextBuffer);
    return SEC_E_OK;
}

class SSPCredentials {
public:
    static const UINT32 MAGIC = 0x5cb2715c;

    SSPCredentials();
    ~SSPCredentials();
    CredHandle toHandle() const;
    static SSPCredentials* fromHandle(PCredHandle handle);

private:
    // non-copyable
    SSPCredentials(const SSPCredentials&) = delete;
    SSPCredentials& operator=(const SSPCredentials&) = delete;

    SSL_CTX* m_ssl_ctx;
    friend class SSPContext;
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
    m_ssl_ctx = SSL_CTX_new(TLS_client_method());
}
SSPCredentials::~SSPCredentials() {
    SSL_CTX_free(m_ssl_ctx);
}

class SSPContext {
public:
    static const UINT32 MAGIC = 0xbe80c313;

    SSPContext(SSPCredentials* cred);
    ~SSPContext();
    bool do_connect();

    CtxtHandle toHandle() const;
    static SSPContext* fromHandle(PCtxtHandle handle);

//private:
    // non-copyable
    SSPContext(const SSPContext&) = delete;
    SSPContext& operator=(const SSPContext&) = delete;

    SSL* m_ssl;
    BIO* m_internal_bio = nullptr;
    BIO* m_network_bio = nullptr;
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
SSPContext::SSPContext(SSPCredentials* cred) {
    m_ssl = SSL_new(cred->m_ssl_ctx);

    BIO_new_bio_pair(&m_internal_bio, 0, &m_network_bio, 0);
    // SSL_set0_[rw]bio take ownership of the passed reference,
    // so if we call both with the same BIO, we need the refcount to be 2.
    BIO_up_ref(m_internal_bio);
    SSL_set0_rbio(m_ssl, m_internal_bio);
    SSL_set0_wbio(m_ssl, m_internal_bio);

    SSL_set_connect_state(m_ssl);
}
SSPContext::~SSPContext() {
    BIO_free(m_network_bio);
    // we don't need to free m_internal_bio because it's owned by m_ssl

    SSL_free(m_ssl);
}
// returns true when handshake is finished
bool SSPContext::do_connect()
{
    int retval;
    retval = SSL_connect(m_ssl);
    printf("SSL_connect returned %d\n", retval);
    if (retval <= 0) {
        printf("Error code is %d\n", SSL_get_error(m_ssl, retval));
    }
    printf("OpenSSL input (internal) buffer has %d bytes left\n", BIO_pending(m_internal_bio));
    printf("OpenSSL output (network) buffer has %d bytes left\n", BIO_pending(m_network_bio));
    return (retval == 1);
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
    printf("[testssp] InitializeSecurityContext credential '%p' (%p) pcontext '%p' target name '%ls' contextReq 0x%x targetdatarep %u pnewcontext %p, pContextAttr %p pexpiry %p\n",
        phCredential, phCredential ? phCredential->dwUpper : 0, phContext, pszTargetName, fContextReq, TargetDataRep, phNewContext, pfContextAttr, ptsExpiry);
    printf("pInput: ");
    dumpBufferDesc(pInput);
    printf("pOutput: ");
    dumpBufferDesc(pOutput);

    SSPContext* ctx = nullptr;
    if (phContext) {
        // this is a non-first call, so we reuse the context the client passed back to us
        ctx = SSPContext::fromHandle(phContext);
        if (!ctx) return SEC_E_INVALID_HANDLE;
    } else {
        // this is the first call, so we create a new context
        SSPCredentials* cred = SSPCredentials::fromHandle(phCredential);
        if (!cred) return SEC_E_INVALID_HANDLE;
        ctx = new SSPContext(cred);
    }

    // if we received some input, give it to OpenSSL.
    // TODO we're assuming it's the *first* buffer if present,
    // we should probably search by type instead.
    if (pInput && pInput->cBuffers > 1 && pInput->pBuffers[0].BufferType == SECBUFFER_TOKEN) {
        printf("We got some input, writing it to the OpenSSL BIO\n");
        BIO_write(ctx->m_network_bio, pInput->pBuffers[0].pvBuffer, pInput->pBuffers[0].cbBuffer);
    }

    bool handshakeFinished = ctx->do_connect();

    printf("Output buffer type %d len %d\n", pOutput->pBuffers[0].BufferType, pOutput->pBuffers[0].cbBuffer);
    if ((fContextReq & ISC_REQ_ALLOCATE_MEMORY) == 0) {
        // client-provided buffers not supported yet
        return SEC_E_NOT_SUPPORTED;
    }
    int size = BIO_pending(ctx->m_network_bio);

    pOutput->pBuffers[0].BufferType = SECBUFFER_TOKEN;
    if (size) {
        printf("There's data to send, returning it in an output buffer\n");
        char* data = (char*)LocalAlloc(0, size);
        BIO_read(ctx->m_network_bio, data, size);
        pOutput->pBuffers[0].cbBuffer = size;
        pOutput->pBuffers[0].pvBuffer = data;
    }
    if (!phContext) {
        // if this is the first call, return the new token
        if (!phNewContext) return SEC_E_INVALID_HANDLE;
        *phNewContext = ctx->toHandle();
    }
    if (handshakeFinished) {
        printf("Handshake finished, returning OK\n");
        return SEC_E_OK;
    } else {
        printf("Handshake didn't finish, returning CONTINUE_NEEDED\n");
        return SEC_I_CONTINUE_NEEDED;
    }
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
