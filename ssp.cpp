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

#include "context_types.h"

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
    for (unsigned long i = 0; i < desc->cBuffers; ++i) {
        const char* typeStr = "??";
        unsigned long typeNum = desc->pBuffers[i].BufferType;
        if (typeNum >= 0 && typeNum <= 24) {
            typeStr = typeMap[typeNum];
        }
        printf(" Buffer[%u]: type %s (%d), size %u\n", i, typeStr, typeNum, desc->pBuffers[i].cbBuffer);
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
    *phCredential = toSecHandle(cred);

    return SEC_E_OK;
}

extern "C"
SECURITY_STATUS SEC_ENTRY myFreeCredentialsHandle(PCredHandle phCredential)
{
    printf("[testssp] FreeCredentialsHandle(%p)\n", phCredential);
    auto* cred = fromSecHandle<SSPCredentials>(phCredential);
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

    // if we get a context requirement we don't support, bail out.
    // instead of listing what we don't support, we list what we do support
    // and fail if there is any flag outside of that
    if (fContextReq & ~(ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_CONFIDENTIALITY | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT)) {
        printf("Request had an unsupported context requirement\n");
        return SEC_E_NOT_SUPPORTED;
    }

    SSPContext* ctx = nullptr;
    if (phContext) {
        // this is a non-first call, so we reuse the context the client passed back to us
        ctx = fromSecHandle<SSPContext>(phContext);
        if (!ctx) return SEC_E_INVALID_HANDLE;
    } else {
        // this is the first call, so we create a new context
        SSPCredentials* cred = fromSecHandle<SSPCredentials>(phCredential);
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
    // allocated memory? yeah we can do that
    *pfContextAttr |= ISC_RET_ALLOCATED_MEMORY;

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
        *phNewContext = toSecHandle(ctx);
    }
    if (handshakeFinished) {
        printf("Handshake finished, returning OK\n");
        *pfContextAttr |= (ISC_RET_STREAM | ISC_RET_CONFIDENTIALITY | ISC_RET_REPLAY_DETECT | ISC_RET_SEQUENCE_DETECT);
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
    auto* ctx = fromSecHandle<SSPContext>(phContext);
    if (ctx) {
        delete ctx;
        return SEC_E_OK;
    }
    else {
        return SEC_E_INVALID_HANDLE;
    }
}

extern "C"
SECURITY_STATUS SEC_ENTRY myQueryContextAttributes(
    _In_  PCtxtHandle   phContext,
    _In_  unsigned long ulAttribute,
    _Out_ void*         pBuffer
) {
    printf("We're being asked for context attribute #%u\n", ulAttribute);
    if (ulAttribute == SECPKG_ATTR_STREAM_SIZES) {
        auto* sizes = static_cast<SecPkgContext_StreamSizes*>(pBuffer);
        sizes->cbHeader = 5;
        sizes->cbMaximumMessage = 16384;
        // The standards give a maximum encryption overhead of 1024 bytes.
        // A comment in OpenSSL says "In practice the value is lower than this.
        // The overhead is the maximum number of padding bytes(256) plus the MAC size."
        // But we'll stick to 1024 to be sure for now.
        sizes->cbTrailer = 1024;
        sizes->cbBlockSize = 16;
        sizes->cBuffers = 4;
        return SEC_E_OK;
    } else {
        return SEC_E_NOT_SUPPORTED;
    }
}

extern "C"
SECURITY_STATUS SEC_ENTRY myEncryptMessage(
    _In_    PCtxtHandle         phContext,
    _In_    unsigned long       fQOP,
    _In_    PSecBufferDesc      pMessage,
    _In_    unsigned long       MessageSeqNo
) {
    auto* ctx = fromSecHandle<SSPContext>(phContext);
    if (!ctx) {
        return SEC_E_INVALID_HANDLE;
    }

    if (fQOP != 0) {
        return SEC_E_NOT_SUPPORTED;
    }

    printf("EncryptMessage called\n");
    dumpBufferDesc(pMessage);

    int retval = SSL_write(ctx->m_ssl, pMessage->pBuffers[1].pvBuffer, pMessage->pBuffers[1].cbBuffer);
    printf("SSL_write returned %d\n", retval);
    int pending = BIO_pending(ctx->m_network_bio);
    printf("and wrote %d bytes to the output BIO\n", pending);

    // we can't *really* rely on the buffers being contiguous
    if (pending <= 5) { return SEC_E_INTERNAL_ERROR; }
    retval = BIO_read(ctx->m_network_bio, pMessage->pBuffers[0].pvBuffer, pMessage->pBuffers[0].cbBuffer);
    printf("Read %d bytes into header buffer\n", retval);
    retval = BIO_read(ctx->m_network_bio, pMessage->pBuffers[1].pvBuffer, pMessage->pBuffers[1].cbBuffer);
    printf("Read %d bytes into data buffer\n", retval);
    if (retval < pMessage->pBuffers[1].cbBuffer) {
        printf("Adjusting size of data buffer\n");
        pMessage->pBuffers[1].cbBuffer = retval;
    }
    retval = BIO_read(ctx->m_network_bio, pMessage->pBuffers[2].pvBuffer, pMessage->pBuffers[2].cbBuffer);
    printf("Read %d bytes into trailer buffer\n", retval);
    if (retval < pMessage->pBuffers[2].cbBuffer) {
        printf("Adjusting size of trailer buffer\n");
        pMessage->pBuffers[2].cbBuffer = retval;
    }

    return SEC_E_OK;
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
    &myQueryContextAttributes, // QueryContextAttributesW
    nullptr, // ImpersonateSecurityContext
    nullptr, // RevertSecurityContext
    nullptr, // MakeSignature
    nullptr, // VerifySignature
    &myFreeContextBuffer, // FreeContextBuffer
    nullptr, // QuerySecurityPackageInfoW
    &myEncryptMessage, // Reserved3, but actually EncryptMessage calls this
    nullptr, // Reserved4
    nullptr, // ExportSecurityContext
    nullptr, // ImportSecurityContextW
    nullptr, // AddCredentialsW
    nullptr, // Reserved8
    nullptr, // QuerySecurityContextToken
    &myEncryptMessage, // EncryptMessage
    nullptr  // DecryptMessage
};

extern "C"
PSecurityFunctionTableW SEC_ENTRY InitSecurityInterfaceW() {
    printf("[testssp] InitSecurityInterface called\n");
    return &g_functionTable;
}
