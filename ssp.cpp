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
    return SEC_E_INTERNAL_ERROR;
}

SecurityFunctionTableW g_functionTable = {
    SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION, // dwVersion
    &myEnumerateSecurityPackagesW, // EnumerateSecurityPackagesW
    nullptr, // QueryCredentialsAttributesW
    &myAcquireCredentialsHandleW, // AcquireCredentialsHandleW
    nullptr, // FreeCredentialsHandle
    nullptr, // Reserved2
    nullptr, // InitializeSecurityContextW
    nullptr, // AcceptSecurityContext
    nullptr, // CompleteAuthToken
    nullptr, // DeleteSecurityContext
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
