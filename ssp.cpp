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

extern "C"
PSecurityFunctionTableW SEC_ENTRY InitSecurityInterfaceW() {
    printf("InitSecurityInterface called in testssp\n");
    return NULL;
}
