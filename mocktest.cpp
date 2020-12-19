// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include "mockssl.h"

#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>

extern "C"
PSecurityFunctionTableW SEC_ENTRY OchannelInitSecurityInterface();

using ::testing::_;
using ::testing::Return;
using ::testing::InSequence;

template<typename T>
class DummyPointer {
public:
    DummyPointer() {
        ptr = (T*)malloc(1);
    }
    ~DummyPointer() {
        free((void*)ptr);
    }
    operator T*() { return ptr; }

    T* ptr;
};

class Fixture : public ::testing::Test {
protected:
    PSecurityFunctionTableW funcTable;

    Fixture() {
        funcTable = OchannelInitSecurityInterface();
    }
};

TEST_F(Fixture, HelloWorld) {
    OpenSSLMock openssl;

    DummyPointer<SSL_METHOD> method;
    DummyPointer<SSL_CTX> ctx;
    {
        InSequence s;
        EXPECT_CALL(openssl, TLS_client_method()).WillOnce(Return(method.ptr));

        EXPECT_CALL(openssl, SSL_CTX_new(method.ptr)).WillOnce(Return(ctx.ptr));
        EXPECT_CALL(openssl, SSL_CTX_free(ctx.ptr));
    }

    CredHandle cred;
    funcTable->AcquireCredentialsHandleW(nullptr, nullptr, 0, nullptr, nullptr, nullptr, nullptr, &cred, nullptr);
    funcTable->FreeCredentialsHandle(&cred);
}
