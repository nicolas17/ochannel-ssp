// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include "mockssl.h"

using ::testing::_;
using ::testing::Return;
using ::testing::InSequence;

void some_wrapper()
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_free(ctx);
}

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

TEST(BasicTest, HelloWorld) {
    OpenSSLMock openssl;

    DummyPointer<SSL_METHOD> method;
    DummyPointer<SSL_CTX> ctx;
    {
        InSequence s;
        EXPECT_CALL(openssl, TLS_client_method()).WillOnce(Return(method.ptr));

        EXPECT_CALL(openssl, SSL_CTX_new(method.ptr)).WillOnce(Return(ctx.ptr));
        EXPECT_CALL(openssl, SSL_CTX_free(ctx.ptr));
    }

    some_wrapper();
}
