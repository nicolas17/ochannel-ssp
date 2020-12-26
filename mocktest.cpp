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

TEST_F(Fixture, CredentialsHandleCreate) {
    OpenSSLMock openssl;

    SSL_CTX* ctx;
    EXPECT_CALL(openssl, SSL_CTX_new(_)).WillOnce([&](auto meth) { return ctx = new ssl_ctx_st(meth); });

    CredHandle cred;
    funcTable->AcquireCredentialsHandleW(nullptr, nullptr, 0, nullptr, nullptr, nullptr, nullptr, &cred, nullptr);

    EXPECT_CALL(openssl, SSL_CTX_free(ctx));
    funcTable->FreeCredentialsHandle(&cred);
}

std::ostream& operator<<(std::ostream& os, const SecBuffer& buf) {
    if (buf.pvBuffer == nullptr) {
        return os << "[null buffer]";
    } else {
        return os << "SecBuffer len " << buf.cbBuffer << " content '" << std::string((const char*)buf.pvBuffer, buf.cbBuffer) << "'";
    }
}

bool operator==(const SecBuffer& buf, const std::string& s) {
    return buf.pvBuffer != nullptr && std::string((const char*)buf.pvBuffer, buf.cbBuffer) == s;
}

TEST_F(Fixture, InitContext) {
    OpenSSLMock openssl;

    SSL_CTX* ctx;
    EXPECT_CALL(openssl, SSL_CTX_new(_)).WillOnce([&](auto meth) { return ctx = new ssl_ctx_st(meth); });

    CredHandle sspCred;
    funcTable->AcquireCredentialsHandleW(nullptr, nullptr, 0, nullptr, nullptr, nullptr, nullptr, &sspCred, nullptr);

    CtxtHandle sspCtx{};
    SecBufferDesc outputBufs{};
    SSL sslObject(ctx);
    EXPECT_CALL(openssl, SSL_new(_)).WillOnce(Return(&sslObject));
    EXPECT_CALL(sslObject, connect()).WillOnce([&] {
        sslObject.wbio->writestr("[starthandshake]");
        return -1;
    });

    SecBuffer outputBuf{};
    outputBufs.ulVersion = SECBUFFER_VERSION;
    outputBufs.cBuffers = 1;
    outputBufs.pBuffers = &outputBuf;

    unsigned long contextAttr;
    int retval = funcTable->InitializeSecurityContextW(
        &sspCred,   // phCredential
        nullptr,    // phContext
        nullptr,    // pszTargetName
        ISC_REQ_ALLOCATE_MEMORY, // fContextReq
        0,          // Reserved1
        0,          // TargetDataRep
        nullptr,    // pInput
        0,          // Reserved2
        &sspCtx,    // phNewContext
        &outputBufs,// pOutput
        &contextAttr, // pfContextAttr
        nullptr     // ptsExpiry
    );
    EXPECT_EQ(outputBufs.pBuffers[0], "[starthandshake]");

    EXPECT_CALL(openssl, SSL_free(&sslObject));
    funcTable->DeleteSecurityContext(&sspCtx);

    EXPECT_CALL(openssl, SSL_CTX_free(ctx));
    funcTable->FreeCredentialsHandle(&sspCred);
}
