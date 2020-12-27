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

class FixtureWithCredHandle : public Fixture {
protected:
    OpenSSLMock openssl;
    SSL_CTX* opensslCtx;
    CredHandle sspCred;

    void SetUp() {
        EXPECT_CALL(openssl, SSL_CTX_new(_)).WillOnce([&](auto meth) { return opensslCtx = new ssl_ctx_st(meth); });
        funcTable->AcquireCredentialsHandleW(nullptr, nullptr, 0, nullptr, nullptr, nullptr, nullptr, &sspCred, nullptr);
    }
    void TearDown() {
        EXPECT_CALL(openssl, SSL_CTX_free(opensslCtx));
        funcTable->FreeCredentialsHandle(&sspCred);
    }
};

TEST_F(FixtureWithCredHandle, InitContext) {

    CtxtHandle sspCtx{};
    SSL sslObject(opensslCtx);
    EXPECT_CALL(openssl, SSL_new(_)).WillOnce(Return(&sslObject));
    EXPECT_CALL(sslObject, connect()).WillOnce([&] {
        sslObject.wbio->writestr("[ClientHello]");
        sslObject.last_error = SSL_ERROR_WANT_READ;
        return -1;
    });

    SecBufferDesc outputBufs{};
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
    ASSERT_EQ(outputBufs.pBuffers[0], "[ClientHello]");
    ASSERT_EQ(retval, SEC_I_CONTINUE_NEEDED);
    funcTable->FreeContextBuffer(outputBufs.pBuffers[0].pvBuffer);
    outputBufs.pBuffers[0].pvBuffer = nullptr;

    SecBufferDesc inputBufs{};
    SecBuffer inputBuf[2]{};
    inputBufs.ulVersion = SECBUFFER_VERSION;
    inputBufs.cBuffers = 2;
    inputBufs.pBuffers = &inputBuf[0];
    inputBuf[0].BufferType = SECBUFFER_TOKEN;
    inputBuf[0].cbBuffer = 13;
    inputBuf[0].pvBuffer = "[ServerHello]";
    inputBuf[1].BufferType = SECBUFFER_EMPTY;

    std::string tmpstr;
    EXPECT_CALL(sslObject, connect()).WillOnce([&] {
        tmpstr = sslObject.rbio->readstr();
        sslObject.wbio->writestr("[ClientKeyExchange]");
        sslObject.last_error = SSL_ERROR_WANT_READ;
        return -1;
    });
    retval = funcTable->InitializeSecurityContextW(
        &sspCred,   // phCredential
        &sspCtx,    // phContext
        nullptr,    // pszTargetName
        ISC_REQ_ALLOCATE_MEMORY, // fContextReq
        0,          // Reserved1
        0,          // TargetDataRep
        &inputBufs, // pInput
        0,          // Reserved2
        nullptr,    // phNewContext
        &outputBufs,// pOutput
        &contextAttr, // pfContextAttr
        nullptr     // ptsExpiry
    );
    ASSERT_EQ(tmpstr, "[ServerHello]");
    ASSERT_EQ(outputBufs.pBuffers[0], "[ClientKeyExchange]");
    ASSERT_EQ(retval, SEC_I_CONTINUE_NEEDED);

    EXPECT_CALL(openssl, SSL_free(&sslObject));
    funcTable->DeleteSecurityContext(&sspCtx);
}
