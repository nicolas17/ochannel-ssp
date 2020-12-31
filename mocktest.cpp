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

// usually called with a string literal; be careful not to use it as an output buffer
// since literals are const
void initSecBufferLiteral(SecBuffer* buf, int type, const char* s) {
    buf->BufferType = type;
    buf->cbBuffer = strlen(s);
    buf->pvBuffer = (void*)s;
}
void initSecBuffer(SecBuffer* buf, int type, char* s, size_t len) {
    buf->BufferType = type;
    buf->cbBuffer = len;
    buf->pvBuffer = s;
}
void initSecBufferDesc(SecBufferDesc* desc, SecBuffer* bufArray, size_t count) {
    desc->ulVersion = SECBUFFER_VERSION;
    desc->cBuffers = count;
    desc->pBuffers = bufArray;
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

    SecBufferDesc outputBufDesc{};
    SecBuffer outputBuf{};
    initSecBufferDesc(&outputBufDesc, &outputBuf, 1);

    const unsigned long REQ_FLAGS = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
    const unsigned long RET_FLAGS = ISC_RET_SEQUENCE_DETECT | ISC_RET_REPLAY_DETECT | ISC_RET_CONFIDENTIALITY | ISC_RET_ALLOCATED_MEMORY | ISC_RET_STREAM;
    unsigned long contextAttr;

    // first call, creates context and returns first output buffer
    EXPECT_CALL(sslObject, connect()).WillOnce([&] {
        sslObject.wbio->writestr("[ClientHello]");
        sslObject.last_error = SSL_ERROR_WANT_READ;
        return -1;
    });
    int retval = funcTable->InitializeSecurityContextW(
        &sspCred,       // phCredential
        nullptr,        // phContext
        nullptr,        // pszTargetName
        REQ_FLAGS,      // fContextReq
        0,              // Reserved1
        0,              // TargetDataRep
        nullptr,        // pInput
        0,              // Reserved2
        &sspCtx,        // phNewContext
        &outputBufDesc, // pOutput
        &contextAttr,   // pfContextAttr
        nullptr         // ptsExpiry
    );
    ASSERT_EQ(outputBuf, "[ClientHello]");
    ASSERT_EQ(outputBuf.BufferType, SECBUFFER_TOKEN);
    ASSERT_EQ(retval, SEC_I_CONTINUE_NEEDED);
    funcTable->FreeContextBuffer(outputBuf.pvBuffer);
    outputBuf.pvBuffer = nullptr;

    SecBufferDesc inputBufDesc{};
    SecBuffer inputBuf[2]{};
    initSecBufferDesc(&inputBufDesc, inputBuf, 2);

    initSecBufferLiteral(&inputBuf[0], SECBUFFER_TOKEN, "[ServerHello]");
    initSecBuffer       (&inputBuf[1], SECBUFFER_EMPTY, nullptr, 0);
    initSecBufferDesc(&inputBufDesc, inputBuf, 2);

    // second call, we give it the existing context and the input buffer
    std::string tmpstr;
    EXPECT_CALL(sslObject, connect()).WillOnce([&] {
        tmpstr = sslObject.rbio->readstr();
        sslObject.wbio->writestr("[ClientKeyExchange]");
        sslObject.last_error = SSL_ERROR_WANT_READ;
        return -1;
    });
    retval = funcTable->InitializeSecurityContextW(
        &sspCred,       // phCredential
        &sspCtx,        // phContext
        nullptr,        // pszTargetName
        REQ_FLAGS,      // fContextReq
        0,              // Reserved1
        0,              // TargetDataRep
        &inputBufDesc,  // pInput
        0,              // Reserved2
        nullptr,        // phNewContext
        &outputBufDesc, // pOutput
        &contextAttr,   // pfContextAttr
        nullptr         // ptsExpiry
    );
    ASSERT_EQ(tmpstr, "[ServerHello]");
    ASSERT_EQ(outputBuf, "[ClientKeyExchange]");
    ASSERT_EQ(retval, SEC_I_CONTINUE_NEEDED);

    // final call, handshake complete
    initSecBufferLiteral(&inputBuf[0], SECBUFFER_TOKEN, "[Finished]");

    EXPECT_CALL(sslObject, connect()).WillOnce([&] {
        tmpstr = sslObject.rbio->readstr();
        sslObject.last_error = 0;
        return 1;
    });
    retval = funcTable->InitializeSecurityContextW(
        &sspCred,       // phCredential
        &sspCtx,        // phContext
        nullptr,        // pszTargetName
        REQ_FLAGS,      // fContextReq
        0,              // Reserved1
        0,              // TargetDataRep
        &inputBufDesc,  // pInput
        0,              // Reserved2
        nullptr,        // phNewContext
        &outputBufDesc, // pOutput
        &contextAttr,   // pfContextAttr
        nullptr         // ptsExpiry
    );
    ASSERT_EQ(tmpstr, "[Finished]");
    ASSERT_EQ(retval, SEC_E_OK);
    ASSERT_EQ(contextAttr, RET_FLAGS);

    EXPECT_CALL(openssl, SSL_free(&sslObject));
    funcTable->DeleteSecurityContext(&sspCtx);
}
class FixtureWithInitContext : public FixtureWithCredHandle {
protected:
    CtxtHandle sspCtx{};
    SSL sslObject;

    FixtureWithInitContext() : sslObject(nullptr) {}

    void SetUp() {
        FixtureWithCredHandle::SetUp();

        // Initialize context with as little code as possible
        EXPECT_CALL(openssl, SSL_new(_)).WillOnce(Return(&sslObject));

        SecBufferDesc outputBufDesc{};
        SecBuffer outputBuf{};
        initSecBufferDesc(&outputBufDesc, &outputBuf, 1);

        const unsigned long REQ_FLAGS = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
        unsigned long contextAttr;

        EXPECT_CALL(sslObject, connect()).WillOnce([&] {
            sslObject.wbio->writestr("[Magic]");
            return 1;
        });
        int retval = funcTable->InitializeSecurityContextW(
            &sspCred,       // phCredential
            nullptr,        // phContext
            nullptr,        // pszTargetName
            REQ_FLAGS,      // fContextReq
            0,              // Reserved1
            0,              // TargetDataRep
            nullptr,        // pInput
            0,              // Reserved2
            &sspCtx,        // phNewContext
            &outputBufDesc, // pOutput
            &contextAttr,   // pfContextAttr
            nullptr         // ptsExpiry
        );
        ASSERT_EQ(outputBuf, "[Magic]");
        ASSERT_EQ(outputBuf.BufferType, SECBUFFER_TOKEN);
        ASSERT_EQ(retval, SEC_E_OK);
        funcTable->FreeContextBuffer(outputBuf.pvBuffer);
    }
    void TearDown() {
        EXPECT_CALL(openssl, SSL_free(&sslObject));
        funcTable->DeleteSecurityContext(&sspCtx);

        FixtureWithCredHandle::TearDown();
    }
};

TEST_F(FixtureWithInitContext, EncryptData) {
    int retval;

    SecPkgContext_StreamSizes streamSizes{};
    retval = funcTable->QueryContextAttributesW(&sspCtx, SECPKG_ATTR_STREAM_SIZES, &streamSizes);
    ASSERT_EQ(retval, SEC_E_OK);

    SecBufferDesc dataBufDesc{};
    SecBuffer dataBuf[4]{};
    std::unique_ptr<char[]> buf = std::make_unique<char[]>(10 + streamSizes.cbHeader + streamSizes.cbTrailer);

    initSecBuffer(&dataBuf[0], SECBUFFER_STREAM_HEADER,  &buf[0], streamSizes.cbHeader);
    initSecBuffer(&dataBuf[1], SECBUFFER_DATA,           &buf[streamSizes.cbHeader], 10);
    initSecBuffer(&dataBuf[2], SECBUFFER_STREAM_TRAILER, &buf[streamSizes.cbHeader + 10], streamSizes.cbTrailer);
    initSecBuffer(&dataBuf[3], SECBUFFER_EMPTY,          nullptr, 0);
    initSecBufferDesc(&dataBufDesc, dataBuf, 4);

    memcpy(dataBuf[1].pvBuffer, "helloworld", 10);

    EXPECT_CALL(sslObject, write(_, _)).WillOnce([&](const void* p, int len) {
        EXPECT_EQ(std::string((const char*)p, len), "helloworld");
        sslObject.wbio->writestr("[0010HELLOWORLD]");
        return len;
    });

    retval = funcTable->EncryptMessage(&sspCtx, 0, &dataBufDesc, 0);
    ASSERT_EQ(retval, SEC_E_OK);
    ASSERT_EQ(dataBuf[0], "[0010");
    ASSERT_EQ(dataBuf[1], "HELLOWORLD");
    ASSERT_EQ(dataBuf[2], "]");
}

// test call to EncryptMessage without passing a SECBUFFER_DATA buffer
TEST_F(FixtureWithInitContext, EncryptMessageBadBufferType) {
    int retval;

    SecBufferDesc dataBufDesc{};
    SecBuffer dataBuf[2]{};
    char buf[5];

    initSecBuffer(&dataBuf[0], SECBUFFER_STREAM_HEADER, &buf[0], 5);
    initSecBuffer(&dataBuf[1], SECBUFFER_EMPTY, nullptr, 0);
    initSecBufferDesc(&dataBufDesc, dataBuf, 2);

    retval = funcTable->EncryptMessage(&sspCtx, 0, &dataBufDesc, 0);
    ASSERT_EQ(retval, SEC_E_INVALID_TOKEN);
}
