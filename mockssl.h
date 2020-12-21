// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#ifndef MOCKSSL_H
#define MOCKSSL_H

#include <openssl/ssl.h>
#include <gmock/gmock.h>

class OpenSSLMock {
public:
    OpenSSLMock();
    ~OpenSSLMock();

    MOCK_METHOD(SSL_CTX *, SSL_CTX_new, (const SSL_METHOD *));
    MOCK_METHOD(void, SSL_CTX_free, (SSL_CTX *));
    MOCK_METHOD(SSL *, SSL_new, (SSL_CTX *));
    MOCK_METHOD(void, SSL_free, (SSL *));

};
struct ssl_ctx_st {
    ssl_ctx_st(const SSL_METHOD * meth);
};
struct ssl_st {
    ssl_st(SSL_CTX * ctx);

    MOCK_METHOD(void, set0_rbio, (BIO *));
    MOCK_METHOD(void, set0_wbio, (BIO *));
    MOCK_METHOD(int, connect, ());
    MOCK_METHOD(int, read, (void *, int));
    MOCK_METHOD(int, write, (const void *, int));
    MOCK_METHOD(int, get_error, (int), (const));
    MOCK_METHOD(void, set_connect_state, ());
};
struct bio_st {
    int refcount;
    std::string readbuf;
    BIO* other_bio;

    static BIO* create();
    static void make_pair(BIO** bio1, BIO** bio2);

    int up_ref();
    int free();
    int read(void* data, int dlen);
    int write(const void* data, int dlen);
    size_t pending();
};

#endif
