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
    MOCK_METHOD(void, SSL_set0_rbio, (SSL *, BIO *));
    MOCK_METHOD(void, SSL_set0_wbio, (SSL *, BIO *));
    MOCK_METHOD(SSL *, SSL_new, (SSL_CTX *));
    MOCK_METHOD(void, SSL_free, (SSL *));
    MOCK_METHOD(int, SSL_connect, (SSL *));
    MOCK_METHOD(int, SSL_read, (SSL *, void *, int));
    MOCK_METHOD(int, SSL_write, (SSL *, const void *, int));
    MOCK_METHOD(int, SSL_get_error, (const SSL *, int));
    MOCK_METHOD(const SSL_METHOD *, TLS_client_method, ());
    MOCK_METHOD(void, SSL_set_connect_state, (SSL *));

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
