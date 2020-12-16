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

    // generated from ssl.h with genmock
    MOCK_METHOD(SSL_CTX *, SSL_CTX_new, (const SSL_METHOD *));
    MOCK_METHOD(void, SSL_CTX_free, (SSL_CTX *));
    MOCK_METHOD(const SSL_METHOD *, TLS_client_method, ());
};

#endif
