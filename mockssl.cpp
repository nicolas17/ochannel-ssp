// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#include "mockssl.h"
#include <openssl/ssl.h>

OpenSSLMock* g_mock = nullptr;

OpenSSLMock::OpenSSLMock() {
    g_mock = this;
}
OpenSSLMock::~OpenSSLMock() {
    g_mock = nullptr;
}

extern "C" {

// generated from ssl.h with genmock

SSL_CTX * SSL_CTX_new(const SSL_METHOD * meth) {
    return g_mock->SSL_CTX_new(meth);
}
void SSL_CTX_free(SSL_CTX * arg0) {
    return g_mock->SSL_CTX_free(arg0);
}
const SSL_METHOD * TLS_client_method() {
    return g_mock->TLS_client_method();
}

}
