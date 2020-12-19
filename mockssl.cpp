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
int BIO_free(BIO * a) {
    return g_mock->BIO_free(a);
}
int BIO_up_ref(BIO * a) {
    return g_mock->BIO_up_ref(a);
}
int BIO_read(BIO * b, void * data, int dlen) {
    return g_mock->BIO_read(b, data, dlen);
}
int BIO_write(BIO * b, const void * data, int dlen) {
    return g_mock->BIO_write(b, data, dlen);
}
long BIO_ctrl(BIO * bp, int cmd, long larg, void * parg) {
    return g_mock->BIO_ctrl(bp, cmd, larg, parg);
}
int BIO_new_bio_pair(BIO ** bio1, size_t writebuf1, BIO ** bio2, size_t writebuf2) {
    return g_mock->BIO_new_bio_pair(bio1, writebuf1, bio2, writebuf2);
}
SSL_CTX * SSL_CTX_new(const SSL_METHOD * meth) {
    return g_mock->SSL_CTX_new(meth);
}
void SSL_CTX_free(SSL_CTX * arg0) {
    return g_mock->SSL_CTX_free(arg0);
}
void SSL_set0_rbio(SSL * s, BIO * rbio) {
    return g_mock->SSL_set0_rbio(s, rbio);
}
void SSL_set0_wbio(SSL * s, BIO * wbio) {
    return g_mock->SSL_set0_wbio(s, wbio);
}
SSL * SSL_new(SSL_CTX * ctx) {
    return g_mock->SSL_new(ctx);
}
void SSL_free(SSL * ssl) {
    return g_mock->SSL_free(ssl);
}
int SSL_connect(SSL * ssl) {
    return g_mock->SSL_connect(ssl);
}
int SSL_read(SSL * ssl, void * buf, int num) {
    return g_mock->SSL_read(ssl, buf, num);
}
int SSL_write(SSL * ssl, const void * buf, int num) {
    return g_mock->SSL_write(ssl, buf, num);
}
int SSL_get_error(const SSL * s, int ret_code) {
    return g_mock->SSL_get_error(s, ret_code);
}
const SSL_METHOD * TLS_client_method() {
    return g_mock->TLS_client_method();
}
void SSL_set_connect_state(SSL * s) {
    return g_mock->SSL_set_connect_state(s);
}

}
