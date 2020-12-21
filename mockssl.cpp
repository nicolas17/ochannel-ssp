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


bio_st* bio_st::create() {
    return new bio_st{};
}
void bio_st::make_pair(BIO** bio1, BIO** bio2) {
    BIO* b1 = bio_st::create();
    BIO* b2 = bio_st::create();
    b1->other_bio = b2;
    b2->other_bio = b1;
    *bio1 = b1;
    *bio2 = b2;
}
int bio_st::up_ref() {
    ++refcount;
    return 1;
}
int bio_st::free() {
    if (--refcount == 0) {
        delete this;
    }
    return 1;
}
int bio_st::read(void* data, int dlen) {
    size_t bytes_read = readbuf.copy((char*)data, dlen);
    readbuf.erase(0, bytes_read);
    return bytes_read;
}
int bio_st::write(const void* data, int dlen) {
    other_bio->readbuf.append((const char*)data, dlen);
    return dlen;
}
size_t bio_st::pending() {
    return readbuf.length();
}

ssl_ctx_st::ssl_ctx_st(const SSL_METHOD*)
{
}
ssl_st::ssl_st(SSL_CTX* ctx)
{
}

extern "C" {

int BIO_free(BIO * a) {
    return a->free();
}
int BIO_up_ref(BIO * a) {
    return a->up_ref();
}
int BIO_read(BIO * b, void * data, int dlen) {
    return b->read(data, dlen);
}
int BIO_write(BIO * b, const void * data, int dlen) {
    return b->write(data, dlen);
}
long BIO_ctrl(BIO * bp, int cmd, long larg, void * parg) {
    switch (cmd) {
    case BIO_CTRL_PENDING:
        return bp->pending();
    }
    return 0;
}
int BIO_new_bio_pair(BIO ** bio1, size_t writebuf1, BIO ** bio2, size_t writebuf2) {
    BIO::make_pair(bio1, bio2);
    return 0;
}

const SSL_METHOD * TLS_client_method() {
    return nullptr;
}
SSL_CTX * SSL_CTX_new(const SSL_METHOD * meth) {
    return g_mock->SSL_CTX_new(meth);
}
void SSL_CTX_free(SSL_CTX * arg0) {
    return g_mock->SSL_CTX_free(arg0);
}
SSL * SSL_new(SSL_CTX * ctx) {
    return g_mock->SSL_new(ctx);
}
void SSL_free(SSL * ssl) {
    return g_mock->SSL_free(ssl);
}
void SSL_set0_rbio(SSL * s, BIO * rbio) {
    s->set0_rbio(rbio);
}
void SSL_set0_wbio(SSL * s, BIO * wbio) {
    s->set0_wbio(wbio);
}
int SSL_connect(SSL * ssl) {
    return ssl->connect();
}
int SSL_read(SSL * ssl, void * buf, int num) {
    return ssl->read(buf, num);
}
int SSL_write(SSL * ssl, const void * buf, int num) {
    return ssl->write(buf, num);
}
int SSL_get_error(const SSL * s, int ret_code) {
    return s->get_error(ret_code);
}
void SSL_set_connect_state(SSL * s) {
    s->set_connect_state();
}

}
