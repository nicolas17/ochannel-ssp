// SPDX-FileCopyrightText: 2021 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#ifndef CONTEXT_TYPES_H
#define CONTEXT_TYPES_H

typedef struct _SecHandle SecHandle, *PSecHandle;
typedef SecHandle CredHandle;
typedef PSecHandle PCredHandle;

typedef SecHandle CtxtHandle;
typedef PSecHandle PCtxtHandle;

#include <openssl/ssl.h>

template<typename T>
typename T::handleType toSecHandle(const T* ptr) {
    return {T::MAGIC, reinterpret_cast<uintptr_t>(ptr)};
}
template<typename T>
T* fromSecHandle(typename T::handleType* handle) {
    if (handle->dwLower == T::MAGIC) {
        return reinterpret_cast<T*>(handle->dwUpper);
    } else {
        return nullptr;
    }
}

class SSPCredentials {
public:
    static const unsigned long MAGIC = 0x5cb2715c;
    typedef CredHandle handleType;

    SSPCredentials();
    ~SSPCredentials();

private:
    // non-copyable
    SSPCredentials(const SSPCredentials&) = delete;
    SSPCredentials& operator=(const SSPCredentials&) = delete;

    SSL_CTX* m_ssl_ctx;
    friend class SSPContext;
};

class SSPContext {
public:
    static const unsigned long MAGIC = 0xbe80c313;
    typedef CtxtHandle handleType;

    SSPContext(SSPCredentials* cred);
    ~SSPContext();
    bool do_connect();
    void log_bio_buffers();

//private:
    // non-copyable
    SSPContext(const SSPContext&) = delete;
    SSPContext& operator=(const SSPContext&) = delete;

    SSL* m_ssl;
    BIO* m_internal_bio = nullptr;
    BIO* m_network_bio = nullptr;
};

#endif
