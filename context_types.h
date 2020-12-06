// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
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

class SSPCredentials {
public:
    static const unsigned long MAGIC = 0x5cb2715c;

    SSPCredentials();
    ~SSPCredentials();
    CredHandle toHandle() const;
    static SSPCredentials* fromHandle(PCredHandle handle);

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

    SSPContext(SSPCredentials* cred);
    ~SSPContext();
    bool do_connect();

    CtxtHandle toHandle() const;
    static SSPContext* fromHandle(PCtxtHandle handle);

//private:
    // non-copyable
    SSPContext(const SSPContext&) = delete;
    SSPContext& operator=(const SSPContext&) = delete;

    SSL* m_ssl;
    BIO* m_internal_bio = nullptr;
    BIO* m_network_bio = nullptr;
};

#endif