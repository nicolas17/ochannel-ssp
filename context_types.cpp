// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#include "context_types.h"

#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN 1

#include <windows.h>
#include <security.h>

SSPCredentials::SSPCredentials() {
    m_ssl_ctx = SSL_CTX_new(TLS_client_method());
}
SSPCredentials::~SSPCredentials() {
    SSL_CTX_free(m_ssl_ctx);
}


SSPContext::SSPContext(SSPCredentials* cred) {
    m_ssl = SSL_new(cred->m_ssl_ctx);

    BIO_new_bio_pair(&m_internal_bio, 0, &m_network_bio, 0);
    // SSL_set0_[rw]bio take ownership of the passed reference,
    // so if we call both with the same BIO, we need the refcount to be 2.
    BIO_up_ref(m_internal_bio);
    SSL_set0_rbio(m_ssl, m_internal_bio);
    SSL_set0_wbio(m_ssl, m_internal_bio);

    SSL_set_connect_state(m_ssl);
}
SSPContext::~SSPContext() {
    BIO_free(m_network_bio);
    // we don't need to free m_internal_bio because it's owned by m_ssl

    SSL_free(m_ssl);
}
// returns true when handshake is finished
bool SSPContext::do_connect()
{
    int retval;
    retval = SSL_connect(m_ssl);
    printf("SSL_connect returned %d\n", retval);
    if (retval <= 0) {
        printf("Error code is %d\n", SSL_get_error(m_ssl, retval));
    }
    printf("OpenSSL input (internal) buffer has %d bytes left\n", BIO_pending(m_internal_bio));
    printf("OpenSSL output (network) buffer has %d bytes left\n", BIO_pending(m_network_bio));
    return (retval == 1);
}
