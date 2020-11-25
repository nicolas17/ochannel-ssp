// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#include "opensslclient.h"

#include <cassert>

#include <openssl/ssl.h>

FILE* logfile;

void log_keys(const SSL*, const char* line) {
    fprintf(logfile, "%s\n", line);
    fflush(logfile);
}

OpenSSLClient::OpenSSLClient()
{
    logfile=fopen("sslkeylog","w");
    m_ctx = SSL_CTX_new(TLS_client_method());
    assert(m_ctx);

    SSL_CTX_set_mode(m_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_keylog_callback(m_ctx, log_keys);

    m_ssl = SSL_new(m_ctx);
    assert(m_ssl);

    BIO_new_bio_pair(&m_internal_bio, 0, &m_network_bio, 0);
    // SSL_set0_[rw]bio take ownership of the passed reference,
    // so if we call both with the same BIO, we need the refcount to be 2.
    BIO_up_ref(m_internal_bio);
    SSL_set0_rbio(m_ssl, m_internal_bio);
    SSL_set0_wbio(m_ssl, m_internal_bio);

    SSL_set_connect_state(m_ssl);
}

OpenSSLClient::~OpenSSLClient()
{
    BIO_free(m_network_bio);
    // we don't need to free m_internal_bio because it's owned by m_ssl

    SSL_free(m_ssl);
    SSL_CTX_free(m_ctx);
}

void OpenSSLClient::send_data(const std::string& data)
{
    printf("Adding %zu bytes to pt. write buffer\n", data.length());
    write_buffer += data;
}

bool OpenSSLClient::do_connect()
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


void OpenSSLClient::send_data_internal()
{
    int retval;
    if (!write_buffer.empty()) {
        printf("Trying to SSL_write %zu bytes\n", write_buffer.length());
        retval = SSL_write(m_ssl, write_buffer.data(), write_buffer.length());

        printf("SSL_write returned %d\n", retval);
        if (retval <= 0) {
            printf("Error code is %d\n", SSL_get_error(m_ssl, retval));
        } else {
            if (retval < write_buffer.length()) {
                printf("SSL_write did a partial write\n");
            } else {
                assert(retval == write_buffer.length());
                printf("SSL_write wrote everything\n");
            }
            write_buffer.erase(0, retval);
        }
    }
}


std::optional<std::string> OpenSSLClient::data_to_send()
{
    // try to get any pending plaintext data written into OpenSSL
    // before checking if there's pending ciphertext to return
    send_data_internal();
    int pending = BIO_pending(m_network_bio);
    if (pending > 0) {
        std::string data;
        data.resize(pending);
        BIO_read(m_network_bio, data.data(), data.length());
        return data;
    }
    return std::nullopt;
}


std::optional<std::string> OpenSSLClient::data_received()
{
    char buf[256];
    printf("OpenSSL input (internal) buffer has %d bytes left\n", BIO_pending(m_internal_bio));
    printf("OpenSSL output (network) buffer has %d bytes left\n", BIO_pending(m_network_bio));
    printf("Will read\n");
    int bytes_read = SSL_read(m_ssl, buf, 256);
    printf("SSL_read returned %d\n", bytes_read);
    if (bytes_read <= 0) {
        printf("Error code is %d\n", SSL_get_error(m_ssl, bytes_read));
    }
    printf("OpenSSL input (internal) buffer has %d bytes left\n", BIO_pending(m_internal_bio));
    printf("OpenSSL output (network) buffer has %d bytes left\n", BIO_pending(m_network_bio));
    if (bytes_read > 0) {
        return std::string(buf, bytes_read);
    }
    return std::nullopt;
}
void OpenSSLClient::receive_data(const std::string& data)
{
    BIO_write(m_network_bio, data.data(), data.length());
}
