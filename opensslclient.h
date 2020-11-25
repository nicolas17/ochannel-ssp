// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENSSLCLIENT_H
#define OPENSSLCLIENT_H

#include <string>
#include <optional>

// TODO use pimpl to avoid having OpenSSL exposed in header?
#include <openssl/ssl.h>

class OpenSSLClient
{
public:

    OpenSSLClient();
    ~OpenSSLClient();

    /// Run the initial negotiation loop.
    bool do_connect();

    /// Ingest raw data we got from the network.
    void receive_data(const std::string& data);
    /// Get raw data to send to the network.
    std::optional<std::string> data_to_send();

    /// Encrypt plaintext data and send it over the SSL connection.
    void send_data(const std::string& data);
    /// Get decrypted plaintext data received from the SSL connection.
    std::optional<std::string> data_received();

private:
    SSL_CTX* m_ctx = nullptr;
    SSL* m_ssl = nullptr;

    BIO* m_internal_bio = nullptr;
    BIO* m_network_bio = nullptr;

    // Plaintext that we couldn't SSL_write yet
    std::string write_buffer;

    void send_data_internal();
};

#endif
