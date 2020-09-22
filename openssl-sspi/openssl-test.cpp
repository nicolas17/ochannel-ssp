// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#include <cstdio>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include <openssl/ssl.h>

#include "scope_guard.hpp"

int main()
{
    WSADATA wsaData;
    int retval;
    retval = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (retval != 0) {
        fprintf(stderr, "WSAStartup failed: %d", retval);
        return 1;
    }
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }
    auto sslctx_guard = sg::make_scope_guard([&] { SSL_CTX_free(ctx); });

    struct addrinfo *result = nullptr;
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    retval = getaddrinfo("overwatch.kde.org", "443", &hints, &result);
    if (retval != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", retval);
        return 1;
    }

    auto addrinfo_guard = sg::make_scope_guard([&] { freeaddrinfo(result); });

    SOCKET sock;
    sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "socket failed: %d\n", retval);
        return 1;
    }
    auto socket_guard = sg::make_scope_guard([&] { closesocket(sock); });

    retval = connect(sock, result->ai_addr, result->ai_addrlen);
    if (retval == SOCKET_ERROR) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "failed to create SSL object\n");
        return 1;
    }
    auto ssl_guard = sg::make_scope_guard([&] { SSL_free(ssl); });

    retval = SSL_set_fd(ssl, sock);
    if (!retval) {
        fprintf(stderr, "Failed to set fd on SSL connection\n");
        return 1;
    }

    retval = SSL_connect(ssl);
    if (retval != 1) {
        fprintf(stderr, "Failed to SSL_connect: %d\n", retval);
    }

    const char* sendbuf = "GET / HTTP/1.1\r\nHost: overwatch.kde.org\r\nConnection: close\r\n\r\n";
    size_t sendsize = strlen(sendbuf);
    retval = SSL_write(ssl, sendbuf, sendsize);
    if (retval != sendsize) {
        fprintf(stderr, "send failed or didn't send all\n");
        return 1;
    }

    char recvbuf[512];
    do {
        retval = SSL_read(ssl, recvbuf, sizeof(recvbuf)-1);
        if (retval > 0) {
            recvbuf[retval] = '\0';
            printf("Got data: <%s>\n", recvbuf);
        } else if (retval == 0) {
            printf("Connection closed\n");
        } else {
            printf("recv failed: %d\n", WSAGetLastError());
        }
    } while (retval > 0);

    return 0;
}
