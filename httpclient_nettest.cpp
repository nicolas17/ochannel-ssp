// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#ifdef WIN32
# define _WIN32_WINNT 0x0600
#endif

#include "httpclient.h"

#ifdef WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
#else
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#endif

#include <cassert>
#include <cstdio>

int sendall(int sock, const char* data, size_t length) {
    int retval;
    size_t remaining = length;
    const char* ptr = data;

    while (remaining > 0) {
        retval = send(sock, ptr, remaining, 0);
        if (retval < 0) return retval;
        if (retval == 0) return retval;
        remaining -= retval;
        ptr += retval;
    }
    return length;
}

int main()
{
    int retval;
#ifdef WIN32
    WSADATA wsaData;
    retval = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (retval != 0) {
        fprintf(stderr, "WSAStartup failed: %d", retval);
        return 1;
    }
#endif

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    inet_pton(AF_INET, "93.184.216.34", &addr.sin_addr);

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    assert(sock>=0);
    retval = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (retval != 0) {
        printf("Failed to connect\n");
        return 1;
    }
    printf("Connected\n");

    HTTPClient client;
    client.make_get_request("/", {{"Host","example.com"}});

    while (true) {

        if (auto http_to_send = client.data_to_send()) {
            printf("Client tells us to send %zu bytes\n", http_to_send->length());
            sendall(sock, http_to_send->data(), http_to_send->length());
        }

        char buf[256];
        printf("Receiving...\n");
        retval = recv(sock, buf, sizeof(buf), 0);
        if (retval <= 0) return 1;

        printf("Got %d bytes from network\n", retval);
        client.receive_data(std::string(buf, retval));

        while (auto maybe_event = client.next_event()) {
            printf("Got event\n");
            auto& event_v = maybe_event.value();
            if (auto resp_event = std::get_if<HTTPClient::ResponseEvent>(&event_v)) {
                printf("Got response with code %d\n", resp_event->status_code);
            } else if (auto data_event = std::get_if<HTTPClient::DataEvent>(&event_v)) {
                printf("Got %zu bytes of data\n", data_event->data.length());
            }
        }
    }

}
