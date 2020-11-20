// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#include "httpclient.h"

#include <cassert>
#include <cstdio>

int main() {
    HTTPClient client;

    assert(!client.data_to_send().has_value());

    client.make_get_request("/", {{"Host","example.com"}});

    assert(client.data_to_send().value() == "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    assert(!client.data_to_send().has_value());

    client.receive_data("HTTP/1.1 200 OK\r\n");
    client.receive_data("Content-Type:   text/plain\r\n");
    assert(!client.next_event().has_value());
    client.receive_data("Content-Length: 4\r\n\r\nabcd");
    {
    auto oevent = client.next_event();
    assert(oevent.has_value());
    auto event = oevent.value();
    assert(std::holds_alternative<HTTPClient::ResponseEvent>(event));
    auto revent = std::get<HTTPClient::ResponseEvent>(event);

    assert(revent.status_code == 200);
    assert(revent.headers == (Headers{{"Content-Type","text/plain"},{"Content-Length","4"}}));
    }
    {
    auto oevent = client.next_event();
    assert(oevent.has_value());
    auto event = oevent.value();
    assert(std::holds_alternative<HTTPClient::DataEvent>(event));
    auto devent = std::get<HTTPClient::DataEvent>(event);
    printf("data '%s'\n", devent.data.c_str());
    assert(devent.data == "abcd");
    }
}
