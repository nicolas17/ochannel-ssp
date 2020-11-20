// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#ifndef HTTPCLIENT_H
#define HTTPCLIENT_H

#include <string>
#include <vector>
#include <variant>
#include <optional>
#include <utility>

using Headers = std::vector<std::pair<std::string, std::string>>;

class HTTPClient
{
public:

    struct ResponseEvent
    {
        int status_code;
        Headers headers;
    };
    struct DataEvent
    {
        std::string data;
    };
    using Event = std::variant<ResponseEvent, DataEvent>;

    void receive_data(const std::string& data);
    std::optional<std::string> data_to_send();

    void make_get_request(const std::string& path, const Headers& headers);

    std::optional<Event> next_event();

private:
    std::string recv_buffer;
    std::string send_buffer;

    enum State {
        IDLE,
        WAIT_RESPONSE,
        WAIT_DATA,
        DONE
    };
    State state=WAIT_RESPONSE;
    size_t content_length=0;
    size_t nbytes_received=0;

public:
    std::optional<HTTPClient::ResponseEvent> handle_response();
    std::optional<HTTPClient::DataEvent> handle_data();
};

class ProtocolError{};

#endif
