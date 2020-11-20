// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#include "httpclient.h"

#include <charconv>
#include <cassert>

#include <cstdio>

void HTTPClient::receive_data(const std::string& data)
{
    recv_buffer.append(data);
    printf("Received %lu bytes, recv buf now size %lu\n", data.length(), recv_buffer.length());
    // process();
}
std::optional<std::string> HTTPClient::data_to_send() {
    if (send_buffer.empty()) {
        return std::nullopt;
    } else {
        // return our send buffer without copying,
        // and replace our send buffer with an empty one
        std::string retval;
        std::swap(retval, this->send_buffer);
        return retval;
    }
}
void HTTPClient::make_get_request(const std::string& path, const Headers& headers) {
    // this has zero checks for validity,
    // eg. newlines in path or headers would make a mess

    send_buffer += "GET " + path + " HTTP/1.1\r\n";
    for (const auto& header : headers) {
        send_buffer += header.first + ": " + header.second + "\r\n";
    }
    send_buffer += "\r\n";
}

inline bool starts_with(const std::string& str, const std::string& prefix) {
    return str.compare(0, prefix.length(), prefix) == 0;
}

template<size_t N>
constexpr size_t literal_len(const char (&a)[N]) { return N-1; }

std::optional<HTTPClient::ResponseEvent> HTTPClient::handle_response()
{
    const size_t request_end = recv_buffer.find("\r\n\r\n");
    if (request_end == std::string::npos) {
        printf("No request end yet, returning null\n");
        return std::nullopt;
    }

    const size_t status_line_end = recv_buffer.find("\r\n");
    if (status_line_end < literal_len("HTTP/1.1 200 ")) {
        printf("Status line too short, failing\n");
        throw ProtocolError();
    }
    if (!starts_with(recv_buffer, "HTTP/1.1 ")) {
        printf("Bad HTTP version, failing\n");
        throw ProtocolError();
    }

    constexpr size_t status_code_offset = literal_len("HTTP/1.1 ");
    unsigned int status_code;
    auto int_result = std::from_chars(
        &recv_buffer[status_code_offset],
        &recv_buffer[status_code_offset+3],
        status_code
    );
    if (int_result.ec != std::errc()) {
        printf("Couldn't parse status code, failing\n");
        throw ProtocolError();
    }
    printf("Parsed status code %u\n", status_code);
    HTTPClient::ResponseEvent event;
    event.status_code = status_code;
    size_t pos = status_line_end+2;

    // pos points immediately after CRLF, so if we find another CRLF, we reached the end
    while (recv_buffer.compare(pos, 2, "\r\n") != 0) {
        size_t colon_pos = recv_buffer.find(':', pos);
        size_t value_pos = recv_buffer.find_first_not_of(" \t", colon_pos+1);
        size_t nl_pos = recv_buffer.find("\r\n", colon_pos);

        std::string name = recv_buffer.substr(pos, colon_pos-pos);
        std::string value = recv_buffer.substr(value_pos, nl_pos-value_pos);

        printf("Header name '%s'\n", name.c_str());
        printf("Header value '%s'\n", value.c_str());

        if (name == "Content-Length") {
            auto parse_result = std::from_chars(value.data(), value.data()+value.size(), this->content_length);
            printf("We parsed content-length value '%s' as %zu, errc %u\n", value.c_str(), content_length, parse_result.ec);
            if (parse_result.ec != std::errc()) {
                throw ProtocolError();
            }
        } else if (name == "Transfer-Encoding") {
            printf("We don't support this yet!\n");
            throw ProtocolError();
        }

        event.headers.push_back({std::move(name), std::move(value)});
        pos = nl_pos+2;
    }
    // request_end points at the beginning of the final CR LF CR LF,
    // while pos points at the second CRLF.
    assert(pos == request_end+2);

    recv_buffer.erase(0, request_end+4);

    state = WAIT_DATA;

    return event;
}

std::optional<HTTPClient::DataEvent> HTTPClient::handle_data()
{
    // TODO this can be optimized in the common case where the whole buffer is returned

    size_t amount_to_read = std::min(content_length-nbytes_received, recv_buffer.length());
    printf("Content length %zu, received %zu, so we still need %zu\n", content_length, nbytes_received, content_length-nbytes_received);
    printf("Buffer has %zu\n", recv_buffer.length());
    printf("We'll read %zu\n", amount_to_read);

    DataEvent event;
    event.data = recv_buffer.substr(0, amount_to_read);

    recv_buffer.erase(0, amount_to_read);
    nbytes_received += amount_to_read;

    if (nbytes_received == content_length) {
        state = DONE;
    }

    return event;
}

std::optional<HTTPClient::Event> HTTPClient::next_event()
{
    if (state == WAIT_RESPONSE) {
        auto response_event = handle_response();
        if (response_event) {
            // this unwraps the optional, creates a variant with the ResponseHeadersEvent,
            // and wraps it in a new optional
            return *response_event;
        }
    } else if (state == WAIT_DATA) {
        auto data_event = handle_data();
        if (data_event) {
            return *data_event;
        }
    }
    return std::nullopt;
}


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
