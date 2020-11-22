# SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.8)

project(openssl-sspi CXX)

find_package(OpenSSL REQUIRED)

add_subdirectory("openssl-sspi")

set(CMAKE_CXX_STANDARD 17)

add_library(httpclient OBJECT httpclient.cpp)

add_executable(httpclient_test httpclient_test.cpp)
target_link_libraries(httpclient_test httpclient)

add_executable(httpclient_nettest httpclient_nettest.cpp)
target_link_libraries(httpclient_nettest httpclient)
if(WIN32)
target_link_libraries(httpclient_nettest ws2_32)
endif()
