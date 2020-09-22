# SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0

find_package(OpenSSL REQUIRED)

add_executable(openssl-test "openssl-test.cpp" "openssl-test.h")
target_link_libraries(openssl-test ws2_32)

target_link_libraries(openssl-test OpenSSL::SSL)
