# SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.8)

project(openssl-sspi CXX)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 17)
