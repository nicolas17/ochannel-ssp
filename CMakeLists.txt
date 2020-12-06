# SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.8)

project(ochannel-ssp CXX)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 17)

add_library(testssp MODULE ssp.cpp context_types.cpp exports.def)
target_link_libraries(testssp OpenSSL::SSL)
