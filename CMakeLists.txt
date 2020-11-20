# SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.8)

project(openssl-sspi CXX)

# Include sub-projects.
add_subdirectory("openssl-sspi")

add_executable(httpclient httpclient.cpp)
set_target_properties(httpclient PROPERTIES CXX_STANDARD 17)
