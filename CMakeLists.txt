# SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.8)

project(ochannel-ssp CXX)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 17)

if(WIN32)
add_library(testssp MODULE ssp.cpp context_types.cpp exports.def)
target_link_libraries(testssp OpenSSL::SSL)
endif()

find_package(GTest REQUIRED NO_MODULE)
add_executable(mocktest mocktest.cpp mockssl.cpp)
target_link_libraries(mocktest GTest::gmock_main)

find_package(Clang)
if (Clang_FOUND)
    add_executable(genmock genmock.cpp)
    target_compile_options(genmock PRIVATE -fno-rtti)
    target_link_libraries(genmock clangTooling)
    target_include_directories(genmock PRIVATE ${CLANG_INCLUDE_DIRS})
endif()
