#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)
project(scratch_pad)


set(INCLUDE_DIR ".")

add_subdirectory(c-utility)

compileAsC99()

include_directories(${HSM_INCLUDE_DIR} ${SHARED_UTIL_INC_FOLDER})

set(source_c_files
    ./scratch_pad.c
)

set(source_h_files
)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

IF(WIN32)
    #windows needs this define
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)

    # Make warning as error
    add_definitions(/WX)
ELSE()
    # Make warning as error
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -Wno-unused-function -Wno-variadic-macros -fPIC")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wno-unused-function -Wno-unused-variable -Wno-variadic-macros -fPIC")

ENDIF(WIN32)

add_executable(scratch_pad ${source_c_files})
target_link_libraries(scratch_pad ${OPENSSL_LIBRARIES})

IF(WIN32)
    target_link_libraries(scratch_pad $ENV{OpenSSLDir}/lib/ssleay32.lib $ENV{OpenSSLDir}/lib/libeay32.lib)
    file(COPY $ENV{OpenSSLDir}/bin/libeay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Release)
    file(COPY $ENV{OpenSSLDir}/bin/ssleay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Release)
ELSE()
ENDIF(WIN32)
