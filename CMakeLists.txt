#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)
project(scratch_pad)


set(INCLUDE_DIR ".")

add_subdirectory(c-utility)

compileAsC99()

include_directories(${HSM_INCLUDE_DIR} ${SHARED_UTIL_INC_FOLDER})

set(source_c_files
    ./blockchain.c
    ./sha_algorithms.c
    ./scratch_pad.c
    ./sha256_impl.c
)

set(source_h_files
    ./blockchain.h
    ./sha_algorithms.h
    ./sha256_impl.h
)

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

add_executable(scratch_pad ${source_h_files} ${source_c_files})
target_link_libraries(scratch_pad aziotsharedutil)
