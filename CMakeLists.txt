#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)
project(scratch_pad)

set(INCLUDE_DIR ".")

#compileAsC99()

add_subdirectory(deps/c-utility)

include_directories(./inc)
include_directories(${AZURE_C_SHARED_UTILITY_INCLUDES})

message("Message: ${AZURE_C_SHARED_UTILITY_INCLUDES}")

# Use solution folders.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(source_c_files
    src/bt_beacon_mgr.c
    ./scratch_pad.c
)

if (WIN32)
    set(source_c_files
        ${source_c_files}
        src/bt_device_discovery_win.c
        src/bt_device_mgr_win.c
    )
else()
    set(source_c_files
        ${source_c_files}
        src/bt_device_discovery_linux.c
        src/bt_device_mgr_linux.c
    )
endif()

set(source_h_files
    inc/bt_beacon_mgr.h
    inc/bt_device_discovery.h
    inc/bt_device_mgr.h
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

add_executable(scratch_pad ${source_c_files})
target_link_libraries(scratch_pad bluetooth aziotsharedutil)
