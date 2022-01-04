cmake_minimum_required(VERSION 3.21.1)
project(of_core_linux VERSION 1.0.1 DESCRIPTION "OpenFiles Platform for Linux")

include(configs/default)
configure_file(include/ofc_linux/config.h.in ofc_linux/config.h @ONLY)
include_directories(
        ${of_core_SOURCE_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR}
        ${of_core_linux_SOURCE_DIR}/include
)

set(SRCS
        src/console_linux.c
        src/env_linux.c
        src/event_linux.c
        src/lock_linux.c
        src/net_linux.c
        src/process_linux.c
        src/socket_linux.c
        src/thread_linux.c
        src/time_linux.c
        src/waitset_linux.c
        )

add_library(of_core_linux STATIC ${SRCS})
target_link_libraries(of_core_linux PUBLIC pthread of_core_static)

set_target_properties(of_core_linux PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(of_core_linux PROPERTIES SOVERSION 1)

