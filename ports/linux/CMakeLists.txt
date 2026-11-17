# Standalone build of the Koios SDK for Linux: the portable core plus the
# Linux port as a static library, the koios-agent daemon and the tests.
# Reached from the top-level CMakeLists.txt when it is not built as an
# ESP-IDF component. It also builds on macOS (tests, operator tools).
#
#   cmake -S . -B build && cmake --build build && ctest --test-dir build
#
# Dependencies: OpenSSL 3, libcurl, cJSON, POSIX threads.
#   -DKOIOS_CJSON_DIR=<dir with cJSON.c and cJSON.h>  build cJSON from source
#                                                     instead of using the
#                                                     system's libcjson

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

option(KOIOS_BUILD_AGENT "Build the koios-agent daemon" ON)
option(KOIOS_BUILD_TOOLS "Build koios-console, the operator's end of a console session" ON)
option(KOIOS_BUILD_SHELL "Build koios-shell, a login shell on a terminal for console sessions" ON)
option(KOIOS_BUILD_TESTS "Build the tests" ON)
set(KOIOS_CJSON_DIR "" CACHE PATH "Directory with cJSON.c and cJSON.h (empty: use the system's libcjson)")

set(SDK_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Threads REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)
find_package(CURL REQUIRED)

add_library(koios_sdk STATIC
    ${SDK_ROOT}/core/cloudlink.c
    ${SDK_ROOT}/core/ota.c
    ${SDK_ROOT}/core/logship.c
    ${SDK_ROOT}/core/metrics.c
    ${SDK_ROOT}/core/console.c
    kp_os_linux.c
    kp_log_linux.c
    kp_logstore_linux.c
    kp_net_linux.c
    kp_http_linux.c
    kp_identity_linux.c
    kp_websocket_linux.c
    kp_ota_linux.c
    kp_metrics_linux.c
    kp_console_linux.c
    console_stream.c
)

# cJSON: the core includes <cJSON.h>.
if(KOIOS_CJSON_DIR)
    target_sources(koios_sdk PRIVATE ${KOIOS_CJSON_DIR}/cJSON.c)
    target_include_directories(koios_sdk PUBLIC ${KOIOS_CJSON_DIR})
else()
    find_path(CJSON_INCLUDE_DIR cJSON.h PATH_SUFFIXES cjson REQUIRED)
    find_library(CJSON_LIBRARY NAMES cjson REQUIRED)
    target_include_directories(koios_sdk PUBLIC ${CJSON_INCLUDE_DIR})
    target_link_libraries(koios_sdk PUBLIC ${CJSON_LIBRARY})
endif()

target_include_directories(koios_sdk
    PUBLIC ${SDK_ROOT}/include ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

# What Kconfig decides on ESP-IDF. A Linux machine has the memory for longer
# lines and a longer backlog; both features are compiled in and switched on
# or off at run time by whoever calls the init functions.
target_compile_definitions(koios_sdk PUBLIC
    CONFIG_KOIOS_SDK_LOGS_ENABLE=1
    CONFIG_KOIOS_SDK_LOGS_TAG_LEN=48
    CONFIG_KOIOS_SDK_LOGS_MSG_LEN=768
    CONFIG_KOIOS_SDK_LOGS_BODY_BYTES=32768
    CONFIG_KOIOS_SDK_METRICS_ENABLE=1
    CONFIG_KOIOS_SDK_METRICS_BACKLOG=30
    CONFIG_KOIOS_SDK_CONSOLE_ENABLE=1
)
if(NOT APPLE)
    target_compile_definitions(koios_sdk PRIVATE _GNU_SOURCE)
endif()
target_compile_options(koios_sdk PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(koios_sdk PUBLIC OpenSSL::SSL OpenSSL::Crypto CURL::libcurl Threads::Threads m)

if(KOIOS_BUILD_AGENT)
    add_executable(koios-agent
        agent/main.c
        agent/config.c
        agent/journal.c
    )
    target_compile_definitions(koios-agent PRIVATE KOIOS_AGENT_VERSION="${PROJECT_VERSION}")
    if(NOT APPLE)
        target_compile_definitions(koios-agent PRIVATE _GNU_SOURCE)
    endif()
    target_compile_options(koios-agent PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_link_libraries(koios-agent PRIVATE koios_sdk)

    include(GNUInstallDirs)
    install(TARGETS koios-agent RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
endif()

if(KOIOS_BUILD_TOOLS)
    add_executable(koios-console tools/koios-console.c)
    if(NOT APPLE)
        target_compile_definitions(koios-console PRIVATE _GNU_SOURCE)
    endif()
    target_compile_options(koios-console PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_link_libraries(koios-console PRIVATE koios_sdk)
    include(GNUInstallDirs)
    install(TARGETS koios-console RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# koios-shell stands alone: no SDK, no TLS. The agent starts it for a session
# (target.<name> = exec:<libexecdir>/koios/koios-shell) or a socket unit does.
if(KOIOS_BUILD_SHELL)
    add_executable(koios-shell tools/koios-shell.c)
    if(NOT APPLE)
        target_compile_definitions(koios-shell PRIVATE _GNU_SOURCE)
    endif()
    target_compile_options(koios-shell PRIVATE -Wall -Wextra -Wno-unused-parameter)
    include(GNUInstallDirs)
    install(TARGETS koios-shell RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/koios)
endif()

if(KOIOS_BUILD_TESTS)
    add_subdirectory(tests)
endif()
