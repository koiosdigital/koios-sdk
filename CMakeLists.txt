cmake_minimum_required(VERSION 3.16)

# Two builds from one tree:
#
#   ESP-IDF component   portable core + ports/esp-idf (this file is included
#                       by the IDF build system, which defines
#                       idf_component_register)
#   standalone (Linux)  portable core + ports/linux as a library, the
#                       koios-agent daemon and the tests: ports/linux/
#
# core/ must stay free of platform includes (cJSON excepted); everything
# platform-specific lives under ports/.

if(COMMAND idf_component_register)
    idf_component_register(
        SRCS
            "core/cloudlink.c"
            "core/ota.c"
            "core/logship.c"
            "core/metrics.c"
            "core/console.c"
            "ports/esp-idf/kp_os_esp.c"
            "ports/esp-idf/kp_log_esp.c"
            "ports/esp-idf/kp_logstore_esp.c"
            "ports/esp-idf/kp_net_esp.c"
            "ports/esp-idf/kp_http_esp.c"
            "ports/esp-idf/kp_identity_esp.c"
            "ports/esp-idf/kp_websocket_esp.c"
            "ports/esp-idf/kp_ota_esp.c"
            "ports/esp-idf/kp_metrics_esp.c"
        INCLUDE_DIRS "include"
        REQUIRES
            kd_common
            cjson
            esp_event
            esp_wifi
            esp_eth
            esp_netif
            esp_timer
            esp_http_client
            esp_https_ota
            esp_hw_support
            esp_common
            freertos
            app_update
            spi_flash
            mbedtls
            nvs_flash
            heap
    )
    return()
endif()

project(koios_sdk VERSION 0.1.0 LANGUAGES C)
enable_testing()  # here, so that ctest in the build directory finds the tests below
add_subdirectory(ports/linux)
