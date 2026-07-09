cmake_minimum_required(VERSION 3.16)

# ESP-IDF component build: portable core + esp-idf port in one component.
# core/ must stay free of ESP-IDF includes (cJSON excepted); everything
# platform-specific lives in ports/esp-idf/.

idf_component_register(
    SRCS
        "core/cloudlink.c"
        "core/ota.c"
        "ports/esp-idf/kp_os_esp.c"
        "ports/esp-idf/kp_log_esp.c"
        "ports/esp-idf/kp_net_esp.c"
        "ports/esp-idf/kp_http_esp.c"
        "ports/esp-idf/kp_identity_esp.c"
        "ports/esp-idf/kp_websocket_esp.c"
        "ports/esp-idf/kp_ota_esp.c"
    INCLUDE_DIRS "include"
    REQUIRES
        kd_common
        cjson
        esp_event
        esp_wifi
        esp_timer
        esp_http_client
        esp_https_ota
        esp_hw_support
        app_update
        mbedtls
)
