// Connectivity port over kd_common's WiFi. Subscribes to the default event
// loop directly (WIFI_EVENT / IP_EVENT) rather than kd_common's internal
// callback lists, so subscription works at any time — including after
// wifi_start() — with no init-order constraint.

#include "koios/port/kp_net.h"
#include "koios/port/kp_log.h"

#include <esp_event.h>
#include <esp_wifi.h>

#include <kd_common.h>

static const char* TAG = "kp_net";

#define MAX_SUBSCRIBERS 4

static struct {
    bool registered;
    kp_net_event_fn on_connect[MAX_SUBSCRIBERS];
    kp_net_event_fn on_disconnect[MAX_SUBSCRIBERS];
    size_t connect_count, disconnect_count;
} s;

static void event_handler(void* arg, esp_event_base_t base, int32_t id, void* data) {
    (void)arg; (void)data;
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        for (size_t i = 0; i < s.connect_count; i++) s.on_connect[i]();
    }
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        for (size_t i = 0; i < s.disconnect_count; i++) s.on_disconnect[i]();
    }
}

static void ensure_registered(void) {
    if (s.registered) return;
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, event_handler, NULL);
    s.registered = true;
}

bool kp_net_is_connected(void) {
    return kd_common_is_wifi_connected();
}

void kp_net_subscribe(kp_net_event_fn on_connect, kp_net_event_fn on_disconnect) {
    ensure_registered();
    if (on_connect) {
        if (s.connect_count < MAX_SUBSCRIBERS) s.on_connect[s.connect_count++] = on_connect;
        else KP_LOGE(TAG, "Too many connect subscribers");
    }
    if (on_disconnect) {
        if (s.disconnect_count < MAX_SUBSCRIBERS) s.on_disconnect[s.disconnect_count++] = on_disconnect;
        else KP_LOGE(TAG, "Too many disconnect subscribers");
    }
}

void kp_net_reset(void) {
    // kd_common's WiFi layer auto-reconnects after a disconnect.
    kd_common_wifi_disconnect();
}
