// Connectivity port over kd_common's WiFi. Subscribes to the default event
// loop directly (WIFI_EVENT / IP_EVENT) rather than kd_common's internal
// callback lists, so subscription works at any time — including after
// wifi_start() — with no init-order constraint.

#include "koios/port/kp_net.h"
#include "koios/port/kp_log.h"

#include <esp_event.h>
#include <esp_wifi.h>
#include <esp_eth.h>
#include <esp_netif.h>

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
    if (base == IP_EVENT && (id == IP_EVENT_STA_GOT_IP || id == IP_EVENT_ETH_GOT_IP)) {
        for (size_t i = 0; i < s.connect_count; i++) s.on_connect[i]();
    }
    else if ((base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) ||
             (base == ETH_EVENT && id == ETHERNET_EVENT_DISCONNECTED)) {
        // Ignore a single interface dropping while another still has an IP (e.g.
        // WiFi being shut down when Ethernet takes over) — only tear the cloud
        // link down once the device is fully offline.
        if (!kd_common_is_network_connected()) {
            for (size_t i = 0; i < s.disconnect_count; i++) s.on_disconnect[i]();
        }
    }
}

static void ensure_registered(void) {
    if (s.registered) return;
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, event_handler, NULL);
    // Ethernet path (kd_common brings up W6100 when configured). Registering
    // these unconditionally is harmless when Ethernet is absent — the events
    // simply never fire.
    esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, event_handler, NULL);
    esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, event_handler, NULL);
    s.registered = true;
}

bool kp_net_is_connected(void) {
    return kd_common_is_wifi_connected();
}

// Re-subscribing an already-registered callback is a no-op: modules that
// deinit/reinit at runtime (cloudlink on cert renewal) subscribe on every
// init and would otherwise fill the table with duplicates.
static void add_subscriber(kp_net_event_fn* list, size_t* count, kp_net_event_fn fn,
                           const char* kind) {
    for (size_t i = 0; i < *count; i++) {
        if (list[i] == fn) return;
    }
    if (*count < MAX_SUBSCRIBERS) list[(*count)++] = fn;
    else KP_LOGE(TAG, "Too many %s subscribers", kind);
}

void kp_net_subscribe(kp_net_event_fn on_connect, kp_net_event_fn on_disconnect) {
    ensure_registered();
    if (on_connect) add_subscriber(s.on_connect, &s.connect_count, on_connect, "connect");
    if (on_disconnect) add_subscriber(s.on_disconnect, &s.disconnect_count, on_disconnect, "disconnect");
}

void kp_net_reset(void) {
    // kd_common's WiFi layer auto-reconnects after a disconnect.
    kd_common_wifi_disconnect();
}
