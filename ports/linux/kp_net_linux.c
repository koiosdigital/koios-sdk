// Connectivity for Linux: "connected" means some interface other than the
// loopback is up, running and has a routable address. A small thread looks
// every two seconds and calls the subscribers when that changes. The port
// does not own the network (NetworkManager or systemd-networkd does), so
// kp_net_reset() only logs.

#include "koios/port/kp_net.h"
#include "koios/port/kp_log.h"
#include "kp_linux.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

static const char* TAG = "kp_net";

#define MAX_SUBSCRIBERS 8
#define POLL_INTERVAL_S 2

static struct {
    pthread_mutex_t lock;
    kp_net_event_fn on_connect[MAX_SUBSCRIBERS];
    kp_net_event_fn on_disconnect[MAX_SUBSCRIBERS];
    size_t connect_count, disconnect_count;
    bool thread_started;
    atomic_bool connected;
    atomic_bool probed;
} s = { .lock = PTHREAD_MUTEX_INITIALIZER };

static bool routable_v4(const struct sockaddr_in* a) {
    const uint32_t ip = ntohl(a->sin_addr.s_addr);
    if ((ip >> 24) == 127) return false;           // loopback
    if ((ip >> 16) == 0xA9FE) return false;        // 169.254/16 link-local
    return ip != 0;
}

static bool routable_v6(const struct sockaddr_in6* a) {
    return !IN6_IS_ADDR_LOOPBACK(&a->sin6_addr) &&
           !IN6_IS_ADDR_LINKLOCAL(&a->sin6_addr) &&
           !IN6_IS_ADDR_UNSPECIFIED(&a->sin6_addr);
}

static bool probe(void) {
    struct ifaddrs* list = NULL;
    if (getifaddrs(&list) != 0) return true;  // cannot tell: let the socket find out
    bool up = false;
    for (struct ifaddrs* i = list; i && !up; i = i->ifa_next) {
        if (!i->ifa_addr) continue;
        if ((i->ifa_flags & IFF_LOOPBACK) || !(i->ifa_flags & IFF_UP) || !(i->ifa_flags & IFF_RUNNING)) continue;
        if (i->ifa_addr->sa_family == AF_INET) {
            up = routable_v4((const struct sockaddr_in*)i->ifa_addr);
        }
        else if (i->ifa_addr->sa_family == AF_INET6) {
            up = routable_v6((const struct sockaddr_in6*)i->ifa_addr);
        }
    }
    freeifaddrs(list);
    return up;
}

static void fire(bool connected) {
    kp_net_event_fn fns[MAX_SUBSCRIBERS];
    size_t n;
    pthread_mutex_lock(&s.lock);
    if (connected) {
        n = s.connect_count;
        memcpy(fns, s.on_connect, n * sizeof(fns[0]));
    }
    else {
        n = s.disconnect_count;
        memcpy(fns, s.on_disconnect, n * sizeof(fns[0]));
    }
    pthread_mutex_unlock(&s.lock);
    for (size_t i = 0; i < n; i++) fns[i]();
}

static void* poll_thread(void* arg) {
    (void)arg;
    for (;;) {
        sleep(POLL_INTERVAL_S);
        const bool now = probe();
        const bool before = atomic_exchange(&s.connected, now);
        if (now != before) {
            KP_LOGI(TAG, "network %s", now ? "up" : "down");
            fire(now);
        }
    }
    return NULL;
}

static void ensure_started(void) {
    pthread_mutex_lock(&s.lock);
    if (!s.thread_started) {
        atomic_store(&s.connected, probe());
        atomic_store(&s.probed, true);
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_t t;
        s.thread_started = pthread_create(&t, &attr, poll_thread, NULL) == 0;
        pthread_attr_destroy(&attr);
    }
    pthread_mutex_unlock(&s.lock);
}

bool kp_net_is_connected(void) {
    if (!atomic_load(&s.probed)) ensure_started();
    return atomic_load(&s.connected);
}

static void add_subscriber(kp_net_event_fn* list, size_t* count, kp_net_event_fn fn, const char* kind) {
    for (size_t i = 0; i < *count; i++) {
        if (list[i] == fn) return;  // modules that re-init subscribe again
    }
    if (*count < MAX_SUBSCRIBERS) list[(*count)++] = fn;
    else KP_LOGE(TAG, "Too many %s subscribers", kind);
}

void kp_net_subscribe(kp_net_event_fn on_connect, kp_net_event_fn on_disconnect) {
    ensure_started();
    pthread_mutex_lock(&s.lock);
    if (on_connect) add_subscriber(s.on_connect, &s.connect_count, on_connect, "connect");
    if (on_disconnect) add_subscriber(s.on_disconnect, &s.disconnect_count, on_disconnect, "disconnect");
    pthread_mutex_unlock(&s.lock);
}

void kp_net_reset(void) {
    KP_LOGW(TAG, "network reset requested; the interfaces belong to the system's network manager, leaving them alone");
}
