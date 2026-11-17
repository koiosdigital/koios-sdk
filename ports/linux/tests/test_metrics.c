// The Linux metrics sampler against a directory of /proc and /sys fixtures
// (values copied from a Jetson Orin NX and from a laptop on Wi-Fi).

#include "check.h"

#include "koios/linux.h"
#include "koios/port/kp_metrics.h"
#include "../kp_metrics_linux.h"

#include <math.h>
#include <stdlib.h>
#include <sys/stat.h>

static char s_root[400];

static void put_file(const char* rel, const char* content) {
    char path[600], dir[600];
    snprintf(path, sizeof(path), "%s%s", s_root, rel);
    snprintf(dir, sizeof(dir), "%s", path);
    for (char* p = dir + strlen(s_root) + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        mkdir(dir, 0755);
        *p = '/';
    }
    FILE* f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "cannot write %s\n", path);
        exit(2);
    }
    fputs(content, f);
    fclose(f);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s SCRATCH_DIR\n", argv[0]);
        return 2;
    }
    snprintf(s_root, sizeof(s_root), "%s/metrics-root", argv[1]);
    mkdir(s_root, 0755);

    const koios_linux_config_t cfg = { .storage_path = argv[1] };
    koios_linux_init(&cfg);
    kp_linux_metrics_set_root(s_root);

    put_file("/proc/uptime", "93784.52 721234.11\n");
    put_file("/proc/loadavg", "0.42 0.37 0.30 2/391 12345\n");
    put_file("/proc/meminfo",
        "MemTotal:       15827052 kB\n"
        "MemFree:         9123456 kB\n"
        "MemAvailable:   12345678 kB\n"
        "Buffers:          123456 kB\n");
    put_file("/proc/stat",
        "cpu  1000 0 500 8000 500 0 0 0 0 0\n"
        "cpu0 125 0 62 1000 62 0 0 0 0 0\n");
    put_file("/proc/net/route",
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "wlan0\t00000000\t0100000A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
        "eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FCFFFF\t0\t0\t0\n");
    put_file("/sys/class/net/eth0/statistics/rx_bytes", "123456789012\n");
    put_file("/sys/class/net/eth0/statistics/tx_bytes", "9876543210\n");
    put_file("/sys/class/net/wlan0/statistics/rx_bytes", "111\n");
    put_file("/sys/class/net/wlan0/statistics/tx_bytes", "222\n");
    put_file("/proc/net/wireless",
        "Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n"
        " face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n"
        " wlan0: 0000   54.  -56.  -256        0      0      0      0      0        0\n");
    put_file("/sys/class/thermal/thermal_zone0/temp", "48250\n");
    put_file("/sys/class/thermal/thermal_zone1/temp", "51500\n");
    put_file("/sys/class/thermal/thermal_zone2/temp", "-274000\n");  // a sensor that is off
    put_file("/proc/1/stat", "");
    put_file("/proc/217/stat", "");
    put_file("/proc/4001/stat", "");
    put_file("/proc/self/stat", "");  // not a process id

    kp_metrics_sample_t m;
    kp_metrics_sample(&m);

    CHECK(m.fields & KP_METRIC_UPTIME);
    CHECK_EQ(m.uptime_s, 93784);
    CHECK(m.fields & KP_METRIC_LOAD1);
    CHECK(fabsf(m.load1 - 0.42f) < 0.001f);
    CHECK(m.fields & KP_METRIC_CPU_CORES);
    CHECK(m.cpu_cores >= 1);
    CHECK(!(m.fields & KP_METRIC_CPU_PCT));  // a share needs two samples

    CHECK(m.fields & KP_METRIC_MEM);
    CHECK_EQ(m.mem_total_bytes, 15827052ull * 1024);
    CHECK_EQ(m.mem_free_bytes, 12345678ull * 1024);  // MemAvailable, not MemFree

    CHECK(m.fields & KP_METRIC_STORAGE);
    CHECK(m.storage_total_bytes > 0 && m.storage_free_bytes <= m.storage_total_bytes);

    CHECK(m.fields & KP_METRIC_TEMP);
    CHECK(fabsf(m.temp_c - 51.5f) < 0.01f);  // the hottest, and not the broken one

    CHECK(m.fields & KP_METRIC_NET_COUNTERS);
    CHECK_STR(m.net_iface, "eth0");  // the default route with the lowest metric
    CHECK_EQ(m.net_rx_bytes, 123456789012ull);
    CHECK_EQ(m.net_tx_bytes, 9876543210ull);
    CHECK(!(m.fields & KP_METRIC_NET_RSSI));  // the uplink is wired

    CHECK(m.fields & KP_METRIC_TASKS);
    CHECK_EQ(m.tasks, 3);
    CHECK(!(m.fields & KP_METRIC_RESET_REASON));

    // Second sample: 1000 more jiffies, 250 of them busy.
    put_file("/proc/stat", "cpu  1150 0 600 8700 550 0 0 0 0 0\n");
    kp_metrics_sample(&m);
    CHECK(m.fields & KP_METRIC_CPU_PCT);
    CHECK(fabsf(m.cpu_pct - 25.0f) < 0.01f);

    // Wi-Fi uplink once the wired route is gone.
    put_file("/proc/net/route",
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "wlan0\t00000000\t0100000A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n");
    kp_metrics_sample(&m);
    CHECK_STR(m.net_iface, "wlan0");
    CHECK_EQ(m.net_rx_bytes, 111);
    CHECK(m.fields & KP_METRIC_NET_RSSI);
    CHECK_EQ(m.net_rssi_dbm, -56);

    // Nothing to read at all: only what needs no file.
    char empty[450];
    snprintf(empty, sizeof(empty), "%s/empty", s_root);
    mkdir(empty, 0755);
    kp_linux_metrics_set_root(empty);
    kp_metrics_sample(&m);
    CHECK(m.fields & KP_METRIC_UPTIME);
    CHECK(!(m.fields & (KP_METRIC_MEM | KP_METRIC_TEMP | KP_METRIC_NET_COUNTERS | KP_METRIC_TASKS | KP_METRIC_LOAD1)));

    CHECK_DONE();
}
