// System metrics from /proc and /sys.
//
// On a system without them (macOS, where the port is built for tests and the
// operator tools) only the uptime and the core count are reported.

#include "koios/port/kp_metrics.h"
#include "koios/port/kp_os.h"
#include "kp_linux.h"
#include "kp_metrics_linux.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <unistd.h>

// Where /proc and /sys are. Tests point this at a directory of fixtures.
static char s_root[256] = "";

// CPU counters of the previous sample (the busy share is a difference).
static struct {
    bool valid;
    unsigned long long total, idle;
} s_cpu;

void kp_linux_metrics_set_root(const char* root) {
    snprintf(s_root, sizeof(s_root), "%s", root ? root : "");
    s_cpu.valid = false;
}

static FILE* open_under_root(const char* path) {
    char full[512];
    snprintf(full, sizeof(full), "%s%s", s_root, path);
    return fopen(full, "r");
}

static bool read_line(const char* path, char* line, size_t size) {
    FILE* f = open_under_root(path);
    if (!f) return false;
    const bool ok = fgets(line, (int)size, f) != NULL;
    fclose(f);
    return ok;
}

static bool read_u64(const char* path, unsigned long long* out) {
    char line[64];
    if (!read_line(path, line, sizeof(line))) return false;
    char* end;
    const unsigned long long v = strtoull(line, &end, 10);
    if (end == line) return false;
    *out = v;
    return true;
}

static void sample_uptime(kp_metrics_sample_t* m) {
    char line[64];
    if (read_line("/proc/uptime", line, sizeof(line))) {
        m->uptime_s = (uint32_t)strtod(line, NULL);
    }
    else {
        m->uptime_s = (uint32_t)(kp_monotonic_us() / 1000000);
    }
    m->fields |= KP_METRIC_UPTIME;
}

static void sample_cpu(kp_metrics_sample_t* m) {
    const long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores > 0) {
        m->cpu_cores = (uint16_t)cores;
        m->fields |= KP_METRIC_CPU_CORES;
    }

    // "cpu  user nice system idle iowait irq softirq steal guest guest_nice"
    char line[256];
    if (read_line("/proc/stat", line, sizeof(line)) && strncmp(line, "cpu ", 4) == 0) {
        unsigned long long v[8] = { 0 };
        const int n = sscanf(line + 4, "%llu %llu %llu %llu %llu %llu %llu %llu",
            &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]);
        if (n >= 4) {
            unsigned long long total = 0;
            for (int i = 0; i < n; i++) total += v[i];
            const unsigned long long idle = v[3] + (n > 4 ? v[4] : 0);  // idle + iowait
            if (s_cpu.valid && total > s_cpu.total && idle >= s_cpu.idle) {
                const double dt = (double)(total - s_cpu.total);
                const double di = (double)(idle - s_cpu.idle);
                double pct = 100.0 * (dt - di) / dt;
                if (pct < 0) pct = 0;
                if (pct > 100) pct = 100;
                m->cpu_pct = (float)pct;
                m->fields |= KP_METRIC_CPU_PCT;
            }
            s_cpu.total = total;
            s_cpu.idle = idle;
            s_cpu.valid = true;
        }
    }

    if (read_line("/proc/loadavg", line, sizeof(line))) {
        m->load1 = (float)strtod(line, NULL);
        m->fields |= KP_METRIC_LOAD1;
    }
}

static void sample_memory(kp_metrics_sample_t* m) {
    FILE* f = open_under_root("/proc/meminfo");
    if (!f) return;
    unsigned long long total_kb = 0, avail_kb = 0, free_kb = 0;
    bool have_total = false, have_avail = false, have_free = false;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemTotal: %llu kB", &total_kb) == 1) have_total = true;
        else if (sscanf(line, "MemAvailable: %llu kB", &avail_kb) == 1) have_avail = true;
        else if (sscanf(line, "MemFree: %llu kB", &free_kb) == 1) have_free = true;
    }
    fclose(f);
    if (have_total && (have_avail || have_free)) {
        m->mem_total_bytes = total_kb * 1024;
        m->mem_free_bytes = (have_avail ? avail_kb : free_kb) * 1024;
        m->fields |= KP_METRIC_MEM;
    }
}

static void sample_storage(kp_metrics_sample_t* m) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    struct statvfs st;
    if (!cfg->storage_path || statvfs(cfg->storage_path, &st) != 0 || st.f_blocks == 0) return;
    m->storage_total_bytes = (uint64_t)st.f_blocks * st.f_frsize;
    m->storage_free_bytes = (uint64_t)st.f_bavail * st.f_frsize;
    m->fields |= KP_METRIC_STORAGE;
}

// The hottest thermal zone. A zone that cannot be read (some are switched
// off) or reports nonsense is skipped.
static void sample_temperature(kp_metrics_sample_t* m) {
    double hottest = -1000;
    for (int zone = 0; zone < 32; zone++) {
        char path[96], line[32];
        snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", zone);
        if (!read_line(path, line, sizeof(line))) {
            // Zones are numbered without gaps on the kernels seen so far, but
            // a missing one is not proof that the next is missing too.
            if (zone >= 8) break;
            continue;
        }
        char* end;
        const long milli = strtol(line, &end, 10);
        if (end == line) continue;
        const double c = milli / 1000.0;
        if (c < -40 || c > 150) continue;
        if (c > hottest) hottest = c;
    }
    if (hottest > -1000) {
        m->temp_c = (float)hottest;
        m->fields |= KP_METRIC_TEMP;
    }
}

// The interface of the default route with the lowest metric.
static bool default_route_iface(char* iface, size_t size) {
    FILE* f = open_under_root("/proc/net/route");
    if (!f) return false;
    char line[256];
    bool found = false;
    unsigned long best_metric = 0;
    if (fgets(line, sizeof(line), f)) {  // header
        while (fgets(line, sizeof(line), f)) {
            char name[16];  // IFNAMSIZ
            unsigned long dest, gateway, flags, refcnt, use, metric;
            if (sscanf(line, "%15s %lx %lx %lx %lu %lu %lu", name, &dest, &gateway, &flags,
                    &refcnt, &use, &metric) != 7) continue;
            if (dest != 0 || !(flags & 0x1)) continue;  // not a default route that is up
            if (!found || metric < best_metric) {
                snprintf(iface, size, "%s", name);
                best_metric = metric;
                found = true;
            }
        }
    }
    fclose(f);
    return found;
}

static void sample_network(kp_metrics_sample_t* m) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    char iface[16] = "";
    if (cfg->net_iface) snprintf(iface, sizeof(iface), "%s", cfg->net_iface);
    else if (!default_route_iface(iface, sizeof(iface))) return;

    // An interface name becomes part of a path: letters, digits and a few
    // punctuation marks only.
    for (const char* p = iface; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' && *p != '.') return;
    }

    char path[128];
    unsigned long long rx, tx;
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", iface);
    const bool have_rx = read_u64(path, &rx);
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", iface);
    if (have_rx && read_u64(path, &tx)) {
        snprintf(m->net_iface, sizeof(m->net_iface), "%s", iface);
        m->net_rx_bytes = rx;
        m->net_tx_bytes = tx;
        m->fields |= KP_METRIC_NET_COUNTERS;
    }

    // "wlan0: 0000   54.  -56.  -256        0      0 ..."  (status, link, level, noise)
    FILE* f = open_under_root("/proc/net/wireless");
    if (!f) return;
    char line[256];
    const size_t nl = strlen(iface);
    while (fgets(line, sizeof(line), f)) {
        const char* p = line;
        while (*p == ' ') p++;
        if (strncmp(p, iface, nl) != 0 || p[nl] != ':') continue;
        unsigned status;
        double link, level;
        if (sscanf(p + nl + 1, "%x %lf. %lf.", &status, &link, &level) == 3 ||
            sscanf(p + nl + 1, "%x %lf %lf", &status, &link, &level) == 3) {
            if (level < 0 && level > -150) {
                m->net_rssi_dbm = (int16_t)level;
                m->fields |= KP_METRIC_NET_RSSI;
            }
        }
        break;
    }
    fclose(f);
}

static void sample_tasks(kp_metrics_sample_t* m) {
    char path[300];
    snprintf(path, sizeof(path), "%s/proc", s_root);
    DIR* dir = opendir(path);
    if (!dir) return;
    uint32_t count = 0;
    struct dirent* e;
    while ((e = readdir(dir)) != NULL) {
        if (isdigit((unsigned char)e->d_name[0])) count++;
    }
    closedir(dir);
    if (count > 0) {
        m->tasks = count;
        m->fields |= KP_METRIC_TASKS;
    }
}

void kp_metrics_sample(kp_metrics_sample_t* out) {
    memset(out, 0, sizeof(*out));
    sample_uptime(out);
    sample_cpu(out);
    sample_memory(out);
    sample_storage(out);
    sample_temperature(out);
    sample_network(out);
    sample_tasks(out);
}
