#pragma once

// System metrics port. The core decides when to sample, how many samples to
// keep while offline and how they are serialised (core/metrics.c); the port
// knows how to read the numbers on its platform. One sample shape serves
// every port: a port fills in what it has and sets the matching bit.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KP_METRIC_UPTIME        (1u << 0)   // uptime_s
#define KP_METRIC_CPU_PCT       (1u << 1)   // cpu_pct
#define KP_METRIC_CPU_CORES     (1u << 2)   // cpu_cores
#define KP_METRIC_LOAD1         (1u << 3)   // load1
#define KP_METRIC_MEM           (1u << 4)   // mem_total_bytes, mem_free_bytes
#define KP_METRIC_MEM_MIN_FREE  (1u << 5)   // mem_min_free_bytes
#define KP_METRIC_MEM_LARGEST   (1u << 6)   // mem_largest_block_bytes
#define KP_METRIC_MEM_INTERNAL  (1u << 7)   // mem_internal_free_bytes
#define KP_METRIC_STORAGE       (1u << 8)   // storage_total_bytes, storage_free_bytes
#define KP_METRIC_TEMP          (1u << 9)   // temp_c
#define KP_METRIC_NET_COUNTERS  (1u << 10)  // net_iface, net_rx_bytes, net_tx_bytes
#define KP_METRIC_NET_RSSI      (1u << 11)  // net_rssi_dbm
#define KP_METRIC_TASKS         (1u << 12)  // tasks
#define KP_METRIC_RESET_REASON  (1u << 13)  // reset_reason

typedef struct {
    uint32_t fields;  // KP_METRIC_* bits: which members below are valid

    uint32_t uptime_s;                 // since boot

    float    cpu_pct;                  // busy share of all cores since the previous sample, 0..100
    uint16_t cpu_cores;
    float    load1;                    // 1-minute load average

    uint64_t mem_total_bytes;          // RAM (Linux) or heap (MCU)
    uint64_t mem_free_bytes;           // available to applications
    uint64_t mem_min_free_bytes;       // lowest mem_free ever seen since boot
    uint64_t mem_largest_block_bytes;  // largest block one allocation could get
    uint64_t mem_internal_free_bytes;  // free internal RAM where the heap also spans external RAM

    uint64_t storage_total_bytes;      // the filesystem the device keeps its data on
    uint64_t storage_free_bytes;

    float    temp_c;                   // hottest sensor the platform exposes

    char     net_iface[16];            // the uplink
    uint64_t net_rx_bytes;             // counters since boot
    uint64_t net_tx_bytes;
    int16_t  net_rssi_dbm;             // when the uplink is a radio

    uint32_t tasks;                    // processes (Linux) or RTOS tasks (MCU)

    char     reset_reason[20];         // why the device last started, e.g. "poweron", "panic"
} kp_metrics_sample_t;

// Take one sample. The port zeroes *out, fills what it can and sets `fields`.
// Called from the metrics task every reporting interval; it may block briefly
// (file reads) but must not take seconds.
void kp_metrics_sample(kp_metrics_sample_t* out);

#ifdef __cplusplus
}
#endif
