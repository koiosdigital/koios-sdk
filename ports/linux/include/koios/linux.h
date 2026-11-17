#pragma once

// Linux port of the Koios SDK: configuration and the few entry points that
// exist only on Linux. Call koios_linux_init() once, before any other SDK
// call; the kp_* ports read their settings from what it stores.
//
// The port uses POSIX threads, OpenSSL 3 (TLS, the WebSocket client, SHA-256,
// and private keys held behind a provider such as PKCS#11) and libcurl (HTTP).
// It also builds on macOS, which is what the tests and the operator tools use.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // ---- Identity (mTLS) ----------------------------------------------------
    // PEM file with the device certificate first and its intermediates after
    // it. Every certificate in it is presented in the TLS handshake.
    const char* cert_file;
    // Optional PEM file with further intermediates to present (appended when
    // not already in cert_file). Use it when the chain on disk stops short of
    // what the server's trust anchor needs.
    const char* extra_chain_file;
    // The private key: a URI an OpenSSL provider understands
    // ("pkcs11:token=...;object=...;type=private") or the path of a PEM file.
    // With a URI the key never enters this process: OpenSSL signs through the
    // provider. Nothing ever prompts for a PIN; a provider that asks gets an
    // empty one.
    const char* key;
    // Optional: the identity counts as ready only once this file exists
    // (for example a "provisioned" marker written by the factory tooling).
    const char* identity_ready_file;

    // ---- TLS trust ----------------------------------------------------------
    // PEM bundle of the roots servers must chain to. NULL: the system's roots.
    const char* ca_file;

    // ---- What this device reports about itself ------------------------------
    const char* device_class;  // fw.class; NULL: "linux-<machine>" from uname
    const char* project;       // fw.project
    const char* version;       // fw.version

    // ---- State ---------------------------------------------------------------
    // Persistent directory (log ring, pending-update record). NULL: none, the
    // log ring lives in memory and a pending update is forgotten on restart.
    const char* state_dir;
    // Directory that survives a restart of the process but not a reboot
    // (a tmpfs such as /run/koios): restart counters. NULL: memory only.
    const char* runtime_dir;

    // ---- Logs -----------------------------------------------------------------
    size_t log_ring_bytes;  // 0 -> 256 KiB
    // Lowest level written to stderr: 0 error, 1 warn, 2 info (default), 3 debug.
    int log_level;
    // Capture the SDK's own log lines into the ship ring. Lines pushed with
    // koios_linux_log_push() are captured either way.
    bool capture_own_logs;

    // ---- Metrics ---------------------------------------------------------------
    const char* storage_path;  // filesystem to report; NULL: "/"
    const char* net_iface;     // NULL: the interface of the default route

    // ---- Updates ---------------------------------------------------------------
    // The port never writes a partition. An update is downloaded into
    // ota_staging_dir and verified; then ota_apply_cmd runs with the file's
    // path, the version and the update id as arguments and must install it
    // WITHOUT restarting. Exit status 0 means installed. ota_restart_cmd runs
    // afterwards to restart into it. Without ota_apply_cmd every update fails
    // with "failed_flash" (do not start koios_ota on such a device).
    const char* ota_staging_dir;
    const char* ota_apply_cmd;
    const char* ota_restart_cmd;

    // ---- Restart ---------------------------------------------------------------
    // Called when the SDK asks for a restart (cloudlink's last escalation
    // step). NULL: the process exits with status 75 and its supervisor
    // restarts it. The machine is never rebooted by the port.
    void (*restart_handler)(void);
} koios_linux_config_t;

// Store the configuration (strings are copied) and set the port up. Returns
// 0, or -1 when a directory cannot be created.
int koios_linux_init(const koios_linux_config_t* cfg);

// Push one log line into the ship ring from outside the SDK (a journal
// follower, an application). level is a koios_log_level_t; ts_ms is the wall
// clock in milliseconds, 0 when unknown.
void koios_linux_log_push(int level, const char* tag, const char* msg, int64_t ts_ms);

// The process status kp_system_restart() exits with when no restart handler
// is set: EX_TEMPFAIL, "try again".
#define KOIOS_LINUX_EXIT_RESTART 75

#ifdef __cplusplus
}
#endif
