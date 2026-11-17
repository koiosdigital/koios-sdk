#pragma once

// koios-agent's configuration file: sections of `key = value` lines.
//
//   [cloud]
//   url = wss://vn-sec.koios.sh
//   auth = mtls
//
// '#' and ';' start a comment. Values are taken as written, without quotes.
// docs/linux.md lists every key.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AGENT_MAX_CONSOLE_TARGETS 8

typedef struct {
    char name[24];
    char address[256];  // host:port on this device, unix:/path or exec:/path with arguments
} agent_console_target_t;

typedef struct {
    // [cloud]
    char* url;
    bool mtls;            // auth = mtls | api_key
    char* api_key_file;   // api_key mode: where the key is read from and an issued one is written
    char* ca_file;

    // [identity]
    char* cert;
    char* extra_chain;
    char* key;
    char* ready_file;

    // [device]
    char* device_class;
    char* project;
    char* version;
    char* variant;
    char* os_release;     // file the three above default from
    char* facts_file;     // JSON object merged into the reported twin

    // [state]
    char* state_dir;
    char* runtime_dir;

    // [logs]
    bool logs;
    bool journal;
    int journal_priority; // 0 (emerg) .. 7 (debug): ship this and more severe
    int journal_backlog;  // lines of history shipped on the very first start
    size_t ring_bytes;

    // [metrics]
    bool metrics;
    uint32_t metrics_interval_s;
    char* storage_path;
    char* net_iface;

    // [ota]
    bool ota;
    char* ota_endpoint;
    char* ota_staging_dir;
    char* ota_apply_cmd;
    char* ota_restart_cmd;

    // [console]
    bool console;
    agent_console_target_t console_targets[AGENT_MAX_CONSOLE_TARGETS];
    size_t console_target_count;
} agent_config_t;

// Fill cfg with the defaults, then with what the file says. Returns 0; on a
// problem it returns -1 and writes a message (file, line, what) into err.
int agent_config_load(const char* path, agent_config_t* cfg, char* err, size_t err_size);

// Value of KEY in an os-release style file (KEY=value or KEY="value"),
// malloc'd, or NULL.
char* agent_os_release_value(const char* path, const char* key);
