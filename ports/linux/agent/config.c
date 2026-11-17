#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static char* trim(char* s) {
    while (isspace((unsigned char)*s)) s++;
    char* end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = '\0';
    return s;
}

static void set_str(char** slot, const char* value) {
    free(*slot);
    *slot = value[0] ? strdup(value) : NULL;
}

static bool parse_bool(const char* v, bool* out) {
    if (!strcasecmp(v, "yes") || !strcasecmp(v, "true") || !strcasecmp(v, "on") || !strcmp(v, "1")) {
        *out = true;
        return true;
    }
    if (!strcasecmp(v, "no") || !strcasecmp(v, "false") || !strcasecmp(v, "off") || !strcmp(v, "0")) {
        *out = false;
        return true;
    }
    return false;
}

static bool parse_uint(const char* v, unsigned long max, unsigned long* out) {
    char* end;
    const unsigned long n = strtoul(v, &end, 10);
    if (end == v || *end != '\0' || n > max) return false;
    *out = n;
    return true;
}

static bool parse_priority(const char* v, int* out) {
    static const char* names[] = { "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug" };
    for (int i = 0; i < 8; i++) {
        if (!strcasecmp(v, names[i])) {
            *out = i;
            return true;
        }
    }
    if (!strcasecmp(v, "error")) { *out = 3; return true; }
    if (!strcasecmp(v, "warn")) { *out = 4; return true; }
    unsigned long n;
    if (parse_uint(v, 7, &n)) { *out = (int)n; return true; }
    return false;
}

// Returns NULL when the key was understood, else what is wrong with it.
static const char* apply(agent_config_t* c, const char* section, const char* key, const char* value) {
    unsigned long n;
#define STR(sec, k, field) if (!strcmp(section, sec) && !strcmp(key, k)) { set_str(&c->field, value); return NULL; }
#define BOOL(sec, k, field) if (!strcmp(section, sec) && !strcmp(key, k)) { \
        return parse_bool(value, &c->field) ? NULL : "expected yes or no"; }

    STR("cloud", "url", url)
    STR("cloud", "api_key_file", api_key_file)
    STR("cloud", "ca_file", ca_file)
    if (!strcmp(section, "cloud") && !strcmp(key, "auth")) {
        if (!strcmp(value, "mtls")) c->mtls = true;
        else if (!strcmp(value, "api_key")) c->mtls = false;
        else return "expected mtls or api_key";
        return NULL;
    }

    STR("identity", "cert", cert)
    STR("identity", "extra_chain", extra_chain)
    STR("identity", "key", key)
    STR("identity", "ready_file", ready_file)

    STR("device", "class", device_class)
    STR("device", "project", project)
    STR("device", "version", version)
    STR("device", "variant", variant)
    STR("device", "os_release", os_release)
    STR("device", "facts_file", facts_file)

    STR("state", "dir", state_dir)
    STR("state", "runtime_dir", runtime_dir)

    BOOL("logs", "enabled", logs)
    BOOL("logs", "journal", journal)
    if (!strcmp(section, "logs") && !strcmp(key, "journal_priority")) {
        return parse_priority(value, &c->journal_priority) ? NULL : "expected a syslog priority (emerg..debug)";
    }
    if (!strcmp(section, "logs") && !strcmp(key, "journal_backlog")) {
        if (!parse_uint(value, 10000, &n)) return "expected a number of lines (0..10000)";
        c->journal_backlog = (int)n;
        return NULL;
    }
    if (!strcmp(section, "logs") && !strcmp(key, "ring_bytes")) {
        if (!parse_uint(value, 64ul << 20, &n) || n < 4096) return "expected a size in bytes (4096..64 MiB)";
        c->ring_bytes = n;
        return NULL;
    }

    BOOL("metrics", "enabled", metrics)
    STR("metrics", "storage_path", storage_path)
    STR("metrics", "net_iface", net_iface)
    if (!strcmp(section, "metrics") && !strcmp(key, "interval_s")) {
        if (!parse_uint(value, 3600, &n) || n < 10) return "expected seconds (10..3600)";
        c->metrics_interval_s = (uint32_t)n;
        return NULL;
    }

    BOOL("ota", "enabled", ota)
    STR("ota", "endpoint", ota_endpoint)
    STR("ota", "staging_dir", ota_staging_dir)
    STR("ota", "apply_cmd", ota_apply_cmd)
    STR("ota", "restart_cmd", ota_restart_cmd)

    BOOL("console", "enabled", console)
    if (!strcmp(section, "console") && !strncmp(key, "target.", 7)) {
        const char* name = key + 7;
        if (!name[0] || strlen(name) >= sizeof(c->console_targets[0].name)) return "target name too long";
        for (const char* p = name; *p; p++) {
            if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') return "target names are letters, digits, - and _";
        }
        if (!strchr(value, ':') || strlen(value) >= sizeof(c->console_targets[0].address)) {
            return "expected host:port";
        }
        if (c->console_target_count >= AGENT_MAX_CONSOLE_TARGETS) return "too many console targets";
        agent_console_target_t* t = &c->console_targets[c->console_target_count++];
        snprintf(t->name, sizeof(t->name), "%s", name);
        snprintf(t->address, sizeof(t->address), "%s", value);
        return NULL;
    }
#undef STR
#undef BOOL
    return "unknown key";
}

int agent_config_load(const char* path, agent_config_t* c, char* err, size_t err_size) {
    memset(c, 0, sizeof(*c));
    c->mtls = true;
    c->logs = true;
    c->journal = true;
    c->journal_priority = 6;
    c->journal_backlog = 200;
    c->metrics = true;
    c->metrics_interval_s = 60;
    set_str(&c->url, "wss://vn-sec.koios.sh");
    set_str(&c->os_release, "/etc/os-release");
    set_str(&c->state_dir, "/var/lib/koios");
    set_str(&c->runtime_dir, "/run/koios");
    set_str(&c->storage_path, "/");

    FILE* f = fopen(path, "r");
    if (!f) {
        snprintf(err, err_size, "%s: cannot open", path);
        return -1;
    }
    char line[1024], section[32] = "";
    int lineno = 0, rc = 0;
    while (rc == 0 && fgets(line, sizeof(line), f)) {
        lineno++;
        char* s = trim(line);
        if (!*s || *s == '#' || *s == ';') continue;
        if (*s == '[') {
            char* end = strchr(s, ']');
            if (!end || (size_t)(end - s - 1) >= sizeof(section)) {
                snprintf(err, err_size, "%s:%d: malformed section", path, lineno);
                rc = -1;
                break;
            }
            *end = '\0';
            snprintf(section, sizeof(section), "%s", trim(s + 1));
            continue;
        }
        char* eq = strchr(s, '=');
        if (!eq) {
            snprintf(err, err_size, "%s:%d: expected key = value", path, lineno);
            rc = -1;
            break;
        }
        *eq = '\0';
        const char* key = trim(s);
        const char* value = trim(eq + 1);
        const char* problem = apply(c, section, key, value);
        if (problem) {
            snprintf(err, err_size, "%s:%d: [%s] %s: %s", path, lineno, section, key, problem);
            rc = -1;
        }
    }
    fclose(f);
    if (rc != 0) return rc;

    if (!c->url || (strncmp(c->url, "wss://", 6) != 0 && strncmp(c->url, "ws://", 5) != 0)) {
        snprintf(err, err_size, "%s: [cloud] url must start with wss:// (or ws:// for a test gateway)", path);
        return -1;
    }
    if (c->mtls && (!c->cert || !c->key)) {
        snprintf(err, err_size, "%s: auth = mtls needs [identity] cert and key", path);
        return -1;
    }
    if (!c->mtls && !c->api_key_file) {
        snprintf(err, err_size, "%s: auth = api_key needs [cloud] api_key_file", path);
        return -1;
    }
    if (c->ota && !c->ota_apply_cmd) {
        snprintf(err, err_size, "%s: [ota] enabled needs apply_cmd (the installer that takes the image)", path);
        return -1;
    }
    return 0;
}

char* agent_os_release_value(const char* path, const char* key) {
    FILE* f = path ? fopen(path, "r") : NULL;
    if (!f) return NULL;
    const size_t kl = strlen(key);
    char line[512];
    char* found = NULL;
    while (!found && fgets(line, sizeof(line), f)) {
        char* s = trim(line);
        if (strncmp(s, key, kl) != 0 || s[kl] != '=') continue;
        char* v = s + kl + 1;
        const size_t n = strlen(v);
        if (n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n - 1] == v[0]) {
            v[n - 1] = '\0';
            v++;
        }
        found = strdup(v);
    }
    fclose(f);
    return found;
}
