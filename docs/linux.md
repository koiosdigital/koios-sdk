# The Linux port and `koios-agent`

`ports/linux` implements the `kp_*` contracts on POSIX threads, OpenSSL 3 and
libcurl. `koios-agent` is a small daemon on top of it that makes a Linux
machine a Koios device: it holds the cloudlink session, reports what the
machine runs, ships its journal, reports system metrics, and hands updates to
an installer the system provides.

An application can also link `libkoios_sdk.a` and call the SDK directly, the
way a firmware does; `ports/linux/include/koios/linux.h` is the one extra
header (`koios_linux_init()` takes the settings a Kconfig would hold).

## Build

```sh
cmake -S . -B build && cmake --build build && ctest --test-dir build
```

Needs OpenSSL 3, libcurl, cJSON and a C11 compiler. On macOS (for the tests
and the operator tools) point CMake at Homebrew's OpenSSL and at a cJSON
source directory:

```sh
cmake -S . -B build -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 -DKOIOS_CJSON_DIR=/path/to/cJSON
```

`ports/linux/tests/run-in-container.sh` builds with `-Werror` in a Debian
container, runs every test, and runs the end-to-end test a second time with
the device key in a PKCS#11 token (SoftHSM behind OpenSSL's pkcs11 provider).

## How each port is done

| Port | On Linux |
|---|---|
| `kp_os` | pthreads. Mutexes and semaphores are a flag under a lock, because the core needs timed takes. One timer thread. Task stack sizes and priorities are ignored |
| `kp_log` | stderr, with journald's `<N>` priority prefix under systemd |
| `kp_logstore` | the same byte ring as on an MCU, in a file-backed mapping under the state directory, so lines survive a crash or restart of the process |
| `kp_net` | "connected" = an interface other than the loopback is up with a routable address; polled every 2 s. `kp_net_reset()` only logs: the interfaces belong to the system |
| `kp_http` | libcurl |
| `kp_identity` | certificate chain from a PEM file; the key through OpenSSL's store, so a `pkcs11:` URI works and the key never enters the process |
| `kp_websocket` | a client written on OpenSSL (RFC 6455), one thread per connection |
| `kp_ota` | downloads to a staging directory, checks size and SHA-256, runs the system's installer. Never writes a partition |
| `kp_metrics` | `/proc` and `/sys` |

Two things differ from an MCU on purpose:

- **"Restart the device" restarts the process.** `kp_system_restart()` exits
  with status 75 and the supervisor starts the agent again (`Restart=always`).
  The restart counters live in the runtime directory (a tmpfs), so they
  survive that and are cleared by a reboot, as RTC memory is by a power cycle.
  The machine is never rebooted by the SDK.
- **The network is not bounced.** NetworkManager or systemd-networkd owns it.

## Identity

```ini
[identity]
cert = /var/lib/luka/identity/chain.pem
extra_chain = /etc/luka/terranova-systems-g1.pem
key = pkcs11:token=luka-id;object=k-sign;type=private
ready_file = /var/lib/luka/identity/provisioned
```

- `cert` holds the device certificate first, then its intermediates. All of
  them go into the TLS handshake. `extra_chain` adds further intermediates
  when the file stops short of what the gateway's trust anchor needs; a
  certificate already present, and any self-signed one, is left out.
- `key` is a file, or a URI an OpenSSL provider serves. For a URI the process
  must run with an OpenSSL configuration that loads the provider
  (`OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf`) and must be allowed to reach
  the token (on OP-TEE: group `teeclnt`).
- **No PIN is ever asked for.** A provider that prompts gets an empty PIN,
  which is how a token that logs callers in by their identity is opened. A
  token that does need a PIN takes it from the URI (`?pin-value=`), and then
  the configuration file is a secret.
- The agent does not renew the certificate. If the gateway asks
  (`cert.renew_required`), it declines; renewal belongs to whoever issued it.

## Configuration

`/etc/koios/agent.conf`; `koios-agent --check` reads it and prints what would
run. Every key, with its default:

```ini
[cloud]
url = wss://vn-sec.koios.sh
auth = mtls                      # or api_key
api_key_file =                   # api_key: read from here; a key the gateway issues is written back
ca_file =                        # roots to trust; empty = the system's

[identity]                       # auth = mtls
cert =
extra_chain =
key =
ready_file =

[device]
class =                          # fw.class; empty = linux-<arch>. Must be a class the platform knows
project =                        # fw.project;  empty = ID of os_release
version =                        # fw.version;  empty = VERSION_ID
variant =                        # fw.variant;  empty = VARIANT_ID
os_release = /etc/os-release
facts_file =                     # a JSON object merged into the reported twin, re-read when it changes

[state]
dir = /var/lib/koios             # log ring, journal cursor, pending update
runtime_dir = /run/koios         # restart counters (tmpfs)

[logs]
enabled = yes
journal = yes                    # follow the systemd journal (journalctl)
journal_priority = info          # this and more severe
journal_backlog = 200            # lines of history on the very first start
ring_bytes = 262144

[metrics]
enabled = yes
interval_s = 60                  # the twin's desired.koios.metrics.interval_s overrides it
storage_path = /                 # the filesystem to report
net_iface =                      # empty = the default route's

[ota]
enabled = no
endpoint = https://ota.api.koios.sh
staging_dir =                    # empty = <state dir>/ota
apply_cmd =                      # required when enabled
restart_cmd =

[console]
enabled = no
target.ssh = 127.0.0.1:22        # the only addresses the device will ever connect a session to
```

## What it reports

On every session, as twin reported state:

```json
{"fw":  {"class": "tegra234", "version": "0.1.0+33c7d7b", "project": "luka", "variant": "zedbox2-orin-nx"},
 "sys": {"hostname": "luka-best-feeling", "os": "Terranova Luka 0.1.0", "kernel": "6.8.12", "arch": "aarch64", "agent": "0.1.0"}}
```

plus whatever `facts_file` holds (for example the installed extensions).
`fw` and `sys` are the agent's; a facts file cannot replace them.

Logs: the agent's own lines and, with `journal = yes`, every journal entry of
the configured priority, with the entry's own timestamp, its priority as the
level and its `SYSLOG_IDENTIFIER` as the tag. The journal is read by
`journalctl --follow --output=json`; the cursor is kept in the state directory
so a restart continues where it stopped.

Metrics: see `include/koios/metrics.h`.

## Updates

The agent never installs anything itself. With `[ota] enabled = yes` it takes
offers from the Koios OTA service, downloads the image into the staging
directory (resuming a dropped transfer), checks its size and SHA-256 against
the offer, and runs

```
<apply_cmd> <file> <version> <update id>
```

which must install the image **without restarting** and exit 0. The agent
then reports `rebooting` and runs `restart_cmd`. After the restart it compares
the version it now reports with the one it was installing and reports
`confirmed` or `rolled_back`. The command line is split on blanks and run
without a shell.

The installer is where the image's signature is checked. The SHA-256 in an
offer proves the download is what Koios meant to send, not that the image is
one the device should run.

## Tests

| Test | What it proves |
|---|---|
| `os`, `os_slots_survive` | timed takes, timers, restart-surviving slots across two processes |
| `logstore_*` | ring order, eviction, consume after an eviction, survival across two processes |
| `metrics` | the `/proc` and `/sys` parsers against fixtures |
| `websocket` | framing both ways against a scripted server (three length forms, fragments, a ping between fragments, bytes one at a time, the size bound), and how each kind of failure is classified |
| `agent_e2e` | the agent binary against a mock gateway with mutual TLS and a mock OTA service: gate on the provisioned marker, a three-level chain completed from `extra_chain`, twin reports, the metrics interval from the desired twin, log shipping, an update through a fake installer with a resumed download, confirmation after the restart, reconnect after the gateway closes the session |
