#pragma once

// One end of a console session: a WebSocket to the gateway's relay on one
// side, a local byte stream on the other. Used by both ends: the device
// (koios-agent: the local stream is one of its targets: a TCP connection, a
// Unix socket or a program it starts, see connect_target in console_stream.c)
// and the operator (koios-console: the local stream is stdin and stdout, for
// ssh's ProxyCommand).
//
// On the wire, binary messages are the stream. Text messages are the two
// ends' control:
//
//   relay  -> device    {"type":"start"}            the operator is there
//   device -> operator  {"type":"ready"}            the target is connected
//   device -> operator  {"type":"error","reason"}   it could not be
//   either -> other     {"type":"ack","bytes":N}    N bytes of the stream were
//                                                   written out locally
//
// Flow control is between the two ends, through the relay: an end sends at
// most KS_WINDOW bytes beyond what the other has acknowledged. The relay
// therefore never holds more than a window, however fast one end reads and
// however slowly the other writes.

#include <stdbool.h>
#include <stddef.h>

#define KS_WINDOW    (256 * 1024)
#define KS_ACK_EVERY (32 * 1024)
#define KS_CHUNK     (16 * 1024)

typedef enum {
    KS_ROLE_DEVICE,
    KS_ROLE_OPERATOR,
} ks_role_t;

typedef struct {
    ks_role_t role;
    const char* url;        // the session's WebSocket for this role
    const char* bearer;     // device: its device JWT
    const char* protocols;  // operator: "koios.console.v1, ticket.<ticket>"
    bool present_identity;  // device, on an mTLS gateway: show the certificate too

    const char* target_address;  // device: host:port, unix:/path or exec:/path; connected when told to start
    int in_fd;                   // operator: the local stream (stdin, stdout)
    int out_fd;
} ks_config_t;

#define KS_OK          0  // the stream ran and ended
#define KS_NOT_STARTED 1  // it never ran; `reason` says why

// Run this end to the end of the session; blocking. `reason` gets a sentence
// for a person when the result is not KS_OK.
int ks_run(const ks_config_t* cfg, char* reason, size_t reason_size);
