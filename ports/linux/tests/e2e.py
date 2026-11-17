#!/usr/bin/env python3
"""End-to-end test of koios-agent against a mock Koios.

What is real: the agent binary, its TLS stack, the certificate chain it
presents, every frame it sends. What is mocked: the gateway (a WebSocket
server with mutual TLS that speaks vn's control frames) and the OTA service
(the three device-plane endpoints). Standard library only, plus the openssl
command line to make the test PKI.

The PKI has the shape of a Luka box's:

    Test Platform Root -> Test Systems G1 -> Test Devices X2 -> the unit

The gateway trusts the root only. The unit's chain file stops at X2, as the
box's does, so the handshake succeeds only if the agent adds G1 from the
extra-chain file.

With --pkcs11 the unit's key is imported into a SoftHSM token and the agent
gets a pkcs11: URI instead of a key file (needs softhsm2-util and OpenSSL's
pkcs11 provider; run in the Linux container).
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
IMAGE = bytes((i * 7 + 3) & 0xFF for i in range(300_000))
IMAGE_SHA = hashlib.sha256(IMAGE).hexdigest()
UPDATE_ID = "upd-0001"

failures = []


def check(cond, what):
    if cond:
        print(f"  ok    {what}")
    else:
        print(f"  FAIL  {what}")
        failures.append(what)


def wait_for(pred, timeout, what):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            check(True, what)
            return True
        time.sleep(0.1)
    check(False, f"{what} (not within {timeout} s)")
    return False


# ------------------------------------------------------------------------------
# Test PKI
# ------------------------------------------------------------------------------

def run(cmd, **kw):
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **kw)
    if res.returncode != 0:
        print(res.stdout)
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return res.stdout


def make_pki(d):
    ext = os.path.join(d, "ext.cnf")
    with open(ext, "w") as f:
        f.write("""
[req]
distinguished_name = dn
prompt = no
[dn]
CN = unused
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[v3_unit]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth,serverAuth
subjectAltName = URI:urn:terranova:hwid:0123456789abcdef
[v3_server]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
""")

    def key(name):
        run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{d}/{name}.key"])

    def issue(name, subject, issuer, section):
        key(name)
        run(["openssl", "req", "-new", "-key", f"{d}/{name}.key", "-subj", subject, "-config", ext,
             "-out", f"{d}/{name}.csr"])
        run(["openssl", "x509", "-req", "-in", f"{d}/{name}.csr", "-CA", f"{d}/{issuer}.pem",
             "-CAkey", f"{d}/{issuer}.key", "-CAcreateserial", "-days", "365", "-sha256",
             "-extfile", ext, "-extensions", section, "-out", f"{d}/{name}.pem"])

    key("root")
    run(["openssl", "req", "-x509", "-new", "-key", f"{d}/root.key", "-subj", "/CN=Test Platform Root",
         "-days", "365", "-sha256", "-config", ext, "-extensions", "v3_ca", "-out", f"{d}/root.pem"])
    issue("g1", "/CN=Test Systems G1", "root", "v3_ca")
    issue("x2", "/CN=Test Devices X2", "g1", "v3_ca")
    issue("unit", "/CN=luka-test-unit/O=Test", "x2", "v3_unit")
    issue("server", "/CN=localhost", "root", "v3_server")

    # What the box has: the leaf with its issuer, and the anchor it pins.
    with open(f"{d}/chain.pem", "w") as out:
        out.write(open(f"{d}/unit.pem").read())
        out.write(open(f"{d}/x2.pem").read())


def setup_pkcs11(d):
    """Import the unit's key into a SoftHSM token; return (key URI, environment)."""
    tokens = os.path.join(d, "softhsm-tokens")
    os.makedirs(tokens, exist_ok=True)
    conf = os.path.join(d, "softhsm2.conf")
    with open(conf, "w") as f:
        f.write(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n")
    env = dict(os.environ, SOFTHSM2_CONF=conf)
    run(["softhsm2-util", "--init-token", "--free", "--label", "luka-id", "--pin", "1234", "--so-pin", "5678"], env=env)
    run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", f"{d}/unit.key", "-out", f"{d}/unit.pk8"])
    run(["softhsm2-util", "--import", f"{d}/unit.pk8", "--token", "luka-id", "--label", "k-sign",
         "--id", "01", "--pin", "1234"], env=env)
    os.remove(f"{d}/unit.pk8")

    module = None
    for cand in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
                 "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"):
        if os.path.exists(cand):
            module = cand
    if not module:
        raise SystemExit("libsofthsm2.so not found")
    import glob
    providers = glob.glob("/usr/lib/*/ossl-modules/pkcs11.so") + glob.glob("/usr/lib/ossl-modules/pkcs11.so")
    if not providers:
        raise SystemExit("OpenSSL's pkcs11 provider (pkcs11.so) not found")
    cnf = os.path.join(d, "openssl-pkcs11.cnf")
    with open(cnf, "w") as f:
        f.write(f"""
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = {providers[0]}
pkcs11-module-path = {module}
# SoftHSM's own teardown runs before OpenSSL's at exit; do not call into it then.
pkcs11-module-quirks = no-deinit
activate = 1
""")
    env["OPENSSL_CONF"] = cnf
    return "pkcs11:token=luka-id;object=k-sign;type=private?pin-value=1234", env


# ------------------------------------------------------------------------------
# Mock gateway (vn)
# ------------------------------------------------------------------------------

class Gateway:
    def __init__(self, d):
        self.frames = []          # (session number, parsed JSON or raw text)
        self.sessions = 0
        self.peer_cns = []
        self.lock = threading.Lock()
        self.close_first_session_after = None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{d}/server.pem", f"{d}/server.key")
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(f"{d}/root.pem")  # the root only, like the edge
        self.ctx = ctx
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    @staticmethod
    def _send(conn, text, opcode=0x1):
        data = text.encode() if isinstance(text, str) else text
        n = len(data)
        if n < 126:
            head = struct.pack("!BB", 0x80 | opcode, n)
        elif n < 65536:
            head = struct.pack("!BBH", 0x80 | opcode, 126, n)
        else:
            head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
        conn.sendall(head + data)

    @staticmethod
    def _recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf

    def _recv_frame(self, conn):
        b0, b1 = self._recv_exact(conn, 2)
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack("!H", self._recv_exact(conn, 2))[0]
        elif n == 127:
            n = struct.unpack("!Q", self._recv_exact(conn, 8))[0]
        if not b1 & 0x80:
            raise ConnectionError("client frame not masked")
        mask = self._recv_exact(conn, 4)
        data = bytearray(self._recv_exact(conn, n))
        for i in range(n):
            data[i] ^= mask[i & 3]
        return b0 & 0x0F, bytes(data)

    def _serve(self, raw):
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as e:
            with self.lock:
                self.peer_cns.append(f"handshake failed: {e}")
            return
        try:
            cert = conn.getpeercert()
            cn = dict(x[0] for x in cert["subject"]).get("commonName")
            req = b""
            while b"\r\n\r\n" not in req:
                req += conn.recv(4096)
            key = [l.split(":", 1)[1].strip() for l in req.decode().split("\r\n")
                   if l.lower().startswith("sec-websocket-key:")][0]
            accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
            conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                          f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").encode())
            with self.lock:
                self.sessions += 1
                session = self.sessions
                self.peer_cns.append(cn)

            self._send(conn, json.dumps({
                "type": "welcome", "device_id": "11111111-2222-3333-4444-555555555555",
                "token": "test.device.token", "expires_at": int(time.time()) + 900,
                "timezone": "America/Indiana/Indianapolis"}))
            self._send(conn, json.dumps({
                "type": "twin.desired", "version": 3,
                "desired": {"koios": {"metrics": {"interval_s": 10}}}}))

            count = 0
            while True:
                opcode, data = self._recv_frame(conn)
                if opcode == 0x8:
                    return
                if opcode == 0x9:
                    self._send(conn, data, 0xA)
                    continue
                if opcode != 0x1:
                    continue
                text = data.decode()
                if text == "ping":
                    self._send(conn, "pong")
                    continue
                try:
                    frame = json.loads(text)
                except ValueError:
                    frame = text
                with self.lock:
                    self.frames.append((session, frame))
                count += 1
                if isinstance(frame, dict) and frame.get("type") == "twin.report":
                    self._send(conn, json.dumps({"type": "twin.report.ack", "version": count}))
                if session == 1 and self.close_first_session_after and count >= self.close_first_session_after:
                    self._send(conn, struct.pack("!H", 1001) + b"going away", 0x8)
                    time.sleep(0.2)
                    return
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def of_type(self, kind, session=None):
        with self.lock:
            return [f for s, f in self.frames
                    if isinstance(f, dict) and f.get("type") == kind and (session is None or s == session)]


# ------------------------------------------------------------------------------
# Mock OTA service
# ------------------------------------------------------------------------------

class Ota:
    def __init__(self, d):
        self.statuses = []
        self.checks = 0
        self.offer = True
        self.ranges = []
        self.auth_ok = True
        ota = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _auth(self):
                ok = self.headers.get("Authorization") == "Bearer test.device.token"
                if not ok:
                    ota.auth_ok = False
                return ok

            def _json(self, code, obj):
                body = json.dumps(obj).encode() if obj is not None else b""
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if not self._auth():
                    return self._json(401, {"error": "no"})
                if self.path == "/v1/ota/check":
                    ota.checks += 1
                    if not ota.offer:
                        return self._json(204, None)
                    return self._json(200, {"data": {"manifest": {
                        "update_id": UPDATE_ID, "version": "2.0.0",
                        "artifact": {"url": f"https://localhost:{ota.port}/v1/ota/updates/{UPDATE_ID}/image",
                                     "size": len(IMAGE), "sha256": IMAGE_SHA, "format": "raw-file"}},
                        "signed": "not-checked-by-the-device-yet"}})
                if self.path == f"/v1/ota/updates/{UPDATE_ID}/image":
                    rng = self.headers.get("Range")
                    ota.ranges.append(rng)
                    start = int(rng.split("=")[1].split("-")[0]) if rng else 0
                    # First request: send a third, then drop the connection, so
                    # the device has to resume.
                    body = IMAGE[start:]
                    cut = len(ota.ranges) == 1
                    self.send_response(206 if rng else 200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(body)))
                    if rng:
                        self.send_header("Content-Range", f"bytes {start}-{len(IMAGE) - 1}/{len(IMAGE)}")
                    self.end_headers()
                    if cut:
                        self.wfile.write(body[:100_000])
                        self.wfile.flush()
                        self.close_connection = True
                        self.connection.close()
                        return
                    self.wfile.write(body)
                    return
                self._json(404, {"error": "not found"})

            def do_POST(self):
                if not self._auth():
                    return self._json(401, {"error": "no"})
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(n) or b"{}")
                if self.path == f"/v1/ota/updates/{UPDATE_ID}/status":
                    ota.statuses.append(body)
                    if body.get("status") in ("confirmed", "rolled_back", "failed"):
                        ota.offer = False
                    return self._json(200, {"data": {"ok": True}})
                self._json(404, {"error": "not found"})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{d}/server.pem", f"{d}/server.key")
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


# ------------------------------------------------------------------------------
# The agent
# ------------------------------------------------------------------------------

def write_config(d, gw, ota, key, version):
    with open(f"{d}/os-release", "w") as f:
        f.write(f'ID=luka\nVERSION_ID="{version}"\nVARIANT_ID=zedbox2-orin-nx\nPRETTY_NAME="Test OS {version}"\n')
    with open(f"{d}/facts.json", "w") as f:
        json.dump({"luka": {"extensions": {"luka-runtime": "0.3.0"}}, "sys": {"hostname": "must-not-win"}}, f)
    with open(f"{d}/install.sh", "w") as f:
        f.write(f"#!/bin/sh\necho \"$2 $3\" > {d}/installed.args\ncp \"$1\" {d}/installed.img\n")
    with open(f"{d}/restart.sh", "w") as f:
        # Stands in for a reboot: end the agent; the test starts the "new OS".
        f.write(f"#!/bin/sh\ntouch {d}/restart.called\nkill -TERM $PPID\n")
    os.chmod(f"{d}/install.sh", 0o755)
    os.chmod(f"{d}/restart.sh", 0o755)
    conf = f"""
[cloud]
url = wss://localhost:{gw.port}
auth = mtls
ca_file = {d}/root.pem

[identity]
cert = {d}/chain.pem
extra_chain = {d}/g1.pem
key = {key}
ready_file = {d}/provisioned

[device]
class = tegra234
os_release = {d}/os-release
facts_file = {d}/facts.json

[state]
dir = {d}/state
runtime_dir = {d}/run

[logs]
enabled = yes
journal = no

[metrics]
enabled = yes
interval_s = 3600
storage_path = {d}

[ota]
enabled = yes
endpoint = https://localhost:{ota.port}
staging_dir = {d}/staging
apply_cmd = {d}/install.sh
restart_cmd = {d}/restart.sh
"""
    with open(f"{d}/agent.conf", "w") as f:
        f.write(conf)


def start_agent(agent, d, env, log_name):
    log = open(f"{d}/{log_name}", "w")
    return subprocess.Popen([agent, "-c", f"{d}/agent.conf", "-v"], stdout=log, stderr=subprocess.STDOUT, env=env)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True)
    ap.add_argument("--scratch", required=True)
    ap.add_argument("--pkcs11", action="store_true")
    args = ap.parse_args()

    d = os.path.abspath(args.scratch)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    make_pki(d)

    env = dict(os.environ)
    key = f"{d}/unit.key"
    if args.pkcs11:
        key, env = setup_pkcs11(d)
        os.remove(f"{d}/unit.key")  # the key now exists only in the token
        print("the unit's key is in a PKCS#11 token; there is no key file")

    gw = Gateway(d)
    ota = Ota(d)
    gw.close_first_session_after = None
    write_config(d, gw, ota, key, "1.0.0")

    check_out = subprocess.run([args.agent, "-c", f"{d}/agent.conf", "--check"], stdout=subprocess.PIPE, text=True, env=env)
    check(check_out.returncode == 0 and "tegra234" in check_out.stdout and "1.0.0" in check_out.stdout,
          "--check reads the configuration and os-release")

    print("phase 1: not provisioned yet")
    proc = start_agent(args.agent, d, env, "agent-1.log")
    time.sleep(3)
    check(gw.sessions == 0 and proc.poll() is None, "no connection before the identity is marked ready")
    open(f"{d}/provisioned", "w").close()

    print("phase 2: first session")
    if not wait_for(lambda: gw.sessions >= 1, 15, "connects once the marker exists (the gate is polled)"):
        proc.kill()
        print(f"the gateway saw: {gw.peer_cns}")
        print("".join(open(f"{d}/agent-1.log").readlines()[-40:]))
        return 1
    check(gw.peer_cns[-1] == "luka-test-unit",
          f"mutual TLS: the gateway saw the unit's certificate through root<-G1<-X2 ({gw.peer_cns[-1]})")

    wait_for(lambda: any("fw" in f.get("state", {}) for f in gw.of_type("twin.report")), 10, "reports fw identity")
    fw = [f["state"]["fw"] for f in gw.of_type("twin.report") if "fw" in f.get("state", {})][0]
    check(fw == {"class": "tegra234", "version": "1.0.0", "project": "luka", "variant": "zedbox2-orin-nx"},
          f"fw = {fw}")

    wait_for(lambda: any("sys" in f.get("state", {}) for f in gw.of_type("twin.report")), 10, "reports the system")
    sysrep = [f["state"] for f in gw.of_type("twin.report") if "sys" in f.get("state", {})][0]
    check(sysrep["sys"].get("os") == "Test OS 1.0.0" and sysrep["sys"].get("hostname") != "must-not-win"
          and "kernel" in sysrep["sys"], f"sys = {sysrep['sys']}")
    check(sysrep.get("luka") == {"extensions": {"luka-runtime": "0.3.0"}}, "facts file merged into the report")

    wait_for(lambda: gw.of_type("twin.desired.ack"), 10, "acknowledges the desired twin")
    check(gw.of_type("twin.desired.ack")[0].get("version") == 3, "ack carries the version")

    wait_for(lambda: gw.of_type("metrics"), 10, "sends a metrics frame with the first session")
    sample = gw.of_type("metrics")[0]["samples"][0]
    check(isinstance(sample.get("uptime_s"), int) and sample.get("ts", 0) > 1.6e12 and sample.get("cpu_cores", 0) >= 1,
          f"sample has uptime, time and cores: {sample}")
    if sys.platform.startswith("linux"):
        check(all(k in sample for k in ("mem_total_bytes", "mem_free_bytes", "storage_total_bytes", "load1", "tasks")),
              "Linux sample has memory, storage, load and tasks")
    # The configuration says hourly; the desired twin says 10 s.
    wait_for(lambda: sum(len(f["samples"]) for f in gw.of_type("metrics")) >= 3, 30,
             "the interval from the desired twin (10 s) is in force")
    if sys.platform.startswith("linux"):
        later = gw.of_type("metrics")[-1]["samples"][-1]
        check("cpu_pct" in later and 0 <= later["cpu_pct"] <= 100, f"cpu_pct after two samples: {later.get('cpu_pct')}")

    wait_for(lambda: gw.of_type("logs"), 10, "ships its log lines")
    lines = [l for f in gw.of_type("logs") for l in f["logs"]]
    check(all({"level", "tag", "message"} <= set(l) for l in lines) and
          any("session ready" in l["message"] for l in lines), "log records have level, tag, message")

    print("phase 3: an update, installed by the system's installer")
    wait_for(lambda: os.path.exists(f"{d}/restart.called"), 60, "the update ran through to the restart hook")
    proc.wait(timeout=20)
    check(proc.returncode == 0, f"the agent ended cleanly on SIGTERM (status {proc.returncode})")
    st = [s.get("status") for s in ota.statuses]
    check(st == ["downloading", "rebooting"], f"status reports in order: {st}")
    check(ota.auth_ok, "every OTA request carried the device token")
    check(len(ota.ranges) >= 2 and ota.ranges[0] is None and ota.ranges[1] == "bytes=100000-",
          f"the interrupted download was resumed, not restarted: {ota.ranges}")
    check(os.path.exists(f"{d}/installed.img") and
          hashlib.sha256(open(f"{d}/installed.img", "rb").read()).hexdigest() == IMAGE_SHA,
          "the installer got the exact image")
    check(open(f"{d}/installed.args").read().strip() == f"2.0.0 {UPDATE_ID}", "the installer got version and update id")
    check(not os.listdir(f"{d}/staging"), "nothing is left in the staging directory")
    check(os.path.exists(f"{d}/state/ota_pending"), "the pending update is recorded for the next start")

    print("phase 4: after the 'reboot' into the new version")
    sessions_before = gw.sessions
    frames_before = len(gw.frames)
    gw.close_first_session_after = None
    write_config(d, gw, ota, key, "2.0.0")
    proc = start_agent(args.agent, d, env, "agent-2.log")
    wait_for(lambda: gw.sessions > sessions_before, 15, "connects again")
    wait_for(lambda: "confirmed" in [s.get("status") for s in ota.statuses], 40, "confirms the update after the restart")
    check(not os.path.exists(f"{d}/state/ota_pending"), "the pending record is cleared")
    with gw.lock:
        new_frames = [f for _, f in gw.frames[frames_before:] if isinstance(f, dict)]
    check(any(f.get("type") == "twin.report" and f.get("state", {}).get("fw", {}).get("version") == "2.0.0"
              for f in new_frames), "reports the new version")

    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=20)
    check(proc.returncode == 0, "stops cleanly")

    print("phase 5: the gateway closes the session; the agent reconnects and loses no log line")
    gw2 = Gateway(d)
    gw2.close_first_session_after = 4
    write_config(d, gw2, ota, key, "2.0.0")
    proc = start_agent(args.agent, d, env, "agent-3.log")
    wait_for(lambda: gw2.sessions >= 2, 30, "a second session after the gateway said 'going away'")
    wait_for(lambda: any("fw" in f.get("state", {}) for f in gw2.of_type("twin.report", session=2)), 10,
             "the new session starts with the fw report again")
    wait_for(lambda: any("Server rejected/closed" in l["message"] or "closed the connection" in l["message"]
                         for f in gw2.of_type("logs", session=2) for l in f["logs"]), 15,
             "lines logged while the link was down arrive afterwards")
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=20)
    check(proc.returncode == 0, "stops cleanly")

    if failures:
        print(f"\n{len(failures)} check(s) failed; agent logs are in {d}")
        for name in ("agent-1.log", "agent-2.log", "agent-3.log"):
            path = f"{d}/{name}"
            if os.path.exists(path):
                print(f"--- {name} (last lines)")
                print("".join(open(path).readlines()[-25:]))
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
