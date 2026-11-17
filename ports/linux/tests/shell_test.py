#!/usr/bin/env python3
"""koios-shell by itself, with the test as the far end of the stream.

    shell_test.py --shell <path to koios-shell>

Python 3 standard library only.
"""
import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time

DATA, RESIZE, EXIT, HELLO = 1, 2, 3, 4
failures = 0


def check(cond, what):
    global failures
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures += 1


def frame(kind, payload=b""):
    return struct.pack("!BI", kind, len(payload)) + payload


class Session:
    def __init__(self, shell, *args):
        self.ours, theirs = socket.socketpair()
        self.proc = subprocess.Popen([shell, *args], stdin=theirs, stdout=theirs, stderr=subprocess.PIPE)
        theirs.close()
        self.ours.settimeout(10)
        self.buf = b""
        self.output = b""
        self.hello = None
        self.status = None

    def send(self, kind, payload=b""):
        self.ours.sendall(frame(kind, payload))

    def type(self, text):
        self.send(DATA, text.encode())

    def pump(self, until, timeout=10):
        """Read frames until `until()` holds. False if the stream ends or time runs out first."""
        deadline = time.time() + timeout
        while not until():
            if time.time() > deadline:
                return False
            try:
                chunk = self.ours.recv(65536)
            except socket.timeout:
                return False
            if not chunk:
                return until()
            self.buf += chunk
            while len(self.buf) >= 5:
                kind, length = struct.unpack("!BI", self.buf[:5])
                if len(self.buf) < 5 + length:
                    break
                payload, self.buf = self.buf[5:5 + length], self.buf[5 + length:]
                if kind == HELLO:
                    self.hello = json.loads(payload.decode())
                elif kind == DATA:
                    self.output += payload
                elif kind == EXIT:
                    self.status = struct.unpack("!i", payload)[0]
        return True


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shell", required=True)
    args = ap.parse_args()

    print("a shell, its terminal's size and its exit status")
    s = Session(args.shell, "--shell", "/bin/sh")
    s.send(RESIZE, struct.pack("!HH", 132, 43))  # at once, as the console does
    check(s.pump(lambda: s.hello is not None), "it says hello first")
    check(s.hello and s.hello.get("user") and s.hello.get("shell") == "/bin/sh",
          f"with the user and the shell ({s.hello})")
    s.type("stty size; echo marker-$((6*7)); test -t 0 && echo is-a-tty; echo home=$HOME term=$TERM koios=$KOIOS_CONSOLE\n")
    check(s.pump(lambda: b"koios=1" in s.output and b"marker-42" in s.output), "what is typed runs and its output comes back")
    check(b"43 132" in s.output, "the shell started at the size sent before it")
    check(b"is-a-tty" in s.output, "its input is a terminal")
    check(b"term=xterm-256color" in s.output and b"home=/" in s.output, "it has a login's environment")
    s.send(RESIZE, struct.pack("!HH", 90, 20))
    s.output = b""
    s.type("stty size\n")
    check(s.pump(lambda: b"20 90" in s.output), "a new size reaches the terminal")
    s.send(9, b"a frame of a kind it does not know")
    s.output = b""
    s.type("echo still-$((1+1))\n")
    check(s.pump(lambda: b"still-2" in s.output), "an unknown frame is skipped")
    s.type("exit 7\n")
    check(s.pump(lambda: s.status is not None), "it reports the exit")
    check(s.status == 7, f"with the shell's status ({s.status})")
    s.proc.wait(timeout=10)
    check(s.proc.returncode == 0, "and ends cleanly")
    s.ours.close()

    print("a session that ends under a running shell")
    s = Session(args.shell, "--shell", "/bin/sh")
    s.pump(lambda: s.hello is not None)
    # The terminal echoes what is typed: look for the number, which only the shell prints.
    s.type("echo PID:$$:; sleep 600\n")
    found = lambda: re.search(rb"PID:(\d+):", s.output)
    s.pump(lambda: found() is not None)
    pid = int(found().group(1)) if found() else -1
    check(alive(pid), f"the shell runs (pid {pid})")
    s.ours.close()
    s.proc.wait(timeout=10)
    deadline = time.time() + 5
    while alive(pid) and time.time() < deadline:
        time.sleep(0.05)
    check(not alive(pid), "the stream's end hangs up the terminal: the shell is gone")
    check(s.proc.returncode == 0, "koios-shell ends cleanly")

    print("a signal as the shell's end, and a shell that does not exist")
    s = Session(args.shell, "--shell", "/bin/sh")
    s.pump(lambda: s.hello is not None)
    s.type("kill -KILL $$\n")
    check(s.pump(lambda: s.status is not None) and s.status == 128 + 9, f"a killed shell is status 137 ({s.status})")
    s.proc.wait(timeout=10)
    s.ours.close()

    s = Session(args.shell, "--shell", "/nonexistent/shell")
    s.proc.wait(timeout=10)
    check(s.proc.returncode != 0, "a shell that cannot run is an error, not a hang")
    s.ours.close()

    s = Session(args.shell, "--user", "no-such-user-here")
    s.proc.wait(timeout=10)
    check(s.proc.returncode != 0, "so is a user that does not exist")
    s.ours.close()

    if failures:
        print(f"{failures} check(s) failed")
    else:
        print("ok")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
