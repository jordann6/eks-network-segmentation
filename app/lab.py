"""Every workload in the segmentation lab, selected by the ROLE env var.

One small stdlib-only image keeps the lab honest: the frontend, backend, mock
database, sensitive service and both receivers share the same code, the same
base image and the same runtime, so the only thing that differs between the
baseline and hardened runs is network policy.

Roles
  frontend      Planted RCE. POST /run executes a shell command and returns its
                output. This is the assumed foothold, not the thing under test.
  api           Backend API. GET /api/orders reads the mock database (the
                permitted route). POST /api/admin/export is the forbidden
                operation the L7 policy denies.
  db            Mock database. Line protocol on TCP: PING -> PONG,
                ORDERS -> JSON rows. Stands in for Postgres without the memory.
  sensitive     A service the frontend has no business reaching. Returns a
                synthetic marker so reachability is unambiguous.
  exfil         Controlled HTTP exfil receiver. Records every marker POSTed to
                /collect; GET /markers lists what arrived.
  dns           Controlled authoritative DNS server for exfil.lab.test. Logs
                every query name (the DNS-channel marker) and answers NXDOMAIN.
                GET /markers on the HTTP side port lists what arrived.

Nothing here is real data. Every marker is synthetic and generated per run.
"""
import json
import os
import socket
import socketserver
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = os.environ.get("ROLE", "")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
DB_HOST = os.environ.get("LAB_DB_HOST", "db.backend.svc.cluster.local.")
DB_PORT = int(os.environ.get("LAB_DB_PORT", "5432"))
SENSITIVE_MARKER = os.environ.get("SENSITIVE_MARKER", "SYNTHETIC-SENSITIVE-RECORD")

MARKERS = []
MARKERS_LOCK = threading.Lock()


def record(marker, via):
    with MARKERS_LOCK:
        MARKERS.append({"marker": marker, "via": via, "at": time.time()})
    print(json.dumps({"event": "marker", "via": via, "marker": marker}), flush=True)


def db_query(command):
    with socket.create_connection((DB_HOST, DB_PORT), timeout=3) as s:
        s.sendall(command.encode() + b"\n")
        return s.makefile().readline().strip()


class Handler(BaseHTTPRequestHandler):
    server_version = "netseg-lab"

    def log_message(self, fmt, *args):
        print(json.dumps({"role": ROLE, "req": fmt % args}), flush=True)

    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode() if n else ""

    def do_GET(self):
        if self.path == "/healthz":
            return self.reply(200, {"role": ROLE, "ok": True})
        if ROLE == "api" and self.path == "/api/orders":
            try:
                rows = json.loads(db_query("ORDERS"))
            except OSError as e:
                return self.reply(502, {"error": f"db unreachable: {e}"})
            return self.reply(200, {"orders": rows})
        if ROLE == "sensitive":
            return self.reply(200, {"record": SENSITIVE_MARKER})
        if ROLE in ("exfil", "dns") and self.path == "/markers":
            with MARKERS_LOCK:
                return self.reply(200, {"markers": list(MARKERS)})
        return self.reply(404, {"error": "not found"})

    def do_POST(self):
        if ROLE == "frontend" and self.path == "/run":
            # THE PLANTED RCE. Deliberate: the lab assumes the attacker already
            # executes commands in this pod and measures what the network lets
            # those commands reach. It must keep working in both runs.
            cmd = json.loads(self.body() or "{}").get("cmd", "")
            timeout = 15
            try:
                p = subprocess.run(  # noqa: S602 - intentional foothold
                    cmd, shell=True, capture_output=True, text=True, timeout=timeout
                )
                out = {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
            except subprocess.TimeoutExpired as e:
                out = {"rc": 124, "stdout": e.stdout or "", "stderr": "timeout"}
            return self.reply(200, out)
        if ROLE == "api" and self.path == "/api/admin/export":
            # The forbidden operation. Reachable at L4 by the frontend in both
            # runs; only the L7 rule decides whether it executes.
            return self.reply(200, {"export": "SYNTHETIC-BULK-EXPORT", "rows": 3})
        if ROLE == "exfil" and self.path == "/collect":
            record(self.body().strip()[:200], "http")
            return self.reply(200, {"received": True})
        return self.reply(404, {"error": "not found"})


class DBHandler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline().decode().strip().upper()
        if line == "PING":
            resp = "PONG"
        elif line == "ORDERS":
            resp = json.dumps([{"id": 1, "sku": "SYN-001"}, {"id": 2, "sku": "SYN-002"}])
        else:
            resp = "ERR"
        self.wfile.write(resp.encode() + b"\n")


def qname(packet):
    labels, i = [], 12
    while packet[i]:
        n = packet[i]
        labels.append(packet[i + 1 : i + 1 + n].decode(errors="replace"))
        i += n + 1
    return ".".join(labels), i + 5


def dns_server(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    while True:
        packet, addr = sock.recvfrom(512)
        try:
            name, end = qname(packet)
        except (IndexError, UnicodeDecodeError):
            continue
        record(name, "dns")
        # Authoritative NXDOMAIN. The marker already arrived in the question,
        # which is the point: a failed lookup still delivers the payload.
        txid, flags = packet[:2], struct.pack(">H", 0x8403)
        counts = struct.pack(">HHHH", 1, 0, 0, 0)
        sock.sendto(txid + flags + counts + packet[12:end], addr)


def main():
    if ROLE == "db":
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        socketserver.ThreadingTCPServer(("0.0.0.0", DB_PORT), DBHandler).serve_forever()
    if ROLE == "dns":
        threading.Thread(target=dns_server, args=(5353,), daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
