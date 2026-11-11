"""Flow-fixture tests for the evidence matchers.

These are the gap the review found: the matchers decided a row's verdict from
Hubble flows, but nothing tested them, and the HTTP matcher looked only at method
and URL. Each fixture below is a flow a loose matcher would wrongly accept as
evidence (or wrongly reject), pinned so the identity/destination/port/protocol
checks actually hold.

Flow shapes mirror the real Hubble records in evidence/*/flows-hardened.jsonl.gz:
L3/L4 policy drops carry drop_reason_desc=POLICY_DENIED; L7 HTTP and DNS proxy
drops carry verdict=DROPPED with no drop_reason_desc.
"""
import unittest

from run import dns_proxy_drops, evidence_for, l34_drops, l7_http_drops


def src(ns="frontend", pod="frontend-abc"):
    return {"namespace": ns, "pod_name": pod,
            "labels": [f"k8s:io.kubernetes.pod.namespace={ns}", "k8s:app=frontend"]}


def dst(ns="sensitive", pod="sensitive-xyz"):
    return {"namespace": ns, "pod_name": pod}


def l34_drop(src_ns="frontend", src_pod="frontend-abc", dpod="sensitive-xyz",
             dst_ns="sensitive", dip="10.0.0.9", proto="TCP", port=8080,
             reason="POLICY_DENIED", verdict="DROPPED"):
    return {"verdict": verdict, "drop_reason_desc": reason,
            "source": src(src_ns, src_pod), "destination": dst(dst_ns, dpod),
            "IP": {"destination": dip}, "l4": {proto: {"destination_port": port}},
            "time": "2026-11-06T00:00:01Z"}


def http_drop(method="POST", url="http://api.backend.svc.cluster.local:8080/api/admin/export",
              src_ns="frontend", dpod="api-123", dst_ns="backend", port=8080,
              verdict="DROPPED"):
    return {"verdict": verdict, "source": src(src_ns), "destination": dst(dst_ns, dpod),
            "l4": {"TCP": {"destination_port": port}},
            "l7": {"http": {"method": method, "url": url}},
            "time": "2026-11-06T00:00:01Z"}


def dns_drop(query="m123abc-hardened.exfil.lab.test.", src_ns="frontend", verdict="DROPPED"):
    return {"verdict": verdict, "source": src(src_ns),
            "destination": {"namespace": "kube-system", "pod_name": "coredns-1"},
            "l4": {"UDP": {"destination_port": 53}},
            "l7": {"dns": {"query": query}}, "time": "2026-11-06T00:00:01Z"}


class TestL34(unittest.TestCase):
    def test_matches_policy_drop_to_destination(self):
        self.assertEqual(len(l34_drops([l34_drop()], "frontend-", "sensitive-")), 1)

    def test_rejects_wrong_source_namespace(self):
        # Same pod-name prefix but a different namespace is not the foothold.
        self.assertEqual(l34_drops([l34_drop(src_ns="other")], "frontend-", "sensitive-"), [])

    def test_rejects_non_policy_drop(self):
        # A non-POLICY drop (e.g. an unsupported-protocol multicast drop) is not
        # evidence that policy did the work.
        self.assertEqual(l34_drops([l34_drop(reason="UNSUPPORTED_L3_PROTOCOL")],
                                   "frontend-", "sensitive-"), [])

    def test_rejects_wrong_port(self):
        self.assertEqual(l34_drops([l34_drop(port=9999)], "frontend-", "sensitive-",
                                   dst_port=8080), [])

    def test_rejects_wrong_protocol(self):
        self.assertEqual(l34_drops([l34_drop(proto="UDP", port=8080)], "frontend-",
                                   "sensitive-", dst_port=8080, proto="TCP"), [])

    def test_rejects_wrong_destination(self):
        self.assertEqual(l34_drops([l34_drop(dpod="other-1", dip="10.9.9.9")],
                                   "frontend-", "sensitive-"), [])

    def test_matches_by_destination_ip(self):
        self.assertEqual(len(l34_drops([l34_drop(dpod="", dip="10.0.0.9")],
                                       "frontend-", "10.0.0.9")), 1)


class TestL7(unittest.TestCase):
    def test_matches_method_path_identity_destination(self):
        self.assertEqual(len(l7_http_drops([http_drop()], "POST", "/api/admin/export")), 1)

    def test_rejects_unrelated_http_drop(self):
        # A dropped POST to admin/export but from a different namespace: a loose
        # matcher counted it; the identity check must not.
        self.assertEqual(l7_http_drops([http_drop(src_ns="kube-system")],
                                       "POST", "/api/admin/export"), [])

    def test_rejects_wrong_method(self):
        self.assertEqual(l7_http_drops([http_drop(method="GET")], "POST", "/api/admin/export"), [])

    def test_rejects_wrong_destination_workload(self):
        self.assertEqual(l7_http_drops([http_drop(dpod="other-1", dst_ns="frontend")],
                                       "POST", "/api/admin/export"), [])

    def test_rejects_wrong_port(self):
        self.assertEqual(l7_http_drops([http_drop(port=9999)], "POST", "/api/admin/export"), [])

    def test_rejects_non_dropped(self):
        self.assertEqual(l7_http_drops([http_drop(verdict="FORWARDED")],
                                       "POST", "/api/admin/export"), [])


class TestDNS(unittest.TestCase):
    def test_matches_marker_query_from_foothold(self):
        self.assertEqual(len(dns_proxy_drops([dns_drop()], "m123abc-hardened")), 1)

    def test_rejects_other_marker(self):
        self.assertEqual(dns_proxy_drops([dns_drop(query="sensitive.sensitive.svc.")],
                                         "m123abc-hardened"), [])

    def test_empty_marker_matches_nothing(self):
        # A missing marker must not let the empty substring match every DNS drop.
        self.assertEqual(dns_proxy_drops([dns_drop()], ""), [])

    def test_rejects_wrong_source_namespace(self):
        self.assertEqual(dns_proxy_drops([dns_drop(src_ns="kube-system")], "m123abc-hardened"), [])


class TestEvidenceWindow(unittest.TestCase):
    WINDOW = {"window": ["2026-11-06T00:00:00Z", "2026-11-06T00:00:05Z"], "dst": "sensitive-"}

    def test_stale_flow_outside_window_is_excluded(self):
        stale = l34_drop()
        stale["time"] = "2026-11-06T00:05:00Z"  # minutes later
        self.assertEqual(evidence_for("frontend-to-sensitive", self.WINDOW, [stale]), [])

    def test_flow_in_window_is_included(self):
        fresh = l34_drop()
        fresh["time"] = "2026-11-06T00:00:02Z"
        self.assertEqual(len(evidence_for("frontend-to-sensitive", self.WINDOW, [fresh])), 1)

    def test_missing_telemetry_yields_no_evidence(self):
        # No flows at all: the matcher returns nothing, and the classifier turns
        # that into error (tested in test_classify).
        self.assertEqual(evidence_for("frontend-to-sensitive", self.WINDOW, []), [])

    def test_flow_with_unparseable_time_is_excluded(self):
        bad = l34_drop()
        bad["time"] = "not-a-time"
        self.assertEqual(evidence_for("frontend-to-sensitive", self.WINDOW, [bad]), [])


if __name__ == "__main__":
    unittest.main()
