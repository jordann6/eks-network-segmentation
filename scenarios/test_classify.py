"""The runner's honesty rules, tested without a cluster.

Every case here is a way a naive harness would print a false "defended". The
classifier must turn each of them into "error" or "skipped" instead.
Run: python3 -m unittest discover -s scenarios
"""
import unittest

from run import classify, display

DROP = [{"verdict": "DROPPED", "drop_reason_desc": "POLICY_DENIED"}]


def res(reached=False, healthy=True, **client):
    return {"reached": reached, "healthy": healthy, "client": client}


class Classify(unittest.TestCase):
    def test_denied_with_evidence_after_exploitable_baseline_is_blocked(self):
        s, _ = classify("frontend-to-sensitive", "attack", "L3/L4", "hardened", res(), DROP, "exploitable")
        self.assertEqual(s, "blocked")

    def test_timeout_without_evidence_is_error_not_blocked(self):
        s, why = classify("frontend-to-sensitive", "attack", "L3/L4", "hardened", res(), [], "exploitable")
        self.assertEqual(s, "error")
        self.assertIn("no enforcement evidence", why)

    def test_failed_baseline_means_no_defense_can_be_claimed(self):
        s, _ = classify("frontend-to-sensitive", "attack", "L3/L4", "hardened", res(), DROP, "error")
        self.assertEqual(s, "skipped")

    def test_baseline_not_reaching_core_target_is_error(self):
        s, _ = classify("frontend-to-sensitive", "attack", "L3/L4", "baseline", res(), [], None)
        self.assertEqual(s, "error")

    def test_baseline_not_reaching_environmental_target_is_skipped(self):
        r = res()
        r["environmental"] = True
        s, _ = classify("metadata", "attack", "L3/L4", "baseline", r, [], None)
        self.assertEqual(s, "skipped")

    def test_unhealthy_destination_is_error(self):
        s, _ = classify("frontend-to-sensitive", "attack", "L3/L4", "hardened", res(healthy=False), DROP, "exploitable")
        self.assertEqual(s, "error")

    def test_l7_drop_without_403_is_error(self):
        s, _ = classify("forbidden-http", "attack", "L7", "hardened", res(http_code="000"), DROP, "exploitable")
        self.assertEqual(s, "error")

    def test_l7_with_403_and_drop_is_blocked(self):
        s, _ = classify("forbidden-http", "attack", "L7", "hardened", res(http_code="403"), DROP, "exploitable")
        self.assertEqual(s, "blocked")

    def test_dns_needs_refused(self):
        s, _ = classify("dns-exfil", "attack", "DNS", "hardened", res(resolver_status="NXDOMAIN"), DROP, "exploitable")
        self.assertEqual(s, "error")
        s, _ = classify("dns-exfil", "attack", "DNS", "hardened", res(resolver_status="REFUSED"), DROP, "exploitable")
        self.assertEqual(s, "blocked")

    def test_reached_is_exploitable_even_with_drops(self):
        s, _ = classify("http-exfil", "attack", "L3/L4", "hardened", res(reached=True), DROP, "exploitable")
        self.assertEqual(s, "exploitable")

    def test_broken_legit_flow_is_reported(self):
        s, _ = classify("frontend-to-api", "legit", "L7", "hardened", res(), [], "allowed")
        self.assertEqual(s, "broken")
        self.assertEqual(display("legit", s, "Allowed", {}), "Denied")

    def test_error_never_displays_as_denied(self):
        self.assertEqual(display("attack", "error", "Denied", {}), "error")

    def test_collection_gap_turns_blocked_into_error(self):
        # Lost telemetry during the run: a matched drop is no longer enough to
        # certify a defense, so the verdict must be error, not a pass.
        s, why = classify("frontend-to-sensitive", "attack", "L3/L4", "hardened",
                          res(), DROP, "exploitable", collection_gap=True)
        self.assertEqual(s, "error")
        self.assertIn("lost events", why)

    def test_collection_gap_does_not_downgrade_exploitable(self):
        # A reached flow is still exploitable even with a collection gap.
        s, _ = classify("http-exfil", "attack", "L3/L4", "hardened",
                        res(reached=True), DROP, "exploitable", collection_gap=True)
        self.assertEqual(s, "exploitable")

    def test_no_gap_still_blocked(self):
        s, _ = classify("frontend-to-sensitive", "attack", "L3/L4", "hardened",
                        res(), DROP, "exploitable", collection_gap=False)
        self.assertEqual(s, "blocked")


if __name__ == "__main__":
    unittest.main()
