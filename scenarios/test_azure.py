"""Tests for the AKS-only parts of the runner (ADR-0006).

The Azure port adds a wire-server row and an Azure IMDS probe without touching
the kind and EKS matrix. These pin that: the extra row appears only on Azure,
the metadata probe sends the right request per cloud and never asks for a token
path, and the wire-server row's evidence is matched on identity, IP and port.
"""
import unittest

import run
from run import classify, evidence_for


class FakePF:
    def __init__(self, stdout="200"):
        self.cmds, self.stdout = [], stdout

    def rce(self, cmd):
        self.cmds.append(cmd)
        return {"rc": 0, "stdout": self.stdout}


def profile(pf):
    return run.Profile("baseline", "t", pf, None)


def wire_drop(dip="168.63.129.16", port=80, src_ns="frontend", pod="frontend-abc"):
    return {"verdict": "DROPPED", "drop_reason_desc": "POLICY_DENY",
            "source": {"namespace": src_ns, "pod_name": pod,
                       "labels": [f"k8s:io.kubernetes.pod.namespace={src_ns}"]},
            "destination": {},
            "IP": {"destination": dip}, "l4": {"TCP": {"destination_port": port}},
            "time": "2026-11-11T00:00:01Z"}


class TestCloudSelection(unittest.TestCase):
    def tearDown(self):
        run.set_cloud("aws")

    def ids(self):
        return [r[0] for r in run.SCENARIOS]

    def test_default_has_no_wireserver_row(self):
        run.set_cloud("aws")
        self.assertNotIn("wireserver", self.ids())

    def test_azure_adds_wireserver_row_once(self):
        run.set_cloud("azure")
        run.set_cloud("azure")
        self.assertEqual(self.ids().count("wireserver"), 1)

    def test_switching_back_removes_row(self):
        run.set_cloud("azure")
        run.set_cloud("aws")
        self.assertNotIn("wireserver", self.ids())

    def test_wireserver_is_not_a_matrix_row(self):
        run.set_cloud("azure")
        row = next(r for r in run.SCENARIOS if r[0] == "wireserver")
        self.assertFalse(row[4])

    def test_unknown_cloud_rejected(self):
        with self.assertRaises(ValueError):
            run.set_cloud("gcp")


class TestProbes(unittest.TestCase):
    def tearDown(self):
        run.set_cloud("aws")

    def test_azure_metadata_probe_uses_azure_header_and_no_token_path(self):
        run.set_cloud("azure")
        pf = FakePF()
        res = profile(pf).p_metadata()
        cmd = pf.cmds[0]
        self.assertIn("Metadata: true", cmd)
        self.assertIn("/metadata/instance", cmd)
        self.assertNotIn("oauth2", cmd)
        self.assertNotIn("identity", cmd)
        self.assertIn("-o /dev/null", cmd)
        self.assertTrue(res["reached"])

    def test_aws_metadata_probe_unchanged(self):
        run.set_cloud("aws")
        pf = FakePF()
        profile(pf).p_metadata()
        self.assertIn("/latest/api/token", pf.cmds[0])
        self.assertNotIn("Metadata: true", pf.cmds[0])

    def test_wireserver_reached_on_any_http_status(self):
        for code in ("200", "400", "404"):
            res = profile(FakePF(code)).p_wireserver()
            self.assertTrue(res["reached"], code)

    def test_wireserver_not_reached_on_no_connection(self):
        for code in ("000", ""):
            res = profile(FakePF(code)).p_wireserver()
            self.assertFalse(res["reached"], code)

    def test_wireserver_probe_discards_body(self):
        pf = FakePF()
        profile(pf).p_wireserver()
        self.assertIn("-o /dev/null", pf.cmds[0])


class TestWireserverEvidence(unittest.TestCase):
    WINDOW = {"window": ["2026-11-11T00:00:00Z", "2026-11-11T00:00:05Z"], "dst": "168.63.129.16"}

    def test_matches_drop_to_wire_server_port_80(self):
        self.assertEqual(len(evidence_for("wireserver", self.WINDOW, [wire_drop()])), 1)

    def test_rejects_other_destination(self):
        self.assertEqual(evidence_for("wireserver", self.WINDOW, [wire_drop(dip="169.254.169.254")]), [])

    def test_rejects_wrong_port(self):
        self.assertEqual(evidence_for("wireserver", self.WINDOW, [wire_drop(port=32526)]), [])

    def test_rejects_other_source_namespace(self):
        self.assertEqual(evidence_for("wireserver", self.WINDOW, [wire_drop(src_ns="backend", pod="api-1")]), [])


class TestWireserverVerdicts(unittest.TestCase):
    ARGS = ("wireserver", "attack", "L3/L4")

    def test_baseline_unreachable_is_skipped_not_defended(self):
        res = {"healthy": True, "reached": False, "environmental": True, "client": {}}
        status, _ = classify(*self.ARGS, "baseline", res, [], None)
        self.assertEqual(status, "skipped")

    def test_hardened_blocked_needs_evidence(self):
        res = {"healthy": True, "reached": False, "environmental": True, "client": {}}
        status, _ = classify(*self.ARGS, "hardened", res, [], "exploitable")
        self.assertEqual(status, "error")
        status, _ = classify(*self.ARGS, "hardened", res, [wire_drop()], "exploitable")
        self.assertEqual(status, "blocked")

    def test_hardened_still_reachable_is_exploitable(self):
        res = {"healthy": True, "reached": True, "environmental": True, "client": {}}
        status, _ = classify(*self.ARGS, "hardened", res, [], "exploitable")
        self.assertEqual(status, "exploitable")


if __name__ == "__main__":
    unittest.main()
