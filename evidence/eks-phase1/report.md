# Connectivity matrix: run `eks-phase1`

- Context: `netseg-eks`
- Cilium: `quay.io/cilium/cilium:v1.20.4`
- Started 2026-11-11T17:18:43Z, finished 2026-11-11T17:22:57Z
- Overall: **PASS**

Only policy objects changed between the baseline and hardened columns. The reschedule column re-runs the hardened profile after the frontend, api and db pods were replaced and moved to the other node (new IPs, same Cilium identities).

| Test | Baseline | Hardened | After reschedule | Enforcement evidence (hardened) |
| ---- | -------- | -------- | ---------------- | ------------------------------- |
| Frontend to permitted backend route (GET /api/orders) | Allowed | Allowed | Allowed | still passes (HTTP 200) |
| Backend to database | Allowed | Allowed | Allowed | still passes (PONG) |
| Frontend to sensitive service | Allowed | Denied | Denied | Hubble DROPPED POLICY_DENIED, identity 56688 to 1565 port 8080 |
| Frontend to controlled exfil receiver | Received | Denied | Denied | Hubble DROPPED POLICY_DENIED, identity 56688 to 5947 port 8080 |
| Synthetic DNS marker to authoritative receiver | Received | Denied | Denied | `REFUSED`; Hubble DNS proxy DROPPED; direct query to receiver timed out: True |
| Frontend to forbidden backend HTTP operation (POST /api/admin/export) | Allowed | Denied | Denied | HTTP 403; Hubble L7 DROPPED `POST http://api.backend.svc.cluster.local:8080/api/admin/export` |

## Supplemental probes

Environment dependent: on kind there is no instance metadata service, so the metadata probe reports `skipped` rather than a false "defended". The live EKS run is where it is measured.

| Probe | Baseline | Hardened | After reschedule | Reason (hardened) |
| ----- | -------- | -------- | ---------------- | ----------------- |
| Frontend reaches instance metadata (prerequisite probe, T1552.005) | Allowed | Denied | Denied | denied with L3/L4 enforcement evidence (8 matching flows) |
| Frontend to public internet (example.com:443) | Allowed | Denied | Denied | denied with L3/L4 enforcement evidence (6 matching flows) |

## Reschedule receipt (identity, not IP)

| Workload | IP before | IP after | Node before | Node after | Identity before | Identity after |
| -------- | --------- | -------- | ----------- | ---------- | --------------- | -------------- |
| frontend/frontend | 10.20.13.117 | 10.20.25.163 | 10.20.0.73 | 10.20.23.240 | 56688 | 56688 |
| backend/api | 10.20.20.144 | 10.20.6.158 | 10.20.23.240 | 10.20.0.73 | 3439 | 3439 |
| backend/db | 10.20.6.231 | 10.20.22.193 | 10.20.0.73 | 10.20.23.240 | 19205 | 19205 |

Every workload moved to the other node: **True**. IPs changed for every workload: **True**. Identities unchanged: **True**. Hardened results identical after reschedule: **True**.

## Preconditions

- Cilium ready: True, Hubble ready: True
- Planted RCE answers as uid 10001; ServiceAccount token in the foothold: absent
- Foothold RBAC (`kubectl auth can-i --as system:serviceaccount:frontend:frontend`):
  - create ciliumnetworkpolicies.cilium.io -n frontend: `no`
  - delete networkpolicies -n frontend: `no`
  - patch pods -n frontend (relabel itself): `no`
  - patch pods -n backend: `no`
  - create pods -n backend: `no`

## Collection

- baseline: 730 Hubble flows exported (`flows-baseline.jsonl.gz`), lost events: 0
- hardened: 1000 Hubble flows exported (`flows-hardened.jsonl.gz`), lost events: 0
- reschedule: 1031 Hubble flows exported (`flows-reschedule.jsonl.gz`), lost events: 0

## Per-scenario detail

### baseline

| Scenario | Status | Expected | Observed | Reason |
| -------- | ------ | -------- | -------- | ------ |
| `frontend-to-api` | allowed | Allowed | Allowed | legitimate flow succeeded |
| `api-to-db` | allowed | Allowed | Allowed | legitimate flow succeeded |
| `frontend-to-sensitive` | exploitable | Allowed | Allowed | attacker reached the destination |
| `http-exfil` | exploitable | Received | Received | attacker reached the destination |
| `dns-exfil` | exploitable | Received | Received | attacker reached the destination |
| `forbidden-http` | exploitable | Allowed | Allowed | attacker reached the destination |
| `metadata` | exploitable | Allowed | Allowed | attacker reached the destination |
| `internet-egress` | exploitable | Allowed | Allowed | attacker reached the destination |

### hardened

| Scenario | Status | Expected | Observed | Reason |
| -------- | ------ | -------- | -------- | ------ |
| `frontend-to-api` | allowed | Allowed | Allowed | legitimate flow succeeded |
| `api-to-db` | allowed | Allowed | Allowed | legitimate flow succeeded |
| `frontend-to-sensitive` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (10 matching flows) |
| `http-exfil` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (10 matching flows) |
| `dns-exfil` | blocked | Denied | Denied | denied with DNS enforcement evidence (1 matching flows) |
| `forbidden-http` | blocked | Denied | Denied | denied with L7 enforcement evidence (1 matching flows) |
| `metadata` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (8 matching flows) |
| `internet-egress` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (6 matching flows) |

### reschedule

| Scenario | Status | Expected | Observed | Reason |
| -------- | ------ | -------- | -------- | ------ |
| `frontend-to-api` | allowed | Allowed | Allowed | legitimate flow succeeded |
| `api-to-db` | allowed | Allowed | Allowed | legitimate flow succeeded |
| `frontend-to-sensitive` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (10 matching flows) |
| `http-exfil` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (10 matching flows) |
| `dns-exfil` | blocked | Denied | Denied | denied with DNS enforcement evidence (1 matching flows) |
| `forbidden-http` | blocked | Denied | Denied | denied with L7 enforcement evidence (1 matching flows) |
| `metadata` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (8 matching flows) |
| `internet-egress` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (6 matching flows) |
