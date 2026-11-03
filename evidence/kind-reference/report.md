# Connectivity matrix: run `kind-reference`

- Context: `kind-netseg`  
- Cilium: `quay.io/cilium/cilium:v1.20.4`  
- Started 2026-11-03T15:23:42Z, finished 2026-11-03T15:25:58Z  
- Overall: **PASS**

Only policy objects changed between the baseline and hardened columns. The reschedule column re-runs the hardened profile after the frontend, api and db pods were replaced and moved to the other node (new IPs, same Cilium identities).

| Test | Baseline | Hardened | After reschedule | Enforcement evidence (hardened) |
| ---- | -------- | -------- | ---------------- | ------------------------------- |
| Frontend to permitted backend route (GET /api/orders) | Allowed | Allowed | Allowed | still passes (HTTP 200) |
| Backend to database | Allowed | Allowed | Allowed | still passes (PONG) |
| Frontend to sensitive service | Allowed | Denied | Denied | Hubble DROPPED POLICY_DENIED, identity 43953 to 35979 port 8080 |
| Frontend to controlled exfil receiver | Received | Denied | Denied | Hubble DROPPED POLICY_DENIED, identity 43953 to 58500 port 8080 |
| Synthetic DNS marker to authoritative receiver | Received | Denied | Denied | `REFUSED`; Hubble DNS proxy DROPPED; direct query to receiver timed out: True |
| Frontend to forbidden backend HTTP operation (POST /api/admin/export) | Allowed | Denied | Denied | HTTP 403; Hubble L7 DROPPED `POST http://api.backend.svc.cluster.local:8080/api/admin/export` |

## Supplemental probes

Environment dependent: on kind there is no instance metadata service, so the metadata probe reports `skipped` rather than a false "defended". The live EKS run is where it is measured.

| Probe | Baseline | Hardened | After reschedule | Reason (hardened) |
| ----- | -------- | -------- | ---------------- | ----------------- |
| Frontend reaches instance metadata (prerequisite probe, T1552.005) | skipped | skipped | skipped | baseline was 'skipped', so no defense can be claimed |
| Frontend to public internet (example.com:443) | Allowed | Denied | Denied | denied with L3/L4 enforcement evidence (6 matching flows) |

## Reschedule receipt (identity, not IP)

| Workload | IP before | IP after | Node before | Node after | Identity before | Identity after |
| -------- | --------- | -------- | ----------- | ---------- | --------------- | -------------- |
| frontend/frontend | 10.244.2.103 | 10.244.1.72 | 172.18.0.4 | 172.18.0.2 | 43953 | 43953 |
| backend/api | 10.244.1.175 | 10.244.2.29 | 172.18.0.2 | 172.18.0.4 | 29076 | 29076 |
| backend/db | 10.244.2.61 | 10.244.1.222 | 172.18.0.4 | 172.18.0.2 | 12880 | 12880 |

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

- baseline: 463 Hubble flows exported (`flows-baseline.jsonl.gz`), lost events: 0
- hardened: 663 Hubble flows exported (`flows-hardened.jsonl.gz`), lost events: 0
- reschedule: 717 Hubble flows exported (`flows-reschedule.jsonl.gz`), lost events: 0

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
| `metadata` | skipped | Allowed | skipped | not reachable even with permissive policy in this environment; cannot measure a defense |
| `internet-egress` | exploitable | Allowed | Allowed | attacker reached the destination |

### hardened

| Scenario | Status | Expected | Observed | Reason |
| -------- | ------ | -------- | -------- | ------ |
| `frontend-to-api` | allowed | Allowed | Allowed | legitimate flow succeeded |
| `api-to-db` | allowed | Allowed | Allowed | legitimate flow succeeded |
| `frontend-to-sensitive` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (10 matching flows) |
| `http-exfil` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (10 matching flows) |
| `dns-exfil` | blocked | Denied | Denied | denied with DNS enforcement evidence (3 matching flows) |
| `forbidden-http` | blocked | Denied | Denied | denied with L7 enforcement evidence (1 matching flows) |
| `metadata` | skipped | Denied | skipped | baseline was 'skipped', so no defense can be claimed |
| `internet-egress` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (6 matching flows) |

### reschedule

| Scenario | Status | Expected | Observed | Reason |
| -------- | ------ | -------- | -------- | ------ |
| `frontend-to-api` | allowed | Allowed | Allowed | legitimate flow succeeded |
| `api-to-db` | allowed | Allowed | Allowed | legitimate flow succeeded |
| `frontend-to-sensitive` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (10 matching flows) |
| `http-exfil` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (10 matching flows) |
| `dns-exfil` | blocked | Denied | Denied | denied with DNS enforcement evidence (3 matching flows) |
| `forbidden-http` | blocked | Denied | Denied | denied with L7 enforcement evidence (1 matching flows) |
| `metadata` | skipped | Denied | skipped | baseline was 'skipped', so no defense can be claimed |
| `internet-egress` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (6 matching flows) |

