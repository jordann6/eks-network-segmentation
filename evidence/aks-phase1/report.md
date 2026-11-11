# Connectivity matrix: run `aks-phase1`

- Context: `netseg-aks`  
- Cilium: `quay.io/cilium/cilium:v1.20.4`  
- Started 2026-11-11T18:56:32Z, finished 2026-11-11T18:59:47Z  
- Overall: **FAIL**

Only policy objects changed between the baseline and hardened columns. The reschedule column re-runs the hardened profile after the frontend, api and db pods were replaced and moved to the other node (new IPs, same Cilium identities).

| Test | Baseline | Hardened | After reschedule | Enforcement evidence (hardened) |
| ---- | -------- | -------- | ---------------- | ------------------------------- |
| Frontend to permitted backend route (GET /api/orders) | Allowed | Allowed | Allowed | still passes (HTTP 200) |
| Backend to database | Allowed | Allowed | Allowed | still passes (PONG) |
| Frontend to sensitive service | Allowed | Denied | Denied | Hubble DROPPED POLICY_DENIED, identity 47712 to 7194 port 8080 |
| Frontend to controlled exfil receiver | Received | Denied | Denied | Hubble DROPPED POLICY_DENIED, identity 47712 to 36927 port 8080 |
| Synthetic DNS marker to authoritative receiver | Received | Denied | Denied | `REFUSED`; Hubble DNS proxy DROPPED; direct query to receiver timed out: True |
| Frontend to forbidden backend HTTP operation (POST /api/admin/export) | Allowed | Denied | Denied | HTTP 403; Hubble L7 DROPPED `POST http://api.backend.svc.cluster.local:8080/api/admin/export` |

## Supplemental probes

Environment dependent: the metadata probe is the Azure IMDS reachability check and the wire server probe is a separate row. Both are measured here (AKS has both endpoints). Host network pods are not covered by pod policy.

| Probe | Baseline | Hardened | After reschedule | Reason (hardened) |
| ----- | -------- | -------- | ---------------- | ----------------- |
| Frontend reaches instance metadata (prerequisite probe, T1552.005) | Allowed | Denied | Denied | denied with L3/L4 enforcement evidence (8 matching flows) |
| Frontend to public internet (example.com:443) | Allowed | Denied | Denied | denied with L3/L4 enforcement evidence (12 matching flows) |
| Frontend reaches the Azure wire server (168.63.129.16, finding) | Allowed | Denied | Denied | denied with L3/L4 enforcement evidence (8 matching flows) |

## Reschedule receipt (identity, not IP)

| Workload | IP before | IP after | Node before | Node after | Identity before | Identity after |
| -------- | --------- | -------- | ----------- | ---------- | --------------- | -------------- |
| frontend/frontend | 10.244.0.114 | 10.244.1.98 | 10.42.0.4 | 10.42.0.5 | 47712 | 47712 |
| backend/api | 10.244.1.135 | 10.244.0.166 | 10.42.0.5 | 10.42.0.4 | 36432 | 36432 |
| backend/db | 10.244.0.44 | 10.244.1.87 | 10.42.0.4 | 10.42.0.5 | 11544 | 11544 |

Every workload moved to the other node: **True**. IPs changed for every workload: **True**. Identities unchanged: **True**. Hardened results identical after reschedule: **True**.

## Preconditions

- Cilium ready: True, Hubble ready: True
- Planted RCE answers as uid 10001; ServiceAccount token in the foothold: absent
- Foothold RBAC (`kubectl auth can-i --as system:serviceaccount:frontend:frontend`):
  - create ciliumnetworkpolicies.cilium.io -n frontend: `no - Azure does not have opinion for this user.`
  - delete networkpolicies -n frontend: `no - Azure does not have opinion for this user.`
  - patch pods -n frontend (relabel itself): `no - Azure does not have opinion for this user.`
  - patch pods -n backend: `no - Azure does not have opinion for this user.`
  - create pods -n backend: `no - Azure does not have opinion for this user.`

## Collection

- baseline: 923 Hubble flows exported (`flows-baseline.jsonl.gz`), lost events: 0
- hardened: 1162 Hubble flows exported (`flows-hardened.jsonl.gz`), lost events: 0
- reschedule: 1218 Hubble flows exported (`flows-reschedule.jsonl.gz`), lost events: 0

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
| `wireserver` | exploitable | Allowed | Allowed | attacker reached the destination |

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
| `internet-egress` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (12 matching flows) |
| `wireserver` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (8 matching flows) |

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
| `internet-egress` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (12 matching flows) |
| `wireserver` | blocked | Denied | Denied | denied with L3/L4 enforcement evidence (8 matching flows) |

