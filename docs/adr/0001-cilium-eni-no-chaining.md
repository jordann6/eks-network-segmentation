# ADR-0001: Cilium with AWS ENI IPAM, no VPC CNI chaining

- **Status:** accepted
- **Date:** 2026-11-03

## Context

The lab's v1 scope needs three kinds of enforcement: identity-based L3/L4, an
L7 HTTP rule (allow `GET /api/orders`, deny `POST /api/admin/export`), and DNS
query-name filtering. On EKS the default CNI is the Amazon VPC CNI, which has
enforced Kubernetes `NetworkPolicy` since v1.14 (August 2023). Cilium can run
either as the sole CNI or chained on top of the VPC CNI. Cilium's own docs list
limitations for L7 policy in AWS chaining mode.

## Decision

Cilium is the only CNI, installed with AWS ENI IPAM and native routing, pinned
to chart 1.20.4. The VPC CNI DaemonSet (`aws-node`) stays installed but is
pinned to a node label nothing carries, so it never schedules. A readiness gate
(`cilium/readiness-gate.sh`) blocks every workload and every scenario run until
Cilium and Hubble are Ready and every pod has a CiliumEndpoint. Nodes carry the
`node.cilium.io/agent-not-ready` NoExecute taint until the agent removes it.

## Alternatives rejected

| Option | Why not |
| ------ | ------- |
| VPC CNI alone with `NetworkPolicy` | Enforces L3/L4 well, but has no L7 HTTP rule and no DNS query-name filtering, which are two of the six matrix rows. |
| Cilium chained on the VPC CNI | Documented L7 limitations in chaining mode; the L7 row would be measuring a known-degraded configuration. |
| Cilium with overlay (cluster-pool IPAM) on EKS | Works, but pods would no longer hold VPC addresses, which moves the EKS run further from how EKS pods are normally addressed. ENI IPAM keeps that the same. |
| Security Groups for Pods | Deferred. It is a separate control with its own compatibility questions under Cilium; adding it would also add a second variable to the experiment (ADR-0002). |

## Consequences

The EKS session has an extra install step and a hard dependency on the node
role carrying ENI permissions (`AmazonEKS_CNI_Policy` plus four read-only
Describe calls in `infra/eks.tf`). kind runs Cilium with Kubernetes host-scope
IPAM instead; only IPAM and routing differ between the two value files, so the
policy engine under test is the same. Revisit if a future version removes the
chaining L7 limitation, since chaining is the lower-friction EKS path.
