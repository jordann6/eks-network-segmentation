# ADR-0003: What this lab does and does not claim about Cilium vs the VPC CNI

- **Status:** accepted
- **Date:** 2026-11-03

## Context

The easy version of this story is wrong. "The VPC CNI has no network policy
and no observability, so use Cilium" was roughly true before August 2023 and
is false now. The VPC CNI enforces Kubernetes `NetworkPolicy` (GA in v1.14) and
emits allow/deny policy decision logs. Label selectors are part of stock
`NetworkPolicy`, so "label-based policy" is not a Cilium differentiator either.

## Decision

The docs, site case study, resume line and any post claim only these Cilium
differentiators, each backed by a row or receipt in the report:

1. **L7 HTTP policy.** Method and path rules enforced by the Envoy proxy
   (the forbidden-operation row, HTTP 403).
2. **DNS-aware egress.** Query-name filtering in the DNS proxy, separate from
   destination filtering (the DNS-marker row, REFUSED; ADR-0004).
3. **Identity-based policy that survives rescheduling.** Policy is keyed to a
   numeric security identity derived from labels, not to pod IPs (the
   reschedule receipt: new IPs, same identities, same results).
4. **The Hubble flow workflow.** Per-flow verdicts and drop reasons, with
   identities, correlated to each scenario's time window.

Everything else in the matrix (default deny, namespace isolation, egress
deny to an IP) is achievable with stock `NetworkPolicy` on the VPC CNI, and
the docs say so. The default-deny file is deliberately plain `NetworkPolicy`
to make that visible.

## Alternatives rejected

| Option | Why not |
| ------ | ------- |
| Run the same matrix on the VPC CNI as a comparison column | Worth doing later; out of v1 scope. Without it, the docs must not imply the VPC CNI would have failed the L3/L4 rows. |
| Claim "Cilium enforces policy, the VPC CNI does not" | False since 2023. |

## Consequences

Every public description has to be checked against this list. A claim not on
it needs a new receipt before it ships.

References:
- VPC CNI NetworkPolicy GA: https://aws.amazon.com/about-aws/whats-new/2023/08/amazon-vpc-cni-kubernetes-networkpolicy-enforcement/
- VPC CNI policy decision logs: https://docs.aws.amazon.com/eks/latest/userguide/network-policies-troubleshooting.html
- Cilium AWS CNI chaining limits: https://docs.cilium.io/en/stable/installation/cni-chaining-aws-cni/
- Cilium ENI IPAM: https://docs.cilium.io/en/stable/network/concepts/ipam/eni/
- Cilium L7 + DNS policy: https://docs.cilium.io/en/stable/security/policy/layer7/
