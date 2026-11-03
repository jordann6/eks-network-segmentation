# ADR-0004: DNS is two controls, query-name filtering and destination filtering

- **Status:** accepted
- **Date:** 2026-11-03

## Context

DNS exfiltration hides data in the query name. The pod asks its resolver for
`<data>.attacker-zone.example`, the resolver forwards to the zone's
authoritative server, and the data has left the cluster in the question,
whether or not the answer is a failure. The lab reproduces this with a
controlled authoritative server for `exfil.lab.test` and a CoreDNS stub zone
that forwards to it. The baseline run shows the marker arriving with an
NXDOMAIN answer.

A common mistake is to treat a `toFQDNs` allowlist as the DNS control.
`toFQDNs` governs which addresses a pod may connect to after resolution; it
says nothing about what the pod may ask, so the marker still leaves inside the
query.

## Decision

Two separate rules, both on the frontend egress policy:

- **Destination filtering (L3/L4):** port 53 is allowed only to kube-dns.
  A query sent straight to the attacker's resolver is dropped.
- **Query-name filtering (L7 DNS):** traffic to kube-dns goes through the
  Cilium DNS proxy, which answers REFUSED for every name except
  `api.backend.svc.cluster.local`. The marker never reaches CoreDNS, so it is
  never forwarded.

The runner tests both paths in the same scenario and judges success at the
receiver.

## Alternatives rejected

| Option | Why not |
| ------ | ------- |
| `toFQDNs` allowlist only | Does not stop data leaving in the query name. |
| Destination filtering only | The cluster resolver itself forwards the marker. |
| A wildcard name pattern for the cluster domain | Wider than the app needs; the frontend resolves exactly one name. |

## Consequences

The result is framed as "blocked the tested DNS channel", not "eliminated every
covert channel". Timing channels, other allowed names, and data in the allowed
HTTP request are out of scope.

Strict query-name allowlists break the resolver's search-list behaviour. With
the default `ndots:5`, musl tries `api.backend.svc.cluster.local.frontend.svc.cluster.local`
first, the proxy correctly refuses it, and musl stops at the first REFUSED
rather than falling through. The fix is `ndots:2` in every pod's `dnsConfig`
(same in both runs), not a wider allowlist.
