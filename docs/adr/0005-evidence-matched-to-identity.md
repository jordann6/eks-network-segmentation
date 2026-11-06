# ADR-0005: Evidence is matched to the full flow identity, and telemetry gaps fail safe

- **Status:** accepted
- **Date:** 2026-11-06

## Context

The runner decides each attack row's verdict by looking for Hubble flows that
show the policy dropping the probe. A review found the matchers too loose to
carry that weight:

- The HTTP (L7) matcher accepted any `DROPPED` flow whose method and URL path
  matched, with no check on source identity, destination, port or protocol. An
  unrelated dropped request to the same path, from any namespace, would have
  counted as evidence that this row was defended.
- The L3/L4 matcher checked the source pod-name prefix and destination but not
  the source namespace, port or protocol.
- Nothing tested the matchers. The only unit tests covered `classify`, with a
  single hand-written drop fixture.
- Hubble reports `lost_events`, and the runner recorded the count in the report,
  but it never affected a verdict. A run that lost telemetry could still read as
  a clean "blocked".

## Decision

1. **Match the full identity.** Every matcher now pins the drop to the foothold's
   pod-name prefix AND its namespace. The L3/L4 matcher also checks destination
   (pod prefix or IP), protocol and, where known, destination port. The L7
   matcher checks the destination workload (pod prefix + namespace) and port in
   addition to method and path. The DNS matcher requires the per-run marker in
   the query and refuses an empty marker, so a missing marker can never match
   every DNS drop.

2. **Keep the drop-reason rule correct per layer.** Only datapath L3/L4 drops
   carry `drop_reason_desc=POLICY_DENIED`, so the L3/L4 matcher still requires a
   `POLICY` reason. The L7-proxy and DNS-proxy denials are recorded as
   `verdict=DROPPED` with no reason, so for those layers the `DROPPED` verdict on
   the matched method/path/marker and identity is the evidence; demanding a
   `POLICY` reason there would reject the real drops (confirmed against
   `evidence/*/flows-hardened.jsonl.gz`).

3. **Telemetry gaps fail safe.** When Hubble reports any lost events during a
   run, a would-be `blocked` verdict is downgraded to `error`: a matched drop no
   longer certifies that nothing also slipped through. `exploitable`, `allowed`,
   `broken` and `skipped` are unaffected.

4. **Test the matchers.** `scenarios/test_matchers.py` adds flow fixtures for
   each matcher: unrelated HTTP drops, wrong namespace, wrong port/protocol,
   wrong destination, stale flows outside the window, unparseable timestamps, and
   missing telemetry. `test_classify.py` adds the collection-gap cases. Both run
   in `make check` and in CI (a new credential-free `unit` job).

## Consequences

The tightened matchers were replayed against the saved kind and EKS reference
evidence: every row that the prior run recorded as `blocked` still produces
matching evidence, and `dns-exfil` now matches only the real marker drop instead
of conflating it with the direct-receiver drop. The collection-gap rule can turn
a live run's row into `error` if Hubble sheds events under load; that is the
intended honest outcome, and the report still prints the `lost_events` count so
the cause is visible.
