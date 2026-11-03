# Evidence

Each run of `make demo` writes `evidence/<run-id>/`:

| File | What it is |
|------|------------|
| `report.md` | The connectivity matrix, supplemental probes, reschedule receipt, preconditions, collection gaps, per-scenario status |
| `report.json` | The same, machine-readable, with each scenario's client output, time window and exemplar Hubble flow |
| `flows-<profile>.jsonl.gz` | Every Hubble flow touching a lab namespace during that profile's window |

Committed runs: `eks-reference/` (the live EKS proof), `kind-reference/` (the
local proof), and `eks-run1-fail/`, the first live run, which reported FAIL
because the node security group dropped the DNS receiver's traffic in the VPC.
It is kept as the receipt that the runner marks an unprovable row `skipped`
instead of "Denied". Ad-hoc runs are gitignored.

Nothing in here is sensitive. Markers are synthetic and generated per run, the
metadata probe discards the IMDSv2 token without printing it, and addresses
are private lab ranges.
