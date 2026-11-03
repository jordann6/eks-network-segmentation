# Evidence

Each run of `make demo` writes `evidence/<run-id>/`:

| File | What it is |
|------|------------|
| `report.md` | The connectivity matrix, supplemental probes, reschedule receipt, preconditions, collection gaps, per-scenario status |
| `report.json` | The same, machine-readable, with each scenario's client output, time window and exemplar Hubble flow |
| `flows-<profile>.jsonl.gz` | Every Hubble flow touching a lab namespace during that profile's window |

Only reference runs are committed: `kind-reference/` (local proof) and, after
the live session, `eks-reference/`. Ad-hoc runs are gitignored.

Nothing in here is sensitive. Markers are synthetic and generated per run, the
metadata probe discards the IMDSv2 token without printing it, and addresses
are private lab ranges.
