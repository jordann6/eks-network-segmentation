# aks-phase1 is a recorded miss, kept beside the passing rerun

Overall FAIL on 2026-11-11, and the cause was the runner, not a control. Every
matrix row, the Azure IMDS row and the wire server row matched exactly as in the
passing rerun (`../aks-phase1b/`). The only failing check was the foothold RBAC
precondition: the runner compared each `kubectl auth can-i` answer to exactly
`no`, and AKS with Azure RBAC for Kubernetes answers
`no - Azure does not have opinion for this user.`, which is also a denial.

Fix in commit `68581f0`: `rbac_denied` accepts `no` or `no - <reason>` only, and
an empty or error answer still fails, so a broken probe cannot read as least
privilege. No threshold moved. The rerun on the same cluster is `aks-phase1b`.
