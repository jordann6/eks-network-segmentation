#!/usr/bin/env bash
# Readiness gate. No lab workload is deployed, and no scenario is run, until
# Cilium and Hubble are Ready and every pod in the cluster is managed by
# Cilium. An unmanaged pod would sit outside policy enforcement and could
# turn a "Denied" into a lie, so it fails the gate rather than warning.
set -euo pipefail

echo "readiness-gate: waiting for Cilium"
cilium status --wait --wait-duration 6m >/dev/null

echo "readiness-gate: waiting for Hubble relay"
kubectl -n kube-system rollout status deployment/hubble-relay --timeout=180s >/dev/null

# Every non-host-network pod must have a CiliumEndpoint.
unmanaged="$(kubectl get pods -A -o json | jq -r '
  .items[] | select(.spec.hostNetwork != true) | select(.status.phase == "Running")
  | "\(.metadata.namespace)/\(.metadata.name)"' | sort)"
managed="$(kubectl get ciliumendpoints -A -o json | jq -r '
  .items[] | "\(.metadata.namespace)/\(.metadata.name)"' | sort)"
missing="$(comm -23 <(echo "$unmanaged") <(echo "$managed") | sed '/^$/d' || true)"
if [[ -n "$missing" ]]; then
  echo "readiness-gate: FAIL, pods not managed by Cilium:" >&2
  echo "$missing" >&2
  exit 1
fi

# Policy enforcement and the L7/DNS proxy must be live, not just the agent.
mode="$(kubectl -n kube-system get configmap cilium-config -o jsonpath='{.data.enable-policy}')"
[[ "$mode" == "default" || "$mode" == "always" ]] || { echo "readiness-gate: FAIL, enable-policy=$mode" >&2; exit 1; }
kubectl -n kube-system rollout status daemonset/cilium-envoy --timeout=180s >/dev/null

echo "readiness-gate: PASS (Cilium + Hubble ready, all pods managed, policy enforcement $mode)"
