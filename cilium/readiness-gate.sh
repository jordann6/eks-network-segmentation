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

# Every running, non-host-network pod must have a CiliumEndpoint. Terminating
# pods are skipped, and a brand-new pod gets up to 60s to be picked up, so a
# rollout in progress (CoreDNS right after the stub-zone restart) does not
# fail the gate, but a pod that stays unmanaged does.
unmanaged_pods() {
  comm -23 \
    <(kubectl get pods -A -o json | jq -r '
        .items[] | select(.spec.hostNetwork != true) | select(.status.phase == "Running")
        | select(.metadata.deletionTimestamp == null)
        | "\(.metadata.namespace)/\(.metadata.name)"' | sort) \
    <(kubectl get ciliumendpoints -A -o json | jq -r '
        .items[] | "\(.metadata.namespace)/\(.metadata.name)"' | sort) | sed '/^$/d' || true
}
missing="$(unmanaged_pods)"
for _ in $(seq 1 12); do
  [[ -z "$missing" ]] && break
  sleep 5
  missing="$(unmanaged_pods)"
done
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
