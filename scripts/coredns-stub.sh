#!/usr/bin/env bash
# Delegate the exfil.lab.test zone to the controlled authoritative receiver.
#
# This reproduces the real DNS-exfiltration path without touching the public
# internet: the pod asks the cluster resolver, the resolver forwards the query
# for the attacker's zone to that zone's authoritative server, and the marker
# rides in the query name. The receiver is ours, so arrival is observable.
#
# Idempotent. Re-run after the dns Service is recreated (its ClusterIP changes).
set -euo pipefail

ZONE="exfil.lab.test"
IP="$(kubectl -n egress-sim get svc dns -o jsonpath='{.spec.clusterIP}')"
[[ -n "$IP" ]] || { echo "coredns-stub: dns receiver Service not found" >&2; exit 1; }

# AKS reconciles the `coredns` ConfigMap, so an edit there is reverted. AKS reads
# customizations from the `coredns-custom` ConfigMap instead: any key ending in
# .server is imported as an extra server block (Microsoft Learn, "Customize CoreDNS
# with Azure Kubernetes Service"). Detect AKS by that ConfigMap (live check L2).
if kubectl -n kube-system get configmap coredns-custom >/dev/null 2>&1; then
  BLOCK="$(printf '%s:53 {\n    errors\n    forward . %s\n}\n' "$ZONE" "$IP")"
  kubectl -n kube-system create configmap coredns-custom --from-literal=exfil.server="$BLOCK" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n kube-system rollout restart deployment coredns >/dev/null
  kubectl -n kube-system rollout status deployment coredns --timeout=120s >/dev/null
  echo "coredns-stub (coredns-custom): $ZONE -> $IP"
  exit 0
fi

CURRENT="$(kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')"
# Drop any previous stub block, then append a fresh one.
BASE="$(printf '%s\n' "$CURRENT" | awk -v z="$ZONE:53 {" '
  $0 == z {skip=1; next}
  skip && $0 == "}" {skip=0; next}
  !skip {print}')"
NEW="$(printf '%s\n%s:53 {\n    errors\n    forward . %s\n}\n' "$BASE" "$ZONE" "$IP")"

kubectl -n kube-system create configmap coredns --from-literal=Corefile="$NEW" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n kube-system rollout restart deployment coredns >/dev/null
kubectl -n kube-system rollout status deployment coredns --timeout=120s >/dev/null
echo "coredns-stub: $ZONE -> $IP"
