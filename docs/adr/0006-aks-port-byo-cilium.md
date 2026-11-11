# ADR-0006: AKS port uses bring-your-own Cilium 1.20.4

- **Status:** accepted
- **Date:** 2026-11-11

## Context

This lab proves six segmentation rows (identity L3/L4, L7 HTTP, DNS query-name,
metadata, internet egress, and the legitimate flows) on kind and EKS with one
pinned Cilium (ADR-0001) and one runner whose matchers key off Hubble flow
identity (ADR-0005). EKS Session B (`evidence/eks-phase1`, 2026-11-11) passed
all six rows with no misses and showed that enforcement follows Cilium identity
across a reschedule. The AKS port is measured against that result, so the
engine under test has to stay the same engine.

The lab leans on specific Cilium settings that `cilium/values-common.yaml`
pins. The L7 proxy and DNS proxy are on, the DNS proxy rejects with REFUSED
(the runner keys DNS evidence off that rcode), and Hubble keeps a 65535-event
ring buffer so a full matrix fits before export.

Facts read from Microsoft Learn on 2026-11-11, all as of that date.

- Azure CNI Powered by Cilium ships a Cilium chosen by AKS. For Kubernetes 1.36
  the stated minimum is Cilium 1.19.6, not 1.20.4. Only label exclusion is
  supported in the `cilium-config` ConfigMap, and changes to other values are
  not supported.
- FQDN filtering and L7 (HTTP, gRPC, Kafka) policy are not available without
  Advanced Container Networking Services (ACNS), which is a paid offering.
  Enabling L7 needs the `--acns-advanced-networkpolicies L7` option.
- With ACNS, FQDN filtering is served by an ACNS Security Agent that resolves
  DNS for pods under an FQDN policy, not by Cilium's own DNS proxy. L7 policy is
  not supported through `CiliumClusterwideNetworkPolicy`, and `ipBlock` cannot
  select pod or node IPs.
- The FQDN concepts page says "Other L7 policies aren't supported" while the
  L7 page documents HTTP rules. The two pages disagree on whether a policy can
  combine an FQDN rule with an L7 rule, so parity is UNVERIFIED rather than
  assumed.
- By default every pod can reach IMDS (169.254.169.254) on AKS. Microsoft's
  IMDS restriction for non host network pods is a preview feature, which is
  also the control this lab exists to test, so the lab must not enable it.

The self-healing lab already runs the BYO path on AKS (`network_plugin =
"none"`, `aksbyocni.enabled`, cluster-pool IPAM, VXLAN tunnel). Its N1, O1 and
L7 and DNS checks passed live on AKS 1.36.5 on 2026-11-11, so the chart
behaviour is proven in this subscription.

## Decision

1. **CNI.** Bring your own Cilium, chart 1.20.4, installed by this repo's
   Makefile on an AKS cluster created with `network_plugin = "none"`. A new
   `cilium/values-aks.yaml` layers on `values-common.yaml` exactly as
   `values-eks.yaml` does, and carries only IPAM and routing (`aksbyocni`,
   cluster-pool IPAM with a pod CIDR clear of the VNet and services, VXLAN
   tunnel, `kubeProxyReplacement` false). The policy engine, L7 proxy, DNS
   proxy, REFUSED rcode and Hubble settings stay identical to kind and EKS.
2. **Same readiness gate, same runner.** `cilium/readiness-gate.sh` still
   blocks workloads until Cilium and Hubble are Ready and every pod has a
   CiliumEndpoint. The runner and matchers are unchanged except for the
   metadata row below. No threshold moves.
3. **Metadata row measures two endpoints.** The existing `metadata` row becomes
   the Azure IMDS probe, and a new `wireserver` row is added beside it.
   - IMDS probe. A reachability request to `169.254.169.254` using the Azure
     header `Metadata: true` against the instance endpoint, body discarded, no
     token path ever requested (same rule as the EKS probe, network access is
     not credential theft). Hardened expects an L3/L4 drop from the explicit
     `egressDeny` on `169.254.169.254/32`, the same policy the EKS lab uses.
   - Wire server probe. A TCP reachability check to `168.63.129.16`, kept as a
     separate row so its result is never merged into the IMDS verdict. It is
     recorded as a finding first. Whether the hardened state should deny it is
     decided after the live probe shows what a pod can actually reach, because
     blocking it can break platform functions (DNS from the platform resolver,
     extension and agent traffic for host processes). Host network pods are not
     covered by pod policy at all, which the report states plainly.
   - Both rows keep `environmental` semantics, so if a probe is not reachable
     even with the permissive baseline the status is `skipped`, never a false
     defended.
4. **Infra location.** A new `infra/azure/` Terraform root beside the existing
   AWS root in `infra/`. The AWS files do not move, so the proven EKS targets
   and evidence paths stay valid. State is local, matching the EKS root, and
   moving it onto the hardened state backend is Phase 6.
5. **Cluster shape.** Two single-node pools so the reschedule row can move
   frontend, api and db onto the other node, as on EKS. `kubernetes_version`
   defaults to 1.36 and is checked with `kubectl version` against the server
   before any row runs (the lesson from the 1.34 default miss). VM sizes follow
   the quota layout that fit on 2026-11-11 (10 regional vCPUs, DSv3 deprecated
   and not raisable, Dsv6 available) and are re-checked in the plan, not
   assumed.
6. **Image.** Azure Container Registry (Basic) replaces ECR, the node pools
   pull through the kubelet identity with `AcrPull`, and the image is built
   with `az acr build` so no local Docker push is needed.
7. **No pod calls Azure in this lab**, so workload identity stays off. The
   OIDC issuer and workload identity are not enabled on this cluster. They come
   back in ADR-0004 (attack range) where they are the fix being tested.
8. **Teardown safety.** Both node pools set a drain timeout so a stranded pod
   cannot hang `terraform destroy` for 45 minutes as happened in the
   self-healing lab. Destroy remains a saved plan the operator applies, then
   `verify-gone`. API access is limited to the operator's /32 by plan-time
   variable, with no default, as on EKS.
9. **Sequence.** Local first. `values-aks.yaml` is rendered and linted offline
   and the kind demo and `make test` stay green with it present. Then one paid
   AKS session. The matrix runs as one demo with nothing else touching the
   cluster. Hubble captures over 1024 KB are truncated with a sha256 meta file
   and the full file kept outside the repo, per the existing convention.

## Alternatives rejected

| Option | Why not |
| ------ | ------- |
| Azure CNI Powered by Cilium with ACNS | Cilium version is chosen by AKS (minimum 1.19.6 on 1.36), the ConfigMap is locked, so the REFUSED rcode and Hubble buffer cannot be pinned. FQDN filtering runs in a separate ACNS agent, not Cilium's DNS proxy, so the DNS row would measure a different mechanism. L7 plus FQDN combination parity is contradicted by two Microsoft pages. It is also a paid add-on. Results would not be comparable to kind and EKS. |
| Azure CNI Powered by Cilium without ACNS | No L7 and no FQDN, which removes two of the six rows. |
| Azure Network Policy Manager or Calico | L3/L4 only for this purpose, same gap as the VPC CNI alternative in ADR-0001. |
| Microsoft IMDS restriction preview for the metadata row | It is the control being tested, it is preview, and enabling it would make the baseline unmeasurable. |
| Move existing `infra/` to `infra/aws/` | Churns the proven EKS targets and evidence paths for no benefit to this port. |

## Consequences

The lab owns Cilium upgrades on AKS, so a Kubernetes or Cilium bump must be
re-proved rather than inherited from AKS. BYO means AKS does not offer
Microsoft support for the CNI, which is acceptable for a lab and is stated in
the README. The runner gains one new row, so the matrix is seven rows on AKS
and six on EKS and kind, and the report labels it Azure-only.

Open items to settle in the live session, none of which block acceptance of
this ADR.

- What a pod can reach at `168.63.129.16`, and whether hardened should deny it.
- Whether the default Azure Linux or Ubuntu node image changes any Cilium
  datapath assumption on 1.36.5 (the self-healing lab ran this combination, so
  expected clean).
- Whether Azure IMDS answers the reachability probe from a pod network
  namespace on the chosen CNI mode without the `Metadata: true` header, which
  decides whether the probe can ever read as reachable with a wrong header.

Revisit if Microsoft documents a way to pin Cilium and set the DNS reject code
under the managed CNI, or if ACNS L7 and FQDN are shown to compose in one
policy. Evidence to collect for a re-decision would be a kind-equivalent run of
the six rows on managed Cilium, recorded as a separate comparison and not
substituted for the BYO result.
