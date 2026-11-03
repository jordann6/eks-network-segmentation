# Runbook: one bounded live EKS session

Goal: regenerate the connectivity matrix against real EKS with Cilium ENI
IPAM and a real instance metadata service, capture Hubble flows, and tear
everything down in the same sitting. The local kind proof (`make kind-up app
demo`) should already pass before any of this is run.

Cost while up: EKS control plane (~$0.10/hr) + 2 x t3.medium on demand
(~$0.08/hr) + one NAT gateway (~$0.045/hr) + data. No load balancer: the runner
reaches the foothold through `kubectl port-forward`. Budget about one hour.

The credentialed `terraform apply` steps are run by the operator from saved
plans, using absolute paths, so a human reads every plan before it executes.

## 0. Preflight

```bash
export AWS_PROFILE=<isolated-lab-profile>
aws sts get-caller-identity          # confirm the throwaway workload account
make check                           # fmt, validate, tflint, checkov, trivy, conftest, unit tests
curl -4 -s ifconfig.me               # must be an IPv4 address (IPv6 /32 is not a valid CIDR)
```

## 1. Infrastructure

```bash
make eks-plan
# read the plan: VPC, NAT, EKS, two single-node groups, ECR, one IAM policy
terraform -chdir=$HOME/eks-network-segmentation/infra apply $HOME/eks-network-segmentation/infra/tfplan
```

Nodes come up with the `node.cilium.io/agent-not-ready` taint, so CoreDNS stays
Pending until Cilium is in. That is expected.

## 2. Cilium (ENI mode) and the readiness gate

```bash
make cilium-eks
```

This updates kubeconfig, pins `aws-node` to a label no node carries, installs
Cilium 1.20.4 with `values-common.yaml` + `values-eks.yaml`, and runs the gate.
If the gate reports unmanaged pods (anything that got a VPC CNI address before
the switch), delete those pods and re-run `cilium/readiness-gate.sh`.

Check ENI mode is really in use:

```bash
kubectl -n kube-system get cm cilium-config -o jsonpath='{.data.ipam}'   # eni
kubectl get ciliumnodes -o wide
```

## 3. Image, workloads, experiment

```bash
make eks-image      # linux/amd64, pushes :<git sha>, writes app/k8s/eks overlay
make app            # gate, apply, CoreDNS stub zone, gate again
make demo RUN_ID=eks-reference
```

On EKS the metadata probe should now be measurable: the baseline must show
the IMDSv2 token endpoint answering (`200`) and the hardened run must show a
Hubble `POLICY_DENY` drop to `169.254.169.254`. If the baseline cannot reach
IMDS, the row reports `skipped`, never "defended"; record why rather than
changing the hop limit mid-session.

Save the evidence before tearing down:

```bash
ls evidence/eks-reference   # report.md, report.json, flows-*.jsonl.gz (committed)
```

## 4. Teardown

```bash
make eks-destroy-plan
terraform -chdir=$HOME/eks-network-segmentation/infra apply $HOME/eks-network-segmentation/infra/destroy.tfplan
make eks-verify-gone       # no cluster, no NAT gateway, no Cilium-managed ENIs
```

`eks-destroy-plan` deletes the workloads and uninstalls Cilium first. Cilium
creates its ENIs with delete-on-termination, so they leave with the nodes;
`eks-verify-gone` confirms it. If an ENI lingers, it blocks subnet deletion:
delete it by ID with `aws ec2 delete-network-interface` and re-run the
destroy plan.

## Known sharp edges

- Under ENI IPAM, pods carry the node security group. `infra/eks.tf` adds a
  self-referencing all-traffic rule; without it, cross-node pod traffic on
  ports the EKS module does not open (the DNS receiver's UDP 5353) is dropped
  in the VPC and looks like a failed baseline.
- The readiness gate retries for 60s, because CoreDNS restarts right after
  the stub zone is written and its new pods need a moment to get endpoints.

- `curl ifconfig.me` can return IPv6; the Makefile uses `curl -4`.
- Strict DNS allowlists need `ndots:2` (already in the manifests; ADR-0004).
- Kubernetes injects `<SERVICE>_PORT` env vars into pods; the manifests set
  `enableServiceLinks: false` and the app reads `LAB_`-prefixed variables.
