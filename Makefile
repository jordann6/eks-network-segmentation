# Kubernetes Network Segmentation Lab: deploy / demo / destroy.
#
# Two targets for the same experiment:
#   kind  local, zero cloud spend. Proves the policy behavior, the runner and
#         the report semantics.            make kind-up app demo kind-down
#   EKS   one bounded live session. Same manifests, same policies, same runner;
#         adds AWS ENI IPAM and a real instance metadata service.
#         make eks-plan, then apply the saved plan yourself, then
#         make cilium-eks eks-image app demo, then make eks-destroy-plan and
#         apply that yourself. Nothing is left running.
#
# Prereqs: docker, kind, kubectl, helm, cilium, hubble, jq, python3;
# terraform + aws for EKS.

SHELL := /usr/bin/env bash
TF := terraform -chdir=infra
CILIUM_VERSION := 1.20.4
KIND_CLUSTER := netseg
IMAGE_TAG := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)

.DEFAULT_GOAL := help

.PHONY: help
help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-17s\033[0m %s\n",$$1,$$2}'

# --- local (kind) -----------------------------------------------------------

.PHONY: kind-up
kind-up: ## Create the kind cluster (no default CNI), install pinned Cilium + Hubble, gate on readiness
	kind create cluster --config kind/cluster.yaml
	helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
	helm repo update cilium >/dev/null
	helm upgrade --install cilium cilium/cilium --version $(CILIUM_VERSION) -n kube-system \
		-f cilium/values-common.yaml -f cilium/values-kind.yaml
	cilium/readiness-gate.sh
	docker build -t netseg-lab:dev app
	kind load docker-image netseg-lab:dev --name $(KIND_CLUSTER)

.PHONY: kind-down
kind-down: ## Delete the kind cluster
	kind delete cluster --name $(KIND_CLUSTER)

# --- shared: workloads and the experiment ----------------------------------

.PHONY: app
app: ## Deploy the four-namespace topology and receivers (refuses to run before the readiness gate passes)
	cilium/readiness-gate.sh
	@if [[ -f app/k8s-eks/kustomization.yaml && "$$(kubectl config current-context)" != kind-* ]]; then \
		kubectl apply -k app/k8s-eks; else kubectl apply -k app/k8s; fi
	for ns in frontend backend sensitive egress-sim; do \
		kubectl -n $$ns rollout status deploy --timeout=180s; done
	scripts/coredns-stub.sh
	cilium/readiness-gate.sh

.PHONY: demo
demo: ## Run baseline -> hardened -> reschedule and write evidence/<run-id>/report.md
	python3 scenarios/run.py $(if $(RUN_ID),--run-id $(RUN_ID),)

.PHONY: baseline
baseline: ## Apply only the permissive policy (manual exploration)
	for ns in frontend backend sensitive; do kubectl -n $$ns delete cnp,netpol --all; done
	kubectl apply -f policy/baseline

.PHONY: hardened
hardened: ## Apply only the hardened policy (manual exploration)
	for ns in frontend backend sensitive; do kubectl -n $$ns delete cnp,netpol --all; done
	kubectl apply -f policy/hardened

.PHONY: test
test: ## Unit-test the runner's honesty rules + evidence matchers (no cluster needed)
	cd scenarios && python3 -m unittest -v test_classify test_matchers

# --- EKS (one bounded live session) ----------------------------------------
# The credentialed apply and destroy are run by the operator from the saved
# plans this prints, not by make, so a human reads every plan first.

.PHONY: eks-plan
eks-plan: ## Write infra/tfplan (endpoint scoped to your IPv4 /32) and print the apply command
	$(TF) init -input=false
	$(TF) plan -input=false -out=tfplan \
		-var='cluster_public_access_cidrs=["'"$$(curl -4 -s ifconfig.me)"'/32"]'
	@echo; echo "Read the plan, then run:  terraform -chdir=$(CURDIR)/infra apply $(CURDIR)/infra/tfplan"

.PHONY: cilium-eks
cilium-eks: ## Point kubectl at EKS, switch off the VPC CNI, install Cilium in ENI mode, gate
	$$($(TF) output -raw configure_kubectl)
	# aws-node stays installed but can never schedule: no node carries this label.
	kubectl -n kube-system patch daemonset aws-node --type=strategic \
		-p '{"spec":{"template":{"spec":{"nodeSelector":{"io.cilium/aws-node-enabled":"true"}}}}}'
	helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
	helm repo update cilium >/dev/null
	helm upgrade --install cilium cilium/cilium --version $(CILIUM_VERSION) -n kube-system \
		-f cilium/values-common.yaml -f cilium/values-eks.yaml
	cilium/readiness-gate.sh

.PHONY: eks-image
eks-image: ## Build linux/amd64, push the git-SHA tag to ECR, write the EKS kustomize overlay
	$(eval ECR := $(shell $(TF) output -raw ecr_repository_url))
	aws ecr get-login-password --region $$($(TF) output -raw region) \
		| docker login --username AWS --password-stdin $(word 1,$(subst /, ,$(ECR)))
	docker buildx build --platform linux/amd64 -t $(ECR):$(IMAGE_TAG) --push app
	mkdir -p app/k8s-eks
	printf 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - ../k8s\nimages:\n  - name: netseg-lab\n    newName: %s\n    newTag: "%s"\n' \
		"$(ECR)" "$(IMAGE_TAG)" > app/k8s-eks/kustomization.yaml

.PHONY: eks-destroy-plan
eks-destroy-plan: ## Remove workloads + Cilium, then write infra/destroy.tfplan and print the destroy command
	-kubectl delete -k app/k8s --ignore-not-found --wait=true
	-helm uninstall cilium -n kube-system --wait
	$(TF) plan -destroy -input=false -out=destroy.tfplan \
		-var='cluster_public_access_cidrs=["'"$$(curl -4 -s ifconfig.me)"'/32"]'
	@echo; echo "Read the plan, then run:  terraform -chdir=$(CURDIR)/infra apply $(CURDIR)/infra/destroy.tfplan"
	@echo "Then:  make eks-verify-gone"

.PHONY: eks-verify-gone
eks-verify-gone: ## Confirm nothing hourly survived: no cluster, no NAT gateway, no lab ENIs
	@# Not read from terraform output: after a destroy the state has no outputs
	@# and terraform prints its warning on stdout, which corrupts the value.
	@r=$${AWS_REGION:-us-east-1}; \
	echo "clusters:   $$(aws eks list-clusters --region $$r --query 'clusters[?@==`netseg`]' --output text)"; \
	echo "nat gws:    $$(aws ec2 describe-nat-gateways --region $$r --filter Name=tag:Project,Values=eks-network-segmentation Name=state,Values=available,pending --query 'NatGateways[].NatGatewayId' --output text)"; \
	echo "lab ENIs:   $$(aws ec2 describe-network-interfaces --region $$r --filters Name=tag:cilium-managed,Values=true --query 'NetworkInterfaces[].NetworkInterfaceId' --output text)"; \
	echo "(all three empty = nothing left running)"

# --- local gates (platform-guardrails equivalents) --------------------------

.PHONY: check
check: ## Static checks: fmt, validate, tflint, checkov (baseline), trivy, conftest, unit tests
	$(TF) fmt -check -recursive
	$(TF) init -backend=false -input=false >/dev/null && $(TF) validate
	tflint --chdir=infra --recursive --minimum-failure-severity=error
	checkov -d infra --framework terraform --quiet --compact --baseline infra/.checkov.baseline
	trivy config --severity CRITICAL,HIGH --exit-code 1 --skip-dirs infra/.terraform infra
	conftest test --parser hcl2 --combine --policy ../platform-guardrails/policy infra/*.tf
	$(MAKE) test
