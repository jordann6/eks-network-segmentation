variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment, tagged onto every resource for cost allocation."
  type        = string
  default     = "lab"
}

variable "cluster_name" {
  description = "EKS cluster name."
  type        = string
  default     = "netseg"
}

variable "cost_center" {
  description = "Chargeback code, house format cc-NNNN, stamped on every resource via default_tags so the shared FinOps gate can allocate the spend."
  type        = string
  default     = "cc-1009"

  validation {
    condition     = can(regex("^cc-[0-9]{4}$", var.cost_center))
    error_message = "cost_center must match the house format cc-NNNN (e.g. cc-1009)."
  }
}

variable "cluster_public_access_cidrs" {
  description = <<-EOT
    CIDRs allowed to reach the public EKS API endpoint. The scenario runner
    drives the cluster from the operator's machine, so the endpoint is public but
    scoped to a single /32. The default is a non-routable placeholder so a bare
    apply fails loudly; `make eks-plan` passes your own IPv4 /32.
  EOT
  type        = list(string)
  default     = ["192.0.2.1/32"] # TEST-NET-1, non-routable: forces an explicit value

  validation {
    condition     = !contains(var.cluster_public_access_cidrs, "0.0.0.0/0")
    error_message = "Refusing 0.0.0.0/0. Scope the endpoint to your own /32."
  }
}

variable "cluster_version" {
  description = "EKS Kubernetes version. Pinned to a standard-support version Cilium 1.20 supports."
  type        = string
  default     = "1.34"
}

variable "node_instance_type" {
  description = "Instance type for each of the two single-node groups."
  type        = string
  default     = "t3.medium"
}

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC."
  type        = string
  default     = "10.20.0.0/16"
}
