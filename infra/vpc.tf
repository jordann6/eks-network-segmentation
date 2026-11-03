data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name = var.cluster_name
  azs  = slice(data.aws_availability_zones.available.names, 0, 2)

  # Must match the provider default_tags casing exactly.
  tags = {
    Project     = "eks-network-segmentation"
    Environment = var.environment
    Owner       = "jordann6"
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

# No firewall layer here on purpose (ADR-0002). An AWS Network Firewall or a
# restrictive egress security group would also deny the exfil and internet
# rows, and the matrix could no longer attribute the denial to pod policy.
# Security groups exist (module defaults) and are identical in both runs.
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${local.name}-vpc"
  cidr = var.vpc_cidr
  azs  = local.azs

  # /20 private subnets: Cilium ENI IPAM hands pods real VPC addresses, so the
  # pod subnets need room.
  private_subnets = ["10.20.0.0/20", "10.20.16.0/20"]
  public_subnets  = ["10.20.101.0/24", "10.20.102.0/24"]

  # Single NAT keeps the hourly footprint small; the internet-egress probe and
  # image pulls go out through it.
  enable_nat_gateway = true
  single_nat_gateway = true

  tags = local.tags
}
