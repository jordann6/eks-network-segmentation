terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Local state on purpose, same rationale as eks-attack-range: a throwaway
  # deploy/demo/destroy lab in an isolated workload account with no shared state
  # bucket, torn down in the same sitting. State holds only lab resources and no
  # credentials. A longer-lived deployment would use an S3 backend in its own
  # account.
  backend "local" {}
}

provider "aws" {
  region = var.region

  # PascalCase, identical to local.tags, so module-created resources carry the
  # CostCenter tag the shared FinOps allocation gate checks for.
  default_tags {
    tags = {
      Project     = "eks-network-segmentation"
      Environment = var.environment
      Owner       = "jordann6"
      ManagedBy   = "terraform"
      CostCenter  = var.cost_center
    }
  }
}
