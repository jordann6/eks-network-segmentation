terraform {
  required_version = ">= 1.10.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.12"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }

  # Local state on purpose, as on EKS and in the self-healing lab: one deploy,
  # demo, destroy session, torn down in the same sitting. State holds only lab
  # resources and no credentials. Moving it onto the hardened state backend is
  # Phase 6 (ADR-0006 decision 4).
  backend "local" {}
}
