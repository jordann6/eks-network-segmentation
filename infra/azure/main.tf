# AKS for the segmentation lab (ADR-0006). Not vulnerable at the infra layer:
# the foothold is planted in the app and the only variable under test is network
# policy, as on EKS. Bring your own CNI: the cluster is created with
# network_plugin "none" and `make cilium-aks` installs the pinned Cilium.

provider "azurerm" {
  subscription_id = var.subscription_id

  # Register nothing implicitly: an unexpected registration is a mutation the
  # operator did not read in the plan.
  resource_provider_registrations = "none"

  features {
    resource_group {
      # Fail closed: a destroy that finds something Terraform did not create in
      # the lab group stops instead of deleting it.
      prevent_deletion_if_contains_resources = true
    }
  }
}

data "azurerm_client_config" "current" {}

locals {
  name = var.cluster_name

  # azurerm has no provider-level default tags, so every resource sets these.
  tags = {
    Project     = "eks-network-segmentation"
    Environment = var.environment
    Owner       = "jordann6"
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
    cost_center = var.cost_center
  }

  node_resource_group = "rg-${local.name}-nodes"

  # BYO Cilium cluster pool; must match cilium/values-aks.yaml and stay clear of
  # the VNet and the service CIDR.
  vnet_cidr    = "10.42.0.0/16"
  nodes_cidr   = "10.42.0.0/22"
  pod_cidr     = "10.244.0.0/16"
  service_cidr = "10.96.0.0/16"
  dns_ip       = "10.96.0.10"
}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "lab" {
  name                = "vnet-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  address_space       = [local.vnet_cidr]
  tags                = local.tags
}

resource "azurerm_subnet" "nodes" {
  name                 = "snet-${local.name}-nodes"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = [local.nodes_cidr]
  # Egress goes through the cluster's load balancer, never the implicit default
  # outbound address.
  default_outbound_access_enabled = false
}

# The control plane joins a subnet the lab owns, so its identity must hold the
# join permission before the cluster exists.
resource "azurerm_user_assigned_identity" "control_plane" {
  name                = "id-${local.name}-aks"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
}

resource "azurerm_role_assignment" "control_plane_subnet" {
  scope                = azurerm_subnet.nodes.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_user_assigned_identity.control_plane.principal_id
  principal_type       = "ServicePrincipal"
}

# The node subnet carries an NSG so the subnet is not unfiltered. The rules stay
# at Azure's defaults plus an explicit no-SSH, no-RDP deny (nodes are reached
# through Run Command only). The default rules already allow VNet-internal
# traffic, so node-to-node VXLAN and pod traffic are unaffected; pod-to-pod
# filtering is the job of the policy under test (ADR-0002).
resource "azurerm_network_security_group" "nodes" {
  name                = "nsg-${local.name}-nodes"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
}

resource "azurerm_network_security_rule" "deny_remote_admin" {
  name                        = "deny-ssh-rdp-all"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["22", "3389"]
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.nodes.name
}

resource "azurerm_subnet_network_security_group_association" "nodes" {
  subnet_id                 = azurerm_subnet.nodes.id
  network_security_group_id = azurerm_network_security_group.nodes.id
}
