# network_policy is unset because the CNI is brought by the lab: the pinned
# Cilium enforces Kubernetes and Cilium network policies (ADR-0006).
#trivy:ignore:AVD-AZU-0043
resource "azurerm_kubernetes_cluster" "lab" {
  #checkov:skip=CKV_AZURE_170:Free tier for a bounded lab session; no SLA needed.
  #checkov:skip=CKV_AZURE_172:The Secrets Store CSI driver is not used; the lab holds no secrets.
  #checkov:skip=CKV_AZURE_115:Public API server limited to the operator's /32 by authorized IP ranges, as on EKS.
  #checkov:skip=CKV_AZURE_6:Authorized ranges come from var.api_authorized_cidrs, which has no default, so a directory scan sees no ranges.
  #checkov:skip=CKV_AZURE_7:Bring your own CNI; the pinned Cilium enforces network policy (ADR-0006).
  #checkov:skip=CKV2_AZURE_29:Bring your own CNI on purpose, the same Cilium and Hubble as kind and EKS (ADR-0006).
  #checkov:skip=CKV_AZURE_117:Encryption at host with platform-managed keys; no customer-managed key in this lab.
  #checkov:skip=CKV_AZURE_232:Two single-node pools by design, so the reschedule row can move workloads to the other node.
  #checkov:skip=CKV_AZURE_116:Azure Policy for Kubernetes is not part of the experiment.
  #checkov:skip=CKV_AZURE_171:No upgrade channel, so the control plane and nodes cannot change mid-run.
  #checkov:skip=CKV_AZURE_4:Container Insights is not used; Hubble is the telemetry under test.
  #checkov:skip=CKV_AZURE_226:Managed OS disks, as in the self-healing lab.
  name                = local.name
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  node_resource_group = local.node_resource_group
  dns_prefix          = local.name
  kubernetes_version  = var.kubernetes_version
  sku_tier            = "Free"
  tags                = local.tags

  # No pod in this lab calls Azure, so the OIDC issuer and workload identity
  # stay off (ADR-0006 decision 7). They return in ADR-0004 where they are the
  # fix under test.
  oidc_issuer_enabled       = false
  workload_identity_enabled = false

  # Entra ID sign-in and Azure RBAC for Kubernetes; no local admin kubeconfig.
  local_account_disabled            = true
  role_based_access_control_enabled = true
  azure_active_directory_role_based_access_control {
    azure_rbac_enabled = true
    tenant_id          = data.azurerm_client_config.current.tenant_id
  }

  # Nodes never change under a run.
  node_os_upgrade_channel = "None"
  run_command_enabled     = true
  azure_policy_enabled    = false

  # azurerm 5.x requires the block. Manual means no node auto-provisioning: the
  # two pools below are the whole fleet.
  node_provisioning_profile {
    mode = "Manual"
  }

  api_server_access_profile {
    authorized_ip_ranges = var.api_authorized_cidrs
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.control_plane.id]
  }

  network_profile {
    network_plugin    = "none"
    pod_cidr          = local.pod_cidr
    service_cidr      = local.service_cidr
    dns_service_ip    = local.dns_ip
    load_balancer_sku = "standard"
    outbound_type     = "loadBalancer"
    load_balancer_profile {
      managed_outbound_ip_count = 1
      # Long port-forwards and Hubble streams survive idle gaps; the default
      # reclaims idle flows after four minutes.
      idle_timeout_in_minutes = 30
    }
  }

  # No Cilium agent-not-ready taint here: with network_plugin "none" the nodes
  # stay NotReady until `make cilium-aks` installs Cilium, and the readiness gate
  # blocks every workload until Cilium manages every pod.
  # Two single-node pools: the reschedule row moves frontend, api and db onto
  # the other node, as on EKS. The default pool is "a".
  default_node_pool {
    name                    = "a"
    vm_size                 = var.node_vm_size
    node_count              = 1
    vnet_subnet_id          = azurerm_subnet.nodes.id
    max_pods                = 60
    os_disk_type            = "Managed"
    os_disk_size_gb         = 64
    host_encryption_enabled = true
    node_public_ip_enabled  = false
    # The manifests pin frontend + db to slot a and api + sensitive to slot b,
    # which makes the permitted chain cross nodes (same labels as kind and EKS).
    node_labels                 = { "lab.node/slot" = "a" }
    temporary_name_for_rotation = "atmp"
    upgrade_settings {
      max_surge = "1"
      # A pod that cannot be evicted must not hang a node operation forever
      # (the self-healing lab lost about 45 minutes to a PDB-stranded drain).
      drain_timeout_in_minutes = 10
    }
    tags = local.tags
  }

  depends_on = [
    azurerm_role_assignment.control_plane_subnet,
    azurerm_subnet_network_security_group_association.nodes,
  ]
}

resource "azurerm_kubernetes_cluster_node_pool" "b" {
  name                    = "b"
  kubernetes_cluster_id   = azurerm_kubernetes_cluster.lab.id
  mode                    = "User"
  vm_size                 = var.node_vm_size
  vnet_subnet_id          = azurerm_subnet.nodes.id
  node_count              = 1
  max_pods                = 60
  os_disk_type            = "Managed"
  os_disk_size_gb         = 64
  host_encryption_enabled = true
  node_public_ip_enabled  = false
  node_labels             = { "lab.node/slot" = "b" }
  upgrade_settings {
    max_surge                = "1"
    drain_timeout_in_minutes = 10
  }
  tags = local.tags

  # Destroy order: the pool goes BEFORE the operator's cluster roles, so kubectl
  # stays authorized while the pool drains. The roles going first left a stuck
  # drain unfixable in the self-healing lab.
  depends_on = [
    azurerm_role_assignment.operator_cluster_user,
    azurerm_role_assignment.operator_cluster_admin,
  ]
}

# --- image ------------------------------------------------------------------

resource "azurerm_container_registry" "lab" {
  #checkov:skip=CKV_AZURE_237:Dedicated data endpoints need Premium; Basic for a lab registry.
  #checkov:skip=CKV_AZURE_233:Zone redundancy needs Premium; Basic for a lab registry.
  #checkov:skip=CKV_AZURE_167:Retention policies need Premium; the registry is destroyed with the lab.
  #checkov:skip=CKV_AZURE_164:Content trust needs Premium; the image is built from this repo at a pinned git SHA.
  #checkov:skip=CKV_AZURE_165:One region, one session; no geo-replication.
  #checkov:skip=CKV_AZURE_166:Image quarantine needs Premium; the image is built from this repo at a pinned git SHA.
  #checkov:skip=CKV_AZURE_163:Registry scanning is not part of the experiment.
  #checkov:skip=CKV_AZURE_139:Private endpoints need Premium; pulls authenticate with the kubelet identity, admin user off.
  name                          = "acr${local.name}${random_string.suffix.result}"
  location                      = azurerm_resource_group.lab.location
  resource_group_name           = azurerm_resource_group.lab.name
  sku                           = "Basic"
  admin_enabled                 = false
  anonymous_pull_enabled        = false
  public_network_access_enabled = true
  tags                          = local.tags
}

# The kubelet identity AKS creates in the node resource group pulls images.
resource "azurerm_role_assignment" "kubelet_acr_pull" {
  scope                = azurerm_container_registry.lab.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.lab.kubelet_identity[0].object_id
  principal_type       = "ServicePrincipal"
}

# --- the operator (whoever runs terraform with az login) --------------------

resource "azurerm_role_assignment" "operator_cluster_user" {
  scope                = azurerm_kubernetes_cluster.lab.id
  role_definition_name = "Azure Kubernetes Service Cluster User Role"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "operator_cluster_admin" {
  scope                = azurerm_kubernetes_cluster.lab.id
  role_definition_name = "Azure Kubernetes Service RBAC Cluster Admin"
  principal_id         = data.azurerm_client_config.current.object_id
}
