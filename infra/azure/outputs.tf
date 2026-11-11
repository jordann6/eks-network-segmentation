output "cluster_name" {
  description = "AKS cluster name."
  value       = azurerm_kubernetes_cluster.lab.name
}

output "resource_group" {
  description = "Lab resource group."
  value       = azurerm_resource_group.lab.name
}

output "node_resource_group" {
  description = "The AKS node resource group."
  value       = local.node_resource_group
}

output "configure_kubectl" {
  description = "Command to point local kubeconfig at this cluster (Entra auth through kubelogin)."
  value       = "az aks get-credentials --resource-group ${azurerm_resource_group.lab.name} --name ${azurerm_kubernetes_cluster.lab.name} --context netseg-aks --overwrite-existing && kubelogin convert-kubeconfig -l azurecli"
}

output "acr_name" {
  description = "Registry name, for az acr build."
  value       = azurerm_container_registry.lab.name
}

output "acr_login_server" {
  description = "Registry login server, the image prefix."
  value       = azurerm_container_registry.lab.login_server
}
