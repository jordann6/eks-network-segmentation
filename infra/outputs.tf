output "cluster_name" {
  description = "EKS cluster name."
  value       = module.eks.cluster_name
}

output "region" {
  description = "AWS region."
  value       = var.region
}

output "configure_kubectl" {
  description = "Command to point local kubeconfig at this cluster."
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name} --alias netseg-eks"
}

output "ecr_repository_url" {
  description = "Push the lab image here."
  value       = aws_ecr_repository.lab.repository_url
}
