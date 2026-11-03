# EKS for the segmentation lab. Unlike eks-attack-range this cluster is not
# vulnerable at the infra layer: the foothold is planted in the app, and the
# only variable under test is network policy. The VPC CNI is switched off by
# `make cilium-eks` (aws-node is pinned to a node label nothing carries) and
# Cilium takes over with AWS ENI IPAM. No CNI chaining: Cilium documents L7
# limitations under chaining and this lab needs L7 and DNS policy (ADR-0001).

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.31"

  cluster_name    = local.name
  cluster_version = var.cluster_version

  # Public endpoint scoped to the operator's /32 (variables.tf refuses
  # 0.0.0.0/0). The runner drives kubectl and Hubble from the laptop.
  cluster_endpoint_public_access       = true
  cluster_endpoint_public_access_cidrs = var.cluster_public_access_cidrs

  authentication_mode                      = "API_AND_CONFIG_MAP"
  enable_cluster_creator_admin_permissions = true

  cluster_enabled_log_types = ["api", "audit", "authenticator"]

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Under Cilium ENI IPAM, pod addresses live on ENIs that carry the NODE
  # security group, so that group is a filter on every cross-node pod-to-pod
  # packet. The module's recommended rules only open node-to-node TCP
  # 1025-65535 and 53/udp, which silently dropped the DNS receiver's UDP 5353 in
  # the VPC before Cilium ever saw it (found on the first live run). Pod-to-pod
  # filtering is the job of the policy under test, so the node group trusts
  # itself on all ports, identically in both runs (ADR-0002).
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node, all ports and protocols (pod-to-pod under Cilium ENI IPAM)"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
  }

  # Two single-node groups instead of one two-node group, so each node gets a
  # distinct lab.node/slot label. The manifests pin frontend + db to slot a and
  # api + sensitive to slot b, which makes the permitted chain cross nodes.
  eks_managed_node_groups = {
    for slot in ["a", "b"] : "slot-${slot}" => {
      instance_types = [var.node_instance_type]
      min_size       = 1
      max_size       = 1
      desired_size   = 1
      capacity_type  = "ON_DEMAND"
      subnet_ids     = [module.vpc.private_subnets[slot == "a" ? 0 : 1]]

      labels = { "lab.node/slot" = slot }

      # Nothing but Cilium (and aws-node, which tolerates everything and is
      # disabled right after) schedules until the Cilium agent is ready on the
      # node and removes this taint. That is the node half of the readiness gate.
      taints = {
        cilium = {
          key    = "node.cilium.io/agent-not-ready"
          value  = "true"
          effect = "NO_EXECUTE"
        }
      }

      # Identical in both runs (ADR-0002). IMDSv2 required; hop limit 2 so that
      # the baseline can actually measure metadata reachability over the pod
      # network. With hop limit 1 the probe would report "skipped", and the
      # network policy row would have nothing to prove. Production sets 1 as
      # well as the egress deny; see the README.
      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 2
      }

      iam_role_additional_policies = {
        cilium_eni = aws_iam_policy.cilium_eni.arn
      }
    }
  }

  tags = local.tags
}

# Cilium's operator allocates ENIs and secondary IPs using the node role
# (it runs host-networked). AmazonEKS_CNI_Policy, which the module attaches,
# covers the ENI mutations; the operator also needs these read-only lookups.
resource "aws_iam_policy" "cilium_eni" {
  name        = "${local.name}-cilium-eni"
  description = "Read-only EC2 lookups Cilium ENI IPAM needs beyond AmazonEKS_CNI_Policy."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "CiliumEniDescribe"
      Effect = "Allow"
      Action = [
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRouteTables",
      ]
      Resource = "*" # Describe* calls do not support resource-level scoping.
    }]
  })

  tags = local.tags
}
