# Registry for the single lab image. Tags are immutable: `make image` pushes
# the git short SHA, so a run's report can name the exact image it measured.
resource "aws_ecr_repository" "lab" {
  name                 = "${local.name}/lab"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true # lets `make destroy` remove it with images inside

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
  }

  tags = local.tags
}
