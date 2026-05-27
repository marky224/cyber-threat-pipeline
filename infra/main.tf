# Terraform + AWS provider configuration.
#
# State is local for v1 (single-operator project). When/if multi-operator
# work demands it, swap in an S3 backend block here. The state file is
# gitignored (see project root .gitignore).
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# CloudFront's ACM certificate must live in us-east-1; pinning all
# resources here keeps the stack single-region.
provider "aws" {
  region = "us-east-1"
}

# ── Data: current AWS account ID (used by the deploy-role trust policy).
data "aws_caller_identity" "current" {}

# ── Data: Route 53 hosted zone for the apex domain.
# Managed outside this project; we look it up by name and reference its
# zone_id for the site's A/AAAA records and the ACM DNS validation.
data "aws_route53_zone" "root" {
  name         = "markandrewmarquez.com"
  private_zone = false
}
