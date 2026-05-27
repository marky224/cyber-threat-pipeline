# Three of these become GitHub Actions secrets after `terraform apply`
# (see infra/README.md for the post-apply checklist):
#
#   site_bucket               → REPORT_BUCKET
#   cloudfront_distribution_id → CLOUDFRONT_DISTRIBUTION_ID
#   deploy_role_arn           → AWS_DEPLOY_ROLE_ARN
#
# `site_url` is the public URL — printed for the operator's convenience.

output "site_bucket" {
  description = "Name of the S3 bucket the Evidence build syncs to."
  value       = aws_s3_bucket.site.bucket
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID; the deploy step invalidates this on each push."
  value       = aws_cloudfront_distribution.site.id
}

output "site_url" {
  description = "Public URL where the static site is served once DNS propagates."
  value       = "https://${var.site_domain}/"
}

output "deploy_role_arn" {
  description = "IAM role ARN the GitHub Actions workflow assumes via OIDC."
  value       = aws_iam_role.deploy.arn
}
