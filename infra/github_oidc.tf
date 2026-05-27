# ──────────────────────────────────────────────────────────────
# github_oidc.tf — GitHub Actions OIDC provider + deploy IAM role
# ──────────────────────────────────────────────────────────────
# Spec 05 §B5/§B7. We Terraform the OIDC trust surface (rather than
# clicking it in by hand) so:
#   • The trust policy is reviewable in code.
#   • Permissions are tightly scoped — no `*` resources.
#   • The whole deploy surface can be re-created in another AWS
#     account by re-applying.
# ──────────────────────────────────────────────────────────────

# GitHub Actions OIDC provider (account-global; one per AWS account).
#
# We look this up as a data source rather than creating it, so other
# projects in the same AWS account that share the OIDC provider keep
# working. AWS only permits one `token.actions.githubusercontent.com`
# provider per account; STS verifies the JWT's signature against
# GitHub's JWKS at runtime, so the per-provider thumbprint is no
# longer load-bearing — any project's provider works for any other.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

# Trust policy: only this repo + this branch (and the matching
# `environment:production` context) may assume the role. PRs from
# forks cannot — their `sub` claim is `pull_request:`, which doesn't
# match either pattern below.
data "aws_iam_policy_document" "deploy_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_repo}:ref:refs/heads/${var.deploy_branch}",
        "repo:${var.github_repo}:environment:production",
      ]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name               = "${var.project_name}-deploy"
  description        = "Assumed by GitHub Actions (OIDC) to sync the Evidence build to S3 + invalidate CloudFront."
  assume_role_policy = data.aws_iam_policy_document.deploy_assume.json

  tags = {
    Project = var.project_name
  }
}

# Permissions: write to the site bucket + invalidate the distribution.
# Nothing else. Both resource ARNs are pinned to specific resources —
# no wildcards.
data "aws_iam_policy_document" "deploy_permissions" {
  statement {
    sid    = "S3Sync"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:GetObject",
    ]
    resources = [
      aws_s3_bucket.site.arn,
      "${aws_s3_bucket.site.arn}/*",
    ]
  }

  statement {
    sid       = "CloudFrontInvalidate"
    effect    = "Allow"
    actions   = ["cloudfront:CreateInvalidation"]
    resources = [aws_cloudfront_distribution.site.arn]
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "${var.project_name}-deploy-policy"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy_permissions.json
}
