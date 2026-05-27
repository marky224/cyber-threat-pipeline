# infra/ — Terraform stack for the Evidence site

Hosts the static Evidence build in AWS:

```
S3 (private)  ◄── OAC ──  CloudFront ── ACM (DNS-validated)
                              │
                              ▼
                          Route 53
                          cyber-intel.markandrewmarquez.com (A + AAAA aliases)

GitHub Actions ── OIDC ── deploy IAM role
    │                              │
    │                              ▼
    └── aws s3 sync + cloudfront create-invalidation
```

Spec: `_private/specs/05-reporting-evidence.md` Part B. The stack is
modeled on `github.com/marky224/cloudwatch-monitor`'s `status-page.tf`
pattern, minus the Lambda/EventBridge canary subsystem, plus a GitHub
OIDC provider + deploy role (cloudwatch-monitor runs Terraform locally
and so has no CI-auth surface to manage; we run deploys from CI).

## Files

| File | Purpose |
|---|---|
| `main.tf` | Terraform + AWS provider config (us-east-1); `data.aws_route53_zone.root` lookup. |
| `variables.tf` | `project_name`, `site_domain`, `github_repo`, `deploy_branch`. |
| `outputs.tf` | `site_bucket`, `cloudfront_distribution_id`, `site_url`, `deploy_role_arn`. |
| `site.tf` | S3 + OAC + CloudFront + ACM + Route 53 A/AAAA. |
| `github_oidc.tf` | OIDC provider + deploy role (tight scope: PutObject/DeleteObject/ListBucket/GetObject on the site bucket; CreateInvalidation on the specific distribution; nothing else). |
| `terraform.tfvars.example` | Public template — copy to `terraform.tfvars` (gitignored) if you override defaults. |

## Apply (one-time, operator action)

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars   # only needed if overriding defaults
terraform init
terraform plan
terraform apply
```

The apply takes a few minutes (CloudFront distribution creation is the
slow step). ACM DNS validation auto-completes via the `aws_route53_record`
resources — no manual record-add step.

**Allow time for DNS / CloudFront propagation:** ACM validation can take
5-30 minutes; CloudFront global distribution another 15-45 minutes. The
apply will return immediately but `https://cyber-intel.markandrewmarquez.com/`
won't respond 200 until both finish.

## After apply: capture three outputs as GitHub Actions secrets

`pipeline.yml` already references these (with the env name listed below);
they must be set in the repo's **Actions secrets** for the deploy step to
work:

| Terraform output | GitHub secret |
|---|---|
| `deploy_role_arn` | `AWS_DEPLOY_ROLE_ARN` |
| `site_bucket` | `REPORT_BUCKET` |
| `cloudfront_distribution_id` | `CLOUDFRONT_DISTRIBUTION_ID` |

```bash
terraform output -raw deploy_role_arn
terraform output -raw site_bucket
terraform output -raw cloudfront_distribution_id
```

## OIDC trust policy: load-bearing

The deploy role's `sub` condition only accepts two patterns:

- `repo:<owner>/<repo>:ref:refs/heads/main` — push/cron from the deploy branch
- `repo:<owner>/<repo>:environment:production` — workflow_dispatch with the production environment

PR-context tokens (`pull_request:`) DO NOT MATCH and cannot assume the
role. **Don't widen this** without a security review — a wildcard would
let any PR from a fork run the deploy step.

## State

State is local for v1 (single-operator project). `terraform.tfstate` is
gitignored. Operator stores it somewhere durable themselves (encrypted
backup, password manager attachment, etc.). When/if multi-operator work
demands it, add an S3 backend block to `main.tf`.

## Re-applying / idempotency

`terraform apply` after a clean plan should report `No changes` (spec
acceptance §8). The only edits that require an apply are:
- Changes to any `.tf` file in this directory.
- Changes to `var.*` values (via `terraform.tfvars`).

The deploy step (`make report`) does NOT need Terraform — it talks to
the bucket + distribution by ID, not by HCL.

## Bootstrap notes

- **Route 53 zone for `markandrewmarquez.com` must already exist** in
  the AWS account (it's not Terraformed here; this project shares the
  zone with other projects). The `data.aws_route53_zone.root` lookup
  fails fast if it's missing.
- **The OIDC provider is account-global** — only one
  `token.actions.githubusercontent.com` provider can exist per AWS
  account. If you've already created one (e.g. for another project),
  replace the `resource "aws_iam_openid_connect_provider" "github"` in
  `github_oidc.tf` with a `data "aws_iam_openid_connect_provider"`
  lookup (or `terraform import` the existing one before apply).
- **Bucket name `${var.project_name}-site`** must be globally unique
  across all S3. The default `cyber-threat-pipeline-site` is specific
  enough; if you fork into a different account, set `project_name`.
