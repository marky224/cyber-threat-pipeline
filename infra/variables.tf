variable "project_name" {
  type        = string
  default     = "cyber-threat-pipeline"
  description = "Prefix for S3 bucket + IAM resource names."
}

variable "site_domain" {
  type        = string
  default     = "cyber-intel.markandrewmarquez.com"
  description = "Public hostname the Evidence site is served from (DECISIONS Q9)."
}

variable "github_repo" {
  type        = string
  default     = "marky224/cyber-threat-pipeline"
  description = "<owner>/<repo>; scopes the OIDC trust policy so only this repo can assume the deploy role."
}

variable "deploy_branch" {
  type        = string
  default     = "main"
  description = "Only this branch (via push or workflow_dispatch from this ref) can assume the deploy role via OIDC."
}
