# ──────────────────────────────────────────────────────────────
# site.tf — Static Evidence site hosting
# ──────────────────────────────────────────────────────────────
# Ported from github.com/marky224/cloudwatch-monitor's status-page.tf
# pattern, with the substitutions called out in spec 05 §B4 and the
# Lambda/EventBridge/canary subsystem removed (we have no canary —
# the build pushes a directory of pre-rendered HTML via `aws s3 sync`).
#
# Resources:
#   • Private S3 bucket — receives `reporting/build/` from the deploy step.
#   • CloudFront distribution with OAC, custom domain, HTTPS.
#   • ACM certificate (DNS-validated, us-east-1).
#   • Route 53 A + AAAA aliases for the site domain.
# ──────────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════
# S3 BUCKET — Static site hosting
# ══════════════════════════════════════════════════════════════

resource "aws_s3_bucket" "site" {
  bucket        = "${var.project_name}-site"
  force_destroy = true

  tags = {
    Project = var.project_name
    Purpose = "Evidence.dev static site"
  }
}

# Block all public access — CloudFront OAC is the only read path.
resource "aws_s3_bucket_public_access_block" "site" {
  bucket = aws_s3_bucket.site.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy: allow only the CloudFront distribution (by ARN) to read.
resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontOAC"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.site.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.site.arn
          }
        }
      }
    ]
  })

  depends_on = [aws_cloudfront_distribution.site]
}

# ══════════════════════════════════════════════════════════════
# ACM CERTIFICATE — HTTPS for the custom domain
# ══════════════════════════════════════════════════════════════

resource "aws_acm_certificate" "site" {
  domain_name       = var.site_domain
  validation_method = "DNS"

  tags = {
    Project = var.project_name
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Auto-create the DNS validation CNAMEs in Route 53.
resource "aws_route53_record" "site_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.site.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  zone_id         = data.aws_route53_zone.root.zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
}

resource "aws_acm_certificate_validation" "site" {
  certificate_arn         = aws_acm_certificate.site.arn
  validation_record_fqdns = [for r in aws_route53_record.site_cert_validation : r.fqdn]
}

# ══════════════════════════════════════════════════════════════
# CLOUDFRONT — CDN + custom domain
# ══════════════════════════════════════════════════════════════

resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "${var.project_name}-site-oac"
  description                       = "OAC for the Evidence site S3 bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Rewrites bare sub-paths to their /index.html so per-route static
# files resolve correctly. Evidence (and most static site generators)
# emit pages at `<route>/index.html`, but a request for `/<route>`
# without the suffix hits S3, which doesn't auto-rewrite — S3 returns
# 404 and the CloudFront error-response below falls back to the home
# page. With this function the URI is rewritten BEFORE S3 sees it.
#
# Rules:
#   /                       →  /index.html (already handled by default_root_object)
#   /freshness              →  /freshness/index.html
#   /analyst-brief          →  /analyst-brief/index.html
#   /freshness/             →  /freshness/index.html
#   /_app/.../foo.js        →  unchanged (has extension)
#   /data/.../bar.parquet   →  unchanged (has extension)
resource "aws_cloudfront_function" "site_uri_rewrite" {
  name    = "${var.project_name}-uri-rewrite"
  runtime = "cloudfront-js-2.0"
  comment = "Rewrite bare sub-paths to their /index.html for Evidence per-route static files"
  publish = true
  code    = <<-EOT
    function handler(event) {
      var request = event.request;
      var uri = request.uri;
      if (uri.endsWith('/')) {
        request.uri = uri + 'index.html';
      } else if (uri.lastIndexOf('.') < uri.lastIndexOf('/')) {
        request.uri = uri + '/index.html';
      }
      return request;
    }
  EOT
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  comment             = "Evidence site for ${var.project_name}"
  price_class         = "PriceClass_100" # US, Canada, Europe — cheapest tier

  aliases = [var.site_domain]

  origin {
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id                = "s3-site"
    origin_access_control_id = aws_cloudfront_origin_access_control.site.id
  }

  default_cache_behavior {
    target_origin_id       = "s3-site"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    # Site is rebuilt weekly. Short TTLs + an invalidation on each
    # deploy give us near-real-time updates without paying for
    # large invalidation batches.
    min_ttl     = 0
    default_ttl = 60
    max_ttl     = 300

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.site_uri_rewrite.arn
    }
  }

  # Fallback for genuine 404s (no matching key after the URI rewrite
  # function ran). Serves the home page so users land on something
  # rather than the raw S3 XML error. The rewrite function above is
  # what makes valid sub-routes like /analyst-brief resolve to the
  # right file; this fallback only kicks in for truly missing paths.
  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/index.html"
  }

  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.site.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  tags = {
    Project = var.project_name
  }
}

# ── Route 53 alias: site domain → CloudFront ───────────────────
# A-record alias (not CNAME): AWS recommends aliases for subdomains
# pointing to CloudFront — faster resolution + no Route 53 query
# charges.
resource "aws_route53_record" "site" {
  zone_id = data.aws_route53_zone.root.zone_id
  name    = var.site_domain
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "site_ipv6" {
  zone_id = data.aws_route53_zone.root.zone_id
  name    = var.site_domain
  type    = "AAAA"

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}
