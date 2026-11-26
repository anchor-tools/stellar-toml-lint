resource "aws_s3_bucket" "anchor" {
  bucket = "example-anchor-toml"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "anchor" {
  bucket = aws_s3_bucket.anchor.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_cloudfront_distribution" "anchor" {
  origin {
    domain_name = aws_s3_bucket.anchor.bucket_regional_domain_name
    origin_id   = "s3-anchor"
  }

  enabled             = true
  default_root_object = ".well-known/stellar.toml"

  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-anchor"
  }

  web_acl_id = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/example/12345678"
}
