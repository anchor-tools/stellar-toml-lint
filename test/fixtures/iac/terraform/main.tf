resource "aws_s3_bucket" "anchor_assets" {
  bucket = "example-anchor-assets"
}

resource "aws_cloudfront_distribution" "cdn" {
  origin {
    domain_name = aws_s3_bucket.anchor_assets.bucket_regional_domain_name
    origin_id   = "S3Origin"
  }

  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
  }
}
