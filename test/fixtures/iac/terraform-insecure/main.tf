resource "aws_s3_bucket" "insecure" {
  bucket = "exposed-bucket"
  acl    = "public-read"
}

resource "aws_cloudfront_distribution" "insecure" {
  enabled = true
}
