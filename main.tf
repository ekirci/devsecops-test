resource "aws_s3_bucket" "b" {
  bucket = "devsecops-insecure-bucket-${random_string.suffix.result}"
  acl    = "public-read" 

  versioning {
    enabled = false
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}
