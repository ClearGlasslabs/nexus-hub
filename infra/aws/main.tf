terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "aws_region" { type = string default = "ca-central-1" }
variable "bucket_name" { type = string }
variable "vpc_id" { type = string }
variable "private_route_table_ids" { type = list(string) }

provider "aws" { region = var.aws_region }

resource "aws_kms_key" "nexus" {
  description             = "Nexus V12 query-object encryption"
  enable_key_rotation    = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "nexus" {
  name          = "alias/nexus-v12"
  target_key_id = aws_kms_key.nexus.key_id
}

resource "aws_s3_bucket" "queries" { bucket = var.bucket_name }
resource "aws_s3_bucket_public_access_block" "queries" {
  bucket                  = aws_s3_bucket.queries.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "queries" {
  bucket = aws_s3_bucket.queries.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.nexus.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "queries" {
  bucket = aws_s3_bucket.queries.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "queries" {
  bucket = aws_s3_bucket.queries.id
  rule {
    id     = "nexus-max-seven-days"
    status = "Enabled"
    filter { prefix = "queries/" }
    expiration { days = 7 }
    noncurrent_version_expiration { noncurrent_days = 7 }
  }
}

resource "aws_s3_bucket_policy" "queries" {
  bucket = aws_s3_bucket.queries.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "DenyUnencryptedTransport",
      Effect    = "Deny",
      Principal = "*",
      Action    = "s3:*",
      Resource  = [aws_s3_bucket.queries.arn, "${aws_s3_bucket.queries.arn}/*"],
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.private_route_table_ids
}

output "kms_key_arn" { value = aws_kms_key.nexus.arn }
output "query_bucket" { value = aws_s3_bucket.queries.bucket }
