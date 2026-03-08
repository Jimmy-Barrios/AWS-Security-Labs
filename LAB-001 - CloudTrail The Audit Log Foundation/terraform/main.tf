# LAB-001: CloudTrail — The Audit Log Foundation
# Terraform deploys the VULNERABLE environment: S3 bucket for trail logs exists,
# but NO CloudTrail trail is created. API activity is not recorded.
# Hardening (enable CloudTrail) is done via AWS CLI in Section 8.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  trail_name = "lab-001-audit-trail"
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition
  trail_arn  = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}

# S3 bucket for CloudTrail log delivery (used after hardening)
resource "aws_s3_bucket" "trail_logs" {
  bucket        = "lab-001-cloudtrail-logs-${local.account_id}"
  force_destroy = true

  tags = {
    Name        = "lab-001-cloudtrail-logs"
    Lab         = "LAB-001"
    Environment = "vulnerable"
  }
}

# Block public access (security baseline)
resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets  = true
}

# Bucket policy allowing CloudTrail to write (required when you create the trail via CLI)
data "aws_iam_policy_document" "cloudtrail_s3" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail_logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail_logs.arn}/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_s3.json
}

# No aws_cloudtrail resource — that is the misconfiguration.
# The defender enables CloudTrail via CLI in Section 8 (Harden & Verify).
