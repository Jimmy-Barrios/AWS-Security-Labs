# LAB-002: IAM Visibility — IAM Reconnaissance Detection
# Terraform deploys the VULNERABLE environment: CloudTrail is enabled for detection,
# but an IAM role has overly permissive IAM read permissions (enumeration).
# Hardening (remove IAM enumeration permissions) is done via AWS CLI in Section 8.

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
  trail_name   = "lab-002-audit-trail"
  account_id   = data.aws_caller_identity.current.account_id
  region       = data.aws_region.current.name
  partition    = data.aws_partition.current.partition
  trail_arn    = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
  log_group    = "lab-002-cloudtrail-events"
  attacker_role = "lab-002-attacker-role"
}

# --- S3 bucket for CloudTrail log delivery ---
resource "aws_s3_bucket" "trail_logs" {
  bucket        = "lab-002-cloudtrail-logs-${local.account_id}"
  force_destroy = true

  tags = {
    Name        = "lab-002-cloudtrail-logs"
    Lab         = "LAB-002"
    Environment = "vulnerable"
  }
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

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

# --- CloudWatch Logs for CloudTrail (detection) ---
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.log_group}"
  retention_in_days  = 7
  kms_key_id        = null

  tags = {
    Name = "lab-002-cloudtrail-events"
    Lab  = "LAB-002"
  }
}

# --- IAM role for CloudTrail to write to CloudWatch Logs ---
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "Lab002CloudTrailCloudWatchRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Lab = "LAB-002"
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "CloudTrailCloudWatchLogsPolicy"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailCreateLogStream"
        Effect = "Allow"
        Action = ["logs:CreateLogStream"]
        Resource = [
          "${aws_cloudwatch_log_group.cloudtrail.arn}:log-stream:${local.account_id}_CloudTrail_${local.region}*"
        ]
      },
      {
        Sid    = "AWSCloudTrailPutLogEvents"
        Effect = "Allow"
        Action = ["logs:PutLogEvents"]
        Resource = [
          "${aws_cloudwatch_log_group.cloudtrail.arn}:log-stream:${local.account_id}_CloudTrail_${local.region}*"
        ]
      }
    ]
  })
}

# --- CloudTrail trail (enabled for defender detection) ---
resource "aws_cloudtrail" "audit" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  include_global_service_events  = true
  is_multi_region_trail          = false
  enable_logging                 = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Lab = "LAB-002"
  }

  depends_on = [
    aws_s3_bucket_policy.trail_logs,
    aws_iam_role_policy.cloudtrail_cloudwatch
  ]
}

# --- Attacker role: IAM enumeration permissions (the misconfiguration) ---
resource "aws_iam_role" "attacker" {
  name = local.attacker_role

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "lab-002-attacker-role"
    Lab  = "LAB-002"
  }
}

# Overly permissive IAM read policy — allows full enumeration (T1087.004)
resource "aws_iam_role_policy" "attacker_iam_enumeration" {
  name = "IAMEnumerationPolicy"
  role = aws_iam_role.attacker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMEnumeration"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:GetUser",
          "iam:GetRole",
          "iam:ListAttachedUserPolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListUserPolicies",
          "iam:ListRolePolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListGroupsForUser",
          "iam:ListGroups",
          "iam:GetGroup",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      }
    ]
  })
}
