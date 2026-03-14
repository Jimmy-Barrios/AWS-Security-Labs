# LAB-003: S3 Public Exposure — Detecting Public S3 Access
# Terraform deploys the VULNERABLE environment: CloudTrail is enabled with S3 data
# events for detection, and a data bucket is intentionally misconfigured as public.
# Hardening (Block Public Access + delete bucket policy) is done via AWS CLI in Section 8.

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
  trail_name       = "lab-003-audit-trail"
  account_id       = data.aws_caller_identity.current.account_id
  region           = data.aws_region.current.name
  partition        = data.aws_partition.current.partition
  trail_arn        = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
  log_group        = "lab-003-cloudtrail-events"
  data_bucket_name = "lab-003-data-${local.account_id}"
}

# --- S3 bucket for CloudTrail log delivery (private and secure) ---
resource "aws_s3_bucket" "trail_logs" {
  bucket        = "lab-003-cloudtrail-logs-${local.account_id}"
  force_destroy = true

  tags = {
    Name        = "lab-003-cloudtrail-logs"
    Lab         = "LAB-003"
    Environment = "audit"
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
  retention_in_days = 7

  tags = {
    Name = "lab-003-cloudtrail-events"
    Lab  = "LAB-003"
  }
}

# --- IAM role for CloudTrail to write to CloudWatch Logs ---
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "Lab003CloudTrailCloudWatchRole"

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
    Lab = "LAB-003"
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

# --- CloudTrail trail with S3 data events enabled for the data bucket ---
resource "aws_cloudtrail" "audit" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    # S3 data events for the vulnerable bucket — captures GetObject and ListBucket
    # calls including anonymous ones (userIdentity.type = "Anonymous")
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.data.arn}/"]
    }
  }

  tags = {
    Lab = "LAB-003"
  }

  depends_on = [
    aws_s3_bucket_policy.trail_logs,
    aws_iam_role_policy.cloudtrail_cloudwatch
  ]
}

# --- Vulnerable S3 data bucket (the misconfiguration) ---
# Block Public Access is explicitly disabled and the bucket policy allows
# s3:ListBucket and s3:GetObject for Principal "*" (unauthenticated access).
resource "aws_s3_bucket" "data" {
  bucket        = local.data_bucket_name
  force_destroy = true

  tags = {
    Name        = "lab-003-data"
    Lab         = "LAB-003"
    Environment = "vulnerable"
  }
}

# All four Block Public Access settings are disabled — this is the misconfiguration.
# A real developer might do this to "quickly share" files with an external party.
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Public bucket policy — s3:ListBucket and s3:GetObject for everyone.
# This is what makes the bucket readable without any AWS credentials.
resource "aws_s3_bucket_policy" "data_public" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicListBucket"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.data.arn
      },
      {
        Sid       = "PublicGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.data.arn}/*"
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.data]
}

# --- Fake "sensitive" files in the data bucket ---
# These files are clearly labelled DEMO-ONLY. They simulate the kind of data
# that ends up in accidentally public S3 buckets in real environments.

resource "aws_s3_object" "financials" {
  bucket       = aws_s3_bucket.data.id
  key          = "reports/q4-financials.csv"
  content_type = "text/csv"
  content      = <<-EOF
    Quarter,Revenue,Expenses,NetIncome
    Q4-2024,4200000,3100000,1100000
    Q3-2024,3900000,2950000,950000
    Q2-2024,3750000,2800000,950000
    Q1-2024,3600000,2750000,850000
  EOF

  tags = {
    Lab         = "LAB-003"
    Sensitivity = "DEMO-ONLY"
  }
}

resource "aws_s3_object" "employee_data" {
  bucket       = aws_s3_bucket.data.id
  key          = "internal/employee-roster.csv"
  content_type = "text/csv"
  content      = <<-EOF
    EmployeeID,Name,Email,Department,Salary
    E001,Jane Smith,jane.smith@example-corp.com,Engineering,95000
    E002,Bob Johnson,bob.j@example-corp.com,Finance,88000
    E003,Alice Chen,a.chen@example-corp.com,Engineering,102000
    E004,Carlos Rivera,carlos.r@example-corp.com,HR,75000
  EOF

  tags = {
    Lab         = "LAB-003"
    Sensitivity = "DEMO-ONLY"
  }
}

resource "aws_s3_object" "app_config" {
  bucket       = aws_s3_bucket.data.id
  key          = "config/app-config.json"
  content_type = "application/json"
  content      = <<-EOF
    {
      "environment": "production",
      "database": {
        "host": "db.example-corp.internal",
        "port": 5432,
        "name": "appdb",
        "username": "app_user",
        "password": "DEMO_FAKE_PASSWORD_NOT_REAL"
      },
      "api_key": "DEMO_FAKE_API_KEY_abc123xyz789_NOT_REAL",
      "region": "us-east-1"
    }
  EOF

  tags = {
    Lab         = "LAB-003"
    Sensitivity = "DEMO-ONLY"
  }
}
