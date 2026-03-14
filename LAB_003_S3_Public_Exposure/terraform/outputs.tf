output "data_bucket_name" {
  description = "Name of the publicly exposed S3 bucket. Use this in all attacker commands."
  value       = aws_s3_bucket.data.id
}

output "data_bucket_arn" {
  description = "ARN of the data bucket."
  value       = aws_s3_bucket.data.arn
}

output "log_group_name" {
  description = "CloudWatch Logs log group for CloudTrail events (query this in Section 7)."
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "trail_name" {
  description = "CloudTrail trail name."
  value       = local.trail_name
}

output "region" {
  description = "AWS region where resources are deployed."
  value       = local.region
}

output "account_id" {
  description = "AWS account ID (needed for account-level Block Public Access commands)."
  value       = local.account_id
}
