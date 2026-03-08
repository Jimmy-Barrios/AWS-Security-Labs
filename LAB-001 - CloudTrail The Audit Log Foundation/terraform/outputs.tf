output "trail_bucket_name" {
  description = "S3 bucket name for CloudTrail logs (use when creating trail in Section 8)."
  value       = aws_s3_bucket.trail_logs.id
}

output "trail_name" {
  description = "Name to use for the CloudTrail trail when enabling via CLI."
  value       = local.trail_name
}

output "region" {
  description = "AWS region where resources are deployed."
  value       = local.region
}
