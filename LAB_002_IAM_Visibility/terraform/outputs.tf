output "attacker_role_arn" {
  description = "ARN of the IAM role to assume for attacker simulation."
  value       = aws_iam_role.attacker.arn
}

output "attacker_role_name" {
  description = "Name of the attacker role (for hardening CLI commands)."
  value       = aws_iam_role.attacker.name
}

output "log_group_name" {
  description = "CloudWatch Logs log group for CloudTrail events."
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "region" {
  description = "AWS region where resources are deployed."
  value       = local.region
}

output "trail_name" {
  description = "CloudTrail trail name."
  value       = local.trail_name
}
