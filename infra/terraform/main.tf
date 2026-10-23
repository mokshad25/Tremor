# ── TREMOR — Terraform Infrastructure ─────────────────────────────────
# Resources: SNS topic + subscription, IAM role/policy, CW log group, CW alarm
#
# Owner: Varad (Phase 4 / Phase 7)

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # TODO (Phase 7): Add S3 backend + DynamoDB lock table
  # backend "s3" {
  #   bucket         = "tremor-terraform-state"
  #   key            = "tremor/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "tremor-terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ─────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email for SNS alert notifications"
  type        = string
  default     = ""
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

# ── SNS Topic ────────────────────────────────────────────────────────

resource "aws_sns_topic" "tremor_alerts" {
  name = "tremor-alerts-${var.environment}"

  tags = {
    Project     = "TREMOR"
    Environment = var.environment
  }
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.tremor_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── CloudWatch Log Group ─────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "tremor" {
  name              = "/tremor/alerts"
  retention_in_days = 30

  tags = {
    Project     = "TREMOR"
    Environment = var.environment
  }
}

# ── CloudWatch Alarm ─────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "tremor-high-error-rate-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ErrorRate"
  namespace           = "Tremor"
  period              = 60
  statistic           = "Average"
  threshold           = 0.5
  alarm_description   = "TREMOR: Error rate exceeds 50% for 2 consecutive minutes"
  alarm_actions       = [aws_sns_topic.tremor_alerts.arn]

  dimensions = {
    Service = "payment-gateway"
  }

  tags = {
    Project     = "TREMOR"
    Environment = var.environment
  }
}

# ── IAM Role (for EC2 / ECS) ────────────────────────────────────────

resource "aws_iam_role" "tremor" {
  name = "tremor-app-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = [
            "ec2.amazonaws.com",
            "ecs-tasks.amazonaws.com"
          ]
        }
      }
    ]
  })

  tags = {
    Project     = "TREMOR"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "tremor" {
  name = "tremor-permissions"
  role = aws_iam_role.tremor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.tremor.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.tremor_alerts.arn
      },
      {
        Effect = "Allow"
        Action = "cloudwatch:PutMetricData"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "Tremor"
          }
        }
        Resource = "*"
      }
    ]
  })
}

# ── Instance Profile (for EC2 deployments) ───────────────────────────

resource "aws_iam_instance_profile" "tremor" {
  name = "tremor-profile-${var.environment}"
  role = aws_iam_role.tremor.name

  tags = {
    Project     = "TREMOR"
    Environment = var.environment
  }
}

# ── Outputs ──────────────────────────────────────────────────────────

output "sns_topic_arn" {
  value       = aws_sns_topic.tremor_alerts.arn
  description = "SNS topic ARN for TREMOR alerts"
}

output "log_group_name" {
  value       = aws_cloudwatch_log_group.tremor.name
  description = "CloudWatch log group for TREMOR alerts"
}

output "iam_role_arn" {
  value       = aws_iam_role.tremor.arn
  description = "IAM role ARN for TREMOR application"
}
