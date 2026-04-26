###############################################################
# IAM — LEAST-PRIVILEGE ROLES
#
# Principles applied:
#   - Each instance has only the permissions it needs
#   - No role uses AdministratorAccess or wildcard policies
#   - SSM Session Manager as a safer alternative to direct SSH
###############################################################

###############################################################
# IAM — FLOW LOGS
###############################################################

resource "aws_iam_role" "flow_log" {
  name = "${local.name_prefix}-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "${local.name_prefix}-flow-log-role"
  }
}

resource "aws_iam_role_policy" "flow_log" {
  name = "${local.name_prefix}-flow-log-policy"
  role = aws_iam_role.flow_log.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "${aws_cloudwatch_log_group.flow_log.arn}:*"
    }]
  })
}

###############################################################
# IAM — BASTION HOST
# Permissions: SSM Session Manager + CloudWatch Logs
###############################################################

resource "aws_iam_role" "bastion" {
  name = "${local.name_prefix}-bastion-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "${local.name_prefix}-bastion-role"
  }
}

# SSM Session Manager — allows access without opening port 22 (safer alternative to SSH)
resource "aws_iam_role_policy_attachment" "bastion_ssm" {
  role       = aws_iam_role.bastion.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# CloudWatch Agent — sends OS metrics and logs
resource "aws_iam_role_policy_attachment" "bastion_cloudwatch" {
  role       = aws_iam_role.bastion.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "bastion" {
  name = "${local.name_prefix}-bastion-profile"
  role = aws_iam_role.bastion.name

  tags = {
    Name = "${local.name_prefix}-bastion-profile"
  }
}

###############################################################
# IAM — PRIVATE INSTANCE (APP)
# Minimum permissions: SSM + CloudWatch
###############################################################

resource "aws_iam_role" "private_app" {
  name = "${local.name_prefix}-private-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "${local.name_prefix}-private-app-role"
  }
}

resource "aws_iam_role_policy_attachment" "private_app_ssm" {
  role       = aws_iam_role.private_app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "private_app_cloudwatch" {
  role       = aws_iam_role.private_app.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Política customizada — acesso mínimo ao S3 (apenas bucket específico)
resource "aws_iam_role_policy" "private_app_s3" {
  name = "${local.name_prefix}-private-app-s3-policy"
  role = aws_iam_role.private_app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlySpecificBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        # Restricted to a specific bucket — no access to other S3 resources
        Resource = [
          "arn:aws:s3:::${local.name_prefix}-app-data",
          "arn:aws:s3:::${local.name_prefix}-app-data/*"
        ]
      },
      {
        Sid    = "DenyAllOtherS3"
        Effect = "Deny"
        Action = "s3:*"
        NotResource = [
          "arn:aws:s3:::${local.name_prefix}-app-data",
          "arn:aws:s3:::${local.name_prefix}-app-data/*"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "private_app" {
  name = "${local.name_prefix}-private-app-profile"
  role = aws_iam_role.private_app.name

  tags = {
    Name = "${local.name_prefix}-private-app-profile"
  }
}
