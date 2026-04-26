###############################################################
# SECURITY GROUPS — Least-Privilege Principle
#
# Rules applied:
#   - Deny all by default (AWS default behavior)
#   - Allow ONLY what is strictly necessary
#   - Restricted egress (avoid using 0.0.0.0/0 indiscriminately)
#   - SG-to-SG references instead of CIDRs where possible
###############################################################

###############################################################
# SG — BASTION HOST
# Only SSH entry point into the VPC
###############################################################

resource "aws_security_group" "bastion" {
  name        = "${local.name_prefix}-bastion-sg"
  description = "Bastion host security group. SSH access restricted to the administrator IP."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name      = "${local.name_prefix}-bastion-sg"
    Role      = "bastion"
    Sensitive = "true"
  }
}

# Ingress: SSH only from the administrator IP (auto-detected)
resource "aws_security_group_rule" "bastion_ssh_in" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = var.allowed_ssh_cidrs != [] ? var.allowed_ssh_cidrs : [local.my_ip_cidr]
  security_group_id = aws_security_group.bastion.id
  description       = "SSH restricted to administrator IP(s) — least-privilege"
}

# Egress: Bastion can only SSH to private instances (via SG reference)
resource "aws_security_group_rule" "bastion_ssh_out" {
  type                     = "egress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.private_instances.id
  security_group_id        = aws_security_group.bastion.id
  description              = "SSH to private instances only"
}

# Egress: HTTPS for system updates (yum update, etc.)
resource "aws_security_group_rule" "bastion_https_out" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.bastion.id
  description       = "HTTPS for OS updates"
}

resource "aws_security_group_rule" "bastion_http_out" {
  type              = "egress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.bastion.id
  description       = "HTTP for package repositories"
}

###############################################################
# SG — PRIVATE INSTANCES
# Accepts connections ONLY from the bastion
###############################################################

resource "aws_security_group" "private_instances" {
  name        = "${local.name_prefix}-private-sg"
  description = "Security group for private instances. SSH access only via bastion host."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-private-sg"
    Role = "private-workload"
  }
}

# Ingress: SSH only from bastion (SG reference — avoids exposing CIDRs)
resource "aws_security_group_rule" "private_ssh_from_bastion" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion.id
  security_group_id        = aws_security_group.private_instances.id
  description              = "SSH exclusively via bastion host"
}

# Egress: HTTPS for AWS APIs and updates (replace with VPC Endpoints in production)
resource "aws_security_group_rule" "private_https_out" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.private_instances.id
  description       = "HTTPS for AWS APIs — replace with VPC Endpoints in production"
}

###############################################################
# SG — ALB (Application Load Balancer) — optional
# Ready for when a web workload is added
###############################################################

resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb-sg"
  description = "ALB security group. Accepts public HTTPS, denies direct HTTP."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-alb-sg"
    Role = "load-balancer"
  }
}

resource "aws_security_group_rule" "alb_https_in" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb.id
  description       = "Public HTTPS — accepts secure web traffic"
}

# HTTP accepted only to redirect to HTTPS (never serve HTTP directly in prod)
resource "aws_security_group_rule" "alb_http_redirect" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb.id
  description       = "HTTP accepted only to redirect to HTTPS"
}

resource "aws_security_group_rule" "alb_to_private" {
  type                     = "egress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.private_instances.id
  security_group_id        = aws_security_group.alb.id
  description              = "ALB forwards traffic to private instances on port 8080"
}
