###############################################################
# VARIABLES
###############################################################

variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "Region must follow the correct format, e.g.: us-east-1, sa-east-1."
  }
}

variable "project_name" {
  description = "Project name — used as prefix for all resources"
  type        = string
  default     = "devsecops-p1"

  validation {
    condition     = length(var.project_name) <= 20
    error_message = "Project name must be 20 characters or fewer."
  }
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "lab"

  validation {
    condition     = contains(["lab", "dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: lab, dev, staging, prod."
  }
}

variable "owner" {
  description = "Project owner name (used for cost allocation tags)"
  type        = string
  default     = "portfolio-owner"
}

variable "vpc_cidr" {
  description = "CIDR block for the main VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "allowed_ssh_cidrs" {
  description = "List of CIDRs allowed to SSH into the bastion. If empty, uses the current public IP."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.allowed_ssh_cidrs : can(cidrhost(cidr, 0))])
    error_message = "All values in allowed_ssh_cidrs must be valid IPv4 CIDRs."
  }
}

variable "bastion_instance_type" {
  description = "EC2 instance type for the bastion host"
  type        = string
  default     = "t3.micro"
}

variable "app_instance_type" {
  description = "EC2 instance type for the private application instance"
  type        = string
  default     = "t3.micro"
}
