# ============================================================================
# AWS Ingress Inspection Architecture - Variables
# ============================================================================

# ============================================================================
# General Configuration
# ============================================================================

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "ingress-inspection"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "availability_zones" {
  description = "List of availability zones to use (must be at least 2)"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# ============================================================================
# VPC Configuration
# ============================================================================

variable "vpc_cidr" {
  description = "CIDR block for the application VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "alb_subnet_cidrs" {
  description = "CIDR blocks for ALB subnets (must match number of AZs)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "gwlbe_subnet_cidrs" {
  description = "CIDR blocks for GWLB Endpoint subnets (must match number of AZs)"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "workload_subnet_cidrs" {
  description = "CIDR blocks for workload subnets (must match number of AZs)"
  type        = list(string)
  default     = ["10.0.21.0/24", "10.0.22.0/24"]
}

# ============================================================================
# VPC Peering Configuration (Jumphost Access)
# ============================================================================

variable "enable_vpc_peering" {
  description = "Enable VPC peering with jumphost VPC"
  type        = bool
  default     = false
}

variable "jumphost_vpc_id" {
  description = "VPC ID of the jumphost VPC (ZS_JH_VPC) for peering. Required if enable_vpc_peering is true."
  type        = string
  default     = ""
}

variable "jumphost_vpc_cidr" {
  description = "CIDR block of the jumphost VPC. Required if enable_vpc_peering is true."
  type        = string
  default     = ""
}

variable "jumphost_route_table_ids" {
  description = "List of route table IDs in the jumphost VPC to add routes to workload VPC"
  type        = list(string)
  default     = []
}

# ============================================================================
# Gateway Load Balancer Configuration
# ============================================================================

variable "gwlb_endpoint_service_name" {
  description = "GWLB Endpoint Service name from the security account (e.g., com.amazonaws.vpce.region.vpce-svc-xxxxx)"
  type        = string
}

variable "enable_gwlb_inspection" {
  description = "Enable traffic inspection via GWLB endpoints. Set to false for testing without GWLB."
  type        = bool
  default     = true
}

# ============================================================================
# Application Load Balancer Configuration
# ============================================================================

variable "alb_internal" {
  description = "Whether the ALB should be internal (true) or internet-facing (false)"
  type        = bool
  default     = false
}

variable "alb_listener_port" {
  description = "Port for ALB listener"
  type        = number
  default     = 80
}

variable "alb_listener_protocol" {
  description = "Protocol for ALB listener (HTTP or HTTPS)"
  type        = string
  default     = "HTTP"
}

variable "alb_certificate_arn" {
  description = "ARN of ACM certificate for HTTPS listener. Required if protocol is HTTPS."
  type        = string
  default     = ""
}

variable "alb_target_port" {
  description = "Port on target instances"
  type        = number
  default     = 80
}

variable "alb_target_protocol" {
  description = "Protocol for target group (HTTP or HTTPS)"
  type        = string
  default     = "HTTP"
}

variable "alb_health_check_path" {
  description = "Health check path for ALB target group"
  type        = string
  default     = "/"
}

variable "alb_health_check_interval" {
  description = "Health check interval in seconds"
  type        = number
  default     = 30
}

variable "alb_health_check_timeout" {
  description = "Health check timeout in seconds"
  type        = number
  default     = 5
}

variable "alb_healthy_threshold" {
  description = "Number of consecutive successful health checks"
  type        = number
  default     = 2
}

variable "alb_unhealthy_threshold" {
  description = "Number of consecutive failed health checks"
  type        = number
  default     = 2
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection for ALB"
  type        = bool
  default     = false
}

# ============================================================================
# Workload EC2 Configuration
# ============================================================================

variable "workload_count" {
  description = "Number of workload EC2 instances to deploy behind the ALB"
  type        = number
  default     = 2
  validation {
    condition     = var.workload_count >= 0 && var.workload_count <= 20
    error_message = "Workload count must be between 0 and 20."
  }
}

variable "workload_instance_type" {
  description = "EC2 instance type for workload instances"
  type        = string
  default     = "t3.micro"
}

variable "workload_key_name" {
  description = "EC2 key pair name for SSH access to workload instances. Required if workload_count > 0."
  type        = string
  default     = ""
}

variable "workload_ami_id" {
  description = "AMI ID for workload instances. If not specified, latest Amazon Linux 2 AMI will be used."
  type        = string
  default     = ""
}

variable "workload_root_volume_size" {
  description = "Root volume size in GB for workload instances"
  type        = number
  default     = 8
}

variable "workload_user_data" {
  description = "User data script for workload instances. If not specified, a basic web server will be installed."
  type        = string
  default     = ""
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring for EC2 instances"
  type        = bool
  default     = false
}

# ============================================================================
# Security Group Configuration
# ============================================================================

variable "allowed_ingress_cidrs" {
  description = "CIDR blocks allowed to access the ALB"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed SSH access to workload instances (typically jumphost VPC CIDR)"
  type        = list(string)
  default     = []
}

# ============================================================================
# Brownfield Configuration
# ============================================================================

variable "create_vpc" {
  description = "Create new VPC or use existing one. Set to false for brownfield deployments."
  type        = bool
  default     = true
}

variable "existing_vpc_id" {
  description = "Existing VPC ID to use. Required if create_vpc is false."
  type        = string
  default     = ""
}

variable "existing_igw_id" {
  description = "Existing Internet Gateway ID. If not specified, a new one will be created."
  type        = string
  default     = ""
}

variable "create_igw" {
  description = "Create new Internet Gateway. Set to false if using existing IGW."
  type        = bool
  default     = true
}

# ============================================================================
# Feature Flags
# ============================================================================

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "flow_logs_retention_days" {
  description = "Retention period for VPC Flow Logs in days"
  type        = number
  default     = 7
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for workload egress traffic"
  type        = bool
  default     = false
}

