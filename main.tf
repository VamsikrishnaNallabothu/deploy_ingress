# ============================================================================
# AWS Ingress Inspection Architecture - Main Configuration
# Architecture: Internet → IGW → GWLB Endpoint → Firewall → GWLB Endpoint → ALB → Workloads
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ============================================================================
# Data Sources (for Brownfield Support)
# ============================================================================

# Get latest Amazon Linux 2 AMI if not specified
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Get existing VPC if using brownfield
data "aws_vpc" "existing" {
  count = var.create_vpc ? 0 : 1
  id    = var.existing_vpc_id
}

# Get existing IGW if specified
data "aws_internet_gateway" "existing" {
  count              = var.create_igw ? 0 : (var.existing_igw_id != "" ? 1 : 0)
  internet_gateway_id = var.existing_igw_id
}

# Get jumphost VPC for peering
data "aws_vpc" "jumphost" {
  count = var.enable_vpc_peering ? 1 : 0
  id    = var.jumphost_vpc_id
}

# ============================================================================
# Local Variables
# ============================================================================

locals {
  common_tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Architecture = "Ingress-Inspection"
    },
    var.tags
  )

  vpc_id = var.create_vpc ? aws_vpc.main[0].id : var.existing_vpc_id
  igw_id = var.create_igw ? aws_internet_gateway.main[0].id : (var.existing_igw_id != "" ? var.existing_igw_id : null)
  
  ami_id = var.workload_ami_id != "" ? var.workload_ami_id : data.aws_ami.amazon_linux_2.id
  
  # Default user data for web server
  default_user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y httpd
    systemctl start httpd
    systemctl enable httpd
    
    # Get instance metadata
    TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
    INSTANCE_ID=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
    LOCAL_IP=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
    AZ=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
    
    # Create index page
    cat <<HTML > /var/www/html/index.html
    <!DOCTYPE html>
    <html>
    <head>
        <title>Ingress Inspection Demo</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
            .container { background: rgba(255,255,255,0.1); padding: 30px; border-radius: 10px; backdrop-filter: blur(10px); }
            h1 { color: #fff; }
            .info { background: rgba(0,0,0,0.2); padding: 15px; border-radius: 5px; margin: 10px 0; }
            .label { font-weight: bold; color: #ffd700; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Ingress Inspection Architecture</h1>
            <div class="info">
                <p><span class="label">Instance ID:</span> $INSTANCE_ID</p>
                <p><span class="label">Private IP:</span> $LOCAL_IP</p>
                <p><span class="label">Availability Zone:</span> $AZ</p>
                <p><span class="label">Status:</span> ✅ Traffic Inspected by GWLB</p>
            </div>
            <p>This instance is protected by Gateway Load Balancer inspection.</p>
            <p><small>All traffic flows through security inspection before reaching this workload.</small></p>
        </div>
    </body>
    </html>
HTML
  EOF

  workload_user_data_final = var.workload_user_data != "" ? var.workload_user_data : local.default_user_data
}

# ============================================================================
# VPC and Internet Gateway
# ============================================================================

resource "aws_vpc" "main" {
  count = var.create_vpc ? 1 : 0

  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-vpc"
    }
  )
}

resource "aws_internet_gateway" "main" {
  count = var.create_igw ? 1 : 0

  vpc_id = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-igw"
    }
  )

  depends_on = [aws_vpc.main]
}

# ============================================================================
# Subnets
# ============================================================================

# ALB Public Subnets
resource "aws_subnet" "alb" {
  count = length(var.availability_zones)

  vpc_id                  = local.vpc_id
  cidr_block              = var.alb_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-alb-subnet-${var.availability_zones[count.index]}"
      Tier = "Public-ALB"
    }
  )

  depends_on = [aws_vpc.main]
}

# GWLB Endpoint Subnets
resource "aws_subnet" "gwlbe" {
  count = length(var.availability_zones)

  vpc_id            = local.vpc_id
  cidr_block        = var.gwlbe_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-gwlbe-subnet-${var.availability_zones[count.index]}"
      Tier = "GWLBE"
    }
  )

  depends_on = [aws_vpc.main]
}

# Workload Private Subnets
resource "aws_subnet" "workload" {
  count = length(var.availability_zones)

  vpc_id            = local.vpc_id
  cidr_block        = var.workload_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-workload-subnet-${var.availability_zones[count.index]}"
      Tier = "Private-Workload"
    }
  )

  depends_on = [aws_vpc.main]
}

# ============================================================================
# Gateway Load Balancer Endpoints
# ============================================================================

resource "aws_vpc_endpoint" "gwlbe" {
  count = var.enable_gwlb_inspection ? length(var.availability_zones) : 0

  vpc_id            = local.vpc_id
  service_name      = var.gwlb_endpoint_service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.gwlbe[count.index].id]

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-gwlbe-${var.availability_zones[count.index]}"
    }
  )

  depends_on = [aws_subnet.gwlbe]
}

# ============================================================================
# VPC Peering (Jumphost Access)
# ============================================================================

resource "aws_vpc_peering_connection" "jumphost" {
  count = var.enable_vpc_peering ? 1 : 0

  vpc_id      = local.vpc_id
  peer_vpc_id = var.jumphost_vpc_id
  auto_accept = true

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-to-jumphost-peering"
      Side = "Requester"
    }
  )

  depends_on = [aws_vpc.main]
}

# ============================================================================
# Route Tables
# ============================================================================

# Route Table for ALB Subnets (with IGW edge association)
resource "aws_route_table" "alb" {
  vpc_id = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-alb-rt"
    }
  )

  depends_on = [aws_vpc.main]
}

# Route to Internet via GWLB Endpoint (for symmetric inspection)
resource "aws_route" "alb_to_internet" {
  count = var.enable_gwlb_inspection ? 1 : 0

  route_table_id         = aws_route_table.alb.id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = aws_vpc_endpoint.gwlbe[0].id

  depends_on = [aws_route_table.alb, aws_vpc_endpoint.gwlbe]
}

# Direct route to IGW if GWLB inspection is disabled
resource "aws_route" "alb_to_igw_direct" {
  count = var.enable_gwlb_inspection ? 0 : 1

  route_table_id         = aws_route_table.alb.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = local.igw_id

  depends_on = [aws_route_table.alb, aws_internet_gateway.main]
}

# Route to Jumphost VPC via peering
resource "aws_route" "alb_to_jumphost" {
  count = var.enable_vpc_peering ? 1 : 0

  route_table_id            = aws_route_table.alb.id
  destination_cidr_block    = var.jumphost_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.jumphost[0].id

  depends_on = [aws_route_table.alb, aws_vpc_peering_connection.jumphost]
}

# Associate ALB subnets with route table
resource "aws_route_table_association" "alb" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.alb[count.index].id
  route_table_id = aws_route_table.alb.id

  depends_on = [aws_subnet.alb, aws_route_table.alb]
}

# Route Table for GWLB Endpoint Subnets
resource "aws_route_table" "gwlbe" {
  count = var.enable_gwlb_inspection ? 1 : 0

  vpc_id = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-gwlbe-rt"
    }
  )

  depends_on = [aws_vpc.main]
}

# Route from GWLBE to Internet Gateway (after inspection)
resource "aws_route" "gwlbe_to_igw" {
  count = var.enable_gwlb_inspection ? 1 : 0

  route_table_id         = aws_route_table.gwlbe[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = local.igw_id

  depends_on = [aws_route_table.gwlbe, aws_internet_gateway.main]
}

# Route from GWLBE to Jumphost VPC via peering
resource "aws_route" "gwlbe_to_jumphost" {
  count = var.enable_gwlb_inspection && var.enable_vpc_peering ? 1 : 0

  route_table_id            = aws_route_table.gwlbe[0].id
  destination_cidr_block    = var.jumphost_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.jumphost[0].id

  depends_on = [aws_route_table.gwlbe, aws_vpc_peering_connection.jumphost]
}

# Associate GWLBE subnets with route table
resource "aws_route_table_association" "gwlbe" {
  count = var.enable_gwlb_inspection ? length(var.availability_zones) : 0

  subnet_id      = aws_subnet.gwlbe[count.index].id
  route_table_id = aws_route_table.gwlbe[0].id

  depends_on = [aws_subnet.gwlbe, aws_route_table.gwlbe]
}

# Route Table for Workload Subnets
resource "aws_route_table" "workload" {
  vpc_id = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-workload-rt"
    }
  )

  depends_on = [aws_vpc.main]
}

# Route from workload to ALB (for return traffic)
# Workloads should route internet traffic via ALB or NAT Gateway
resource "aws_route" "workload_default" {
  count = var.enable_nat_gateway ? 1 : 0

  route_table_id         = aws_route_table.workload.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[0].id

  depends_on = [aws_route_table.workload, aws_nat_gateway.main]
}

# Route to Jumphost VPC via peering
resource "aws_route" "workload_to_jumphost" {
  count = var.enable_vpc_peering ? 1 : 0

  route_table_id            = aws_route_table.workload.id
  destination_cidr_block    = var.jumphost_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.jumphost[0].id

  depends_on = [aws_route_table.workload, aws_vpc_peering_connection.jumphost]
}

# Associate workload subnets with route table
resource "aws_route_table_association" "workload" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.workload[count.index].id
  route_table_id = aws_route_table.workload.id

  depends_on = [aws_subnet.workload, aws_route_table.workload]
}

# IGW Edge Association (Route Table for IGW ingress)
resource "aws_route_table" "igw_edge" {
  count = var.enable_gwlb_inspection ? 1 : 0

  vpc_id = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-igw-edge-rt"
    }
  )

  depends_on = [aws_vpc.main]
}

# Route from IGW to ALB subnets via GWLB Endpoint (immediate inspection)
resource "aws_route" "igw_to_alb_via_gwlbe" {
  count = var.enable_gwlb_inspection ? length(var.availability_zones) : 0

  route_table_id         = aws_route_table.igw_edge[0].id
  destination_cidr_block = var.alb_subnet_cidrs[count.index]
  vpc_endpoint_id        = aws_vpc_endpoint.gwlbe[count.index].id

  depends_on = [aws_route_table.igw_edge, aws_vpc_endpoint.gwlbe]
}

# Associate IGW with edge route table
resource "aws_route_table_association" "igw_edge" {
  count = var.enable_gwlb_inspection ? 1 : 0

  gateway_id     = local.igw_id
  route_table_id = aws_route_table.igw_edge[0].id

  depends_on = [aws_route_table.igw_edge, aws_internet_gateway.main]
}

# Add routes in Jumphost VPC route tables
resource "aws_route" "jumphost_to_workload" {
  count = var.enable_vpc_peering ? length(var.jumphost_route_table_ids) : 0

  route_table_id            = var.jumphost_route_table_ids[count.index]
  destination_cidr_block    = var.vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.jumphost[0].id

  depends_on = [aws_vpc_peering_connection.jumphost]
}

# ============================================================================
# NAT Gateway (Optional, for workload egress)
# ============================================================================

resource "aws_eip" "nat" {
  count = var.enable_nat_gateway ? 1 : 0

  domain = "vpc"

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-nat-eip"
    }
  )

  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  count = var.enable_nat_gateway ? 1 : 0

  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.alb[0].id

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-nat-gw"
    }
  )

  depends_on = [aws_eip.nat, aws_subnet.alb]
}

# ============================================================================
# Security Groups
# ============================================================================

# ALB Security Group
resource "aws_security_group" "alb" {
  name_prefix = "${var.project_name}-${var.environment}-alb-"
  description = "Security group for Application Load Balancer"
  vpc_id      = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-alb-sg"
    }
  )

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_vpc.main]
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTP from specified CIDRs"

  from_port   = var.alb_listener_port
  to_port     = var.alb_listener_port
  ip_protocol = "tcp"
  cidr_ipv4   = var.allowed_ingress_cidrs[0]

  depends_on = [aws_security_group.alb]
}

resource "aws_vpc_security_group_egress_rule" "alb_to_workload" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow traffic to workload instances"

  from_port                    = var.alb_target_port
  to_port                      = var.alb_target_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.workload.id

  depends_on = [aws_security_group.alb, aws_security_group.workload]
}

# Workload Security Group
resource "aws_security_group" "workload" {
  name_prefix = "${var.project_name}-${var.environment}-workload-"
  description = "Security group for workload EC2 instances"
  vpc_id      = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-workload-sg"
    }
  )

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_vpc.main]
}

resource "aws_vpc_security_group_ingress_rule" "workload_from_alb" {
  security_group_id = aws_security_group.workload.id
  description       = "Allow traffic from ALB"

  from_port                    = var.alb_target_port
  to_port                      = var.alb_target_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id

  depends_on = [aws_security_group.workload, aws_security_group.alb]
}

resource "aws_vpc_security_group_ingress_rule" "workload_ssh" {
  count = var.enable_vpc_peering && length(var.ssh_allowed_cidrs) > 0 ? 1 : 0

  security_group_id = aws_security_group.workload.id
  description       = "Allow SSH from jumphost VPC"

  from_port   = 22
  to_port     = 22
  ip_protocol = "tcp"
  cidr_ipv4   = var.ssh_allowed_cidrs[0]

  depends_on = [aws_security_group.workload]
}

resource "aws_vpc_security_group_egress_rule" "workload_all" {
  security_group_id = aws_security_group.workload.id
  description       = "Allow all outbound traffic"

  ip_protocol = "-1"
  cidr_ipv4   = "0.0.0.0/0"

  depends_on = [aws_security_group.workload]
}

# ============================================================================
# Application Load Balancer
# ============================================================================

resource "aws_lb" "main" {
  name               = "${var.project_name}-${var.environment}-alb"
  internal           = var.alb_internal
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.alb[*].id

  enable_deletion_protection = var.enable_deletion_protection
  enable_http2              = true
  enable_cross_zone_load_balancing = true

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-alb"
    }
  )

  depends_on = [aws_subnet.alb, aws_security_group.alb]
}

resource "aws_lb_target_group" "main" {
  name_prefix = "wkld-"
  port        = var.alb_target_port
  protocol    = var.alb_target_protocol
  vpc_id      = local.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    healthy_threshold   = var.alb_healthy_threshold
    unhealthy_threshold = var.alb_unhealthy_threshold
    timeout             = var.alb_health_check_timeout
    interval            = var.alb_health_check_interval
    path                = var.alb_health_check_path
    protocol            = var.alb_target_protocol
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-tg"
    }
  )

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_vpc.main]
}

resource "aws_lb_listener" "main" {
  load_balancer_arn = aws_lb.main.arn
  port              = var.alb_listener_port
  protocol          = var.alb_listener_protocol
  certificate_arn   = var.alb_listener_protocol == "HTTPS" ? var.alb_certificate_arn : null

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }

  depends_on = [aws_lb.main, aws_lb_target_group.main]
}

# ============================================================================
# Workload EC2 Instances
# ============================================================================

resource "aws_instance" "workload" {
  count = var.workload_count

  ami           = local.ami_id
  instance_type = var.workload_instance_type
  key_name      = var.workload_key_name != "" ? var.workload_key_name : null
  
  # Distribute instances across AZs
  subnet_id = aws_subnet.workload[count.index % length(var.availability_zones)].id
  
  vpc_security_group_ids = [aws_security_group.workload.id]
  
  user_data = local.workload_user_data_final
  
  monitoring = var.enable_detailed_monitoring

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.workload_root_volume_size
    delete_on_termination = true
    encrypted             = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-workload-${count.index + 1}"
    }
  )

  lifecycle {
    ignore_changes = [ami]
  }

  depends_on = [aws_subnet.workload, aws_security_group.workload]
}

# Register workload instances with target group
resource "aws_lb_target_group_attachment" "workload" {
  count = var.workload_count

  target_group_arn = aws_lb_target_group.main.arn
  target_id        = aws_instance.workload[count.index].id
  port             = var.alb_target_port

  depends_on = [aws_instance.workload, aws_lb_target_group.main]
}

# ============================================================================
# VPC Flow Logs (Optional)
# ============================================================================

resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name              = "/aws/vpc/${var.project_name}-${var.environment}-flow-logs"
  retention_in_days = var.flow_logs_retention_days

  tags = local.common_tags
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name_prefix = "${var.project_name}-flow-logs-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name = "flow-logs-policy"
  role = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_flow_log" "main" {
  count = var.enable_flow_logs ? 1 : 0

  iam_role_arn    = aws_iam_role.flow_logs[0].arn
  log_destination = aws_cloudwatch_log_group.flow_logs[0].arn
  traffic_type    = "ALL"
  vpc_id          = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${var.environment}-flow-logs"
    }
  )

  depends_on = [aws_cloudwatch_log_group.flow_logs, aws_iam_role_policy.flow_logs]
}

