# ============================================================================
# AWS Ingress Inspection Architecture - Main Configuration
# Architecture: Internet → IGW → GWLB Endpoint → Firewall → GWLB Endpoint → ALB → Workloads
# ============================================================================

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
  count = local.config.CREATE_VPC ? 0 : 1
  id    = local.config.EXISTING_VPC_ID
}

# Get existing IGW if specified
data "aws_internet_gateway" "existing" {
  count              = local.config.CREATE_IGW ? 0 : (try(local.config.EXISTING_IGW_ID, "") != "" ? 1 : 0)
  internet_gateway_id = local.config.EXISTING_IGW_ID
}

# Get jumphost VPC for peering
data "aws_vpc" "jumphost" {
  count = local.config.ENABLE_VPC_PEERING ? 1 : 0
  id    = local.config.JUMPHOST_VPC_ID
}

# ============================================================================
# Local Variables
# ============================================================================

locals {
  # Resource naming - all resources use NAME_PREFIX from config.yaml
  resource_prefix = local.name_prefix

  # VPC and network resources
  vpc_id = local.config.CREATE_VPC ? aws_vpc.main[0].id : local.config.EXISTING_VPC_ID
  igw_id = local.config.CREATE_IGW ? aws_internet_gateway.main[0].id : (try(local.config.EXISTING_IGW_ID, "") != "" ? local.config.EXISTING_IGW_ID : null)
  
  # AMI selection
  ami_id = try(local.config.WORKLOAD_AMI_ID, "") != "" ? local.config.WORKLOAD_AMI_ID : data.aws_ami.amazon_linux_2.id
  
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

  workload_user_data_final = local.config.WORKLOAD_USER_DATA != "" ? local.config.WORKLOAD_USER_DATA : local.default_user_data
}

# ============================================================================
# VPC and Internet Gateway
# ============================================================================

resource "aws_vpc" "main" {
  count = local.config.CREATE_VPC ? 1 : 0

  cidr_block           = local.config.VPC_CIDR
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-vpc"
    }
  )
}

resource "aws_internet_gateway" "main" {
  count = local.config.CREATE_IGW ? 1 : 0

  vpc_id = local.vpc_id

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-igw"
    }
  )

  depends_on = [aws_vpc.main]
}

# ============================================================================
# Subnets
# ============================================================================

# ALB Public Subnets
resource "aws_subnet" "alb" {
  count = length(local.config.AVAILABILITY_ZONES)

  vpc_id                  = local.vpc_id
  cidr_block              = local.config.ALB_SUBNET_CIDRS[count.index]
  availability_zone       = local.config.AVAILABILITY_ZONES[count.index]
  map_public_ip_on_launch = true

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-alb-subnet-${local.config.AVAILABILITY_ZONES[count.index]}"
      Tier = "Public-ALB"
    }
  )

  depends_on = [aws_vpc.main]
}

# GWLB Endpoint Subnets
resource "aws_subnet" "gwlbe" {
  count = length(local.config.AVAILABILITY_ZONES)

  vpc_id            = local.vpc_id
  cidr_block        = local.config.GWLBE_SUBNET_CIDRS[count.index]
  availability_zone = local.config.AVAILABILITY_ZONES[count.index]

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-gwlbe-subnet-${local.config.AVAILABILITY_ZONES[count.index]}"
      Tier = "GWLBE"
    }
  )

  depends_on = [aws_vpc.main]
}

# Workload Private Subnets
resource "aws_subnet" "workload" {
  count = length(local.config.AVAILABILITY_ZONES)

  vpc_id            = local.vpc_id
  cidr_block        = local.config.WORKLOAD_SUBNET_CIDRS[count.index]
  availability_zone = local.config.AVAILABILITY_ZONES[count.index]

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-workload-subnet-${local.config.AVAILABILITY_ZONES[count.index]}"
      Tier = "Private-Workload"
    }
  )

  depends_on = [aws_vpc.main]
}

# ============================================================================
# Gateway Load Balancer Endpoints
# ============================================================================

resource "aws_vpc_endpoint" "gwlbe" {
  count = local.config.ENABLE_GWLB_INSPECTION ? length(local.config.AVAILABILITY_ZONES) : 0

  vpc_id            = local.vpc_id
  service_name      = local.config.GWLB_ENDPOINT_SERVICE_NAME
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.gwlbe[count.index].id]

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-gwlbe-${local.config.AVAILABILITY_ZONES[count.index]}"
    }
  )

  depends_on = [aws_subnet.gwlbe]
}

# ============================================================================
# VPC Peering (Jumphost Access)
# ============================================================================

resource "aws_vpc_peering_connection" "jumphost" {
  count = local.config.ENABLE_VPC_PEERING ? 1 : 0

  vpc_id      = local.vpc_id
  peer_vpc_id = local.config.JUMPHOST_VPC_ID
  auto_accept = true

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-to-jumphost-peering"
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
    local.tags,
    {
      Name = "${local.resource_prefix}-alb-rt"
    }
  )

  depends_on = [aws_vpc.main]
}

# Route to Internet via GWLB Endpoint (for symmetric inspection)
resource "aws_route" "alb_to_internet" {
  count = local.config.ENABLE_GWLB_INSPECTION ? 1 : 0

  route_table_id         = aws_route_table.alb.id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = aws_vpc_endpoint.gwlbe[0].id

  depends_on = [aws_route_table.alb, aws_vpc_endpoint.gwlbe]
}

# Direct route to IGW if GWLB inspection is disabled
resource "aws_route" "alb_to_igw_direct" {
  count = local.config.ENABLE_GWLB_INSPECTION ? 0 : 1

  route_table_id         = aws_route_table.alb.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = local.igw_id

  depends_on = [aws_route_table.alb, aws_internet_gateway.main]
}

# Route to Jumphost VPC via peering
resource "aws_route" "alb_to_jumphost" {
  count = local.config.ENABLE_VPC_PEERING ? 1 : 0

  route_table_id            = aws_route_table.alb.id
  destination_cidr_block    = local.config.JUMPHOST_VPC_CIDR
  vpc_peering_connection_id = aws_vpc_peering_connection.jumphost[0].id

  depends_on = [aws_route_table.alb, aws_vpc_peering_connection.jumphost]
}

# Associate ALB subnets with route table
resource "aws_route_table_association" "alb" {
  count = length(local.config.AVAILABILITY_ZONES)

  subnet_id      = aws_subnet.alb[count.index].id
  route_table_id = aws_route_table.alb.id

  depends_on = [aws_subnet.alb, aws_route_table.alb]
}

# Route Table for GWLB Endpoint Subnets
resource "aws_route_table" "gwlbe" {
  count = local.config.ENABLE_GWLB_INSPECTION ? 1 : 0

  vpc_id = local.vpc_id

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-gwlbe-rt"
    }
  )

  depends_on = [aws_vpc.main]
}

# Route from GWLBE to Internet Gateway (after inspection)
resource "aws_route" "gwlbe_to_igw" {
  count = local.config.ENABLE_GWLB_INSPECTION ? 1 : 0

  route_table_id         = aws_route_table.gwlbe[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = local.igw_id

  depends_on = [aws_route_table.gwlbe, aws_internet_gateway.main]
}

# Route from GWLBE to Jumphost VPC via peering
resource "aws_route" "gwlbe_to_jumphost" {
  count = local.config.ENABLE_GWLB_INSPECTION && local.config.ENABLE_VPC_PEERING ? 1 : 0

  route_table_id            = aws_route_table.gwlbe[0].id
  destination_cidr_block    = local.config.JUMPHOST_VPC_CIDR
  vpc_peering_connection_id = aws_vpc_peering_connection.jumphost[0].id

  depends_on = [aws_route_table.gwlbe, aws_vpc_peering_connection.jumphost]
}

# Associate GWLBE subnets with route table
resource "aws_route_table_association" "gwlbe" {
  count = local.config.ENABLE_GWLB_INSPECTION ? length(local.config.AVAILABILITY_ZONES) : 0

  subnet_id      = aws_subnet.gwlbe[count.index].id
  route_table_id = aws_route_table.gwlbe[0].id

  depends_on = [aws_subnet.gwlbe, aws_route_table.gwlbe]
}

# Route Table for Workload Subnets
resource "aws_route_table" "workload" {
  vpc_id = local.vpc_id

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-workload-rt"
    }
  )

  depends_on = [aws_vpc.main]
}

# Route from workload to ALB (for return traffic)
# Workloads should route internet traffic via ALB or NAT Gateway
resource "aws_route" "workload_default" {
  count = local.config.ENABLE_NAT_GATEWAY ? 1 : 0

  route_table_id         = aws_route_table.workload.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[0].id

  depends_on = [aws_route_table.workload, aws_nat_gateway.main]
}

# Route to Jumphost VPC via peering
resource "aws_route" "workload_to_jumphost" {
  count = local.config.ENABLE_VPC_PEERING ? 1 : 0

  route_table_id            = aws_route_table.workload.id
  destination_cidr_block    = local.config.JUMPHOST_VPC_CIDR
  vpc_peering_connection_id = aws_vpc_peering_connection.jumphost[0].id

  depends_on = [aws_route_table.workload, aws_vpc_peering_connection.jumphost]
}

# Associate workload subnets with route table
resource "aws_route_table_association" "workload" {
  count = length(local.config.AVAILABILITY_ZONES)

  subnet_id      = aws_subnet.workload[count.index].id
  route_table_id = aws_route_table.workload.id

  depends_on = [aws_subnet.workload, aws_route_table.workload]
}

# IGW Edge Association (Route Table for IGW ingress)
resource "aws_route_table" "igw_edge" {
  count = local.config.ENABLE_GWLB_INSPECTION ? 1 : 0

  vpc_id = local.vpc_id

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-igw-edge-rt"
    }
  )

  depends_on = [aws_vpc.main]
}

# Route from IGW to ALB subnets via GWLB Endpoint (immediate inspection)
resource "aws_route" "igw_to_alb_via_gwlbe" {
  count = local.config.ENABLE_GWLB_INSPECTION ? length(local.config.AVAILABILITY_ZONES) : 0

  route_table_id         = aws_route_table.igw_edge[0].id
  destination_cidr_block = local.config.ALB_SUBNET_CIDRS[count.index]
  vpc_endpoint_id        = aws_vpc_endpoint.gwlbe[count.index].id

  depends_on = [aws_route_table.igw_edge, aws_vpc_endpoint.gwlbe]
}

# Associate IGW with edge route table
resource "aws_route_table_association" "igw_edge" {
  count = local.config.ENABLE_GWLB_INSPECTION ? 1 : 0

  gateway_id     = local.igw_id
  route_table_id = aws_route_table.igw_edge[0].id

  depends_on = [aws_route_table.igw_edge, aws_internet_gateway.main]
}

# Add routes in Jumphost VPC route tables
resource "aws_route" "jumphost_to_workload" {
  count = local.config.ENABLE_VPC_PEERING ? length(local.config.JUMPHOST_ROUTE_TABLE_IDS) : 0

  route_table_id            = local.config.JUMPHOST_ROUTE_TABLE_IDS[count.index]
  destination_cidr_block    = local.config.VPC_CIDR
  vpc_peering_connection_id = aws_vpc_peering_connection.jumphost[0].id

  depends_on = [aws_vpc_peering_connection.jumphost]
}

# ============================================================================
# NAT Gateway (Optional, for workload egress)
# ============================================================================

resource "aws_eip" "nat" {
  count = local.config.ENABLE_NAT_GATEWAY ? 1 : 0

  domain = "vpc"

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-nat-eip"
    }
  )

  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  count = local.config.ENABLE_NAT_GATEWAY ? 1 : 0

  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.alb[0].id

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-nat-gw"
    }
  )

  depends_on = [aws_eip.nat, aws_subnet.alb]
}

# ============================================================================
# Security Groups
# ============================================================================

# ALB Security Group
resource "aws_security_group" "alb" {
  name_prefix = "${local.resource_prefix}-alb-"
  description = "Security group for Application Load Balancer"
  vpc_id      = local.vpc_id

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-alb-sg"
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

  from_port   = local.config.ALB_LISTENER_PORT
  to_port     = local.config.ALB_LISTENER_PORT
  ip_protocol = "tcp"
  cidr_ipv4   = local.config.ALLOWED_INGRESS_CIDRS[0]

  depends_on = [aws_security_group.alb]
}

resource "aws_vpc_security_group_egress_rule" "alb_to_workload" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow traffic to workload instances"

  from_port                    = local.config.ALB_TARGET_PORT
  to_port                      = local.config.ALB_TARGET_PORT
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.workload.id

  depends_on = [aws_security_group.alb, aws_security_group.workload]
}

# Workload Security Group
resource "aws_security_group" "workload" {
  name_prefix = "${local.resource_prefix}-workload-"
  description = "Security group for workload EC2 instances"
  vpc_id      = local.vpc_id

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-workload-sg"
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

  from_port                    = local.config.ALB_TARGET_PORT
  to_port                      = local.config.ALB_TARGET_PORT
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id

  depends_on = [aws_security_group.workload, aws_security_group.alb]
}

resource "aws_vpc_security_group_ingress_rule" "workload_ssh" {
  count = local.config.ENABLE_VPC_PEERING && length(local.config.SSH_ALLOWED_CIDRS) > 0 ? 1 : 0

  security_group_id = aws_security_group.workload.id
  description       = "Allow SSH from jumphost VPC"

  from_port   = 22
  to_port     = 22
  ip_protocol = "tcp"
  cidr_ipv4   = local.config.SSH_ALLOWED_CIDRS[0]

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
  name               = "${local.resource_prefix}-alb"
  internal           = local.config.ALB_INTERNAL
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.alb[*].id

  enable_deletion_protection = local.config.ENABLE_DELETION_PROTECTION
  enable_http2              = true
  enable_cross_zone_load_balancing = true

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-alb"
    }
  )

  depends_on = [aws_subnet.alb, aws_security_group.alb]
}

resource "aws_lb_target_group" "main" {
  name_prefix = "wkld-"
  port        = local.config.ALB_TARGET_PORT
  protocol    = local.config.ALB_TARGET_PROTOCOL
  vpc_id      = local.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    healthy_threshold   = local.config.ALB_HEALTHY_THRESHOLD
    unhealthy_threshold = local.config.ALB_UNHEALTHY_THRESHOLD
    timeout             = local.config.ALB_HEALTH_CHECK_TIMEOUT
    interval            = local.config.ALB_HEALTH_CHECK_INTERVAL
    path                = local.config.ALB_HEALTH_CHECK_PATH
    protocol            = local.config.ALB_TARGET_PROTOCOL
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-tg"
    }
  )

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_vpc.main]
}

resource "aws_lb_listener" "main" {
  load_balancer_arn = aws_lb.main.arn
  port              = local.config.ALB_LISTENER_PORT
  protocol          = local.config.ALB_LISTENER_PROTOCOL
  certificate_arn   = local.config.ALB_LISTENER_PROTOCOL == "HTTPS" ? local.config.ALB_CERTIFICATE_ARN : null

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
  count = local.config.WORKLOAD_COUNT

  ami           = local.ami_id
  instance_type = local.config.WORKLOAD_INSTANCE_TYPE
  key_name      = local.config.WORKLOAD_KEY_NAME != "" ? local.config.WORKLOAD_KEY_NAME : null
  
  # Distribute instances across AZs
  subnet_id = aws_subnet.workload[count.index % length(local.config.AVAILABILITY_ZONES)].id
  
  vpc_security_group_ids = [aws_security_group.workload.id]
  
  user_data = local.workload_user_data_final
  
  monitoring = local.config.ENABLE_DETAILED_MONITORING

  root_block_device {
    volume_type           = "gp3"
    volume_size           = local.config.WORKLOAD_ROOT_VOLUME_SIZE
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
    local.tags,
    {
      Name = "${local.resource_prefix}-workload-${count.index + 1}"
    }
  )

  lifecycle {
    ignore_changes = [ami]
  }

  depends_on = [aws_subnet.workload, aws_security_group.workload]
}

# Register workload instances with target group
resource "aws_lb_target_group_attachment" "workload" {
  count = local.config.WORKLOAD_COUNT

  target_group_arn = aws_lb_target_group.main.arn
  target_id        = aws_instance.workload[count.index].id
  port             = local.config.ALB_TARGET_PORT

  depends_on = [aws_instance.workload, aws_lb_target_group.main]
}

# ============================================================================
# VPC Flow Logs (Optional)
# ============================================================================

resource "aws_cloudwatch_log_group" "flow_logs" {
  count = local.config.ENABLE_FLOW_LOGS ? 1 : 0

  name              = "/aws/vpc/${local.resource_prefix}-flow-logs"
  retention_in_days = local.config.FLOW_LOGS_RETENTION_DAYS

  tags = local.tags
}

resource "aws_iam_role" "flow_logs" {
  count = local.config.ENABLE_FLOW_LOGS ? 1 : 0

  name_prefix = "${local.resource_prefix}-flow-logs-"

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

  tags = local.tags
}

resource "aws_iam_role_policy" "flow_logs" {
  count = local.config.ENABLE_FLOW_LOGS ? 1 : 0

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
  count = local.config.ENABLE_FLOW_LOGS ? 1 : 0

  iam_role_arn    = aws_iam_role.flow_logs[0].arn
  log_destination = aws_cloudwatch_log_group.flow_logs[0].arn
  traffic_type    = "ALL"
  vpc_id          = local.vpc_id

  tags = merge(
    local.tags,
    {
      Name = "${local.resource_prefix}-flow-logs"
    }
  )

  depends_on = [aws_cloudwatch_log_group.flow_logs, aws_iam_role_policy.flow_logs]
}

