# ============================================================================
# AWS Ingress Inspection Architecture - Outputs
# ============================================================================

# ============================================================================
# VPC Information
# ============================================================================

output "vpc_id" {
  description = "ID of the application VPC"
  value       = local.vpc_id
}

output "vpc_cidr" {
  description = "CIDR block of the application VPC"
  value       = var.create_vpc ? aws_vpc.main[0].cidr_block : data.aws_vpc.existing[0].cidr_block
}

output "availability_zones" {
  description = "Availability zones used for deployment"
  value       = var.availability_zones
}

# ============================================================================
# Subnet Information
# ============================================================================

output "alb_subnet_ids" {
  description = "IDs of ALB subnets"
  value       = aws_subnet.alb[*].id
}

output "alb_subnet_cidrs" {
  description = "CIDR blocks of ALB subnets"
  value       = aws_subnet.alb[*].cidr_block
}

output "gwlbe_subnet_ids" {
  description = "IDs of GWLB Endpoint subnets"
  value       = aws_subnet.gwlbe[*].id
}

output "gwlbe_subnet_cidrs" {
  description = "CIDR blocks of GWLB Endpoint subnets"
  value       = aws_subnet.gwlbe[*].cidr_block
}

output "workload_subnet_ids" {
  description = "IDs of workload subnets"
  value       = aws_subnet.workload[*].id
}

output "workload_subnet_cidrs" {
  description = "CIDR blocks of workload subnets"
  value       = aws_subnet.workload[*].cidr_block
}

# ============================================================================
# Gateway Load Balancer Endpoints
# ============================================================================

output "gwlb_endpoint_ids" {
  description = "IDs of GWLB Endpoints"
  value       = var.enable_gwlb_inspection ? aws_vpc_endpoint.gwlbe[*].id : []
}

output "gwlb_endpoint_network_interface_ids" {
  description = "Network interface IDs of GWLB Endpoints"
  value       = var.enable_gwlb_inspection ? aws_vpc_endpoint.gwlbe[*].network_interface_ids : []
}

output "gwlb_inspection_enabled" {
  description = "Whether GWLB inspection is enabled"
  value       = var.enable_gwlb_inspection
}

# ============================================================================
# Application Load Balancer
# ============================================================================

output "alb_id" {
  description = "ID of the Application Load Balancer"
  value       = aws_lb.main.id
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.main.arn
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer (use this to access your application)"
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = aws_lb.main.zone_id
}

output "alb_target_group_arn" {
  description = "ARN of the ALB target group"
  value       = aws_lb_target_group.main.arn
}

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb.id
}

output "alb_url" {
  description = "URL to access the Application Load Balancer"
  value       = "${var.alb_listener_protocol == "HTTPS" ? "https" : "http"}://${aws_lb.main.dns_name}"
}

# ============================================================================
# Workload Instances
# ============================================================================

output "workload_instance_ids" {
  description = "IDs of workload EC2 instances"
  value       = aws_instance.workload[*].id
}

output "workload_private_ips" {
  description = "Private IP addresses of workload instances"
  value       = aws_instance.workload[*].private_ip
}

output "workload_availability_zones" {
  description = "Availability zones of workload instances"
  value       = aws_instance.workload[*].availability_zone
}

output "workload_subnet_assignments" {
  description = "Subnet IDs where workload instances are deployed"
  value       = aws_instance.workload[*].subnet_id
}

output "workload_count" {
  description = "Number of workload instances deployed"
  value       = var.workload_count
}

output "workload_security_group_id" {
  description = "ID of the workload security group"
  value       = aws_security_group.workload.id
}

output "workload_details" {
  description = "Detailed information about each workload instance"
  value = {
    for idx, instance in aws_instance.workload : instance.id => {
      instance_id       = instance.id
      private_ip        = instance.private_ip
      availability_zone = instance.availability_zone
      subnet_id         = instance.subnet_id
      instance_type     = instance.instance_type
      ami_id            = instance.ami
    }
  }
}

# ============================================================================
# VPC Peering (Jumphost)
# ============================================================================

output "vpc_peering_connection_id" {
  description = "ID of the VPC peering connection to jumphost VPC"
  value       = var.enable_vpc_peering ? aws_vpc_peering_connection.jumphost[0].id : null
}

output "vpc_peering_enabled" {
  description = "Whether VPC peering is enabled"
  value       = var.enable_vpc_peering
}

output "jumphost_vpc_id" {
  description = "ID of the jumphost VPC (if peering is enabled)"
  value       = var.enable_vpc_peering ? var.jumphost_vpc_id : null
}

output "jumphost_vpc_cidr" {
  description = "CIDR block of the jumphost VPC (if peering is enabled)"
  value       = var.enable_vpc_peering ? var.jumphost_vpc_cidr : null
}

# ============================================================================
# Route Tables
# ============================================================================

output "alb_route_table_id" {
  description = "ID of the ALB route table"
  value       = aws_route_table.alb.id
}

output "gwlbe_route_table_id" {
  description = "ID of the GWLB Endpoint route table"
  value       = var.enable_gwlb_inspection ? aws_route_table.gwlbe[0].id : null
}

output "workload_route_table_id" {
  description = "ID of the workload route table"
  value       = aws_route_table.workload.id
}

output "igw_edge_route_table_id" {
  description = "ID of the IGW edge route table"
  value       = var.enable_gwlb_inspection ? aws_route_table.igw_edge[0].id : null
}

# ============================================================================
# Internet Gateway
# ============================================================================

output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = local.igw_id
}

# ============================================================================
# NAT Gateway (if enabled)
# ============================================================================

output "nat_gateway_id" {
  description = "ID of the NAT Gateway (if enabled)"
  value       = var.enable_nat_gateway ? aws_nat_gateway.main[0].id : null
}

output "nat_gateway_public_ip" {
  description = "Public IP of the NAT Gateway (if enabled)"
  value       = var.enable_nat_gateway ? aws_eip.nat[0].public_ip : null
}

# ============================================================================
# VPC Flow Logs
# ============================================================================

output "flow_logs_log_group_name" {
  description = "CloudWatch log group name for VPC Flow Logs"
  value       = var.enable_flow_logs ? aws_cloudwatch_log_group.flow_logs[0].name : null
}

output "flow_logs_enabled" {
  description = "Whether VPC Flow Logs are enabled"
  value       = var.enable_flow_logs
}

# ============================================================================
# Connection Information
# ============================================================================

output "ssh_connection_info" {
  description = "SSH connection information for workload instances (via jumphost)"
  value = var.enable_vpc_peering && var.workload_count > 0 ? {
    instructions = "Connect from jumphost VPC using: ssh -i <key-file> ec2-user@<workload-ip>"
    workload_ips = aws_instance.workload[*].private_ip
    key_name     = var.workload_key_name
  } : null
}

output "test_commands" {
  description = "Commands to test the architecture"
  value = {
    test_alb                = "curl ${aws_lb.main.dns_name}"
    test_alb_https          = var.alb_listener_protocol == "HTTPS" ? "curl https://${aws_lb.main.dns_name}" : "N/A - HTTP listener configured"
    check_target_health     = "aws elbv2 describe-target-health --target-group-arn ${aws_lb_target_group.main.arn}"
    view_flow_logs          = var.enable_flow_logs ? "aws logs tail ${aws_cloudwatch_log_group.flow_logs[0].name} --follow" : "N/A - Flow logs not enabled"
    ssh_to_workload_example = var.enable_vpc_peering && var.workload_count > 0 ? "ssh -i ~/.ssh/${var.workload_key_name}.pem ec2-user@${aws_instance.workload[0].private_ip}" : "N/A"
  }
}

# ============================================================================
# Architecture Summary
# ============================================================================

output "architecture_summary" {
  description = "Summary of the deployed architecture"
  value = {
    architecture_type     = "Ingress Inspection (IGW → GWLB Endpoint → Firewall → ALB → Workloads)"
    vpc_cidr              = var.create_vpc ? aws_vpc.main[0].cidr_block : data.aws_vpc.existing[0].cidr_block
    availability_zones    = var.availability_zones
    workload_count        = var.workload_count
    gwlb_inspection       = var.enable_gwlb_inspection ? "Enabled" : "Disabled"
    vpc_peering           = var.enable_vpc_peering ? "Enabled (Jumphost access)" : "Disabled"
    nat_gateway           = var.enable_nat_gateway ? "Enabled" : "Disabled"
    flow_logs             = var.enable_flow_logs ? "Enabled" : "Disabled"
    alb_endpoint          = "${var.alb_listener_protocol == "HTTPS" ? "https" : "http"}://${aws_lb.main.dns_name}"
  }
}

# ============================================================================
# Deployment Information
# ============================================================================

output "deployment_info" {
  description = "Information about the deployment"
  value = {
    project_name        = var.project_name
    environment         = var.environment
    region              = var.aws_region
    terraform_workspace = terraform.workspace
    deployment_mode     = var.create_vpc ? "Greenfield (New VPC)" : "Brownfield (Existing VPC)"
  }
}

# ============================================================================
# Next Steps
# ============================================================================

output "next_steps" {
  description = "Recommended next steps after deployment"
  value = [
    "1. Test ALB connectivity: curl ${aws_lb.main.dns_name}",
    "2. Verify target health: aws elbv2 describe-target-health --target-group-arn ${aws_lb_target_group.main.arn}",
    var.enable_gwlb_inspection ? "3. Check GWLB endpoint status: aws ec2 describe-vpc-endpoints --vpc-endpoint-ids ${join(" ", aws_vpc_endpoint.gwlbe[*].id)}" : "3. GWLB inspection disabled - enable for production use",
    var.enable_vpc_peering ? "4. Test SSH access from jumphost: ssh -i ~/.ssh/${var.workload_key_name}.pem ec2-user@${var.workload_count > 0 ? aws_instance.workload[0].private_ip : "<workload-ip>"}" : "4. VPC peering not enabled - enable for jumphost access",
    var.enable_flow_logs ? "5. Monitor VPC Flow Logs: aws logs tail ${aws_cloudwatch_log_group.flow_logs[0].name} --follow" : "5. Enable VPC Flow Logs for traffic analysis",
    "6. Configure DNS record pointing to: ${aws_lb.main.dns_name}",
    "7. Review security group rules and tighten as needed",
    var.enable_gwlb_inspection ? "8. Verify firewall rules in GWLB target instances" : "8. Configure GWLB endpoints before production use"
  ]
}

