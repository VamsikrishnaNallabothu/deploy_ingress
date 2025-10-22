# Deployment Guide - AWS Ingress Inspection Architecture

This guide provides step-by-step instructions for deploying the ingress inspection architecture.

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Greenfield Deployment](#greenfield-deployment-new-vpc)
3. [Brownfield Deployment](#brownfield-deployment-existing-vpc)
4. [VPC Peering Setup](#vpc-peering-setup)
5. [Post-Deployment Validation](#post-deployment-validation)
6. [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

### AWS Prerequisites

- [ ] AWS Account with appropriate permissions
- [ ] AWS CLI configured with credentials
- [ ] Terraform >= 1.0 installed
- [ ] Access to GWLB Endpoint Service in security account

### Required Information

Gather the following information before deployment:

1. **GWLB Configuration**
   ```bash
   # Get GWLB Endpoint Service Name from security team
   # Format: com.amazonaws.vpce.<region>.vpce-svc-<service-id>
   GWLB_SERVICE_NAME="com.amazonaws.vpce.us-east-1.vpce-svc-xxxxx"
   ```

2. **EC2 Key Pair**
   ```bash
   # Create key pair if you don't have one
   aws ec2 create-key-pair \
     --key-name my-inspection-key \
     --query 'KeyMaterial' \
     --output text > ~/.ssh/my-inspection-key.pem
   
   chmod 400 ~/.ssh/my-inspection-key.pem
   ```

3. **Jumphost VPC Information** (if using VPC peering)
   ```bash
   # Get jumphost VPC ID
   aws ec2 describe-vpcs \
     --filters "Name=tag:Name,Values=ZS_JH_VPC" \
     --query 'Vpcs[0].{VpcId:VpcId,CidrBlock:CidrBlock}' \
     --output table
   
   # Get route table IDs
   aws ec2 describe-route-tables \
     --filters "Name=vpc-id,Values=<jumphost-vpc-id>" \
     --query 'RouteTables[*].RouteTableId' \
     --output table
   ```

4. **Network Planning**
   - VPC CIDR: `10.0.0.0/16` (or your choice)
   - ALB Subnets: `10.0.1.0/24`, `10.0.2.0/24`
   - GWLB Endpoint Subnets: `10.0.11.0/24`, `10.0.12.0/24`
   - Workload Subnets: `10.0.21.0/24`, `10.0.22.0/24`
   - Availability Zones: `us-east-1a`, `us-east-1b`

### Permission Requirements

Ensure your AWS credentials have the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "elasticloadbalancing:*",
        "logs:*",
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy",
        "iam:PassRole"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Greenfield Deployment (New VPC)

### Step 1: Clone Repository and Setup

```bash
# Navigate to project directory
cd aws-inspection-architecture

# Verify Terraform installation
terraform version
```

### Step 2: Create Configuration File

```bash
# Copy example configuration
cp terraform.tfvars.example terraform.tfvars

# Edit configuration
vim terraform.tfvars
```

**Minimal Configuration (`terraform.tfvars`):**

```hcl
# General
project_name = "my-ingress-inspection"
environment  = "prod"
aws_region   = "us-east-1"

# Network
availability_zones = ["us-east-1a", "us-east-1b"]
vpc_cidr          = "10.0.0.0/16"

# GWLB (REQUIRED - Get from security team)
gwlb_endpoint_service_name = "com.amazonaws.vpce.us-east-1.vpce-svc-xxxxx"
enable_gwlb_inspection     = true

# Workloads
workload_count        = 2
workload_key_name     = "my-inspection-key"
workload_instance_type = "t3.micro"

# VPC Peering (Optional)
enable_vpc_peering       = true
jumphost_vpc_id          = "vpc-xxxxx"
jumphost_vpc_cidr        = "10.100.0.0/16"
jumphost_route_table_ids = ["rtb-xxxxx"]
ssh_allowed_cidrs        = ["10.100.0.0/16"]

# Optional Features
enable_flow_logs = true
enable_nat_gateway = false
```

### Step 3: Initialize Terraform

```bash
# Initialize Terraform (downloads providers)
terraform init

# Expected output:
# Terraform has been successfully initialized!
```

### Step 4: Plan Deployment

```bash
# Generate and review execution plan
terraform plan -out=tfplan

# Review the plan carefully:
# - Number of resources to be created
# - VPC and subnet configurations
# - Security group rules
# - EC2 instances
```

**Expected Resources (typical deployment):**

```
Plan: 45+ to add, 0 to change, 0 to destroy.
```

### Step 5: Deploy Infrastructure

```bash
# Apply the plan
terraform apply tfplan

# Or apply directly (will prompt for confirmation)
terraform apply

# Type 'yes' when prompted
```

**Deployment Time:** Approximately 5-8 minutes

### Step 6: Capture Outputs

```bash
# View all outputs
terraform output

# Save important outputs
terraform output -json > deployment-outputs.json

# Get ALB DNS name
terraform output -raw alb_dns_name

# Get workload IPs
terraform output -json workload_private_ips | jq -r '.[]'
```

---

## Brownfield Deployment (Existing VPC)

### When to Use Brownfield

- You have an existing VPC you want to use
- Internet Gateway already exists
- You want to integrate with existing infrastructure

### Step 1: Identify Existing Resources

```bash
# List your VPCs
aws ec2 describe-vpcs \
  --query 'Vpcs[*].{ID:VpcId,Name:Tags[?Key==`Name`].Value|[0],CIDR:CidrBlock}' \
  --output table

# Get Internet Gateway for the VPC
aws ec2 describe-internet-gateways \
  --filters "Name=attachment.vpc-id,Values=<your-vpc-id>" \
  --query 'InternetGateways[0].InternetGatewayId' \
  --output text
```

### Step 2: Configure for Brownfield

```hcl
# terraform.tfvars

# General
project_name = "my-ingress-inspection"
environment  = "prod"
aws_region   = "us-east-1"

# Brownfield Configuration
create_vpc      = false
existing_vpc_id = "vpc-0a1b2c3d4e5f"
create_igw      = false
existing_igw_id = "igw-0a1b2c3d4e5f"

# Network (subnets will be created in existing VPC)
availability_zones    = ["us-east-1a", "us-east-1b"]
alb_subnet_cidrs      = ["10.50.1.0/24", "10.50.2.0/24"]
gwlbe_subnet_cidrs    = ["10.50.11.0/24", "10.50.12.0/24"]
workload_subnet_cidrs = ["10.50.21.0/24", "10.50.22.0/24"]

# GWLB Configuration
gwlb_endpoint_service_name = "com.amazonaws.vpce.us-east-1.vpce-svc-xxxxx"

# Workloads
workload_count    = 2
workload_key_name = "my-inspection-key"

# VPC Peering (if needed)
enable_vpc_peering       = true
jumphost_vpc_id          = "vpc-xxxxx"
jumphost_vpc_cidr        = "10.100.0.0/16"
jumphost_route_table_ids = ["rtb-xxxxx"]
```

### Step 3: Verify No CIDR Conflicts

```bash
# Check existing subnets in VPC
aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=<your-vpc-id>" \
  --query 'Subnets[*].{CIDR:CidrBlock,AZ:AvailabilityZone}' \
  --output table

# Ensure your new subnet CIDRs don't overlap
```

### Step 4: Deploy

```bash
# Initialize and apply
terraform init
terraform plan
terraform apply
```

---

## VPC Peering Setup

### Overview

VPC peering enables secure SSH access from a jumphost/bastion VPC to workload instances.

### Architecture

```
┌──────────────────────┐         ┌──────────────────────┐
│  Jumphost VPC        │         │  Workload VPC        │
│  (ZS_JH_VPC)         │◄───────►│  (New/Existing)      │
│  10.100.0.0/16       │ Peering │  10.0.0.0/16         │
│                      │         │                      │
│  ┌────────────────┐ │         │  ┌────────────────┐  │
│  │ Jumphost VM    │─┼─────────┼─►│ Workload VMs   │  │
│  │ SSH Client     │ │         │  │ Target Servers │  │
│  └────────────────┘ │         │  └────────────────┘  │
└──────────────────────┘         └──────────────────────┘
```

### Step 1: Get Jumphost VPC Information

```bash
# Get VPC ID
JUMPHOST_VPC_ID=$(aws ec2 describe-vpcs \
  --filters "Name=tag:Name,Values=ZS_JH_VPC" \
  --query 'Vpcs[0].VpcId' \
  --output text)

# Get VPC CIDR
JUMPHOST_VPC_CIDR=$(aws ec2 describe-vpcs \
  --vpc-ids $JUMPHOST_VPC_ID \
  --query 'Vpcs[0].CidrBlock' \
  --output text)

# Get all route table IDs in jumphost VPC
JUMPHOST_RT_IDS=$(aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=$JUMPHOST_VPC_ID" \
  --query 'RouteTables[*].RouteTableId' \
  --output text)

echo "VPC ID: $JUMPHOST_VPC_ID"
echo "VPC CIDR: $JUMPHOST_VPC_CIDR"
echo "Route Tables: $JUMPHOST_RT_IDS"
```

### Step 2: Configure Peering in terraform.tfvars

```hcl
# VPC Peering Configuration
enable_vpc_peering = true

jumphost_vpc_id   = "vpc-0a1b2c3d"  # From step 1
jumphost_vpc_cidr = "10.100.0.0/16" # From step 1

# All route tables in jumphost VPC
jumphost_route_table_ids = [
  "rtb-abc123",
  "rtb-def456"
]

# Allow SSH from jumphost VPC
ssh_allowed_cidrs = ["10.100.0.0/16"]
```

### Step 3: Deploy with Peering

```bash
terraform apply
```

### Step 4: Verify Peering

```bash
# Get peering connection ID
PEERING_ID=$(terraform output -raw vpc_peering_connection_id)

# Verify peering is active
aws ec2 describe-vpc-peering-connections \
  --vpc-peering-connection-ids $PEERING_ID \
  --query 'VpcPeeringConnections[0].Status.Code' \
  --output text

# Expected: active
```

### Step 5: Verify Routes

```bash
# Check workload VPC route to jumphost
aws ec2 describe-route-tables \
  --filters "Name=tag:Name,Values=*workload*" \
  --query 'RouteTables[*].Routes[?VpcPeeringConnectionId]' \
  --output table

# Check jumphost VPC route to workload
aws ec2 describe-route-tables \
  --route-table-ids rtb-xxxxx \
  --query 'RouteTables[*].Routes[?VpcPeeringConnectionId]' \
  --output table
```

### Step 6: Test SSH Access

```bash
# Get workload IP
WORKLOAD_IP=$(terraform output -json workload_private_ips | jq -r '.[0]')

# From jumphost VM:
ssh -i ~/.ssh/my-inspection-key.pem ec2-user@$WORKLOAD_IP

# If successful, you should see:
# [ec2-user@ip-10-0-21-10 ~]$
```

---

## Post-Deployment Validation

### 1. Infrastructure Validation

```bash
# Verify all resources created
terraform state list

# Check resource count
terraform state list | wc -l
```

### 2. VPC and Networking

```bash
# Verify VPC
aws ec2 describe-vpcs \
  --vpc-ids $(terraform output -raw vpc_id) \
  --query 'Vpcs[0].{ID:VpcId,CIDR:CidrBlock,State:State}'

# Verify subnets
aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$(terraform output -raw vpc_id)" \
  --query 'Subnets[*].{ID:SubnetId,CIDR:CidrBlock,AZ:AvailabilityZone}' \
  --output table
```

### 3. GWLB Endpoints

```bash
# Check GWLB endpoint status
terraform output -json gwlb_endpoint_ids | jq -r '.[]' | while read vpce; do
  aws ec2 describe-vpc-endpoints \
    --vpc-endpoint-ids $vpce \
    --query 'VpcEndpoints[0].{ID:VpcEndpointId,State:State,ServiceName:ServiceName}'
done

# Expected: State = "available"
```

### 4. Application Load Balancer

```bash
# Check ALB state
aws elbv2 describe-load-balancers \
  --load-balancer-arns $(terraform output -raw alb_arn) \
  --query 'LoadBalancers[0].{State:State.Code,DNS:DNSName}'

# Check target health
aws elbv2 describe-target-health \
  --target-group-arn $(terraform output -raw alb_target_group_arn) \
  --query 'TargetHealthDescriptions[*].{Instance:Target.Id,Health:TargetHealth.State,Reason:TargetHealth.Reason}' \
  --output table

# Expected: Health = "healthy"
```

### 5. Workload Instances

```bash
# Check instance states
terraform output -json workload_instance_ids | jq -r '.[]' | while read instance; do
  aws ec2 describe-instances \
    --instance-ids $instance \
    --query 'Reservations[0].Instances[0].{ID:InstanceId,State:State.Name,IP:PrivateIpAddress}'
done

# Expected: State = "running"
```

### 6. Test Application Connectivity

```bash
# Test HTTP connectivity
ALB_DNS=$(terraform output -raw alb_dns_name)
curl -v http://$ALB_DNS

# Expected: HTTP 200 OK with HTML content

# Test multiple times to verify load balancing
for i in {1..10}; do
  curl -s http://$ALB_DNS | grep "Private IP"
done
```

### 7. Security Validation

```bash
# Verify security groups
echo "ALB Security Group:"
aws ec2 describe-security-group-rules \
  --filters "Name=group-id,Values=$(terraform output -raw alb_security_group_id)" \
  --query 'SecurityGroupRules[*].{Type:IsEgress,Protocol:IpProtocol,Port:FromPort,Source:CidrIpv4}' \
  --output table

echo "\nWorkload Security Group:"
aws ec2 describe-security-group-rules \
  --filters "Name=group-id,Values=$(terraform output -raw workload_security_group_id)" \
  --query 'SecurityGroupRules[*].{Type:IsEgress,Protocol:IpProtocol,Port:FromPort,Source:CidrIpv4}' \
  --output table
```

### 8. VPC Flow Logs

```bash
# Verify flow logs are enabled
aws logs describe-log-groups \
  --log-group-name-prefix "/aws/vpc"

# Tail flow logs
aws logs tail $(terraform output -raw flow_logs_log_group_name) --follow
```

---

## Troubleshooting

### Issue: GWLB Endpoint Shows "Failed" State

**Symptoms:**
```bash
$ terraform apply
Error: error creating VPC Endpoint: InvalidServiceName
```

**Solutions:**

1. **Verify Service Name**
   ```bash
   # Check service name format
   aws ec2 describe-vpc-endpoint-services \
     --service-names com.amazonaws.vpce.us-east-1.vpce-svc-xxxxx
   ```

2. **Check Cross-Account Permissions**
   - Verify endpoint service has permission for your account
   - Contact security team to whitelist your AWS account

3. **Verify Region Match**
   - Ensure GWLB service and VPC are in same region

### Issue: ALB Target Health "Unhealthy"

**Symptoms:**
```bash
$ aws elbv2 describe-target-health ...
TargetHealth.State: unhealthy
TargetHealth.Reason: Target.FailedHealthChecks
```

**Solutions:**

1. **Check Security Groups**
   ```bash
   # Verify ALB can reach workload instances
   aws ec2 describe-security-group-rules \
     --filters "Name=group-id,Values=$(terraform output -raw workload_security_group_id)"
   
   # Should allow traffic from ALB security group on target port
   ```

2. **Verify Web Server Running**
   ```bash
   # SSH to instance and check
   ssh -i key.pem ec2-user@10.0.21.10
   sudo systemctl status httpd
   curl localhost
   ```

3. **Check Health Check Path**
   ```bash
   # Verify health check path exists
   curl http://10.0.21.10/
   ```

### Issue: Cannot SSH to Workload from Jumphost

**Symptoms:**
```bash
$ ssh ec2-user@10.0.21.10
Connection timed out
```

**Solutions:**

1. **Verify VPC Peering**
   ```bash
   aws ec2 describe-vpc-peering-connections \
     --vpc-peering-connection-ids $(terraform output -raw vpc_peering_connection_id)
   
   # Status should be: "active"
   ```

2. **Check Route Tables**
   ```bash
   # Verify route exists in jumphost VPC
   aws ec2 describe-route-tables \
     --route-table-ids rtb-xxxxx \
     --query 'RouteTables[*].Routes[?DestinationCidrBlock==`10.0.0.0/16`]'
   ```

3. **Verify Security Groups**
   ```bash
   # Check SSH allowed from jumphost CIDR
   aws ec2 describe-security-group-rules \
     --filters "Name=group-id,Values=$(terraform output -raw workload_security_group_id)" \
     --query 'SecurityGroupRules[?FromPort==`22`]'
   ```

### Issue: Terraform State Lock

**Symptoms:**
```bash
Error: Error acquiring the state lock
```

**Solutions:**

1. **Wait for Other Operations**
   - Another terraform operation may be in progress
   - Wait for it to complete

2. **Force Unlock (use carefully)**
   ```bash
   # Get lock ID from error message
   terraform force-unlock <lock-id>
   ```

### Issue: Resource Already Exists

**Symptoms:**
```bash
Error: A resource with the ID "..." already exists
```

**Solutions:**

1. **Import Existing Resource**
   ```bash
   terraform import aws_vpc.main vpc-xxxxx
   terraform import aws_subnet.alb[0] subnet-xxxxx
   ```

2. **Use Data Source**
   - Modify configuration to use existing resources
   - Set `create_vpc = false` and provide `existing_vpc_id`

---

## Next Steps

After successful deployment:

1. **Configure DNS**
   ```bash
   # Create Route53 record pointing to ALB
   aws route53 change-resource-record-sets \
     --hosted-zone-id Z123456789 \
     --change-batch file://dns-change.json
   ```

2. **Enable HTTPS**
   ```bash
   # Request ACM certificate
   aws acm request-certificate \
     --domain-name example.com \
     --validation-method DNS
   
   # Update terraform.tfvars
   alb_listener_protocol = "HTTPS"
   alb_certificate_arn   = "arn:aws:acm:..."
   
   # Apply changes
   terraform apply
   ```

3. **Set Up Monitoring**
   - CloudWatch dashboards
   - ALB access logs
   - VPC Flow Logs analysis

4. **Configure Backups**
   - AWS Backup for EC2 instances
   - Terraform state in S3 with versioning

5. **Security Hardening**
   - Review and tighten security group rules
   - Enable AWS Config rules
   - Set up AWS Security Hub

---

## Support

For issues or questions:

1. Check [README.md](README.md) for architecture overview
2. Review [TESTING.md](TESTING.md) for testing procedures
3. Consult Terraform documentation
4. Open an issue on GitHub

---

**Deployment Guide Version 1.0**  
**Last Updated: 2025-10-22**

