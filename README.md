# AWS Ingress Inspection Architecture

[![Terraform](https://img.shields.io/badge/Terraform-1.0+-purple?logo=terraform)](https://www.terraform.io/)
[![AWS](https://img.shields.io/badge/AWS-Cloud-orange?logo=amazon-aws)](https://aws.amazon.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## 🔒 Overview

A production-ready Terraform infrastructure for deploying AWS ingress traffic inspection architecture using Gateway Load Balancer (GWLB) endpoints. This solution ensures **all internet traffic is inspected by network firewalls** before reaching your workloads.

### Architecture Flow

```
Internet → IGW → GWLB Endpoint → Firewall (Security Account) → GWLB Endpoint → ALB → Workload Instances
```

### Key Features

- ✅ **Centralized Security Inspection**: All ingress traffic routed through GWLB for firewall inspection
- ✅ **High Availability**: Multi-AZ deployment across all components
- ✅ **Symmetric Routing**: Ensures bidirectional traffic flows through the same firewall instance
- ✅ **Jumphost Integration**: VPC peering support for secure management access
- ✅ **Brownfield Ready**: Works with existing VPCs and infrastructure
- ✅ **Configurable Workloads**: Deploy variable number of EC2 instances behind ALB
- ✅ **Production Ready**: Includes monitoring, flow logs, and security best practices

## 📋 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                            INTERNET                                 │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                   ┌─────────▼──────────┐
                   │  Internet Gateway  │
                   └─────────┬──────────┘
                             │
              ┌──────────────┴──────────────┐
              │   IGW Edge Route Table      │
              │  Routes to GWLB Endpoints   │
              └──────────────┬──────────────┘
                             │
                   ┌─────────▼──────────┐
                   │  GWLB Endpoint     │◄─────┐
                   │  (AZ-1 / AZ-2)     │      │
                   └─────────┬──────────┘      │
                             │                  │
                    [GENEVE Encapsulation]     │
                             │                  │
        ┌────────────────────▼──────────────────┴────────────┐
        │         Security Account (Cross-Account)           │
        │  ┌──────────────────────────────────────────────┐  │
        │  │  Gateway Load Balancer (GWLB)                │  │
        │  └────────────┬─────────────────────────────────┘  │
        │               │                                     │
        │  ┌────────────▼──────────────┐                     │
        │  │  Firewall Instances (NGFW)│                     │
        │  │  - Stateful Inspection    │                     │
        │  │  - IDS/IPS                │                     │
        │  │  - Threat Prevention      │                     │
        │  └────────────┬──────────────┘                     │
        └───────────────┼────────────────────────────────────┘
                        │
            [Traffic Returns After Inspection]
                        │
                   ┌────▼─────┐
                   │GWLB EP   │
                   │Subnet RT │──► Routes to ALB
                   └────┬─────┘
                        │
           ┌────────────▼──────────────┐
           │  Application Load Balancer│
           │       (Multi-AZ)          │
           └────────────┬──────────────┘
                        │
        ┌───────────────┴────────────────┐
        │                                │
  ┌─────▼──────┐                  ┌─────▼──────┐
  │ Workload 1 │                  │ Workload 2 │
  │  (AZ-1)    │                  │  (AZ-2)    │
  │  EC2       │                  │  EC2       │
  └────────────┘                  └────────────┘

        ┌──────────────────────────┐
        │   Jumphost VPC (ZS_JH)   │
        │   VPC Peering            │◄──── Management Access
        │   for SSH Access         │
        └──────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

1. **AWS Account** with appropriate permissions
2. **Terraform** >= 1.0 installed
3. **GWLB Endpoint Service Name** from your security account
4. **EC2 Key Pair** created for SSH access
5. **Optional**: Jumphost VPC ID for management access

### Step 1: Clone and Configure

```bash
# Clone or navigate to the repository
cd aws-inspection-architecture

# Copy example configuration
cp config.yaml.example config.yaml

# Edit with your values
vim config.yaml
```

### Step 2: Configure Variables

Edit `config.yaml` with your specific values:

```yaml
# Required Configuration
AWS_REGION: "us-east-1"
GWLB_ENDPOINT_SERVICE_NAME: "com.amazonaws.vpce.us-east-1.vpce-svc-xxxxx"
WORKLOAD_KEY_NAME: "my-keypair"
WORKLOAD_COUNT: 2

# VPC Peering (Optional but Recommended)
ENABLE_VPC_PEERING: true
JUMPHOST_VPC_ID: "vpc-xxxxx"
JUMPHOST_VPC_CIDR: "10.100.0.0/16"
JUMPHOST_ROUTE_TABLE_IDS:
  - "rtb-xxxxx"
SSH_ALLOWED_CIDRS:
  - "10.100.0.0/16"
```

### Step 3: Deploy

```bash
# Initialize Terraform
./ztgw_infra init

# Review planned changes
./ztgw_infra plan

# Create infrastructure
./ztgw_infra create

# Note the outputs
terraform output alb_dns_name
terraform output workload_private_ips
```

### Step 4: Test

```bash
# Test ALB connectivity
curl $(terraform output -raw alb_dns_name)

# Check target health
aws elbv2 describe-target-health \
  --target-group-arn $(terraform output -raw alb_target_group_arn)

# SSH to workload (from jumphost)
ssh -i ~/.ssh/my-keypair.pem ec2-user@<workload-private-ip>
```

## 📚 Configuration Reference

### Essential Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `gwlb_endpoint_service_name` | GWLB Endpoint Service from security account | Yes | - |
| `workload_key_name` | EC2 key pair name for SSH access | Yes* | "" |
| `workload_count` | Number of workload instances (0-20) | No | 2 |
| `enable_vpc_peering` | Enable VPC peering with jumphost | No | false |
| `jumphost_vpc_id` | Jumphost VPC ID for peering | Yes** | "" |
| `jumphost_vpc_cidr` | Jumphost VPC CIDR block | Yes** | "" |

\* Required if `workload_count` > 0  
\** Required if `enable_vpc_peering` = true

### VPC Peering Configuration

To enable management access from a jumphost/bastion VPC:

```hcl
enable_vpc_peering       = true
jumphost_vpc_id          = "vpc-0a1b2c3d4e5f"
jumphost_vpc_cidr        = "10.100.0.0/16"
jumphost_route_table_ids = ["rtb-abc123", "rtb-def456"]
ssh_allowed_cidrs        = ["10.100.0.0/16"]
```

This configuration:
1. Creates VPC peering connection between workload VPC and jumphost VPC
2. Adds routes in both VPCs for bidirectional communication
3. Configures security groups to allow SSH from jumphost CIDR
4. Enables secure management access to workload instances

### Workload Configuration

```yaml
WORKLOAD_COUNT: 4                    # Deploy 4 instances
WORKLOAD_INSTANCE_TYPE: "t3.small"   # Instance type
WORKLOAD_KEY_NAME: "my-keypair"      # SSH key
```

### Brownfield Deployment

To deploy in an existing VPC:

```yaml
CREATE_VPC: false
EXISTING_VPC_ID: "vpc-existing123"
CREATE_IGW: false
EXISTING_IGW_ID: "igw-existing456"
```

## 🏗️ Architecture Components

### 1. VPC and Subnets

- **ALB Subnets**: Public subnets hosting the Application Load Balancer
- **GWLB Endpoint Subnets**: Dedicated subnets for GWLB endpoints
- **Workload Subnets**: Private subnets for application instances

### 2. Gateway Load Balancer Integration

- **GWLB Endpoints**: One per AZ for traffic inspection
- **Cross-Account Service**: Connects to firewall GWLB in security account
- **Symmetric Routing**: Ensures both directions use same firewall instance

### 3. Application Load Balancer

- **Internet-Facing**: Distributes traffic to workload instances
- **Multi-AZ**: High availability across availability zones
- **Health Checks**: Automated health monitoring of targets
- **Security**: Integrated with security groups and GWLB inspection

### 4. Workload Instances

- **Auto-Configured**: Deploys with web server for testing
- **Distributed**: Spread across multiple AZs
- **Secure**: Private subnets, encrypted volumes, IMDSv2
- **Managed**: SSH access via jumphost VPC peering

### 5. Routing Architecture

```
Ingress Flow:
Internet → IGW → [IGW Edge RT] → GWLB EP → Firewall → GWLB EP → [GWLB RT] → ALB → Workloads

Egress Flow:
Workloads → ALB → [ALB RT] → GWLB EP → Firewall → GWLB EP → [GWLB RT] → IGW → Internet

Management Access:
Jumphost → [VPC Peering] → Workloads
```

## 📊 Outputs

After deployment, Terraform provides comprehensive outputs:

### Primary Outputs

- `alb_dns_name`: DNS name to access your application
- `alb_url`: Full URL (http:// or https://)
- `workload_private_ips`: List of all workload private IPs
- `workload_instance_ids`: List of EC2 instance IDs

### Networking Outputs

- `vpc_id`: VPC ID
- `subnet_ids`: All subnet IDs by tier
- `gwlb_endpoint_ids`: GWLB endpoint IDs
- `vpc_peering_connection_id`: Peering connection ID

### Monitoring Outputs

- `flow_logs_log_group_name`: CloudWatch log group for VPC Flow Logs
- `test_commands`: Ready-to-use testing commands
- `next_steps`: Recommended actions after deployment

### Example Output

```bash
$ terraform output

alb_dns_name = "ingress-inspection-dev-alb-1234567890.us-east-1.elb.amazonaws.com"
alb_url = "http://ingress-inspection-dev-alb-1234567890.us-east-1.elb.amazonaws.com"

workload_private_ips = [
  "10.0.21.10",
  "10.0.22.15",
]

architecture_summary = {
  architecture_type = "Ingress Inspection (IGW → GWLB Endpoint → Firewall → ALB → Workloads)"
  gwlb_inspection = "Enabled"
  vpc_peering = "Enabled (Jumphost access)"
  workload_count = 2
}
```

## 🔍 Testing and Validation

### 1. Test ALB Connectivity

```bash
# HTTP test
curl $(terraform output -raw alb_dns_name)

# Expected: HTML page showing workload instance details
```

### 2. Verify Target Health

```bash
aws elbv2 describe-target-health \
  --target-group-arn $(terraform output -raw alb_target_group_arn) \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State]' \
  --output table
```

### 3. Check GWLB Endpoints

```bash
aws ec2 describe-vpc-endpoints \
  --vpc-endpoint-ids $(terraform output -json gwlb_endpoint_ids | jq -r '.[]') \
  --query 'VpcEndpoints[*].[VpcEndpointId,State]' \
  --output table
```

### 4. Test SSH Access (via Jumphost)

```bash
# From jumphost VPC
ssh -i ~/.ssh/my-keypair.pem ec2-user@10.0.21.10

# Verify connectivity
curl localhost
```

### 5. Monitor VPC Flow Logs

```bash
aws logs tail /aws/vpc/ingress-inspection-dev-flow-logs --follow
```

## 🛡️ Security Features

### Network Security

- ✅ All traffic inspected by GWLB before reaching workloads
- ✅ Security groups limiting access between tiers
- ✅ Private subnets for workload instances (no direct internet access)
- ✅ VPC Flow Logs for traffic monitoring
- ✅ IGW edge association for immediate inspection

### Instance Security

- ✅ Encrypted EBS volumes
- ✅ IMDSv2 enforced (protection against SSRF attacks)
- ✅ SSH access only via jumphost VPC peering
- ✅ Security group rules following least privilege
- ✅ No public IP addresses on workload instances

### Operational Security

- ✅ Terraform state management (configure S3 backend)
- ✅ Resource tagging for governance
- ✅ CloudWatch logs for auditing
- ✅ Deletion protection available for ALB
- ✅ Proper dependency management for clean teardown

## 💰 Cost Estimation

### Monthly Costs (us-east-1, 2 AZs)

| Resource | Cost | Notes |
|----------|------|-------|
| GWLB Endpoints (2) | ~$18 | $0.0125/hour per endpoint |
| Application Load Balancer | ~$16-25 | Base + LCU charges |
| EC2 Instances (2x t3.micro) | ~$15 | On-demand pricing |
| VPC Flow Logs | ~$5 | Depends on traffic volume |
| NAT Gateway (optional) | ~$32 | If enabled |
| Data Transfer | Variable | Depends on traffic |
| **Total (without NAT)** | **~$54-63/month** | |

### Cost Optimization Tips

1. Use Reserved Instances for predictable workloads
2. Enable only necessary features (NAT Gateway, Flow Logs)
3. Use appropriate instance types
4. Configure Flow Logs retention appropriately
5. Consider Savings Plans for long-term deployments

## 🔧 Maintenance and Operations

### Scaling Workloads

```bash
# Edit config.yaml
# WORKLOAD_COUNT: 4

# Apply changes
./ztgw_infra create

# Instances automatically registered with ALB
```

### Adding New Subnets

```bash
# Edit config.yaml
# AVAILABILITY_ZONES:
#   - "us-east-1a"
#   - "us-east-1b"
#   - "us-east-1c"
# ALB_SUBNET_CIDRS:
#   - "10.0.1.0/24"
#   - "10.0.2.0/24"
#   - "10.0.3.0/24"

# Apply changes
./ztgw_infra create
```

### Updating Security Groups

Security groups are managed in `main.tf`:
- Modify `aws_security_group` resources
- Run `terraform apply` to update

### Disaster Recovery

```bash
# Backup Terraform state
terraform state pull > backup-$(date +%Y%m%d).tfstate

# Export configuration
terraform show -json > infrastructure-$(date +%Y%m%d).json
```

## 📖 Additional Documentation

- [`DEPLOYMENT.md`](DEPLOYMENT.md) - Detailed deployment guide
- [`TESTING.md`](TESTING.md) - Comprehensive testing procedures
- [`ARCHITECTURE-DIAGRAM.txt`](ARCHITECTURE-DIAGRAM.txt) - Visual architecture diagrams
- [`config.yaml.example`](config.yaml.example) - All configuration options

## 🐛 Troubleshooting

### ALB Shows Unhealthy Targets

```bash
# Check security group rules
aws ec2 describe-security-groups --group-ids <workload-sg-id>

# Verify instances are running
aws ec2 describe-instances --instance-ids <instance-id>

# Check ALB target health
aws elbv2 describe-target-health --target-group-arn <tg-arn>
```

### Cannot SSH to Workload Instances

```bash
# Verify VPC peering is active
aws ec2 describe-vpc-peering-connections --vpc-peering-connection-ids <pcx-id>

# Check route tables
aws ec2 describe-route-tables --route-table-ids <rtb-id>

# Verify security group allows SSH
aws ec2 describe-security-group-rules --filters "Name=group-id,Values=<sg-id>"
```

### GWLB Endpoint Issues

```bash
# Check endpoint status
aws ec2 describe-vpc-endpoints --vpc-endpoint-ids <vpce-id>

# Verify service name
aws ec2 describe-vpc-endpoint-services --service-names <service-name>

# Check cross-account permissions
```

## 🗑️ Cleanup

To destroy all resources:

```bash
# Review resources to be destroyed
terraform plan -destroy

# Destroy infrastructure
terraform destroy

# Confirm by typing: yes
```

**Note**: Terraform handles dependency order automatically, ensuring:
1. EC2 instances deregistered from target groups
2. VPC peering connections deleted
3. GWLB endpoints removed
4. Subnets and VPC deleted last

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙋 Support

For issues, questions, or contributions:

- Open an issue on GitHub
- Review existing documentation
- Contact the platform team

## 📚 References

- [AWS Gateway Load Balancer](https://aws.amazon.com/elasticloadbalancing/gateway-load-balancer/)
- [VPC Endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints.html)
- [Application Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/)
- [VPC Peering](https://docs.aws.amazon.com/vpc/latest/peering/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

---

**Built with ❤️ using Terraform and AWS**

