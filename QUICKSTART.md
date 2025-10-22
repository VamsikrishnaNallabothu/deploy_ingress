# Quick Start Guide - AWS Ingress Inspection Architecture

Get up and running in **10 minutes** with this streamlined deployment guide.

## 🚀 Fast Track Deployment

### Step 1: Prerequisites (2 min)

```bash
# Verify Terraform is installed
terraform version  # Should be >= 1.0

# Verify AWS CLI is configured
aws sts get-caller-identity

# Gather required information
# ✓ GWLB Endpoint Service Name from security team
# ✓ EC2 Key Pair name
# ✓ Jumphost VPC ID (if using VPC peering)
```

### Step 2: Configure (3 min)

```bash
# Navigate to project directory
cd aws-inspection-architecture

# Create configuration file
cp config.yaml.example config.yaml

# Edit with your values (use vim, nano, or your preferred editor)
vim config.yaml
```

**Minimal Required Configuration:**

```yaml
# Required
GWLB_ENDPOINT_SERVICE_NAME: "com.amazonaws.vpce.us-east-1.vpce-svc-XXXXX"
WORKLOAD_KEY_NAME: "my-keypair"
WORKLOAD_COUNT: 2

# Optional but Recommended (VPC Peering for Management)
ENABLE_VPC_PEERING: true
JUMPHOST_VPC_ID: "vpc-XXXXX"
JUMPHOST_VPC_CIDR: "10.100.0.0/16"
JUMPHOST_ROUTE_TABLE_IDS:
  - "rtb-XXXXX"
SSH_ALLOWED_CIDRS:
  - "10.100.0.0/16"
```

### Step 3: Deploy (5 min)

```bash
# Use the deployment script
./ztgw_infra init     # Initialize Terraform
./ztgw_infra plan     # Preview changes
./ztgw_infra create   # Create infrastructure (will take ~5 minutes)

# Or use Terraform directly
terraform init
terraform plan
terraform apply
```

### Step 4: Test (2 min)

```bash
# Get ALB DNS name
ALB_DNS=$(terraform output -raw alb_dns_name)

# Test connectivity
curl http://$ALB_DNS

# Expected: HTML page with instance information

# Check workload IPs
terraform output workload_private_ips

# Test SSH from jumphost (if peering enabled)
ssh -i ~/.ssh/my-keypair.pem ec2-user@<workload-ip>
```

## ✅ Success Indicators

You know it's working when:

1. **`terraform apply` completes successfully**
   ```
   Apply complete! Resources: 45 added, 0 changed, 0 destroyed.
   ```

2. **ALB returns HTTP 200**
   ```bash
   $ curl -I http://$ALB_DNS
   HTTP/1.1 200 OK
   ```

3. **All targets are healthy**
   ```bash
   $ aws elbv2 describe-target-health --target-group-arn $(terraform output -raw alb_target_group_arn)
   # All targets show: "State": "healthy"
   ```

4. **GWLB endpoints are available**
   ```bash
   $ terraform output gwlb_endpoint_ids
   # Shows endpoint IDs, all in "available" state
   ```

## 📋 Common Configurations

### Configuration 1: Development/Testing

**Use Case:** Testing without GWLB inspection, minimal resources

```yaml
PROJECT_NAME: "dev-test"
ENVIRONMENT: "dev"
WORKLOAD_COUNT: 1
WORKLOAD_INSTANCE_TYPE: "t3.micro"
ENABLE_GWLB_INSPECTION: false  # Test without GWLB first
ENABLE_VPC_PEERING: false
ENABLE_NAT_GATEWAY: false
ENABLE_FLOW_LOGS: false
```

**Cost:** ~$15/month  
**Deploy Time:** 3-4 minutes

---

### Configuration 2: Production with Jumphost Access

**Use Case:** Full production deployment with management access

```yaml
PROJECT_NAME: "prod-ingress"
ENVIRONMENT: "prod"
WORKLOAD_COUNT: 4
WORKLOAD_INSTANCE_TYPE: "t3.small"
ENABLE_GWLB_INSPECTION: true
ENABLE_VPC_PEERING: true
ENABLE_NAT_GATEWAY: true
ENABLE_FLOW_LOGS: true
ENABLE_DELETION_PROTECTION: true

GWLB_ENDPOINT_SERVICE_NAME: "com.amazonaws.vpce.us-east-1.vpce-svc-XXXXX"
JUMPHOST_VPC_ID: "vpc-XXXXX"
JUMPHOST_VPC_CIDR: "10.100.0.0/16"
JUMPHOST_ROUTE_TABLE_IDS:
  - "rtb-XXXXX"
  - "rtb-YYYYY"
```

**Cost:** ~$120/month  
**Deploy Time:** 6-8 minutes

---

### Configuration 3: Brownfield (Existing VPC)

**Use Case:** Deploy into existing VPC infrastructure

```yaml
# Use existing VPC
CREATE_VPC: false
EXISTING_VPC_ID: "vpc-existing123"
CREATE_IGW: false
EXISTING_IGW_ID: "igw-existing456"

# Define subnets in existing VPC CIDR
VPC_CIDR: "10.50.0.0/16"  # Must match existing VPC
ALB_SUBNET_CIDRS:
  - "10.50.1.0/24"
  - "10.50.2.0/24"
GWLBE_SUBNET_CIDRS:
  - "10.50.11.0/24"
  - "10.50.12.0/24"
WORKLOAD_SUBNET_CIDRS:
  - "10.50.21.0/24"
  - "10.50.22.0/24"

# Rest of configuration
GWLB_ENDPOINT_SERVICE_NAME: "com.amazonaws.vpce.us-east-1.vpce-svc-XXXXX"
WORKLOAD_COUNT: 2
WORKLOAD_KEY_NAME: "my-keypair"
```

**Benefit:** Integrates with existing infrastructure  
**Deploy Time:** 5-7 minutes

---

### Configuration 4: HTTPS with ACM Certificate

**Use Case:** Production with SSL/TLS termination at ALB

```yaml
# ALB Configuration for HTTPS
ALB_LISTENER_PROTOCOL: "HTTPS"
ALB_LISTENER_PORT: 443
ALB_CERTIFICATE_ARN: "arn:aws:acm:us-east-1:123456789012:certificate/xxxxx"

# Optionally redirect HTTP to HTTPS (configure after initial deployment)
```

**Note:** Certificate must be requested/imported in ACM before deployment

---

## 🔍 Verification Commands

### Check All Resources

```bash
# Count deployed resources
terraform state list | wc -l

# View all outputs
terraform output

# Generate JSON output for automation
terraform output -json > outputs.json
```

### Verify Networking

```bash
# Check VPC
aws ec2 describe-vpcs --vpc-ids $(terraform output -raw vpc_id)

# Check subnets
aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$(terraform output -raw vpc_id)" \
  --query 'Subnets[*].{CIDR:CidrBlock,AZ:AvailabilityZone,Type:Tags[?Key==`Tier`].Value|[0]}'

# Check GWLB endpoints
aws ec2 describe-vpc-endpoints \
  --vpc-endpoint-ids $(terraform output -json gwlb_endpoint_ids | jq -r '.[]')
```

### Verify Application

```bash
# Test ALB
curl -v http://$(terraform output -raw alb_dns_name)

# Check target health
aws elbv2 describe-target-health \
  --target-group-arn $(terraform output -raw alb_target_group_arn)

# Test load balancing (should see different IPs)
for i in {1..5}; do
  curl -s http://$(terraform output -raw alb_dns_name) | grep "Private IP"
done
```

### Monitor Logs

```bash
# Tail VPC Flow Logs
aws logs tail $(terraform output -raw flow_logs_log_group_name) --follow

# Check ALB access logs (if enabled)
aws s3 ls s3://your-alb-logs-bucket/
```

## 🐛 Quick Troubleshooting

### Issue: `terraform apply` fails with "InvalidServiceName"

**Solution:**
```bash
# Verify GWLB service name format
# Should be: com.amazonaws.vpce.<region>.vpce-svc-<service-id>

# Test service exists
aws ec2 describe-vpc-endpoint-services \
  --service-names com.amazonaws.vpce.us-east-1.vpce-svc-XXXXX
```

### Issue: ALB shows unhealthy targets

**Solution:**
```bash
# Check instance status
terraform output workload_instance_ids | jq -r '.[]' | xargs -I {} \
  aws ec2 describe-instances --instance-ids {}

# Check security groups
terraform output workload_security_group_id | xargs -I {} \
  aws ec2 describe-security-group-rules --filters "Name=group-id,Values={}"

# SSH to instance and check web server
ssh -i key.pem ec2-user@<ip>
sudo systemctl status httpd
curl localhost
```

### Issue: Cannot SSH from jumphost

**Solution:**
```bash
# Verify VPC peering
aws ec2 describe-vpc-peering-connections \
  --vpc-peering-connection-ids $(terraform output -raw vpc_peering_connection_id)

# Check routes
aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=$(terraform output -raw vpc_id)" \
  --query 'RouteTables[*].Routes[?VpcPeeringConnectionId]'
```

### Issue: `terraform destroy` hangs

**Solution:**
```bash
# Check for resource dependencies
terraform state list

# Force unlock if needed (use carefully)
terraform force-unlock <lock-id>

# Manually delete problematic resources, then retry
aws ec2 delete-vpc-endpoints --vpc-endpoint-ids vpce-xxxxx
terraform destroy
```

## 📖 Next Steps

After successful deployment:

1. **Configure DNS**
   - Point your domain to ALB DNS name
   - Use Route53 alias record for better performance

2. **Enable HTTPS**
   - Request ACM certificate
   - Update configuration with certificate ARN
   - Redeploy with `terraform apply`

3. **Set Up Monitoring**
   - CloudWatch dashboards for ALB metrics
   - VPC Flow Logs analysis
   - Set up alarms for unhealthy targets

4. **Security Hardening**
   - Review security group rules
   - Enable AWS Config rules
   - Set up AWS Security Hub

5. **Backup Strategy**
   - AWS Backup for EC2 instances
   - Terraform state in S3 with versioning
   - Document recovery procedures

## 📚 Additional Resources

- **[README.md](README.md)** - Complete architecture overview
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Detailed deployment guide
- **[TESTING.md](TESTING.md)** - Comprehensive testing procedures
- **[terraform.tfvars.example](terraform.tfvars.example)** - All configuration options

## 💡 Pro Tips

1. **Start Simple:** Deploy without GWLB inspection first, then enable it
2. **Test VPC Peering:** Verify jumphost access before production
3. **Use Workspaces:** Separate dev/staging/prod with Terraform workspaces
4. **Tag Everything:** Use consistent tagging for cost allocation
5. **Backup State:** Configure S3 backend before production use

## 🎯 Success Checklist

- [ ] Terraform installed and configured
- [ ] AWS credentials set up
- [ ] GWLB endpoint service name obtained
- [ ] EC2 key pair created
- [ ] Configuration file created and validated
- [ ] `terraform init` successful
- [ ] `terraform plan` reviewed
- [ ] `terraform apply` completed
- [ ] ALB returns HTTP 200
- [ ] All targets healthy
- [ ] VPC peering active (if enabled)
- [ ] SSH access working (if enabled)
- [ ] Outputs captured and documented

**Ready to deploy?** Run `terraform apply` and you're live in minutes!

---

**Quick Start Guide Version 1.0**  
**Last Updated: 2025-10-22**

