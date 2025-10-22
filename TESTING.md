# Testing Guide - AWS Ingress Inspection Architecture

Comprehensive testing procedures to validate your ingress inspection architecture deployment.

## Table of Contents

1. [Testing Overview](#testing-overview)
2. [Pre-Test Setup](#pre-test-setup)
3. [Infrastructure Tests](#infrastructure-tests)
4. [Connectivity Tests](#connectivity-tests)
5. [Security Tests](#security-tests)
6. [Performance Tests](#performance-tests)
7. [Failure Scenario Tests](#failure-scenario-tests)
8. [Automated Testing](#automated-testing)

---

## Testing Overview

### Testing Objectives

- ✅ Verify all infrastructure components are deployed correctly
- ✅ Confirm traffic flows through GWLB endpoints for inspection
- ✅ Validate ALB distributes traffic to healthy targets
- ✅ Ensure security groups properly restrict access
- ✅ Test VPC peering for jumphost access
- ✅ Verify symmetric routing through firewalls
- ✅ Validate high availability across AZs

### Testing Levels

1. **Unit Tests**: Individual component validation
2. **Integration Tests**: End-to-end traffic flow
3. **Security Tests**: Security posture validation
4. **Performance Tests**: Load and latency testing
5. **Resilience Tests**: Failure scenario testing

---

## Pre-Test Setup

### 1. Export Terraform Outputs

```bash
# Export commonly used outputs as environment variables
export VPC_ID=$(terraform output -raw vpc_id)
export ALB_DNS=$(terraform output -raw alb_dns_name)
export ALB_ARN=$(terraform output -raw alb_arn)
export TG_ARN=$(terraform output -raw alb_target_group_arn)
export WORKLOAD_IPS=$(terraform output -json workload_private_ips | jq -r '.[]' | tr '\n' ' ')
export JUMPHOST_VPC_ID=$(terraform output -raw jumphost_vpc_id)
export PEERING_ID=$(terraform output -raw vpc_peering_connection_id)

# Display for verification
echo "VPC ID: $VPC_ID"
echo "ALB DNS: $ALB_DNS"
echo "Workload IPs: $WORKLOAD_IPS"
```

### 2. Install Testing Tools

```bash
# Install required tools
# On macOS
brew install curl jq watch wrk

# On Amazon Linux/RHEL
sudo yum install -y curl jq

# Install wrk for load testing
git clone https://github.com/wg/wrk.git
cd wrk && make && sudo cp wrk /usr/local/bin/
```

### 3. Create Test Scripts Directory

```bash
mkdir -p test-scripts
cd test-scripts
```

---

## Infrastructure Tests

### Test 1: Verify VPC and Subnets

```bash
#!/bin/bash
# test-vpc.sh

echo "=== VPC Validation ==="

# Check VPC exists and is available
echo "Checking VPC..."
aws ec2 describe-vpcs \
  --vpc-ids $VPC_ID \
  --query 'Vpcs[0].{ID:VpcId,CIDR:CidrBlock,State:State}' \
  --output table

# Count subnets
SUBNET_COUNT=$(aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'length(Subnets)')

echo "\nTotal Subnets: $SUBNET_COUNT"
echo "Expected: 6 (2 ALB + 2 GWLBE + 2 Workload)"

if [ $SUBNET_COUNT -eq 6 ]; then
  echo "✅ PASS: Correct number of subnets"
else
  echo "❌ FAIL: Expected 6 subnets, found $SUBNET_COUNT"
fi

# Verify subnet distribution across AZs
echo "\n=== Subnet Distribution ==="
aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'Subnets[*].{AZ:AvailabilityZone,CIDR:CidrBlock,Type:Tags[?Key==`Tier`].Value|[0]}' \
  --output table
```

### Test 2: Verify GWLB Endpoints

```bash
#!/bin/bash
# test-gwlb-endpoints.sh

echo "=== GWLB Endpoint Validation ==="

GWLB_ENDPOINTS=$(terraform output -json gwlb_endpoint_ids | jq -r '.[]')

for ENDPOINT in $GWLB_ENDPOINTS; do
  echo "\nChecking endpoint: $ENDPOINT"
  
  STATE=$(aws ec2 describe-vpc-endpoints \
    --vpc-endpoint-ids $ENDPOINT \
    --query 'VpcEndpoints[0].State' \
    --output text)
  
  SERVICE=$(aws ec2 describe-vpc-endpoints \
    --vpc-endpoint-ids $ENDPOINT \
    --query 'VpcEndpoints[0].ServiceName' \
    --output text)
  
  echo "  State: $STATE"
  echo "  Service: $SERVICE"
  
  if [ "$STATE" == "available" ]; then
    echo "  ✅ PASS: Endpoint is available"
  else
    echo "  ❌ FAIL: Endpoint state is $STATE (expected: available)"
  fi
done
```

### Test 3: Verify Application Load Balancer

```bash
#!/bin/bash
# test-alb.sh

echo "=== ALB Validation ==="

# Check ALB state
ALB_STATE=$(aws elbv2 describe-load-balancers \
  --load-balancer-arns $ALB_ARN \
  --query 'LoadBalancers[0].State.Code' \
  --output text)

echo "ALB State: $ALB_STATE"

if [ "$ALB_STATE" == "active" ]; then
  echo "✅ PASS: ALB is active"
else
  echo "❌ FAIL: ALB state is $ALB_STATE (expected: active)"
fi

# Check ALB scheme
SCHEME=$(aws elbv2 describe-load-balancers \
  --load-balancer-arns $ALB_ARN \
  --query 'LoadBalancers[0].Scheme' \
  --output text)

echo "ALB Scheme: $SCHEME"

# Check listener configuration
echo "\n=== Listener Configuration ==="
aws elbv2 describe-listeners \
  --load-balancer-arn $ALB_ARN \
  --query 'Listeners[*].{Port:Port,Protocol:Protocol}' \
  --output table

# Check target group health
echo "\n=== Target Health ==="
aws elbv2 describe-target-health \
  --target-group-arn $TG_ARN \
  --query 'TargetHealthDescriptions[*].{Instance:Target.Id,Port:Target.Port,Health:TargetHealth.State,Reason:TargetHealth.Reason}' \
  --output table

HEALTHY_COUNT=$(aws elbv2 describe-target-health \
  --target-group-arn $TG_ARN \
  --query 'length(TargetHealthDescriptions[?TargetHealth.State==`healthy`])')

TOTAL_COUNT=$(aws elbv2 describe-target-health \
  --target-group-arn $TG_ARN \
  --query 'length(TargetHealthDescriptions)')

echo "\nHealthy Targets: $HEALTHY_COUNT / $TOTAL_COUNT"

if [ $HEALTHY_COUNT -eq $TOTAL_COUNT ]; then
  echo "✅ PASS: All targets are healthy"
else
  echo "❌ FAIL: Only $HEALTHY_COUNT out of $TOTAL_COUNT targets are healthy"
fi
```

### Test 4: Verify VPC Peering

```bash
#!/bin/bash
# test-vpc-peering.sh

echo "=== VPC Peering Validation ==="

if [ -z "$PEERING_ID" ] || [ "$PEERING_ID" == "null" ]; then
  echo "ℹ️  VPC Peering not enabled, skipping tests"
  exit 0
fi

# Check peering connection status
PEERING_STATUS=$(aws ec2 describe-vpc-peering-connections \
  --vpc-peering-connection-ids $PEERING_ID \
  --query 'VpcPeeringConnections[0].Status.Code' \
  --output text)

echo "Peering Status: $PEERING_STATUS"

if [ "$PEERING_STATUS" == "active" ]; then
  echo "✅ PASS: VPC peering is active"
else
  echo "❌ FAIL: VPC peering status is $PEERING_STATUS (expected: active)"
fi

# Verify routes in workload VPC
echo "\n=== Workload VPC Routes to Jumphost ==="
aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'RouteTables[*].Routes[?VpcPeeringConnectionId]' \
  --output table

# Verify routes in jumphost VPC
echo "\n=== Jumphost VPC Routes to Workload ==="
aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=$JUMPHOST_VPC_ID" \
  --query 'RouteTables[*].Routes[?VpcPeeringConnectionId]' \
  --output table
```

---

## Connectivity Tests

### Test 5: HTTP Connectivity Test

```bash
#!/bin/bash
# test-http-connectivity.sh

echo "=== HTTP Connectivity Test ==="

# Single request
echo "Testing single HTTP request..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://$ALB_DNS)

echo "HTTP Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" == "200" ]; then
  echo "✅ PASS: HTTP connectivity successful"
else
  echo "❌ FAIL: Expected HTTP 200, got $HTTP_CODE"
fi

# Full response
echo "\n=== Full HTTP Response ==="
curl -v http://$ALB_DNS 2>&1 | head -20

# Test response time
echo "\n=== Response Time Test ==="
for i in {1..10}; do
  TIME=$(curl -s -o /dev/null -w "%{time_total}" http://$ALB_DNS)
  echo "Request $i: ${TIME}s"
done
```

### Test 6: Load Balancing Test

```bash
#!/bin/bash
# test-load-balancing.sh

echo "=== Load Balancing Test ==="
echo "Testing distribution across workload instances..."

# Make 100 requests and count responses from each instance
declare -A INSTANCE_COUNT

for i in {1..100}; do
  RESPONSE=$(curl -s http://$ALB_DNS | grep -oP 'Private IP:</span> \K[0-9.]+')
  ((INSTANCE_COUNT[$RESPONSE]++))
  echo -ne "Progress: $i/100\r"
done

echo -e "\n\n=== Distribution Results ==="
for IP in "${!INSTANCE_COUNT[@]}"; do
  COUNT=${INSTANCE_COUNT[$IP]}
  echo "Instance $IP: $COUNT requests (${COUNT}%)"
done

# Check if distribution is reasonable (within 20% of expected)
EXPECTED=50
VARIANCE=10

ALL_BALANCED=true
for COUNT in "${INSTANCE_COUNT[@]}"; do
  if [ $COUNT -lt $((EXPECTED - VARIANCE)) ] || [ $COUNT -gt $((EXPECTED + VARIANCE)) ]; then
    ALL_BALANCED=false
  fi
done

if $ALL_BALANCED; then
  echo "\n✅ PASS: Load is reasonably balanced"
else
  echo "\n⚠️  WARN: Load distribution may be unbalanced"
fi
```

### Test 7: SSH Connectivity Test (via Jumphost)

```bash
#!/bin/bash
# test-ssh-connectivity.sh

echo "=== SSH Connectivity Test (from Jumphost) ==="

if [ -z "$PEERING_ID" ] || [ "$PEERING_ID" == "null" ]; then
  echo "ℹ️  VPC Peering not enabled, skipping SSH tests"
  exit 0
fi

echo "⚠️  Note: This test must be run from a jumphost VM in the peered VPC"
echo ""

for IP in $WORKLOAD_IPS; do
  echo "Testing SSH to $IP..."
  
  # Test with timeout
  timeout 5 ssh -o StrictHostKeyChecking=no \
                 -o ConnectTimeout=3 \
                 -i ~/.ssh/your-key.pem \
                 ec2-user@$IP \
                 "echo 'SSH connection successful to $IP'" 2>/dev/null
  
  if [ $? -eq 0 ]; then
    echo "✅ PASS: SSH connectivity to $IP successful"
  else
    echo "❌ FAIL: Cannot connect to $IP via SSH"
  fi
  echo ""
done
```

---

## Security Tests

### Test 8: Security Group Validation

```bash
#!/bin/bash
# test-security-groups.sh

echo "=== Security Group Validation ==="

ALB_SG=$(terraform output -raw alb_security_group_id)
WORKLOAD_SG=$(terraform output -raw workload_security_group_id)

echo "ALB Security Group: $ALB_SG"
echo "Workload Security Group: $WORKLOAD_SG"

# Check ALB ingress rules
echo "\n=== ALB Ingress Rules ==="
aws ec2 describe-security-group-rules \
  --filters "Name=group-id,Values=$ALB_SG" \
  --query 'SecurityGroupRules[?!IsEgress].{Protocol:IpProtocol,Port:FromPort,Source:CidrIpv4}' \
  --output table

# Check workload ingress rules
echo "\n=== Workload Ingress Rules ==="
aws ec2 describe-security-group-rules \
  --filters "Name=group-id,Values=$WORKLOAD_SG" \
  --query 'SecurityGroupRules[?!IsEgress].{Protocol:IpProtocol,Port:FromPort,Source:ReferencedGroupInfo.GroupId}' \
  --output table

# Verify workload instances only accept traffic from ALB
WORKLOAD_ACCEPTS_FROM_ALB=$(aws ec2 describe-security-group-rules \
  --filters "Name=group-id,Values=$WORKLOAD_SG" \
  --query "SecurityGroupRules[?!IsEgress && ReferencedGroupInfo.GroupId=='$ALB_SG'] | length(@)")

if [ "$WORKLOAD_ACCEPTS_FROM_ALB" -gt 0 ]; then
  echo "\n✅ PASS: Workload security group accepts traffic from ALB"
else
  echo "\n❌ FAIL: Workload security group does not have rule for ALB"
fi
```

### Test 9: Network ACL Validation

```bash
#!/bin/bash
# test-network-acls.sh

echo "=== Network ACL Validation ==="

# Get subnet IDs
ALB_SUBNETS=$(terraform output -json alb_subnet_ids | jq -r '.[]')
WORKLOAD_SUBNETS=$(terraform output -json workload_subnet_ids | jq -r '.[]')

echo "=== ALB Subnet NACLs ==="
for SUBNET in $ALB_SUBNETS; do
  NACL=$(aws ec2 describe-network-acls \
    --filters "Name=association.subnet-id,Values=$SUBNET" \
    --query 'NetworkAcls[0].NetworkAclId' \
    --output text)
  
  echo "\nSubnet: $SUBNET, NACL: $NACL"
  
  aws ec2 describe-network-acls \
    --network-acl-ids $NACL \
    --query 'NetworkAcls[0].Entries[*].{Rule:RuleNumber,Protocol:Protocol,Port:PortRange.From,CIDR:CidrBlock,Action:RuleAction,Egress:Egress}' \
    --output table
done
```

### Test 10: Verify Traffic Inspection Path

```bash
#!/bin/bash
# test-inspection-path.sh

echo "=== Traffic Inspection Path Validation ==="

# Check IGW edge route table
IGW_RT=$(terraform output -raw igw_edge_route_table_id 2>/dev/null)

if [ ! -z "$IGW_RT" ] && [ "$IGW_RT" != "null" ]; then
  echo "=== IGW Edge Route Table ==="
  aws ec2 describe-route-tables \
    --route-table-ids $IGW_RT \
    --query 'RouteTables[0].Routes[*].{Destination:DestinationCidrBlock,Target:VpcEndpointId,Gateway:GatewayId}' \
    --output table
  
  # Verify routes point to GWLB endpoints
  GWLB_ROUTES=$(aws ec2 describe-route-tables \
    --route-table-ids $IGW_RT \
    --query 'RouteTables[0].Routes[?VpcEndpointId] | length(@)')
  
  if [ "$GWLB_ROUTES" -gt 0 ]; then
    echo "\n✅ PASS: IGW routes traffic through GWLB endpoints"
  else
    echo "\n❌ FAIL: IGW does not route through GWLB endpoints"
  fi
else
  echo "⚠️  GWLB inspection not enabled or IGW edge route table not found"
fi

# Check ALB subnet route table
ALB_RT=$(terraform output -raw alb_route_table_id)

echo "\n=== ALB Subnet Route Table ==="
aws ec2 describe-route-tables \
  --route-table-ids $ALB_RT \
  --query 'RouteTables[0].Routes[*].{Destination:DestinationCidrBlock,Target:VpcEndpointId,Gateway:GatewayId}' \
  --output table
```

---

## Performance Tests

### Test 11: Latency Test

```bash
#!/bin/bash
# test-latency.sh

echo "=== Latency Test ==="

echo "Running 100 requests to measure latency..."

TIMES=()
for i in {1..100}; do
  TIME=$(curl -s -o /dev/null -w "%{time_total}" http://$ALB_DNS)
  TIMES+=($TIME)
  echo -ne "Progress: $i/100\r"
done

echo -e "\n"

# Calculate statistics
IFS=$'\n' SORTED=($(sort -n <<<"${TIMES[*]}"))
MIN=${SORTED[0]}
MAX=${SORTED[-1]}
P50=${SORTED[49]}
P95=${SORTED[94]}
P99=${SORTED[98]}

# Calculate average
SUM=0
for TIME in "${TIMES[@]}"; do
  SUM=$(echo "$SUM + $TIME" | bc)
done
AVG=$(echo "scale=3; $SUM / ${#TIMES[@]}" | bc)

echo "=== Latency Statistics ==="
echo "Min:     ${MIN}s"
echo "Average: ${AVG}s"
echo "P50:     ${P50}s"
echo "P95:     ${P95}s"
echo "P99:     ${P99}s"
echo "Max:     ${MAX}s"

# Performance assessment
P95_THRESHOLD=1.0
if (( $(echo "$P95 < $P95_THRESHOLD" | bc -l) )); then
  echo "\n✅ PASS: P95 latency (${P95}s) is under threshold (${P95_THRESHOLD}s)"
else
  echo "\n⚠️  WARN: P95 latency (${P95}s) exceeds threshold (${P95_THRESHOLD}s)"
fi
```

### Test 12: Load Test

```bash
#!/bin/bash
# test-load.sh

echo "=== Load Test ==="

if ! command -v wrk &> /dev/null; then
  echo "❌ wrk is not installed. Install with: brew install wrk (macOS) or build from source"
  exit 1
fi

echo "Running load test: 100 connections, 10 threads, 30 seconds..."

wrk -t10 -c100 -d30s --latency http://$ALB_DNS

echo "\n=== Target Health After Load Test ==="
aws elbv2 describe-target-health \
  --target-group-arn $TG_ARN \
  --query 'TargetHealthDescriptions[*].{Instance:Target.Id,Health:TargetHealth.State}' \
  --output table
```

---

## Failure Scenario Tests

### Test 13: Single Instance Failure

```bash
#!/bin/bash
# test-instance-failure.sh

echo "=== Instance Failure Test ==="

# Get first workload instance
FIRST_INSTANCE=$(terraform output -json workload_instance_ids | jq -r '.[0]')

echo "Simulating failure by stopping instance: $FIRST_INSTANCE"

# Stop instance
aws ec2 stop-instances --instance-ids $FIRST_INSTANCE

echo "Waiting 30 seconds for health checks..."
sleep 30

# Check target health
echo "\n=== Target Health During Failure ==="
aws elbv2 describe-target-health \
  --target-group-arn $TG_ARN \
  --query 'TargetHealthDescriptions[*].{Instance:Target.Id,Health:TargetHealth.State,Reason:TargetHealth.Reason}' \
  --output table

# Test connectivity still works
echo "\n=== Testing ALB Connectivity During Failure ==="
for i in {1..10}; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://$ALB_DNS)
  echo "Request $i: HTTP $HTTP_CODE"
  
  if [ "$HTTP_CODE" != "200" ]; then
    echo "❌ FAIL: ALB returned non-200 status during failover"
    break
  fi
done

# Restart instance
echo "\nRestarting instance..."
aws ec2 start-instances --instance-ids $FIRST_INSTANCE

echo "✅ Test complete. Instance will recover automatically."
```

### Test 14: AZ Failure Simulation

```bash
#!/bin/bash
# test-az-failure.sh

echo "=== AZ Failure Simulation ==="

# Get instances in first AZ
AZ1=$(echo ${WORKLOAD_IPS} | cut -d' ' -f1)
INSTANCES_AZ1=$(terraform output -json workload_details | jq -r ".[] | select(.availability_zone | endswith(\"a\")) | .instance_id")

echo "Simulating AZ failure by stopping all instances in first AZ..."

for INSTANCE in $INSTANCES_AZ1; do
  echo "Stopping $INSTANCE"
  aws ec2 stop-instances --instance-ids $INSTANCE
done

echo "\nWaiting 45 seconds for health checks and failover..."
sleep 45

# Test connectivity
echo "\n=== Testing Service Availability During AZ Failure ==="
SUCCESS=0
FAIL=0

for i in {1..20}; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://$ALB_DNS)
  if [ "$HTTP_CODE" == "200" ]; then
    ((SUCCESS++))
  else
    ((FAIL++))
  fi
  echo -ne "Requests: $SUCCESS success, $FAIL failed\r"
  sleep 1
done

echo -e "\n"

if [ $FAIL -eq 0 ]; then
  echo "✅ PASS: Service remained available during AZ failure"
else
  echo "⚠️  WARN: $FAIL requests failed during AZ failure"
fi

# Restart instances
echo "\nRestarting instances..."
for INSTANCE in $INSTANCES_AZ1; do
  aws ec2 start-instances --instance-ids $INSTANCE
done
```

---

## Automated Testing

### Master Test Script

```bash
#!/bin/bash
# run-all-tests.sh

echo "================================"
echo "  AWS Ingress Inspection Tests  "
echo "================================"
echo ""

# Export outputs
source ./export-outputs.sh

TEST_DIR="test-scripts"
RESULTS_FILE="test-results-$(date +%Y%m%d-%H%M%S).log"

echo "Running all tests... Output: $RESULTS_FILE"
echo ""

# Run all test scripts
for TEST in $TEST_DIR/test-*.sh; do
  echo "Running: $TEST"
  bash $TEST 2>&1 | tee -a $RESULTS_FILE
  echo "---" >> $RESULTS_FILE
  echo ""
done

echo "All tests complete. Results saved to: $RESULTS_FILE"

# Generate summary
echo "=== Test Summary ===" | tee -a $RESULTS_FILE
grep -c "✅ PASS" $RESULTS_FILE | xargs echo "Passed:"
grep -c "❌ FAIL" $RESULTS_FILE | xargs echo "Failed:"
grep -c "⚠️  WARN" $RESULTS_FILE | xargs echo "Warnings:"
```

---

## Continuous Testing

### CloudWatch Synthetic Monitoring

Create a CloudWatch Synthetics canary for continuous testing:

```python
# canary-script.py
from aws_synthetics.selenium import synthetics_webdriver as webdriver
from aws_synthetics.common import synthetics_logger as logger

def main():
    url = "http://YOUR-ALB-DNS-HERE"
    
    # Create browser instance
    browser = webdriver.Chrome()
    browser.get(url)
    
    # Take screenshot
    browser.save_screenshot("loaded.png")
    
    # Verify page loaded
    assert "Ingress Inspection" in browser.page_source
    
    logger.info("✅ Canary test passed")
    
    browser.quit()

def handler(event, context):
    return main()
```

---

## Test Report Template

```markdown
# Test Execution Report

**Date:** YYYY-MM-DD
**Environment:** Production/Staging/Dev
**Tester:** Name

## Infrastructure Tests
- [ ] VPC and Subnets: PASS/FAIL
- [ ] GWLB Endpoints: PASS/FAIL
- [ ] Application Load Balancer: PASS/FAIL
- [ ] VPC Peering: PASS/FAIL

## Connectivity Tests
- [ ] HTTP Connectivity: PASS/FAIL
- [ ] Load Balancing: PASS/FAIL
- [ ] SSH Connectivity: PASS/FAIL

## Security Tests
- [ ] Security Groups: PASS/FAIL
- [ ] Traffic Inspection Path: PASS/FAIL

## Performance Tests
- [ ] Latency (P95 < 1s): PASS/FAIL
- [ ] Load Test: PASS/FAIL

## Resilience Tests
- [ ] Single Instance Failure: PASS/FAIL
- [ ] AZ Failure: PASS/FAIL

## Issues Found
1. [Description]
2. [Description]

## Recommendations
1. [Action item]
2. [Action item]
```

---

**Testing Guide Version 1.0**  
**Last Updated: 2025-10-22**

