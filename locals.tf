# ============================================================================
# Local Values - Configuration Loading from config.yaml
# ============================================================================

locals {
  # Load configuration from YAML file
  config_file = fileexists("${path.module}/config.yaml") ? "${path.module}/config.yaml" : "${path.module}/config.yaml.example"
  config_raw  = yamldecode(file(local.config_file))

  # Configuration with defaults for optional values
  config = merge(
    {
      # Required parameters (must be in config.yaml)
      # Listed here for documentation purposes only
      # AWS_REGION - REQUIRED
      # AWS_ACCESS_KEY_ID - REQUIRED
      # AWS_SECRET_ACCESS_KEY - REQUIRED
      # NAME_PREFIX - REQUIRED
      # ENVIRONMENT - REQUIRED
      # AVAILABILITY_ZONES - REQUIRED
      # VPC_CIDR - REQUIRED
      # ALB_SUBNET_CIDRS - REQUIRED
      # GWLBE_SUBNET_CIDRS - REQUIRED
      # WORKLOAD_SUBNET_CIDRS - REQUIRED
      # GWLB_ENDPOINT_SERVICE_NAME - REQUIRED (but can be empty for testing)
      
      # Defaults for GWLB (can be empty for testing without inspection)
      GWLB_ENDPOINT_SERVICE_NAME  = ""
      ENABLE_GWLB_INSPECTION      = true
      
      # Defaults for ALB configurations
      ALB_INTERNAL                = false
      ALB_LISTENER_PORT           = 80
      ALB_LISTENER_PROTOCOL       = "HTTP"
      ALB_TARGET_PORT             = 80
      ALB_CERTIFICATE_ARN         = ""
      ALB_TARGET_PROTOCOL         = "HTTP"
      ALB_HEALTH_CHECK_PATH       = "/"
      ALB_HEALTH_CHECK_INTERVAL   = 30
      ALB_HEALTH_CHECK_TIMEOUT    = 5
      ALB_HEALTHY_THRESHOLD       = 2
      ALB_UNHEALTHY_THRESHOLD     = 2
      
      # Defaults for workload configurations
      WORKLOAD_COUNT              = 2
      WORKLOAD_INSTANCE_TYPE      = "t3.micro"
      WORKLOAD_KEY_NAME           = ""
      WORKLOAD_AMI_ID             = ""
      WORKLOAD_USER_DATA          = ""
      WORKLOAD_ROOT_VOLUME_SIZE   = 8
      
      # Defaults for VPC peering
      ENABLE_VPC_PEERING          = false
      JUMPHOST_VPC_ID             = ""
      JUMPHOST_VPC_CIDR           = ""
      JUMPHOST_ROUTE_TABLE_IDS    = []
      
      # Defaults for security configurations
      ALLOWED_INGRESS_CIDRS       = ["0.0.0.0/0"]
      SSH_ALLOWED_CIDRS           = []
      
      # Defaults for optional features
      ENABLE_FLOW_LOGS            = true
      FLOW_LOGS_RETENTION_DAYS    = 7
      ENABLE_NAT_GATEWAY          = false
      ENABLE_DETAILED_MONITORING  = false
      ENABLE_DELETION_PROTECTION  = false
      
      # Defaults for brownfield
      CREATE_VPC                  = true
      CREATE_IGW                  = true
      EXISTING_VPC_ID             = ""
      EXISTING_IGW_ID             = ""
    },
    local.config_raw
  )

  # Extract key configuration values
  name_prefix    = local.config.NAME_PREFIX
  environment    = local.config.ENVIRONMENT
  aws_region     = local.config.AWS_REGION
  aws_account_id = try(local.config.AWS_ACCOUNT_ID, "")

  # Common tags
  tags = merge(
    {
      NamePrefix   = local.name_prefix
      Environment  = local.environment
      ManagedBy    = "Terraform"
      Architecture = "Ingress-Inspection"
    },
    {}
  )
}

