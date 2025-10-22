# ============================================================================
# Local Values - Configuration Loading from config.yaml
# ============================================================================

locals {
  # Load configuration from YAML file
  config_file = fileexists("${path.module}/config.yaml") ? "${path.module}/config.yaml" : "${path.module}/config.yaml.example"
  config      = yamldecode(file(local.config_file))

  # Extract key configuration values
  name_prefix = local.config.NAME_PREFIX
  environment = local.config.ENVIRONMENT
  aws_region  = local.config.AWS_REGION

  # Common tags
  tags = merge(
    {
      NamePrefix   = local.name_prefix
      Environment  = local.environment
      ManagedBy    = "Terraform"
      Architecture = "Ingress-Inspection"
    },
    try(var.tags, {})
  )
}

