# ============================================================================
# Local Values - Configuration Loading from config.yaml
# ============================================================================

locals {
  # Load configuration from YAML file
  config_file = fileexists("${path.module}/config.yaml") ? "${path.module}/config.yaml" : "${path.module}/config.yaml.example"
  config      = yamldecode(file(local.config_file))

  # Common tags
  tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Architecture = "Ingress-Inspection"
    },
    var.tags
  )
}

