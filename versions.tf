# ============================================================================
# Terraform and Provider Version Constraints
# ============================================================================

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Optional: Configure backend for state storage
  # Uncomment and configure based on your requirements
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "ingress-inspection/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-state-lock"
  # }
}

provider "aws" {
  region     = local.config.AWS_REGION
  access_key = local.config.AWS_ACCESS_KEY_ID
  secret_key = local.config.AWS_SECRET_ACCESS_KEY

  default_tags {
    tags = local.tags
  }
}

