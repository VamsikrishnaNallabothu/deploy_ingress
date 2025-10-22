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

