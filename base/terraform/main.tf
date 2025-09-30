terraform {
  required_providers {
    auth0 = {
      source  = "auth0/auth0"
      version = "~> 1.0"
    }
  }
}

provider "auth0" {
  domain        = var.auth0_domain
  client_id     = var.auth0_client_id
  client_secret = var.auth0_client_secret
}

# Load config.yml from base folder
locals {
  config = yamldecode(file("${path.module}/../config.yml"))
}

# Create Auth0 Client from config.yml
resource "auth0_client" "sample_app" {
  name        = local.config.client.name
  description = local.config.client.description
  app_type    = local.config.client.app_type
  
  # URLs
  callbacks           = local.config.client.callbacks
  allowed_logout_urls = local.config.client.allowed_logout_urls
  web_origins         = local.config.client.allowed_web_origins
  
  # Grant types
  grant_types = local.config.client.grant_types
  
  # OIDC settings
  oidc_conformant = local.config.client.oidc_conformant
  
  # JWT configuration
  jwt_configuration {
    lifetime_in_seconds = local.config.client.jwt_configuration.lifetime_in_seconds
    alg                 = local.config.client.jwt_configuration.alg
  }
  
  # Refresh token configuration
  refresh_token {
    rotation_type   = local.config.client.refresh_token.rotation_type
    expiration_type = local.config.client.refresh_token.expiration_type
    token_lifetime  = local.config.client.refresh_token.token_lifetime
  }
}

# Outputs
output "client_id" {
  value       = auth0_client.sample_app.client_id
  description = "Auth0 Client ID"
}

output "client_name" {
  value       = auth0_client.sample_app.name
  description = "Auth0 Client Name"
}

output "client_secret" {
  value       = auth0_client.sample_app.client_secret
  description = "Auth0 Client Secret"
  sensitive   = true
}