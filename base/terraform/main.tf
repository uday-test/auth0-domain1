terraform {
  required_providers {
    auth0 = {
      source  = "auth0/auth0"
      version = "~> 1.0"
    }
  }
}

provider "auth0" {
  # Reads from AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET env vars
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

output "app_type" {
  value       = auth0_client.sample_app.app_type
  description = "Auth0 Application Type"
}

# SPAs don't have client_secret attribute at all - just don't output it