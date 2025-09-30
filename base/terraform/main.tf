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

# Load config.yml from base folder (same directory as terraform folder)
locals {
  config = yamldecode(file("${path.module}/../config.yml"))
}

# Create Auth0 Client from config.yml
resource "auth0_client" "sample_app" {
  name        = local.config.client.name
  description = local.config.client.description
  app_type    = local.config.client.app_type
  
  callbacks           = local.config.client.callbacks
  allowed_logout_urls = local.config.client.allowed_logout_urls
  # Remove 'allowed_origins' - not supported
  # Remove 'allowed_web_origins' - not supported
  web_origins         = local.config.client.allowed_web_origins
  
  grant_types                = local.config.client.grant_types
  token_endpoint_auth_method = local.config.client.token_endpoint_auth_method
  
  cross_origin_auth = local.config.client.cross_origin_auth
  oidc_conformant   = local.config.client.oidc_conformant
  sso_disabled      = local.config.client.sso_disabled
  
  jwt_configuration {
    lifetime_in_seconds = local.config.client.jwt_configuration.lifetime_in_seconds
    alg                 = local.config.client.jwt_configuration.alg
  }
  
  refresh_token {
    rotation_type   = local.config.client.refresh_token.rotation_type
    expiration_type = local.config.client.refresh_token.expiration_type
    token_lifetime  = local.config.client.refresh_token.token_lifetime
  }
}

# Output the created client details
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