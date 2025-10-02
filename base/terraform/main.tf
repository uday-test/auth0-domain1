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

locals {
  baseline_security = yamldecode(file("${path.module}/../baseline-security.yml"))
  config            = yamldecode(file("${path.module}/../config.yml"))
}

# ===========================================
# TENANT-LEVEL RESOURCES
# ===========================================

resource "auth0_branding" "tenant" {
  logo_url = local.baseline_security.branding.logo_url
  
  colors {
    primary         = local.baseline_security.branding.primary_color
    page_background = local.baseline_security.branding.page_background
  }
  
  font {
    url = local.baseline_security.branding.font_url
  }
}

resource "auth0_prompt" "login" {
  universal_login_experience = local.baseline_security.universal_login.experience
  identifier_first           = local.baseline_security.universal_login.identifier_first
}

resource "auth0_connection" "database" {
  name     = local.baseline_security.connections.database.name
  strategy = "auth0"
  
  options {
    password_policy = local.baseline_security.identity_access.password_policy.strength
    
    password_complexity_options {
      min_length = local.baseline_security.identity_access.password_policy.min_length
    }
    
    password_history {
      enable = local.baseline_security.identity_access.password_policy.history.enabled
      size   = local.baseline_security.identity_access.password_policy.history.size
    }
    
    password_no_personal_info {
      enable = true
    }
    
    brute_force_protection = true
  }
}

resource "auth0_connection_clients" "database_clients" {
  connection_id   = auth0_connection.database.id
  enabled_clients = [auth0_client.sample_app.id]
}

resource "auth0_guardian" "mfa" {
  policy = local.baseline_security.mfa.policy
  
  otp = local.baseline_security.mfa.factors.otp
  
  phone {
    enabled       = local.baseline_security.mfa.factors.sms
    provider      = "auth0"
    message_types = ["sms"]
  }
  
  webauthn_roaming {
    enabled = local.baseline_security.mfa.factors.webauthn
  }
  
  webauthn_platform {
    enabled = local.baseline_security.mfa.factors.webauthn
  }
}

# ===========================================
# APPLICATION-LEVEL RESOURCES
# ===========================================

resource "auth0_client" "sample_app" {
  name        = local.config.client.name
  description = local.config.client.description
  app_type    = local.config.client.app_type
  
  callbacks           = local.config.client.callbacks
  allowed_logout_urls = local.config.client.allowed_logout_urls
  web_origins         = local.config.client.allowed_web_origins
  
  grant_types = local.config.client.grant_types
  
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

# ===========================================
# OUTPUTS
# ===========================================

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

output "tenant_branding" {
  value = {
    logo_url = auth0_branding.tenant.logo_url
    colors   = auth0_branding.tenant.colors
  }
  description = "Tenant branding configuration"
}

output "database_connection" {
  value = {
    name = auth0_connection.database.name
    id   = auth0_connection.database.id
  }
  description = "Database connection details"
}

output "mfa_enabled" {
  value = {
    policy = auth0_guardian.mfa.policy
    otp    = auth0_guardian.mfa.otp
  }
  description = "MFA configuration status"
}