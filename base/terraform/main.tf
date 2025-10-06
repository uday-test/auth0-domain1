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

# Load all configuration files
locals {
  app_oidc      = yamldecode(file("${path.module}/../base-line/configs/app-oidc.yml"))
  auth_settings = yamldecode(file("${path.module}/../base-line/configs/auth-settings.yml"))
  risk_settings = yamldecode(file("${path.module}/../base-line/configs/risk-settings.yml"))
  ux_settings   = yamldecode(file("${path.module}/../base-line/configs/ux-settings.yml"))
}

# ===========================================
# AUTH0 CLIENT/APPLICATION
# ===========================================

resource "auth0_client" "app" {
  name            = local.app_oidc.auth0_client.name
  app_type        = local.app_oidc.auth0_client.app_type
  is_first_party  = local.app_oidc.auth0_client.is_first_party
  oidc_conformant = local.app_oidc.auth0_client.oidc_conformant
  callbacks       = local.app_oidc.auth0_client.callbacks
  grant_types     = local.app_oidc.auth0_client.grant_types
  
  jwt_configuration {
    lifetime_in_seconds = local.app_oidc.auth0_client.jwt_configuration.lifetime_in_seconds
    secret_encoded      = local.app_oidc.auth0_client.jwt_configuration.secret_encoded
    alg                 = local.app_oidc.auth0_client.jwt_configuration.alg
  }
  
  refresh_token {
    rotation_type   = local.app_oidc.auth0_client.refresh_token.rotation_type
    expiration_type = local.app_oidc.auth0_client.refresh_token.expiration_type
  }
}

# ===========================================
# TENANT-LEVEL RESOURCES
# ===========================================

# Branding
resource "auth0_branding" "tenant" {
  logo_url = local.ux_settings.branding.logo_url
  
  colors {
    primary         = local.ux_settings.branding.primary_color
    page_background = local.ux_settings.branding.page_background
  }
  
  font {
    url = local.ux_settings.branding.font_url
  }
}

# Universal Login
resource "auth0_prompt" "login" {
  universal_login_experience = local.auth_settings.universal_login.experience
  identifier_first           = local.auth_settings.universal_login.identifier_first
}

# Database Connection
resource "auth0_connection" "database" {
  name     = local.auth_settings.connections.database.name
  strategy = "auth0"
  
  options {
    password_policy = local.auth_settings.identity_access.password_policy.strength
    
    password_complexity_options {
      min_length = local.auth_settings.identity_access.password_policy.min_length
    }
    
    password_history {
      enable = local.auth_settings.identity_access.password_policy.history.enabled
      size   = local.auth_settings.identity_access.password_policy.history.size
    }
    
    password_no_personal_info {
      enable = true
    }
    
    brute_force_protection = local.risk_settings.brute_force_protection.enabled
  }
}

# Multi-Factor Authentication
resource "auth0_guardian" "mfa" {
  policy = local.auth_settings.mfa.policy
  
  otp = local.auth_settings.mfa.factors.otp
  
  phone {
    enabled       = local.auth_settings.mfa.factors.sms
    provider      = "auth0"
    message_types = ["sms"]
  }
  
  webauthn_roaming {
    enabled = local.auth_settings.mfa.factors.webauthn
  }
  
  webauthn_platform {
    enabled = local.auth_settings.mfa.factors.webauthn
  }
}

# ===========================================
# OUTPUTS
# ===========================================

output "auth0_client" {
  value = {
    name            = auth0_client.app.name
    client_id       = auth0_client.app.client_id
    app_type        = auth0_client.app.app_type
    oidc_conformant = auth0_client.app.oidc_conformant
    grant_types     = auth0_client.app.grant_types
  }
  description = "Auth0 client/application configuration"
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

output "mfa_configuration" {
  value = {
    policy = auth0_guardian.mfa.policy
    otp    = auth0_guardian.mfa.otp
  }
  description = "MFA configuration status"
}