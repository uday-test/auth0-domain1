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
  app_oidc      = yamldecode(file("${path.module}/../configs/app-oidc.yml"))
  auth_settings = yamldecode(file("${path.module}/../configs/auth-settings.yml"))
  risk_settings = yamldecode(file("${path.module}/../configs/risk-settings.yml"))
  ux_settings   = yamldecode(file("${path.module}/../configs/ux-settings.yml"))
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

output "oidc_configuration" {
  value = {
    issuer                  = local.app_oidc.oidc.issuer
    supported_grant_types   = local.app_oidc.oidc.supported_grant_types
    security_enforce_pkce   = local.app_oidc.oidc.security.enforce_pkce
  }
  description = "Tenant OIDC configuration"
}