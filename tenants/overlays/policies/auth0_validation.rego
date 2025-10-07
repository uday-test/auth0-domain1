
package main

import rego.v1

# ========== ENVIRONMENT DETECTION ==========

# Detect environment from OIDC issuer URL pattern
env := "dev" if {
    input.oidc
    contains(input.oidc.issuer, "dev-")
}

env := "qa" if {
    input.oidc
    contains(input.oidc.issuer, "qa-")
}

env := "prod" if {
    input.oidc
    not contains(input.oidc.issuer, "dev-")
    not contains(input.oidc.issuer, "qa-")
}

# Detect QA from security origins for auth files
env := "qa" if {
    not input.oidc
    input.security
    input.security.allowed_origins
    some origin in input.security.allowed_origins
    contains(origin, "qa-")
}

# Detect dev from security origins for auth files  
env := "dev" if {
    not input.oidc
    input.security
    input.security.allowed_origins
    some origin in input.security.allowed_origins
    contains(origin, "localhost")
}

# Detect from branding URLs
env := "qa" if {
    not input.oidc
    not input.security
    input.branding
    contains(input.branding.logo_url, "/qa/")
}

env := "dev" if {
    not input.oidc
    not input.security
    input.branding
    contains(input.branding.logo_url, "/dev/")
}

# Default to prod
env := "prod" if {
    not input.oidc
    not input.security
    not input.branding
}

# ========== OIDC VALIDATION ==========

deny contains msg if {
    input.oidc
    required_https := data.oidc_standards.security_requirements.require_https[env]
    actual_https := object.get(input.oidc.security, "require_https", false)
    actual_https != required_https
    msg := sprintf("OIDC [%s]: HTTPS requirement mismatch. Required: %v, Actual: %v", [env, required_https, actual_https])
}

deny contains msg if {
    input.oidc
    required_pkce := data.oidc_standards.security_requirements.enforce_pkce[env]
    actual_pkce := object.get(input.oidc.security, "enforce_pkce", false)
    actual_pkce != required_pkce
    msg := sprintf("OIDC [%s]: PKCE enforcement mismatch. Required: %v, Actual: %v", [env, required_pkce, actual_pkce])
}

deny contains msg if {
    input.oidc
    allowed_grants := data.oidc_standards.allowed_grant_types[env]
    actual_grants := object.get(input.oidc, "supported_grant_types", [])
    invalid_grants := [grant | grant := actual_grants[_]; not grant in allowed_grants]
    count(invalid_grants) > 0
    msg := sprintf("OIDC [%s]: Unauthorized grant types: %v. Allowed: %v", [env, invalid_grants, allowed_grants])
}

# ========== AUTH VALIDATION ==========

deny contains msg if {
    input.connections
    count(input.connections.database) > 0
    required_policy := data.auth_standards.password_requirements.minimum_policy[env]
    actual_policy := object.get(input.connections.database[0], "password_policy", "")
    actual_policy != required_policy
    msg := sprintf("Auth [%s]: Password policy mismatch. Required: %s, Actual: %s", [env, required_policy, actual_policy])
}

deny contains msg if {
    input.connections
    count(input.connections.database) > 0
    required_length := data.auth_standards.password_requirements.min_length[env]
    actual_length := object.get(object.get(input.connections.database[0], "password_complexity_options", {}), "min_length", 0)
    actual_length != required_length
    msg := sprintf("Auth [%s]: Password minimum length mismatch. Required: %d, Actual: %d", [env, required_length, actual_length])
}

deny contains msg if {
    input.guardian
    required_mfa := data.auth_standards.guardian_requirements.mfa_enforcement[env]
    actual_mfa := object.get(input.guardian, "enabled", false)
    actual_mfa != required_mfa
    msg := sprintf("Auth [%s]: MFA enforcement mismatch. Required: %v, Actual: %v", [env, required_mfa, actual_mfa])
}

deny contains msg if {
    input.tokens
    input.tokens.access_token
    required_token_lifetime := data.auth_standards.token_requirements.max_access_token[env]
    actual_lifetime := object.get(input.tokens.access_token, "lifetime_in_seconds", 0)
    actual_lifetime != required_token_lifetime
    msg := sprintf("Auth [%s]: Access token lifetime mismatch. Required: %d, Actual: %d", [env, required_token_lifetime, actual_lifetime])
}

# ========== RISK VALIDATION ==========

deny contains msg if {
    input.attack_protection

    required_bf := data.risk_standards.attack_protection.brute_force_required[env]
    actual_bf := object.get(object.get(input.attack_protection, "brute_force_protection", {}), "enabled", false)
    actual_bf != required_bf
    msg := sprintf("Risk [%s]: Brute force protection mismatch. Required: %v, Actual: %v", [env, required_bf, actual_bf])
}

deny contains msg if {
    input.bot_detection
    
    required_bot := data.risk_standards.bot_detection_required[env]
    actual_bot := object.get(input.bot_detection, "enabled", false)
    actual_bot != required_bot
    msg := sprintf("Risk [%s]: Bot detection mismatch. Required: %v, Actual: %v", [env, required_bot, actual_bot])
}

# ========== UX VALIDATION ==========

deny contains msg if {
    input.branding
    approved_domains := data.ux_standards.branding_requirements.approved_domains
    logo_url := object.get(input.branding, "logo_url", "")
    url_parts := split(logo_url, "/")
    count(url_parts) > 2
    domain := url_parts[2]
    not domain in approved_domains
    msg := sprintf("UX [%s]: Unauthorized branding domain '%s'. Approved: %v", [env, domain, approved_domains])
}

deny contains msg if {
    input.branding
    approved_colors := data.ux_standards.branding_requirements.approved_colors
    primary_color := object.get(object.get(input.branding, "colors", {}), "primary", "")
    not primary_color in approved_colors
    primary_color != ""
    msg := sprintf("UX [%s]: Unauthorized primary color '%s'. Approved: %v", [env, primary_color, approved_colors])
}

deny contains msg if {
    input.email_templates
    approved_email_domains := data.ux_standards.email_requirements.approved_domains
    verify_email_from := object.get(object.get(input.email_templates, "verify_email", {}), "from", "")
    email_parts := split(verify_email_from, "@")
    count(email_parts) > 1
    email_domain := email_parts[1]
    not email_domain in approved_email_domains
    msg := sprintf("UX [%s]: verify_email uses unauthorized domain '%s'. Approved: %v", [env, email_domain, approved_email_domains])
}

deny contains msg if {
    input.email_templates
    input.email_templates.reset_password
    approved_email_domains := data.ux_standards.email_requirements.approved_domains
    reset_email_from := object.get(input.email_templates.reset_password, "from", "")
    email_parts := split(reset_email_from, "@")
    count(email_parts) > 1
    email_domain := email_parts[1]
    not email_domain in approved_email_domains
    msg := sprintf("UX [%s]: reset_password uses unauthorized domain '%s'. Approved: %v", [env, email_domain, approved_email_domains])
}