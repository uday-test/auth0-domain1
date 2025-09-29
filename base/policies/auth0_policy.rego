package main

import rego.v1

# Import standards from tenants-common
tokens_standards := data.tokens_standards
security_standards := data.security_standards
organization_standards := data.organization_standards

# Get app configurations from input
app_tokens := input.tokens
app_security := input.security
app_orgs := input.orgs
app_type := input.app_type

# =============================================================================
# TOKEN VALIDATION
# =============================================================================

# Validate access token lifetime - below minimum
deny contains msg if {
    app_type_lower := lower(app_type)
    min_lifetime := tokens_standards.access_token[app_type_lower].lifetime_in_seconds.min
    actual_lifetime := app_tokens.jwt_configuration.lifetime_in_seconds
    
    actual_lifetime < min_lifetime
    msg := sprintf("Access token lifetime %d is below minimum %d for %s apps", [actual_lifetime, min_lifetime, app_type])
}

# Validate access token lifetime - above maximum
deny contains msg if {
    app_type_lower := lower(app_type)
    max_lifetime := tokens_standards.access_token[app_type_lower].lifetime_in_seconds.max
    actual_lifetime := app_tokens.jwt_configuration.lifetime_in_seconds
    
    actual_lifetime > max_lifetime
    msg := sprintf("Access token lifetime %d exceeds maximum %d for %s apps", [actual_lifetime, max_lifetime, app_type])
}

# Validate JWT algorithm
deny contains msg if {
    required_alg := tokens_standards.jwt_configuration.alg
    actual_alg := app_tokens.jwt_configuration.alg
    
    actual_alg != required_alg
    msg := sprintf("JWT algorithm must be %s, found %s", [required_alg, actual_alg])
}

# Validate refresh token lifetime - below minimum
deny contains msg if {
    app_type_lower := lower(app_type)
    min_lifetime := tokens_standards.refresh_token[app_type_lower].lifetime_in_seconds.min
    actual_lifetime := app_tokens.refresh_token.token_lifetime
    
    actual_lifetime < min_lifetime
    msg := sprintf("Refresh token lifetime %d is below minimum %d for %s apps", [actual_lifetime, min_lifetime, app_type])
}

# Validate refresh token lifetime - above maximum
deny contains msg if {
    app_type_lower := lower(app_type)
    max_lifetime := tokens_standards.refresh_token[app_type_lower].lifetime_in_seconds.max
    actual_lifetime := app_tokens.refresh_token.token_lifetime
    
    actual_lifetime > max_lifetime
    msg := sprintf("Refresh token lifetime %d exceeds maximum %d for %s apps", [actual_lifetime, max_lifetime, app_type])
}

# Validate refresh token rotation
deny contains msg if {
    app_type_lower := lower(app_type)
    required_rotation := tokens_standards.refresh_token[app_type_lower].rotation_type
    actual_rotation := app_tokens.refresh_token.rotation_type
    
    actual_rotation != required_rotation
    msg := sprintf("Refresh token rotation_type must be '%s', found '%s'", [required_rotation, actual_rotation])
}

# Validate refresh token expiration
deny contains msg if {
    app_type_lower := lower(app_type)
    required_expiration := tokens_standards.refresh_token[app_type_lower].expiration_type
    actual_expiration := app_tokens.refresh_token.expiration_type
    
    actual_expiration != required_expiration
    msg := sprintf("Refresh token expiration_type must be '%s', found '%s'", [required_expiration, actual_expiration])
}

# =============================================================================
# SECURITY VALIDATION
# =============================================================================

# Validate token endpoint auth method
deny contains msg if {
    app_type_lower := lower(app_type)
    required_method := security_standards.authentication.token_endpoint_auth_method[app_type_lower]
    actual_method := app_security.token_endpoint_auth_method
    
    actual_method != required_method
    msg := sprintf("Token endpoint auth method must be '%s' for %s apps, found '%s'", [required_method, app_type, actual_method])
}

# Validate OIDC conformant
deny contains msg if {
    required_oidc := security_standards.authentication.oidc_conformant
    actual_oidc := app_security.oidc_conformant
    
    actual_oidc != required_oidc
    msg := sprintf("OIDC conformant must be %v, found %v", [required_oidc, actual_oidc])
}

# Validate cross-origin auth
deny contains msg if {
    app_type_lower := lower(app_type)
    required_cors := security_standards.authentication.cross_origin_auth[app_type_lower]
    actual_cors := app_security.cross_origin_auth
    
    actual_cors != required_cors
    msg := sprintf("Cross-origin auth must be %v for %s apps, found %v", [required_cors, app_type, actual_cors])
}

# Validate required grant types are present
deny contains msg if {
    app_type_lower := lower(app_type)
    required_grants := security_standards.grant_types[app_type_lower].required
    actual_grants := app_security.grant_types
    
    some required_grant in required_grants
    not required_grant in actual_grants
    msg := sprintf("Required grant type '%s' is missing for %s apps", [required_grant, app_type])
}

# Validate forbidden grant types are not present
deny contains msg if {
    app_type_lower := lower(app_type)
    forbidden_grants := security_standards.grant_types[app_type_lower].forbidden
    actual_grants := app_security.grant_types
    
    some forbidden_grant in forbidden_grants
    forbidden_grant in actual_grants
    msg := sprintf("Forbidden grant type '%s' found in %s app configuration", [forbidden_grant, app_type])
}

# Validate response types
deny contains msg if {
    app_type_lower := lower(app_type)
    required_response_types := security_standards.response_types[app_type_lower]
    actual_response_types := app_security.response_types
    
    not arrays_equal(required_response_types, actual_response_types)
    msg := sprintf("Response types must be %v for %s apps, found %v", [required_response_types, app_type, actual_response_types])
}

# Validate forbidden response types
deny contains msg if {
    forbidden_response_types := security_standards.response_types.forbidden
    actual_response_types := app_security.response_types
    
    some forbidden_type in forbidden_response_types
    forbidden_type in actual_response_types
    msg := sprintf("Forbidden response type '%s' found in configuration", [forbidden_type])
}

# Validate CORS for SPA - allowed_origins
deny contains msg if {
    app_type_lower := lower(app_type)
    app_type_lower == "spa"
    cors_requirement := security_standards.cors.allowed_origins[app_type_lower]
    cors_requirement == "required"
    
    not app_security.allowed_origins
    msg := "SPA apps must have allowed_origins configured"
}

# Validate CORS for SPA - allowed_web_origins
deny contains msg if {
    app_type_lower := lower(app_type)
    app_type_lower == "spa"
    cors_requirement := security_standards.cors.allowed_web_origins[app_type_lower]
    cors_requirement == "required"
    
    not app_security.allowed_web_origins
    msg := "SPA apps must have allowed_web_origins configured for silent authentication"
}

# =============================================================================
# ORGANIZATION VALIDATION
# =============================================================================

# Validate organization usage
deny contains msg if {
    app_type_lower := lower(app_type)
    required_usage := organization_standards.usage_policies[app_type_lower].organization_usage
    actual_usage := app_orgs.organization_usage
    
    actual_usage != required_usage
    msg := sprintf("Organization usage must be '%s' for %s apps, found '%s'", [required_usage, app_type, actual_usage])
}

# Validate organization require behavior
deny contains msg if {
    app_type_lower := lower(app_type)
    required_behavior := organization_standards.usage_policies[app_type_lower].organization_require_behavior
    actual_behavior := app_orgs.organization_require_behavior
    
    actual_behavior != required_behavior
    msg := sprintf("Organization require behavior must be '%s' for %s apps, found '%s'", [required_behavior, app_type, actual_behavior])
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

# Helper to compare arrays (order-independent)
arrays_equal(arr1, arr2) if {
    count(arr1) == count(arr2)
    every item in arr1 {
        item in arr2
    }
}

# =============================================================================
# WARNINGS
# =============================================================================

warn contains msg if {
    app_type_lower := lower(app_type)
    recommended_lifetime := tokens_standards.access_token[app_type_lower].lifetime_in_seconds.recommended
    actual_lifetime := app_tokens.jwt_configuration.lifetime_in_seconds
    
    actual_lifetime != recommended_lifetime
    msg := sprintf("Access token lifetime %d differs from recommended %d for %s apps", [actual_lifetime, recommended_lifetime, app_type])
}

warn contains msg if {
    app_type_lower := lower(app_type)
    recommended_lifetime := tokens_standards.refresh_token[app_type_lower].lifetime_in_seconds.recommended
    actual_lifetime := app_tokens.refresh_token.token_lifetime
    
    actual_lifetime != recommended_lifetime
    msg := sprintf("Refresh token lifetime %d differs from recommended %d for %s apps", [actual_lifetime, recommended_lifetime, app_type])
}