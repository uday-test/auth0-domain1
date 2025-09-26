package main

import rego.v1

# ========== DATA NORMALIZATION ==========

# Get required password policy from data
required_password_min := object.get(object.get(data.passwordPolicy, "length", {}), "min", 0)
required_password_history := object.get(data.passwordPolicy, "history", 0)

# Normalize required MFA factors - handles both array and object formats
required_factors := object.union(array_factors, object_factors)

# Handle array format: [{name: "otp", enabled: true}, ...]
array_factors := {lower(factor.name): factor.enabled |
    some factor in object.get(data.guardianMfaPolicy, "factors", [])
    is_object(factor)
    factor.name
}

# Handle object format: {"otp": {enabled: true}, ...}  
object_factors := {lower(name): factors[name].enabled |
    factors := object.get(data.guardianMfaPolicy, "factors", {})
    not is_array(factors)
    some name in object.keys(factors)
    is_object(factors[name])
}

# Normalize input MFA factors
input_factors := object.union(input_array_factors, input_object_factors)

input_array_factors := {lower(factor.name): factor.enabled |
    some factor in object.get(input.guardianMfaPolicy, "factors", [])
    is_object(factor)
    factor.name
}

input_object_factors := {lower(name): factors[name].enabled |
    factors := object.get(input.guardianMfaPolicy, "factors", {})
    not is_array(factors)
    some name in object.keys(factors)
    is_object(factors[name])
}

# ========== VALIDATION HELPERS ==========

valid_password_config if {
    input.passwordPolicy
    input.passwordPolicy.length
}

valid_mfa_config if {
    input.guardianMfaPolicy
    input.guardianMfaPolicy.factors
}

# ========== DENY RULES ==========

# Deny if password minimum length is too low
deny contains msg if {
    valid_password_config
    input_min := object.get(object.get(input.passwordPolicy, "length", {}), "min", -1)
    input_min != -1
    input_min < required_password_min
    msg := sprintf("Password minimum length (%d) must be >= %d", [input_min, required_password_min])
}

deny contains msg if {
    valid_password_config
    object.get(object.get(input.passwordPolicy, "length", {}), "min", -1) == -1
    required_password_min > 0
    msg := sprintf("Password minimum length is missing; required >= %d", [required_password_min])
}

# Deny if password history is too low
deny contains msg if {
    valid_password_config
    input_history := object.get(input.passwordPolicy, "history", -1)
    input_history != -1
    input_history < required_password_history
    msg := sprintf("Password history (%d) must be >= %d", [input_history, required_password_history])
}

deny contains msg if {
    valid_password_config
    object.get(input.passwordPolicy, "history", -1) == -1
    required_password_history > 0
    msg := sprintf("Password history is missing; required >= %d", [required_password_history])
}

# Deny if required MFA factor is missing
deny contains msg if {
    valid_mfa_config
    some required_factor_name in object.keys(required_factors)
    required_factors[required_factor_name] == true
    not required_factor_name in object.keys(input_factors)
    msg := sprintf("Required MFA factor '%s' is missing from configuration", [required_factor_name])
}

# Deny if required MFA factor is disabled when it should be enabled
deny contains msg if {
    valid_mfa_config
    some required_factor_name in object.keys(required_factors)
    required_factors[required_factor_name] == true
    required_factor_name in object.keys(input_factors)
    input_factors[required_factor_name] != true
    msg := sprintf("Required MFA factor '%s' must be enabled but found disabled", [required_factor_name])
}

# Deny if forbidden MFA factor is enabled when it should be disabled
deny contains msg if {
    valid_mfa_config
    some required_factor_name in object.keys(required_factors)
    required_factors[required_factor_name] == false
    required_factor_name in object.keys(input_factors)
    input_factors[required_factor_name] == true
    msg := sprintf("MFA factor '%s' must be disabled but, found enabled", [required_factor_name])
}