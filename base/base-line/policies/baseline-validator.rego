package main

# This policy validates baseline configurations against their standards
# Designed for Conftest with merged config and standard files
# Uses non-recursive approach compatible with OPA

import rego.v1

# ============================================
# HELPER FUNCTIONS
# ============================================

# Check if a key exists in an object
has_key(obj, key) if {
    _ = obj[key]
}

# ============================================
# FIND ALL CONFIGURATION SECTIONS
# ============================================

# Get all top-level keys from config
config_sections contains section if {
    some section, _ in input.config
}

# Get all top-level keys from standard
standard_sections contains section if {
    some section, _ in input.standard
}

# ============================================
# MISSING SECTION VALIDATION
# ============================================

# Check for missing entire sections
deny contains msg if {
    some section in standard_sections
    input.standard[section].required == true
    not has_key(input.config, section)
    msg := sprintf("BASELINE: Missing required section: %s", [section])
}

# ============================================
# FIELD VALIDATION - Using walk()
# ============================================

# Find all required fields using walk
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.required == true
    
    # Build the full path and check if it exists in config
    not path_exists_in_section(input.config[section], path)
    
    path_str := concat(".", path)
    msg := sprintf("BASELINE [%s]: Missing required field: %s", [section, path_str])
}

# Helper to check if a path exists (handles up to 5 levels)
path_exists_in_section(obj, path) if {
    count(path) == 0
}

path_exists_in_section(obj, path) if {
    count(path) == 1
    has_key(obj, path[0])
}

path_exists_in_section(obj, path) if {
    count(path) == 2
    has_key(obj, path[0])
    has_key(obj[path[0]], path[1])
}

path_exists_in_section(obj, path) if {
    count(path) == 3
    has_key(obj, path[0])
    has_key(obj[path[0]], path[1])
    has_key(obj[path[0]][path[1]], path[2])
}

path_exists_in_section(obj, path) if {
    count(path) == 4
    has_key(obj, path[0])
    has_key(obj[path[0]], path[1])
    has_key(obj[path[0]][path[1]], path[2])
    has_key(obj[path[0]][path[1]][path[2]], path[3])
}

path_exists_in_section(obj, path) if {
    count(path) == 5
    has_key(obj, path[0])
    has_key(obj[path[0]], path[1])
    has_key(obj[path[0]][path[1]], path[2])
    has_key(obj[path[0]][path[1]][path[2]], path[3])
    has_key(obj[path[0]][path[1]][path[2]][path[3]], path[4])
}

# Get value at path (handles up to 5 levels)
get_value_at_path(obj, path) := obj if {
    count(path) == 0
}

get_value_at_path(obj, path) := obj[path[0]] if {
    count(path) == 1
}

get_value_at_path(obj, path) := obj[path[0]][path[1]] if {
    count(path) == 2
}

get_value_at_path(obj, path) := obj[path[0]][path[1]][path[2]] if {
    count(path) == 3
}

get_value_at_path(obj, path) := obj[path[0]][path[1]][path[2]][path[3]] if {
    count(path) == 4
}

get_value_at_path(obj, path) := obj[path[0]][path[1]][path[2]][path[3]][path[4]] if {
    count(path) == 5
}

# ============================================
# VALUE VALIDATIONS
# ============================================

# must_equal validation
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.must_equal != null
    path_exists_in_section(input.config[section], path)
    actual := get_value_at_path(input.config[section], path)
    actual != spec.must_equal
    path_str := concat(".", path)
    msg := sprintf("BASELINE [%s]: Field '%s' must equal %v, got %v", [section, path_str, spec.must_equal, actual])
}

# must_not_equal validation
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.must_not_equal != null
    path_exists_in_section(input.config[section], path)
    actual := get_value_at_path(input.config[section], path)
    actual == spec.must_not_equal
    path_str := concat(".", path)
    msg := sprintf("BASELINE [%s]: Field '%s' must not equal %v", [section, path_str, spec.must_not_equal])
}

# min_value validation
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.min_value
    path_exists_in_section(input.config[section], path)
    actual := get_value_at_path(input.config[section], path)
    is_number(actual)
    actual < spec.min_value
    path_str := concat(".", path)
    msg := sprintf("BASELINE [%s]: Field '%s' must be at least %v, got %v", [section, path_str, spec.min_value, actual])
}

# max_value validation
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.max_value
    path_exists_in_section(input.config[section], path)
    actual := get_value_at_path(input.config[section], path)
    is_number(actual)
    actual > spec.max_value
    path_str := concat(".", path)
    msg := sprintf("BASELINE [%s]: Field '%s' must be at most %v, got %v", [section, path_str, spec.max_value, actual])
}

# must_start_with validation
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.must_start_with
    path_exists_in_section(input.config[section], path)
    actual := get_value_at_path(input.config[section], path)
    is_string(actual)
    not startswith(actual, spec.must_start_with)
    path_str := concat(".", path)
    msg := sprintf("BASELINE [%s]: Field '%s' must start with '%s'", [section, path_str, spec.must_start_with])
}

# must_end_with validation
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.must_end_with
    path_exists_in_section(input.config[section], path)
    actual := get_value_at_path(input.config[section], path)
    is_string(actual)
    not endswith(actual, spec.must_end_with)
    path_str := concat(".", path)
    msg := sprintf("BASELINE [%s]: Field '%s' must end with '%s'", [section, path_str, spec.must_end_with])
}

# must_contain validation
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.must_contain
    path_exists_in_section(input.config[section], path)
    actual := get_value_at_path(input.config[section], path)
    is_string(actual)
    not contains(actual, spec.must_contain)
    path_str := concat(".", path)
    msg := sprintf("BASELINE [%s]: Field '%s' must contain '%s'", [section, path_str, spec.must_contain])
}

# must_match_pattern validation
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.must_match_pattern
    path_exists_in_section(input.config[section], path)
    actual := get_value_at_path(input.config[section], path)
    is_string(actual)
    not regex.match(spec.must_match_pattern, actual)
    path_str := concat(".", path)
    msg := sprintf("BASELINE [%s]: Field '%s' must match pattern '%s'", [section, path_str, spec.must_match_pattern])
}

# must_include validation (for arrays)
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.must_include
    path_exists_in_section(input.config[section], path)
    actual := get_value_at_path(input.config[section], path)
    is_array(actual)
    some item in spec.must_include
    not item in actual
    path_str := concat(".", path)
    msg := sprintf("BASELINE [%s]: Field '%s' must include '%s'", [section, path_str, item])
}

# must_not_include validation (for arrays)
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.must_not_include
    path_exists_in_section(input.config[section], path)
    actual := get_value_at_path(input.config[section], path)
    is_array(actual)
    some item in spec.must_not_include
    item in actual
    path_str := concat(".", path)
    msg := sprintf("BASELINE [%s]: Field '%s' must not include '%s'", [section, path_str, item])
}

# allowed_values validation (enum)
deny contains msg if {
    some section in standard_sections
    has_key(input.config, section)
    walk(input.standard[section], [path, spec])
    is_object(spec)
    spec.allowed_values
    path_exists_in_section(input.config[section], path)
    actual := get_value_at_path(input.config[section], path)
    not actual in spec.allowed_values
    path_str := concat(".", path)
    allowed := concat(", ", spec.allowed_values)
    msg := sprintf("BASELINE [%s]: Field '%s' must be one of [%s], got %v", [section, path_str, allowed, actual])
}