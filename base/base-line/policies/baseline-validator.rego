package main

# This policy validates baseline configurations against their standards

# ============================================
# HELPER FUNCTION - Check if key exists in object
# ============================================

has_key(obj, key) if {
    _ = obj[key]
}

# ============================================
# VALIDATION RULES - Level 1 fields
# ============================================

deny contains msg if {
    some key, value in input.standard
    is_object(value)
    value.required == true
    not has_key(input.config, key)
    msg := sprintf("BASELINE: Missing required field: %s", [key])
}

# ============================================
# VALIDATION RULES - Level 2 fields
# ============================================

deny contains msg if {
    some key1, obj1 in input.standard
    is_object(obj1)
    some key2, value in obj1
    is_object(value)
    value.required == true
    has_key(input.config, key1)
    not has_key(input.config[key1], key2)
    path := concat(".", [key1, key2])
    msg := sprintf("BASELINE: Missing required field: %s", [path])
}

# ============================================
# VALIDATION RULES - Level 3 fields
# ============================================

deny contains msg if {
    some key1, obj1 in input.standard
    is_object(obj1)
    some key2, obj2 in obj1
    is_object(obj2)
    some key3, value in obj2
    is_object(value)
    value.required == true
    has_key(input.config, key1)
    has_key(input.config[key1], key2)
    not has_key(input.config[key1][key2], key3)
    path := concat(".", [key1, key2, key3])
    msg := sprintf("BASELINE: Missing required field: %s", [path])
}

# ============================================
# VALIDATION RULES - Level 4 fields
# ============================================

deny contains msg if {
    some key1, obj1 in input.standard
    is_object(obj1)
    some key2, obj2 in obj1
    is_object(obj2)
    some key3, obj3 in obj2
    is_object(obj3)
    some key4, value in obj3
    is_object(value)
    value.required == true
    has_key(input.config, key1)
    has_key(input.config[key1], key2)
    has_key(input.config[key1][key2], key3)
    not has_key(input.config[key1][key2][key3], key4)
    path := concat(".", [key1, key2, key3, key4])
    msg := sprintf("BASELINE: Missing required field: %s", [path])
}

# ============================================
# VALUE VALIDATIONS - Iterate through ALL levels
# ============================================

# must_equal at level 2
deny contains msg if {
    some key1, obj1 in input.standard
    is_object(obj1)
    some key2, value in obj1
    is_object(value)
    value.must_equal != null
    has_key(input.config, key1)
    has_key(input.config[key1], key2)
    input.config[key1][key2] != value.must_equal
    path := concat(".", [key1, key2])
    msg := sprintf("BASELINE: Field '%s' must equal %v, got %v", [path, value.must_equal, input.config[key1][key2]])
}

# must_equal at level 3
deny contains msg if {
    some key1, obj1 in input.standard
    is_object(obj1)
    some key2, obj2 in obj1
    is_object(obj2)
    some key3, value in obj2
    is_object(value)
    value.must_equal != null
    has_key(input.config, key1)
    has_key(input.config[key1], key2)
    has_key(input.config[key1][key2], key3)
    input.config[key1][key2][key3] != value.must_equal
    path := concat(".", [key1, key2, key3])
    msg := sprintf("BASELINE: Field '%s' must equal %v, got %v", [path, value.must_equal, input.config[key1][key2][key3]])
}

# must_equal at level 4
deny contains msg if {
    some key1, obj1 in input.standard
    is_object(obj1)
    some key2, obj2 in obj1
    is_object(obj2)
    some key3, obj3 in obj2
    is_object(obj3)
    some key4, value in obj3
    is_object(value)
    value.must_equal != null
    has_key(input.config, key1)
    has_key(input.config[key1], key2)
    has_key(input.config[key1][key2], key3)
    has_key(input.config[key1][key2][key3], key4)
    input.config[key1][key2][key3][key4] != value.must_equal
    path := concat(".", [key1, key2, key3, key4])
    msg := sprintf("BASELINE: Field '%s' must equal %v, got %v", [path, value.must_equal, input.config[key1][key2][key3][key4]])
}

# must_start_with at level 2
deny contains msg if {
    some key1, obj1 in input.standard
    is_object(obj1)
    some key2, value in obj1
    is_object(value)
    value.must_start_with
    has_key(input.config, key1)
    has_key(input.config[key1], key2)
    is_string(input.config[key1][key2])
    not startswith(input.config[key1][key2], value.must_start_with)
    path := concat(".", [key1, key2])
    msg := sprintf("BASELINE: Field '%s' must start with '%s'", [path, value.must_start_with])
}

# must_contain at level 2
deny contains msg if {
    some key1, obj1 in input.standard
    is_object(obj1)
    some key2, value in obj1
    is_object(value)
    value.must_contain
    has_key(input.config, key1)
    has_key(input.config[key1], key2)
    is_string(input.config[key1][key2])
    not contains(input.config[key1][key2], value.must_contain)
    path := concat(".", [key1, key2])
    msg := sprintf("BASELINE: Field '%s' must contain '%s'", [path, value.must_contain])
}

# must_match_pattern at level 2
deny contains msg if {
    some key1, obj1 in input.standard
    is_object(obj1)
    some key2, value in obj1
    is_object(value)
    value.must_match_pattern
    has_key(input.config, key1)
    has_key(input.config[key1], key2)
    is_string(input.config[key1][key2])
    not regex.match(value.must_match_pattern, input.config[key1][key2])
    path := concat(".", [key1, key2])
    msg := sprintf("BASELINE: Field '%s' must match pattern '%s'", [path, value.must_match_pattern])
}

# must_include at level 2
deny contains msg if {
    some key1, obj1 in input.standard
    is_object(obj1)
    some key2, value in obj1
    is_object(value)
    value.must_include
    has_key(input.config, key1)
    has_key(input.config[key1], key2)
    is_array(input.config[key1][key2])
    some item in value.must_include
    not item in input.config[key1][key2]
    path := concat(".", [key1, key2])
    msg := sprintf("BASELINE: Field '%s' must include '%s'", [path, item])
}

# min_value at level 3
deny contains msg if {
    some key1, obj1 in input.standard
    is_object(obj1)
    some key2, obj2 in obj1
    is_object(obj2)
    some key3, value in obj2
    is_object(value)
    value.min_value
    has_key(input.config, key1)
    has_key(input.config[key1], key2)
    has_key(input.config[key1][key2], key3)
    is_number(input.config[key1][key2][key3])
    input.config[key1][key2][key3] < value.min_value
    path := concat(".", [key1, key2, key3])
    msg := sprintf("BASELINE: Field '%s' must be at least %v, got %v", [path, value.min_value, input.config[key1][key2][key3]])
}