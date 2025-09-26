package main

import rego.v1

# Test warning - should always show
warn contains msg if {
    msg := "Policy loaded successfully"
}

# Simple test denial
deny contains msg if {
    input_min := object.get(object.get(input.passwordPolicy, "length", {}), "min", -1)
    input_min != -1
    input_min < 16
    msg := sprintf("Password minimum length (%d) must be >= 16", [input_min])
}