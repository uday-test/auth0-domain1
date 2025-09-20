package auth0.policy

# This rule denies any pull request from modifying files within the base directory.
deny[msg] {
    # Check if any file in the PR has a path that starts with "base/"
    some i
    path := input.files[i].path
    startswith(path, "base/")
    msg := "PRs are not allowed to modify files in the /base directory. These files are owned by the CIAM team and managed via a separate process."
}

# This rule denies any pull request from modifying files within the overlays directory.
deny[msg] {
    # Check if any file in the PR has a path that starts with "overlays/"
    some i
    path := input.files[i].path
    startswith(path, "overlays/")
    msg := "PRs are not allowed to modify files in the /overlays directory. These files are owned by the CIAM team and managed via a separate process."
}

# This rule restricts app teams from modifying tenant configurations for non-dev environments.
deny[msg] {
    some i
    path := input.files[i].path
    startswith(path, "tenants/")
    # Explicitly allow changes only to the dev tenant directory
    not startswith(path, "tenants/dev/")
    msg := "PRs are only allowed to modify files in their designated dev tenant. All promotions to QA and Prod are handled by the CIAM team's promotion pipeline."
}