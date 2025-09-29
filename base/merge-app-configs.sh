#!/bin/bash
# merge-app-configs.sh - Merge each app's modular configs into one combined file

APP_NAME=$1

if [ -z "$APP_NAME" ]; then
    echo "Usage: ./merge-app-configs.sh <app_name>"
    echo "Example: ./merge-app-configs.sh app1"
    exit 1
fi

# Check current directory structure
if [ ! -d "base" ]; then
    echo "Error: Not in correct directory. Please run from auth0-domain1 root"
    exit 1
fi

APP_DIR="apps/${APP_NAME}"

if [ ! -d "$APP_DIR" ]; then
    echo "Error: App directory ${APP_DIR} not found"
    echo "Available apps:"
    ls apps/ 2>/dev/null || echo "No apps directory found"
    exit 1
fi

echo "Merging configs for app: $APP_NAME"

# Determine app type
APP_TYPE="spa"
if [[ "$APP_NAME" == *"app2"* ]] || [[ "$APP_NAME" == *"web"* ]]; then
    APP_TYPE="regular_web"
elif [[ "$APP_NAME" == *"mobile"* ]] || [[ "$APP_NAME" == *"native"* ]]; then
    APP_TYPE="native"
fi

echo "Detected app type: $APP_TYPE"

# Check if YAML files exist
if [ ! -f "${APP_DIR}/tokens.yml" ] || [ ! -f "${APP_DIR}/security.yml" ] || [ ! -f "${APP_DIR}/orgs.yml" ]; then
    echo "Error: Missing required YAML files in ${APP_DIR}"
    echo "Required files: tokens.yml, security.yml, orgs.yml"
    ls -la ${APP_DIR}/
    exit 1
fi

# Create combined config for this app
OUTPUT_FILE="${APP_DIR}/${APP_NAME}-combined.yml"

echo "Creating ${OUTPUT_FILE}..."

cat > ${OUTPUT_FILE} <<EOF
app_type: "${APP_TYPE}"
tokens:
$(yq eval '.' ${APP_DIR}/tokens.yml | sed 's/^/  /')
security:
$(yq eval '.' ${APP_DIR}/security.yml | sed 's/^/  /')
orgs:
$(yq eval '.' ${APP_DIR}/orgs.yml | sed 's/^/  /')
EOF

echo "✓ Created ${OUTPUT_FILE}"

echo ""
echo "Running conftest validation..."
conftest test \
  --policy base/policies/ \
  --data base/tenants-common \
  ${OUTPUT_FILE}