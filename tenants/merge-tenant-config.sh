
#!/bin/bash
# merge-tenant-configs.sh

ENV=$1

if [ -z "$ENV" ]; then
    echo "Usage: ./merge-tenant-configs.sh <environment>"
    echo "Example: ./merge-tenant-configs.sh qa"
    exit 1
fi

echo "Merging configs for environment: $ENV"

# Clean up any existing merged files
rm -f ${ENV}-tenant*-combined.yml

# Loop through all tenant directories
for tenant_dir in ${ENV}/tenant*/; do
    if [ -d "$tenant_dir" ]; then
        tenant_name=$(basename "$tenant_dir")
        echo "Processing $tenant_name..."
        
        # Check if YAML files exist
        if ls ${tenant_dir}/*.yml 1> /dev/null 2>&1; then
            # Merge all YAML files for this tenant
            yq eval-all '. as $item ireduce ({}; . * $item)' \
              ${tenant_dir}/*.yml \
              > ${ENV}-${tenant_name}-combined.yml
            
            echo "✓ Created ${ENV}-${tenant_name}-combined.yml"
        else
            echo "⚠ No YAML files found in $tenant_dir"
        fi
    fi
done

echo ""
echo "Running conftest validation..."
conftest test --policy overlays/policies/ --data overlays/validators/ ${ENV}-tenant*-combined.yml