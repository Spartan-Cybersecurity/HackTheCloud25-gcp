#!/bin/bash

# Comprehensive fix for all platform issues in microservices-demo
# This script fixes all Dockerfiles to use explicit linux/amd64 platform

set -e

echo "🔧 Fixing all platform issues for Apple Silicon compatibility..."

# List of services that use $BUILDPLATFORM
SERVICES=(
    "adminservice"
    "adservice" 
    "checkoutservice"
    "currencyservice"
    "frontend"
    "paymentservice"
    "productcatalogservice"
    "recommendationservice"
    "shippingservice"
    "shoppingassistantservice"
)

# Fix cartservice (already done but included for completeness)
echo "📦 Fixing cartservice Dockerfile..."
sed -i '' 's/--platform=\$BUILDPLATFORM/--platform=linux\/amd64/g' ./src/cartservice/src/Dockerfile
sed -i '' 's/-a \$TARGETARCH/-a amd64/g' ./src/cartservice/src/Dockerfile

# Fix emailservice (already done but included for completeness)  
echo "📧 Fixing emailservice Dockerfile..."
sed -i '' 's/--platform=\$BUILDPLATFORM/--platform=linux\/amd64/g' ./src/emailservice/Dockerfile

# Fix loadgenerator (doesn't use $BUILDPLATFORM but might have issues)
echo "🔄 Fixing loadgenerator Dockerfile..."
sed -i '' 's/FROM python:3.12.8-alpine/FROM --platform=linux\/amd64 python:3.12.8-alpine/g' ./src/loadgenerator/Dockerfile

# Fix all other services that use $BUILDPLATFORM
for service in "${SERVICES[@]}"; do
    dockerfile_path="./src/${service}/Dockerfile"
    if [ -f "$dockerfile_path" ]; then
        echo "🛠️  Fixing ${service} Dockerfile..."
        sed -i '' 's/--platform=\$BUILDPLATFORM/--platform=linux\/amd64/g' "$dockerfile_path"
    else
        echo "⚠️  Warning: Dockerfile not found for ${service}"
    fi
done

echo "✅ All Dockerfiles have been fixed for Apple Silicon compatibility!"
echo ""
echo "🚀 Now you can run the deployment with:"
echo "   export DOCKER_BUILDKIT=1"
echo "   export DOCKER_DEFAULT_PLATFORM=linux/amd64"
echo "   skaffold run --default-repo=us-central1-docker.pkg.dev/arctic-bee-470901-c4/microservices-demo"
echo ""
echo "Or use the simplified script:"
echo "   ./build-setup.sh"
