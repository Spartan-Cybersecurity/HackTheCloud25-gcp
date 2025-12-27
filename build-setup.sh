#!/bin/bash

# Comprehensive deployment script for Apple Silicon Macs
# This script ensures all platform issues are resolved before deployment

set -e

echo "🚀 Starting comprehensive deployment for Apple Silicon..."

# Step 1: Fix all Dockerfiles if not already done
if [ ! -f ".platform-fixed" ]; then
    echo "🔧 Applying platform fixes to all Dockerfiles..."
    ./fix-all-platforms.sh
    touch .platform-fixed
    echo "✅ Platform fixes applied and marked"
else
    echo "✅ Platform fixes already applied"
fi

# Step 2: Set Docker BuildKit platform variables
echo "🐳 Setting Docker environment variables..."
export DOCKER_BUILDKIT=1
export DOCKER_DEFAULT_PLATFORM=linux/amd64

# Step 3: Clean up any existing deployments to avoid conflicts
echo "🧹 Cleaning up existing deployments..."
kubectl delete deployment --all --ignore-not-found=true
kubectl delete service --all --ignore-not-found=true
sleep 5

# Step 4: Run skaffold with the specified repository
echo "📦 Starting skaffold deployment..."
skaffold run --default-repo=us-central1-docker.pkg.dev/arctic-bee-470901-c4/microservices-demo

# Step 5: Force rebuild and deploy adminservice with local code
echo "🔧 Building and deploying adminservice with local code..."
docker build --platform=linux/amd64 -t us-central1-docker.pkg.dev/arctic-bee-470901-c4/microservices-demo/adminservice:725f214-dirty ./src/adminservice
docker push us-central1-docker.pkg.dev/arctic-bee-470901-c4/microservices-demo/adminservice:725f214-dirty
kubectl apply -f kubernetes-manifests/adminservice.yaml

# Step 6: Verify all services are running
echo "🔍 Verifying deployment status..."
kubectl get pods
echo ""
kubectl get services

echo "🎉 Deployment completed!"
