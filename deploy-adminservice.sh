#!/bin/bash

# Script to build and deploy adminservice with local code
# This ensures the SSRF functionality works correctly

set -e

echo "🔧 Building adminservice with local code..."

# Set Docker environment for cross-platform building
export DOCKER_BUILDKIT=1
export DOCKER_DEFAULT_PLATFORM=linux/amd64

# Build the adminservice image
docker build --platform=linux/amd64 \
  -t us-central1-docker.pkg.dev/arctic-bee-470901-c4/microservices-demo/adminservice:725f214-dirty \
  ./src/adminservice

echo "📤 Pushing adminservice image..."
docker push us-central1-docker.pkg.dev/arctic-bee-470901-c4/microservices-demo/adminservice:725f214-dirty

echo "🚀 Deploying adminservice..."
kubectl apply -f kubernetes-manifests/adminservice.yaml

echo "⏳ Waiting for adminservice to be ready..."
kubectl wait --for=condition=ready pod -l app=adminservice --timeout=60s

echo "✅ Adminservice deployed successfully!"
echo "🔍 Checking adminservice status..."
kubectl get pods -l app=adminservice
kubectl get service adminservice
