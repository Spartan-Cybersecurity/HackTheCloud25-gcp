#!/bin/bash

# Set the repository prefix
REPO_PREFIX="us-central1-docker.pkg.dev/arctic-bee-470901-c4/microservices-demo"
TAG="725f214"

echo "Building cartservice with explicit platform settings..."

# Use Docker Buildx with explicit platform and architecture settings
docker buildx build \
  --platform=linux/amd64 \
  --build-arg TARGETARCH=amd64 \
  --load \
  -t ${REPO_PREFIX}/cartservice:${TAG} \
  -f /Users/gerardoeliasib/gerh-data/EkoCloudSec/gcp-ctf-25/src/cartservice/src/Dockerfile \
  /Users/gerardoeliasib/gerh-data/EkoCloudSec/gcp-ctf-25/src/cartservice/src

# Push the image if build is successful
if [ $? -eq 0 ]; then
  echo "Build successful, pushing image..."
  docker push ${REPO_PREFIX}/cartservice:${TAG}
  echo "Done!"
else
  echo "Build failed."
  exit 1
fi
