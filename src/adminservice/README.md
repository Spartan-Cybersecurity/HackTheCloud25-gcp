# Admin Service

Admin Service is a microservice that provides server-side URL fetching capabilities for administrative purposes.

## Overview

This service exposes an HTTP endpoint that performs server-side requests to specified URLs and returns the response status and body content (limited to 2KB) as plain text.

## API Endpoints

### POST /fetch
Performs a server-side HTTP GET request to the specified URL.

**Request:**
- Method: `POST`
- Content-Type: `application/x-www-form-urlencoded`
- Body parameter: `url` - The URL to fetch

**Response:**
- Content-Type: `text/plain`
- Format:
  ```
  Status: <HTTP_STATUS_CODE> <HTTP_STATUS_TEXT>
  
  Body:
  <RESPONSE_BODY_FIRST_2KB>
  ```

**Example:**
```bash
curl -X POST http://adminservice:8080/fetch \
  -d "url=http://169.254.169.254/computeMetadata/v1/instance/name" \
  -H "Metadata-Flavor: Google"
```

### GET /health
Health check endpoint for Kubernetes probes.

**Response:**
- Status: `200 OK`
- Body: `OK`

## Configuration

The service can be configured using environment variables:

- `PORT`: HTTP server port (default: 8080)
- `ENABLE_TRACING`: Enable OpenTelemetry tracing (1 to enable)
- `ENABLE_PROFILER`: Enable Stackdriver profiler (1 to enable)
- `COLLECTOR_SERVICE_ADDR`: OpenTelemetry collector address (required if tracing enabled)

## Security Features

- Runs as non-root user (uid/gid 1000)
- Read-only root filesystem
- All Linux capabilities dropped
- Network policies restrict egress traffic
- Request timeout: 10 seconds
- Response body limited to 2KB

## Network Access

The service is configured with a NetworkPolicy that allows:
- DNS resolution (UDP port 53)
- HTTP/HTTPS traffic (TCP ports 80, 443)
- Specific access to metadata service (169.254.169.254/32)

## Deployment

The service is automatically deployed as part of the Online Boutique application when using:

```bash
kubectl apply -f ./release/kubernetes-manifests.yaml
```

Or with Skaffold:

```bash
skaffold run
```

## Resource Requirements

- CPU: 100m (request), 200m (limit)
- Memory: 64Mi (request), 128Mi (limit)

## Monitoring

The service includes:
- Readiness and liveness probes on `/health`
- OpenTelemetry tracing support
- Structured JSON logging
- Optional Stackdriver profiling
