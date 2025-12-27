# Admin Service Integration Guide

## Overview

The Admin Service has been successfully integrated into the Online Boutique microservices demo application. This document provides details on the implementation and deployment process.

## Architecture Integration

The admin-service follows the established patterns of the Online Boutique application:

### Language Selection
- **Chosen**: Go
- **Rationale**: Consistency with existing HTTP services (frontend, shippingservice, productcatalogservice, checkoutservice)
- **Benefits**: Native `net/http` support, established build patterns, security model alignment

### Service Design
- **Type**: HTTP REST service
- **Port**: 8080 (standard for HTTP services in the project)
- **Protocol**: HTTP/1.1 with OpenTelemetry instrumentation
- **Security**: Non-root execution, read-only filesystem, minimal capabilities

## SSRF Functionality

### Endpoint Specification
```
POST /fetch
Content-Type: application/x-www-form-urlencoded
Body: url=<target_url>
```

### Response Format
```
Status: <code> <message>

Body:
<first_2kb_of_response>
```

### Security Controls
- Request timeout: 10 seconds
- Response size limit: 2KB
- Network policy restrictions
- Authorized access to metadata service (169.254.169.254/32)

## Deployment Integration

### Kubernetes Manifests
The service has been integrated into the main deployment pipeline:

1. **Individual manifest**: `kubernetes-manifests/adminservice.yaml`
2. **Consolidated manifest**: Added to `release/kubernetes-manifests.yaml`
3. **Build configuration**: Added to `skaffold.yaml`

### Network Policy
A dedicated NetworkPolicy (`adminservice-netpol`) controls egress traffic:
- DNS resolution allowed
- HTTP/HTTPS traffic permitted
- Specific metadata service access authorized

### Resource Allocation
- **CPU**: 100m request, 200m limit
- **Memory**: 64Mi request, 128Mi limit
- **Scaling**: Single replica (can be adjusted based on needs)

## Deployment Verification

After running the standard deployment commands:

```bash
gcloud container clusters create-auto online-boutique \
  --project=${PROJECT_ID} --region=${REGION}
kubectl apply -f ./release/kubernetes-manifests.yaml
```

Verify the service is running:

```bash
# Check pod status
kubectl get pods -l app=adminservice

# Check service endpoint
kubectl get svc adminservice

# Test health endpoint
kubectl port-forward svc/adminservice 8080:8080
curl http://localhost:8080/health
```

## Testing the SSRF Endpoint

Once deployed, test the SSRF functionality:

```bash
# Port forward to access the service
kubectl port-forward svc/adminservice 8080:8080

# Test metadata service access
curl -X POST http://localhost:8080/fetch \
  -d "url=http://169.254.169.254/computeMetadata/v1/instance/name" \
  -H "Metadata-Flavor: Google"

# Test external URL
curl -X POST http://localhost:8080/fetch \
  -d "url=https://httpbin.org/json"
```

## Monitoring and Observability

The service includes standard observability features:

- **Health Checks**: `/health` endpoint for K8s probes
- **Tracing**: OpenTelemetry integration (when enabled)
- **Logging**: Structured JSON logs with logrus
- **Profiling**: Optional Stackdriver profiler support

## Security Considerations

### Container Security
- Non-root execution (uid/gid 1000)
- Read-only root filesystem
- All Linux capabilities dropped
- No privilege escalation allowed

### Network Security
- Egress traffic controlled by NetworkPolicy
- DNS resolution limited to necessary ports
- HTTP/HTTPS access restricted but functional
- Metadata service access explicitly authorized

### Application Security
- Request timeouts prevent hanging connections
- Response size limits prevent memory exhaustion
- Input validation on URL parameters
- Error handling prevents information leakage

## Maintenance

### Updating the Service
To modify the admin-service:

1. Update source code in `src/adminservice/`
2. Test locally with `go run main.go`
3. Build and deploy with `skaffold run`

### Scaling Considerations
- Current configuration uses single replica
- Can be scaled horizontally if needed
- Resource limits may need adjustment for high load

### Troubleshooting
Common issues and solutions:

1. **Pod not starting**: Check resource limits and security context
2. **Network connectivity**: Verify NetworkPolicy allows required egress
3. **Metadata access denied**: Ensure GKE workload identity is configured
4. **Build failures**: Verify Go dependencies and Docker build context
