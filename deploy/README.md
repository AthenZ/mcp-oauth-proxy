# MCP Oauth Proxy Deployment

This directory contains Helm charts for deploying the Athenz MCP Oauth Proxy to Amazon EKS.

## Prerequisites

### Required Tools
- `kubectl` configured for your EKS cluster
- `helm` v3.x
- `aws` CLI configured with appropriate permissions

### Required AWS Resources
- EKS cluster with Kubernetes 1.32+
- AWS Load Balancer Controller installed
- ECR repository for container images
- IAM role for service account (IRSA) configured

## Quick Start

### 1. Build and Push Container Image

```bash
./mvnw package

# Build Docker image
docker build -f src/main/docker/Dockerfile -t mcp-oauth-proxy .

# Tag and push to ECR
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-west-2.amazonaws.com
docker tag mcp-oauth-proxy:latest 123456789012.dkr.ecr.us-west-2.amazonaws.com/mcp-oauth-proxy:latest
docker push 123456789012.dkr.ecr.us-west-2.amazonaws.com/mcp-oauth-proxy:latest
```

### 2. Configure Values

Create a `values-prod.yaml` file based on `values.yaml` and customize it for your environment.

### 3. Deploy

```bash
# Create namespace
kubectl create namespace mcp-oauth-proxy

# Install/upgrade with Helm
helm upgrade --install mcp-oauth-proxy ./deploy/mcp-oauth-proxy \
  --namespace mcp-oauth-proxy \
  --values values-prod.yaml
```

### Certificate Management

```bash
kubectl create secret tls server-tls --cert=tls.cert.pem --key=tls.key.pem
```

### Secret Management

Add provider specific client secrets to Kubernetes secrets to use for secondary oauth flow.

### IAM Roles for Service Accounts (IRSA)

Create an IAM role with the following trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/oidc.eks.REGION.amazonaws.com/id/OIDC_ID"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.REGION.amazonaws.com/id/OIDC_ID:sub": "system:serviceaccount:mcp-oauth-proxy:mcp-oauth-proxy",
          "oidc.eks.REGION.amazonaws.com/id/OIDC_ID:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
```

### Health Checks

The deployment includes comprehensive health checks:
- **Liveness probe**: `/q/health/live`
- **Readiness probe**: `/q/health/ready`
- **ALB health check**: `/q/health`

### Metrics
TBD

Metrics are available at: `https://your-app/q/metrics`

### Logging

Configure logging levels per environment:

```yaml
application:
  logging:
    level: INFO  # DEBUG for development
```

## Security

### Pod Security

- Runs as non-root user
- Read-only root filesystem
- Drops all capabilities
- No privilege escalation

### Network Security

Enable network policies for additional security.

### Certificate Security

- Certificates are mounted read-only
- Automatic certificate reloading
- Support for short-lived certificates

## Scaling

### Horizontal Pod Autoscaler

```yaml
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

### Pod Disruption Budget

Ensures high availability during updates:

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

## Troubleshooting

### Common Issues

1. **Pod not starting**: Check certificate paths and permissions
2. **Health check failures**: Verify TLS configuration
3. **Ingress not working**: Check ALB controller and certificates
4. **OIDC errors**: Verify Okta configuration

### Debugging Commands

```bash
# Check pod status
kubectl get pods -n mcp-oauth-proxy

# Check pod logs
kubectl logs -f deployment/mcp-oauth-proxy -n mcp-oauth-proxy

# Test health endpoint
kubectl port-forward service/mcp-oauth-proxy 8443:4443 -n mcp-oauth-proxy
curl -k https://localhost:8443/q/health
```

## Cleanup

```bash
# Uninstall Helm release
helm uninstall mcp-oauth-proxy -n mcp-oauth-proxy

# Delete namespace
kubectl delete namespace mcp-oauth-proxy
``` 