#!/bin/bash

set -e

# Configuration
NAMESPACE=${NAMESPACE:-"athenz-webhook"}
RELEASE_NAME=${RELEASE_NAME:-"mcp-oauth-proxy"}
CHART_PATH=${CHART_PATH:-"./deploy/mcp-oauth-proxy"}
VALUES_FILE=${VALUES_FILE:-"values-prod.yaml"}
DRY_RUN=${DRY_RUN:-"false"}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v helm &> /dev/null; then
        log_error "helm is not installed or not in PATH"
        exit 1
    fi
    
    # Check kubectl connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Create namespace if it doesn't exist
create_namespace() {
    log_info "Creating namespace if not exists: $NAMESPACE"
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
}

# Validate Helm chart
validate_chart() {
    log_info "Validating Helm chart..."
    helm lint "$CHART_PATH"
    
    if [ "$?" -ne 0 ]; then
        log_error "Helm chart validation failed"
        exit 1
    fi
    
    log_info "Helm chart validation passed"
}

# Deploy or upgrade
deploy() {
    log_info "Deploying $RELEASE_NAME to namespace $NAMESPACE"
    
    HELM_ARGS=(
        "upgrade" "--install" "$RELEASE_NAME" "$CHART_PATH"
        "--namespace" "$NAMESPACE"
        "--create-namespace"
        "--wait"
        "--timeout" "10m"
    )
    
    if [ -f "$VALUES_FILE" ]; then
        log_info "Using values file: $VALUES_FILE"
        HELM_ARGS+=("--values" "$VALUES_FILE")
    else
        log_warn "Values file not found: $VALUES_FILE"
    fi
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "Running in dry-run mode"
        HELM_ARGS+=("--dry-run")
    fi
    
    helm "${HELM_ARGS[@]}"
    
    if [ "$?" -eq 0 ]; then
        log_info "Deployment successful"
    else
        log_error "Deployment failed"
        exit 1
    fi
}

# Check deployment status
check_status() {
    log_info "Checking deployment status..."
    
    # Wait for rollout to complete
    kubectl rollout status deployment/"$RELEASE_NAME" -n "$NAMESPACE" --timeout=300s
    
    # Check pod status
    kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=mcp-oauth-proxy"
    
    # Check service
    kubectl get service -n "$NAMESPACE" "$RELEASE_NAME"
    
    # Check ingress
    kubectl get ingress -n "$NAMESPACE" "$RELEASE_NAME" || log_warn "Ingress not found or disabled"
}

# Health check
health_check() {
    log_info "Performing health check..."
    
    # Port forward for health check
    kubectl port-forward service/"$RELEASE_NAME" 8443:4443 -n "$NAMESPACE" &
    PF_PID=$!
    
    # Wait for port forward to be ready
    sleep 5
    
    # Perform health check
    if curl -k -f https://localhost:8443/q/health/ready &> /dev/null; then
        log_info "Health check passed"
    else
        log_error "Health check failed"
        kill $PF_PID 2>/dev/null || true
        exit 1
    fi
    
    # Clean up port forward
    kill $PF_PID 2>/dev/null || true
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Deploy Athenz IDP Webhook to EKS"
    echo ""
    echo "Environment Variables:"
    echo "  NAMESPACE        Kubernetes namespace (default: athenz-webhook)"
    echo "  RELEASE_NAME     Helm release name (default: mcp-oauth-proxy)"
    echo "  CHART_PATH       Path to Helm chart (default: ./deploy/mcp-oauth-proxy)"
    echo "  VALUES_FILE      Values file path (default: values-prod.yaml)"
    echo "  DRY_RUN          Dry run mode (default: false)"
    echo ""
    echo "Options:"
    echo "  --dry-run        Run in dry-run mode"
    echo "  --skip-health    Skip health check"
    echo "  --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Deploy with defaults"
    echo "  $0 --dry-run                         # Dry run"
    echo "  VALUES_FILE=values-dev.yaml $0       # Use different values file"
    echo "  NAMESPACE=my-namespace $0            # Use different namespace"
}

# Parse arguments
SKIP_HEALTH=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-health)
            SKIP_HEALTH=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    log_info "Starting deployment of Athenz IDP Webhook"
    log_info "Namespace: $NAMESPACE"
    log_info "Release: $RELEASE_NAME"
    log_info "Chart: $CHART_PATH"
    log_info "Values: $VALUES_FILE"
    log_info "Dry Run: $DRY_RUN"
    
    check_prerequisites
    validate_chart
    create_namespace
    deploy
    
    if [ "$DRY_RUN" != "true" ]; then
        check_status
        
        if [ "$SKIP_HEALTH" != "true" ]; then
            health_check
        fi
        
        log_info "Deployment completed successfully!"
        log_info "Access your service at: https://$(kubectl get ingress $RELEASE_NAME -n $NAMESPACE -o jsonpath='{.spec.rules[0].host}' 2>/dev/null || echo 'localhost')"
    else
        log_info "Dry run completed successfully!"
    fi
}

# Run main function
main "$@" 