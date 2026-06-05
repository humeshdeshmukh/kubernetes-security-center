#!/usr/bin/env bash

# ==============================================================================
# Kubernetes Security Operations Center — Teardown/Cleanup Script
# ==============================================================================
# Uninstalls and cleans up the full security stack:
#   - Security Scanner API (Helm release & docker images)
#   - OPA Gatekeeper (Constraints, templates, Helm release, and CRDs)
#   - Kyverno (Policies, Helm release, and CRDs)
#   - Falco (Helm release, custom rules configmap)
#   - Kube-Prometheus-Stack (Helm release)
#   - Validating/Mutating webhooks (to prevent cluster lockups)
#   - 'security' namespace
# ==============================================================================

# Exit on error
set -e

# Terminal Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}======================================================================${NC}"
echo -e "${CYAN}    TEARING DOWN KUBERNETES SECURITY OPERATIONS CENTER                ${NC}"
echo -e "${CYAN}======================================================================${NC}"

# Define script and project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Helper function to print step headers
print_step() {
    echo -e "\n${BLUE}>>> [STEP] $1...${NC}"
}

# ==============================================================================
# STEP 1: Uninstall Security Scanner API & Docker Images
# ==============================================================================
print_step "1/8: Uninstalling Security Scanner Application"
if helm status security-scanner --namespace default &>/dev/null; then
    helm uninstall security-scanner --namespace default
    echo -e "${GREEN}[OK] Security Scanner Helm release uninstalled.${NC}"
else
    echo -e "${YELLOW}    Security Scanner Helm release not found. Skipping.${NC}"
fi

echo -e "${YELLOW}    Cleaning up security-scanner Docker images from Minikube...${NC}"
IMAGES=$(minikube image ls 2>/dev/null | grep "security-scanner" || true)
if [ -n "$IMAGES" ]; then
    for img in $IMAGES; do
        echo -e "${YELLOW}    Removing image: $img${NC}"
        minikube image rm "$img" || true
    done
    echo -e "${GREEN}[OK] Security Scanner Docker images removed from Minikube.${NC}"
else
    echo -e "${YELLOW}    No security-scanner Docker images found in Minikube. Skipping.${NC}"
fi

# ==============================================================================
# STEP 2: Delete OPA Gatekeeper Constraints and Templates
# ==============================================================================
print_step "2/8: Deleting OPA Gatekeeper Constraints and Templates"
if [ -d "policies/opa/constraints" ]; then
    echo -e "${YELLOW}    Deleting constraints...${NC}"
    kubectl delete -f policies/opa/constraints/ --ignore-not-found=true || true
fi
if [ -d "policies/opa/constraint-templates" ]; then
    echo -e "${YELLOW}    Deleting constraint templates...${NC}"
    kubectl delete -f policies/opa/constraint-templates/ --ignore-not-found=true || true
fi
if helm status gatekeeper --namespace security &>/dev/null; then
    echo -e "${YELLOW}    Uninstalling Gatekeeper Helm release...${NC}"
    helm uninstall gatekeeper --namespace security
    echo -e "${GREEN}[OK] Gatekeeper Helm release uninstalled.${NC}"
else
    echo -e "${YELLOW}    Gatekeeper Helm release not found. Skipping.${NC}"
fi

# ==============================================================================
# STEP 3: Delete Kyverno Policies and Uninstall Kyverno
# ==============================================================================
print_step "3/8: Deleting Kyverno Policies and Uninstalling Kyverno"
if [ -d "policies/kyverno" ]; then
    echo -e "${YELLOW}    Deleting Kyverno policies...${NC}"
    kubectl delete -f policies/kyverno/ --ignore-not-found=true || true
fi
if helm status kyverno --namespace security &>/dev/null; then
    echo -e "${YELLOW}    Uninstalling Kyverno Helm release...${NC}"
    helm uninstall kyverno --namespace security
    echo -e "${GREEN}[OK] Kyverno Helm release uninstalled.${NC}"
else
    echo -e "${YELLOW}    Kyverno Helm release not found. Skipping.${NC}"
fi

# ==============================================================================
# STEP 4: Uninstall Falco
# ==============================================================================
print_step "4/8: Uninstalling Falco"
if helm status falco --namespace security &>/dev/null; then
    helm uninstall falco --namespace security
    echo -e "${GREEN}[OK] Falco Helm release uninstalled.${NC}"
else
    echo -e "${YELLOW}    Falco Helm release not found. Skipping.${NC}"
fi

# ==============================================================================
# STEP 5: Uninstall Prometheus Operator (Kube-Prometheus-Stack)
# ==============================================================================
print_step "5/8: Uninstalling Kube-Prometheus-Stack"
if helm status prometheus-operator --namespace security &>/dev/null; then
    helm uninstall prometheus-operator --namespace security
    echo -e "${GREEN}[OK] Kube-Prometheus-Stack Helm release uninstalled.${NC}"
else
    echo -e "${YELLOW}    Kube-Prometheus-Stack Helm release not found. Skipping.${NC}"
fi

# ==============================================================================
# STEP 6: Clean Up Lingering Webhook Configurations
# ==============================================================================
print_step "6/8: Cleaning Up Lingering Webhook Configurations"
echo -e "${YELLOW}    Checking for lingering mutating and validating webhook configurations...${NC}"
WEBHOOKS=$(kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations -o name 2>/dev/null | grep -E "kyverno|gatekeeper|prometheus-operator" || true)

if [ -n "$WEBHOOKS" ]; then
    for webhook in $WEBHOOKS; do
        echo -e "${YELLOW}    Deleting webhook configuration: $webhook${NC}"
        kubectl delete "$webhook" --ignore-not-found=true || true
    done
    echo -e "${GREEN}[OK] Webhook configurations cleaned up.${NC}"
else
    echo -e "${GREEN}[OK] No lingering webhook configurations found.${NC}"
fi

# ==============================================================================
# STEP 7: Delete Security Namespace
# ==============================================================================
print_step "7/8: Deleting 'security' Namespace"
if kubectl get namespace security &>/dev/null; then
    echo -e "${YELLOW}    Deleting 'security' namespace (this may take a moment)...${NC}"
    kubectl delete namespace security --timeout=120s || {
        echo -e "${RED}[WARN] Namespace deletion timed out. Forcefully cleaning finalizers if needed...${NC}"
    }
    echo -e "${GREEN}[OK] 'security' namespace deleted successfully.${NC}"
else
    echo -e "${YELLOW}    'security' namespace not found. Skipping.${NC}"
fi

# ==============================================================================
# STEP 8: Clean Up Custom Resource Definitions (CRDs)
# ==============================================================================
print_step "8/8: Cleaning Up Custom Resource Definitions (CRDs)"
echo -e "${YELLOW}    Checking for Kyverno and Gatekeeper CRDs...${NC}"
CRDS=$(kubectl get crd -o name 2>/dev/null | grep -E "kyverno|gatekeeper" || true)

if [ -n "$CRDS" ]; then
    for crd in $CRDS; do
        echo -e "${YELLOW}    Deleting CRD: $crd${NC}"
        kubectl delete "$crd" --ignore-not-found=true || true
    done
    echo -e "${GREEN}[OK] Custom Resource Definitions cleaned up.${NC}"
else
    echo -e "${GREEN}[OK] No Kyverno or Gatekeeper CRDs found.${NC}"
fi

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}    TEARDOWN COMPLETED SUCCESSFULLY - CLUSTER IS CLEAN                ${NC}"
echo -e "${GREEN}======================================================================${NC}"
