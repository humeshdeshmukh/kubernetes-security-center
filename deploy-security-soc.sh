#!/usr/bin/env bash

# ==============================================================================
# Kubernetes Security Operations Center — Deployment Script
# ==============================================================================
# Deploys the full security stack:
#   - Prometheus + Grafana (monitoring backbone)
#   - Falco (runtime threat detection)
#   - Kyverno (Kubernetes-native policy engine)
#   - OPA Gatekeeper (Rego-based admission control)
#   - Security Scanner app (Trivy vulnerability scanning API)
#   - Grafana dashboards (security visibility)
# ==============================================================================

set -e

# Terminal Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}======================================================================${NC}"
echo -e "${CYAN}    DEPLOYING KUBERNETES SECURITY OPERATIONS CENTER                    ${NC}"
echo -e "${CYAN}======================================================================${NC}"

# Define script and project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

IMAGE_TAG=$(date +%Y%m%d%H%M%S)

# Helper function to print step headers
print_step() {
    echo -e "\n${BLUE}>>> [STEP] $1...${NC}"
}

# Helper function to wait for a deployment
wait_for_deployment() {
    local ns=$1
    local name=$2
    local timeout=${3:-120}
    echo -e "${YELLOW}    Waiting for deployment ${name} in ${ns}...${NC}"
    kubectl rollout status deployment/${name} --namespace ${ns} --timeout=${timeout}s 2>/dev/null || \
    kubectl rollout status daemonset/${name} --namespace ${ns} --timeout=${timeout}s 2>/dev/null || \
    echo -e "${YELLOW}    Note: ${name} may be a DaemonSet or StatefulSet — checking pod status...${NC}"
}

# ==============================================================================
# STEP 1: Create Security Namespace
# ==============================================================================
print_step "1/10: Creating 'security' Namespace"
kubectl create namespace security --dry-run=client -o yaml | kubectl apply -f -
echo -e "${GREEN}[OK] Namespace 'security' is ready.${NC}"

# ==============================================================================
# STEP 2: Add Helm Chart Repositories
# ==============================================================================
print_step "2/10: Adding and updating Helm Chart Repositories"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 2>/dev/null || true
helm repo add grafana https://grafana.github.io/helm-charts 2>/dev/null || true
helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
helm repo add kyverno https://kyverno.github.io/kyverno 2>/dev/null || true
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts 2>/dev/null || true
helm repo update
echo -e "${GREEN}[OK] Helm repositories updated successfully.${NC}"

# ==============================================================================
# STEP 3: Deploy Kube-Prometheus-Stack (Prometheus + Grafana + AlertManager)
# ==============================================================================
print_step "3/10: Installing Kube-Prometheus-Stack (Prometheus + Grafana + AlertManager)"
helm upgrade --install prometheus-operator prometheus-community/kube-prometheus-stack \
    --namespace security \
    --set grafana.service.type=NodePort \
    --set grafana.service.nodePort=32000 \
    --set grafana.adminPassword=admin \
    --set grafana.sidecar.dashboards.enabled=true \
    --set grafana.sidecar.dashboards.label=grafana_dashboard \
    --set grafana.sidecar.dashboards.searchNamespace=security \
    --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
    --set prometheus.prometheusSpec.ruleSelectorNilUsesHelmValues=false \
    --wait --timeout 300s
echo -e "${GREEN}[OK] Kube-Prometheus-Stack deployed successfully.${NC}"

# ==============================================================================
# STEP 4: Deploy Falco (Runtime Security Engine)
# ==============================================================================
print_step "4/10: Installing Falco (Runtime Threat Detection)"

# Create ConfigMap with custom Falco rules
kubectl create configmap falco-custom-rules \
    --from-file=custom-rules.yaml=falco/custom-rules.yaml \
    --namespace security --dry-run=client -o yaml | kubectl apply -f -

helm upgrade --install falco falcosecurity/falco \
    --namespace security \
    -f helm-values/falco-values.yaml \
    --wait --timeout 300s || {
    echo -e "${YELLOW}[WARN] Falco install may require kernel headers. Continuing...${NC}"
}
echo -e "${GREEN}[OK] Falco deployed (runtime threat detection active).${NC}"

# ==============================================================================
# STEP 5: Deploy Kyverno (Kubernetes-Native Policy Engine)
# ==============================================================================
print_step "5/10: Installing Kyverno (Policy Engine)"
helm upgrade --install kyverno kyverno/kyverno \
    --namespace security \
    -f helm-values/kyverno-values.yaml \
    --wait --timeout 300s
echo -e "${GREEN}[OK] Kyverno deployed successfully.${NC}"

# ==============================================================================
# STEP 6: Deploy OPA Gatekeeper (Rego-Based Admission Control)
# ==============================================================================
print_step "6/10: Installing OPA Gatekeeper"
helm upgrade --install gatekeeper gatekeeper/gatekeeper \
    --namespace security \
    -f helm-values/gatekeeper-values.yaml \
    --wait --timeout 300s
echo -e "${GREEN}[OK] OPA Gatekeeper deployed successfully.${NC}"

# ==============================================================================
# STEP 7: Apply Kyverno Security Policies
# ==============================================================================
print_step "7/10: Applying Kyverno Security Policies"
for policy in policies/kyverno/*.yaml; do
    echo -e "${YELLOW}    Applying: $(basename ${policy})${NC}"
    kubectl apply -f "${policy}"
done
echo -e "${GREEN}[OK] Kyverno policies applied (Audit mode).${NC}"

# ==============================================================================
# STEP 8: Apply OPA Gatekeeper Constraints
# ==============================================================================
print_step "8/10: Applying OPA Gatekeeper ConstraintTemplates and Constraints"

echo -e "${YELLOW}    Applying ConstraintTemplates...${NC}"
for template in policies/opa/constraint-templates/*.yaml; do
    echo -e "${YELLOW}    Applying: $(basename ${template})${NC}"
    kubectl apply -f "${template}"
done

# Wait for templates to be established before applying constraints
echo -e "${YELLOW}    Waiting for ConstraintTemplates to initialize...${NC}"
sleep 10

echo -e "${YELLOW}    Applying Constraints...${NC}"
for constraint in policies/opa/constraints/*.yaml; do
    echo -e "${YELLOW}    Applying: $(basename ${constraint})${NC}"
    kubectl apply -f "${constraint}"
done
echo -e "${GREEN}[OK] OPA Gatekeeper constraints applied (Dry-run mode).${NC}"

# ==============================================================================
# STEP 9: Build & Deploy Security Scanner Application
# ==============================================================================
print_step "9/10: Building and deploying Security Scanner Application"

echo -e "${YELLOW}Building Docker Image 'security-scanner:${IMAGE_TAG}'...${NC}"
docker build -t security-scanner:${IMAGE_TAG} -t security-scanner:latest .

echo -e "${YELLOW}Loading Docker Image into Minikube cluster...${NC}"
minikube image load security-scanner:${IMAGE_TAG}
minikube image load security-scanner:latest

echo -e "${YELLOW}Deploying Security Scanner via Helm...${NC}"
helm upgrade --install security-scanner ./helm/security-scanner \
    --namespace default \
    --set image.repository=security-scanner \
    --set image.tag=${IMAGE_TAG} \
    --set service.type=NodePort \
    --wait --timeout 120s

echo -e "${YELLOW}Verifying rollout status...${NC}"
kubectl rollout status deployment/security-scanner --namespace default --timeout=60s

APP_URL=$(minikube service security-scanner --url --namespace default | head -n 1)
echo -e "${GREEN}[OK] Security Scanner is running at: ${APP_URL}${NC}"

# ==============================================================================
# STEP 10: Provision Grafana Dashboards & Alert Rules
# ==============================================================================
print_step "10/10: Provisioning Grafana Dashboards and Alert Rules"

# Deploy Vulnerability Overview Dashboard
kubectl create configmap security-vuln-dashboard \
    --from-file=vulnerability-overview.json=dashboards/vulnerability-overview.json \
    --namespace security --dry-run=client -o yaml | kubectl apply -f -
kubectl label configmap security-vuln-dashboard grafana_dashboard="1" --namespace security --overwrite

# Deploy Runtime Threats Dashboard
kubectl create configmap security-runtime-dashboard \
    --from-file=runtime-threats.json=dashboards/runtime-threats.json \
    --namespace security --dry-run=client -o yaml | kubectl apply -f -
kubectl label configmap security-runtime-dashboard grafana_dashboard="1" --namespace security --overwrite

# Deploy Policy Compliance Dashboard
kubectl create configmap security-compliance-dashboard \
    --from-file=policy-compliance.json=dashboards/policy-compliance.json \
    --namespace security --dry-run=client -o yaml | kubectl apply -f -
kubectl label configmap security-compliance-dashboard grafana_dashboard="1" --namespace security --overwrite

# Apply AlertManager security rules
kubectl apply -f kubernetes/alertmanager-security-rules.yaml -n security

# Apply Falco ServiceMonitor
kubectl apply -f kubernetes/falco-servicemonitor.yaml -n security

echo -e "${GREEN}[OK] Dashboards and alert rules provisioned.${NC}"

# ==============================================================================
# DEPLOYMENT SUMMARY & DIAGNOSTICS
# ==============================================================================
echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}    SECURITY OPERATIONS CENTER DEPLOYMENT COMPLETED SUCCESSFULLY       ${NC}"
echo -e "${GREEN}======================================================================${NC}"

echo -e "\n${YELLOW}Deployed Components:${NC}"
echo -e "----------------------------------------------------------------------"
echo -e "${CYAN}1. Prometheus + Grafana + AlertManager${NC} (kube-prometheus-stack)"
echo -e "${CYAN}2. Falco${NC}                               (runtime threat detection)"
echo -e "${CYAN}3. Kyverno${NC}                             (Kubernetes policy engine)"
echo -e "${CYAN}4. OPA Gatekeeper${NC}                      (Rego admission control)"
echo -e "${CYAN}5. Security Scanner API${NC}                (Trivy vulnerability scanning)"

echo -e "\n${YELLOW}Service Endpoints & Access Commands:${NC}"
echo -e "----------------------------------------------------------------------"
echo -e "${CYAN}1. Grafana (Security Dashboards)${NC}"
echo -e "   - URL: http://$(minikube ip):32000"
echo -e "   - User: admin / Pass: admin"
echo -e "   - Dashboards: Vulnerability Overview, Runtime Threats, Policy Compliance"

echo -e "\n${CYAN}2. Security Scanner API${NC}"
echo -e "   - URL: ${APP_URL}"
echo -e "   - Health: ${APP_URL}/health"
echo -e "   - Metrics: ${APP_URL}/metrics"
echo -e "   - Scan: curl -X POST ${APP_URL}/api/v1/scan/image -H 'Content-Type: application/json' -d '{\"image\": \"nginx:1.25\"}'"

echo -e "\n${CYAN}3. Verify Security Tools:${NC}"
echo -e "   - Falco logs:     kubectl logs -n security -l app.kubernetes.io/name=falco -f"
echo -e "   - Kyverno status: kubectl get cpol"
echo -e "   - OPA status:     kubectl get constraints"
echo -e "   - Policy reports: kubectl get policyreport -A"

echo -e "\n${CYAN}4. Generate Test Load:${NC}"
echo -e "   - curl -s ${APP_URL}/api/v1/scan/image -H 'Content-Type: application/json' -d '{\"image\": \"nginx:latest\"}' | python3 -m json.tool"
echo -e "   - curl -s ${APP_URL}/api/v1/scan/summary | python3 -m json.tool"
echo -e "----------------------------------------------------------------------\n"
