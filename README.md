<div align="center">

# 🛡️ Kubernetes Security Operations Center

### Built by [Humesh Deshmukh](https://github.com/humeshdeshmukh) · DevOps Portfolio Project #3

[![Kubernetes](https://img.shields.io/badge/Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![Trivy](https://img.shields.io/badge/Trivy-1904DA?style=for-the-badge&logo=aquasecurity&logoColor=white)](https://aquasecurity.github.io/trivy)
[![Falco](https://img.shields.io/badge/Falco-00AEC7?style=for-the-badge&logo=falco&logoColor=white)](https://falco.org)
[![Kyverno](https://img.shields.io/badge/Kyverno-FF6D00?style=for-the-badge&logo=kubernetes&logoColor=white)](https://kyverno.io)
[![OPA](https://img.shields.io/badge/OPA_Gatekeeper-7D9EC0?style=for-the-badge&logo=openpolicyagent&logoColor=white)](https://open-policy-agent.github.io/gatekeeper)
[![Grafana](https://img.shields.io/badge/Grafana-F46800?style=for-the-badge&logo=grafana&logoColor=white)](https://grafana.com)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Helm](https://img.shields.io/badge/Helm-0F1689?style=for-the-badge&logo=helm&logoColor=white)](https://helm.sh)

![Status](https://img.shields.io/badge/Status-✅%20Fully%20Operational-brightgreen?style=flat-square)
![Stage](https://img.shields.io/badge/Portfolio%20Stage-Mid--Level%20DevOps%20Engineer-blue?style=flat-square)
![Project](https://img.shields.io/badge/Project-3%20of%2010-orange?style=flat-square)

> A **production-grade Kubernetes Security Operations Center** that provides vulnerability scanning (Trivy), runtime threat detection (Falco), policy enforcement (Kyverno + OPA Gatekeeper), and unified security dashboards (Grafana) — covering the full spectrum of Kubernetes security from image build to runtime.

</div>

---

## 👋 About This Project

Hi, I'm **Humesh Deshmukh** — a DevOps Engineer building a 10-project portfolio that covers modern cloud-native engineering. This is **Project 3**, where I built a complete Kubernetes security platform that protects clusters at every layer:

- **Shift-Left**: Scan container images for CVEs before deployment
- **Admission Control**: Enforce security policies at deploy time via Kyverno & OPA
- **Runtime Defense**: Detect live threats (reverse shells, crypto mining) with Falco
- **Visibility**: Unified security dashboards in Grafana with alerting

This is the same security stack used by companies like Shopify, Mercari, and DigitalOcean to protect their Kubernetes infrastructure.

### 🔗 Portfolio Links

| | |
|---|---|
| 🌐 **Portfolio** | [humeshdeshmukh.dev](https://github.com/humeshdeshmukh) |
| 💼 **LinkedIn** | [linkedin.com/in/humeshdeshmukh](https://linkedin.com/in/humeshdeshmukh) |
| 🐙 **GitHub** | [github.com/humeshdeshmukh](https://github.com/humeshdeshmukh) |
| 📧 **Email** | <humeshdeshmukh0@gmail.com> |

---

## 🎯 What I Built & Why It Matters

| What I Did | Skill Demonstrated |
|---|---|
| Built a Trivy-based vulnerability scanner REST API | DevSecOps, Shift-Left Security |
| Wrote Falco rules for reverse shell, privesc, crypto mining | Runtime Security, Threat Detection |
| Created 5 Kyverno ClusterPolicies for Pod Security | Kubernetes-native Policy Enforcement |
| Built OPA Gatekeeper ConstraintTemplates with Rego | Policy-as-Code, Rego Language |
| Designed 3 Grafana security dashboards | Security Posture Visualization |
| Wrote PrometheusRule CRDs for security alerting | Incident Response, SRE Practices |
| Hardened containers: non-root, read-only rootfs, CAP_DROP ALL | Container Security Best Practices |
| Automated full stack deploy via Helm + bash | Infrastructure as Code |

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes Cluster (Minikube)                       │
│                                                                            │
│   ┌─────────────────────── Admission Control ─────────────────────────┐   │
│   │                                                                    │   │
│   │   ┌──────────────┐              ┌──────────────────┐              │   │
│   │   │   Kyverno     │              │  OPA Gatekeeper   │              │   │
│   │   │  5 Policies   │              │  2 Constraints    │              │   │
│   │   │  (Audit Mode) │              │  (Dry-run Mode)   │              │   │
│   │   └──────────────┘              └──────────────────┘              │   │
│   └────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│   ┌─────────────── Runtime Security ──────────────────┐                   │
│   │                                                    │                   │
│   │   ┌──────────────────────────────────────┐        │                   │
│   │   │            Falco (DaemonSet)          │        │                   │
│   │   │  eBPF kernel monitoring               │        │                   │
│   │   │  · Reverse shell detection            │        │                   │
│   │   │  · Privilege escalation detection     │        │                   │
│   │   │  · Crypto mining detection            │        │                   │
│   │   │  · Package manager detection          │        │                   │
│   │   └──────────────┬───────────────────────┘        │                   │
│   │                  │ alerts                          │                   │
│   └──────────────────│─────────────────────────────────┘                   │
│                      │                                                     │
│   ┌──────────────────│── Vulnerability Scanning ──────────────────────┐   │
│   │                  │                                                 │   │
│   │   ┌──────────────▼───────────────────────────────┐               │   │
│   │   │      Security Scanner API (Flask + Trivy)     │               │   │
│   │   │  POST /api/v1/scan/image → Trivy CLI scan     │               │   │
│   │   │  GET  /api/v1/scan/results → cached results   │               │   │
│   │   │  GET  /api/v1/scan/summary → aggregate stats  │               │   │
│   │   │  GET  /metrics → Prometheus security metrics   │               │   │
│   │   └──────────────┬───────────────────────────────┘               │   │
│   │                  │                                                 │   │
│   └──────────────────│─────────────────────────────────────────────────┘   │
│                      │                                                     │
│   ┌──────────────────│── Monitoring & Alerting ───────────────────────┐   │
│   │                  │                                                 │   │
│   │   ┌──────────────▼──────┐    ┌──────────────────┐                │   │
│   │   │     Prometheus       │    │   AlertManager    │                │   │
│   │   │  (scrapes all tools) │───▶│  (security alerts)│                │   │
│   │   └──────────────┬──────┘    └──────────────────┘                │   │
│   │                  │                                                 │   │
│   │   ┌──────────────▼──────────────────────────────┐                │   │
│   │   │              Grafana (NodePort :32000)        │                │   │
│   │   │  📊 Vulnerability Overview Dashboard          │                │   │
│   │   │  🔴 Runtime Threats Dashboard                 │                │   │
│   │   │  ✅ Policy Compliance Dashboard               │                │   │
│   │   └─────────────────────────────────────────────┘                │   │
│   └────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Tech Stack

| Component | Tool | Role |
|---|---|---|
| **Vulnerability Scanning** | Trivy | Scan container images for CVEs |
| **Runtime Security** | Falco | eBPF-based syscall monitoring |
| **Policy (K8s-native)** | Kyverno | Validate/Mutate Kubernetes resources |
| **Policy (Rego-based)** | OPA Gatekeeper | Rego constraint evaluation |
| **Metrics** | Prometheus | Scrape & store security metrics |
| **Visualization** | Grafana | Security posture dashboards |
| **Alerting** | AlertManager | Route security alerts |
| **App Framework** | Flask + Gunicorn | Scanner API microservice |
| **Packaging** | Helm | All deployments |
| **Container** | Docker (multi-stage) | Secure minimal images |
| **Orchestration** | Kubernetes (Minikube) | Local cluster |

---

## 📁 Project Structure

```
03-kubernetes-security-center/
│
├── 📄 README.md                                ← You are here
├── 📄 .gitignore
├── 🐳 Dockerfile                               # Multi-stage build + Trivy CLI
├── 📄 Makefile                                  # Build shortcuts
├── 🚀 deploy-security-soc.sh                   # One-shot deployment automation
│
├── 📂 app/                                      # Security Scanner microservice
│   ├── main.py                                  # Flask API + Prometheus metrics
│   ├── scanner.py                               # Trivy CLI integration module
│   ├── requirements.txt                         # Python dependencies
│   └── tests/
│       └── test_main.py                         # Unit tests (pytest)
│
├── 📂 helm/
│   └── security-scanner/                        # Helm chart for scanner app
│       ├── Chart.yaml
│       ├── values.yaml                          # Security-hardened defaults
│       └── templates/
│           ├── deployment.yaml                  # Non-root, read-only rootfs
│           ├── service.yaml                     # NodePort for Minikube
│           ├── servicemonitor.yaml              # Prometheus auto-discovery
│           ├── configmap.yaml
│           ├── serviceaccount.yaml              # RBAC identity
│           ├── clusterrole.yaml                 # Read-only cluster access
│           └── clusterrolebinding.yaml
│
├── 📂 helm-values/                              # Tool configuration
│   ├── falco-values.yaml                        # eBPF driver, JSON output
│   ├── kyverno-values.yaml                      # Audit mode, exclusions
│   └── gatekeeper-values.yaml                   # Dry-run, exempt namespaces
│
├── 📂 policies/                                 # Security policies
│   ├── kyverno/
│   │   ├── disallow-privileged.yaml             # Block privileged containers
│   │   ├── require-labels.yaml                  # Require app + team labels
│   │   ├── require-resource-limits.yaml         # Enforce CPU/memory limits
│   │   ├── disallow-latest-tag.yaml             # Block :latest images
│   │   └── require-readonly-rootfs.yaml         # Enforce read-only rootfs
│   └── opa/
│       ├── constraint-templates/
│       │   ├── k8s-required-labels.yaml         # Rego: required labels
│       │   └── k8s-block-nodeport.yaml          # Rego: block NodePort
│       └── constraints/
│           ├── require-app-label.yaml           # Enforce app + owner labels
│           └── block-nodeport-svc.yaml          # Block NodePort in prod
│
├── 📂 falco/                                    # Runtime security rules
│   └── custom-rules.yaml                        # Reverse shell, privesc, mining
│
├── 📂 dashboards/                               # Grafana dashboards (JSON)
│   ├── vulnerability-overview.json              # CVE counts, severity, trends
│   ├── runtime-threats.json                     # Falco alerts timeline
│   └── policy-compliance.json                   # Kyverno/OPA pass/fail rates
│
└── 📂 kubernetes/                               # Raw K8s manifests
    ├── alertmanager-security-rules.yaml         # PrometheusRule CRDs
    └── falco-servicemonitor.yaml                # Scrape Falco metrics
```

---

## 🚀 Deploy It Yourself

### Prerequisites

```bash
# Required tools
minikube version   # Local Kubernetes cluster
helm version       # Package manager (v3+)
docker version     # Container build
kubectl version    # Cluster management
```

### One-Command Deploy

```bash
git clone https://github.com/humeshdeshmukh/devops-portfolio
cd 03-kubernetes-security-center

chmod +x deploy-security-soc.sh
./deploy-security-soc.sh
```

### Manual Step-by-Step

```bash
# 1. Start Minikube with sufficient resources
minikube start --memory=6144 --cpus=4

# 2. Add Helm repos
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo add kyverno https://kyverno.github.io/kyverno
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update

# 3. Create security namespace
kubectl create namespace security

# 4. Deploy Prometheus + Grafana
helm install prometheus-operator prometheus-community/kube-prometheus-stack \
  -n security --set grafana.service.type=NodePort --set grafana.service.nodePort=32000

# 5. Deploy Falco
helm install falco falcosecurity/falco -n security -f helm-values/falco-values.yaml

# 6. Deploy Kyverno + policies
helm install kyverno kyverno/kyverno -n security -f helm-values/kyverno-values.yaml
kubectl apply -f policies/kyverno/

# 7. Deploy OPA Gatekeeper + constraints
helm install gatekeeper gatekeeper/gatekeeper -n security -f helm-values/gatekeeper-values.yaml
kubectl apply -f policies/opa/constraint-templates/
sleep 10
kubectl apply -f policies/opa/constraints/

# 8. Build and deploy the security scanner
docker build -t security-scanner:latest .
minikube image load security-scanner:latest
helm install security-scanner ./helm/security-scanner --set service.type=NodePort
```

---

## 🌐 Access the Platform

> Get your Minikube IP: `minikube ip`

| Service | URL | Credentials |
|---|---|---|
| 🟠 **Grafana** | `http://<minikube-ip>:32000` | `admin` / `admin` |
| 🛡️ **Scanner API** | `http://<minikube-ip>:31900/` | — |
| ❤️ **Health Check** | `http://<minikube-ip>:31900/health` | — |
| 📈 **Prometheus Metrics** | `http://<minikube-ip>:31900/metrics` | — |

---

## 📊 Grafana Dashboards

### 1. Vulnerability Overview Dashboard

Security posture at a glance:

- **Total CVEs** — stat panel with severity threshold colors
- **Critical / High** — individual severity counters
- **Severity Breakdown** — donut chart (CRITICAL/HIGH/MEDIUM/LOW)
- **Scan History** — stacked bar chart (success vs failure)
- **Vulnerability Trend** — time series with per-severity lines
- **Scan Duration (p95/p50)** — performance tracking

### 2. Runtime Threats Dashboard

Falco-powered threat visibility:

- **Alert Counters** — Critical, Warning, Notice stats
- **Alert Timeline** — stacked bar chart by severity over time
- **Top Rules Triggered** — bar chart of most active Falco rules
- **Threat Categories** — donut chart by priority level
- **Alerts by Namespace** — which namespaces are generating alerts
- **Alerts by Image** — which images are triggering detections

### 3. Policy Compliance Dashboard

Kyverno + OPA compliance tracking:

- **Compliance Score** — gauge (0–100%) with color thresholds
- **Kyverno Pass/Fail** — stat panels
- **OPA Violations** — total constraint violations
- **Policy Results Over Time** — pass/fail trend lines
- **Per-Policy Results** — horizontal bar chart by policy name
- **Violations by Constraint** — OPA constraint breakdown

---

## 🔐 Security Policies

### Kyverno Policies (Kubernetes-Native)

| Policy | Type | What It Enforces |
|---|---|---|
| `disallow-privileged` | Validate | Blocks `privileged: true` containers |
| `require-labels` | Validate | Requires `app.kubernetes.io/name` + `team` labels |
| `require-resource-limits` | Validate | Enforces CPU/memory limits on all containers |
| `disallow-latest-tag` | Validate | Blocks `:latest` image tag |
| `require-readonly-rootfs` | Validate | Enforces `readOnlyRootFilesystem: true` |

> All policies run in **Audit** mode — they log violations but don't block deployments.
> Switch to `Enforce` mode by changing `validationFailureAction: Enforce` in each policy.

### OPA Gatekeeper Policies (Rego-Based)

| ConstraintTemplate | Constraint | What It Enforces |
|---|---|---|
| `K8sRequiredLabels` | `require-app-and-owner-labels` | `app` + `owner` labels on Deployments |
| `K8sBlockNodePort` | `block-nodeport-in-production` | No NodePort services outside dev namespaces |

> All constraints run in **dry-run** mode (`enforcementAction: dryrun`).

---

## 🦅 Falco Runtime Rules

| Rule | Threat | Priority | Detection Logic |
|---|---|---|---|
| Reverse Shell Detected | Command & Control | 🔴 CRITICAL | Shell process + outbound network connection |
| Privilege Escalation via setuid | Privilege Escalation | ⚠️ WARNING | setuid/setgid/setresuid syscalls in containers |
| Container Running as Root | Privilege Escalation | 📋 NOTICE | UID 0 process spawn in non-system namespace |
| Crypto Mining Process | Resource Hijacking | 🔴 CRITICAL | Known miner process names or stratum protocol |
| Outbound Mining Pool Connection | Resource Hijacking | ⚠️ WARNING | Connections to mining pool ports (3333, 4444, etc.) |
| Package Manager in Container | Post-Exploitation | 📋 NOTICE | apt/yum/pip/npm execution in running container |

---

## 🔔 Scanner API Usage

### Scan a Container Image

```bash
curl -X POST http://<minikube-ip>:31900/api/v1/scan/image \
  -H 'Content-Type: application/json' \
  -d '{"image": "nginx:1.25"}' | python3 -m json.tool
```

### View Scan Results

```bash
curl -s http://<minikube-ip>:31900/api/v1/scan/results | python3 -m json.tool
```

### Get Vulnerability Summary

```bash
curl -s http://<minikube-ip>:31900/api/v1/scan/summary | python3 -m json.tool
```

### Check Security Metrics (Prometheus)

```bash
curl -s http://<minikube-ip>:31900/metrics | grep security_
```

---

## 🚨 Alerting Rules

| Alert Name | Condition | Severity | Action |
|---|---|---|---|
| `CriticalVulnerabilitiesDetected` | Any CRITICAL CVE found | 🔴 critical | Remediate immediately |
| `HighVulnerabilityCountExceeded` | Total CVEs > 100 | ⚠️ warning | Prioritize remediation |
| `ScanFailureRateHigh` | > 30% scan failures | ⚠️ warning | Check Trivy + scanner logs |
| `FalcoCriticalAlert` | Any Falco CRITICAL event | 🔴 critical | Investigate active compromise |
| `FalcoHighAlertRate` | > 20 alerts in 5min | ⚠️ warning | Check for attack or noisy rules |
| `KyvernoPolicyViolationsHigh` | > 10 policy failures | ⚠️ warning | Review `kubectl get policyreport` |
| `GatekeeperViolationsDetected` | > 5 constraint violations | ⚠️ warning | Review `kubectl get constraints` |
| `SecurityScannerDown` | Scanner unreachable 2min | 🔴 critical | Check pod status |
| `SecurityScannerHighLatency` | p95 > 2s | ⚠️ warning | Profile slow scans |

---

## 🔧 Key Engineering Decisions

### Why both Kyverno AND OPA Gatekeeper?

They serve complementary roles:

- **Kyverno** is Kubernetes-native — policies are written in YAML, no new language to learn. Ideal for teams that want simple, declarative policies.
- **OPA Gatekeeper** uses **Rego** — a full policy language that can express complex logic (e.g., cross-resource validation). Used when you need more power than YAML allows.

In a real organization, you'd likely pick one. Having both demonstrates proficiency with the two dominant policy engines in the Kubernetes ecosystem.

### Why Audit/Dry-run mode instead of Enforce?

In production, you'd gradually promote policies from Audit → Enforce after validating they don't break existing workloads. Starting in Audit mode lets you:

1. See what would fail without blocking anything
2. Fix violations before flipping the switch
3. Avoid self-inflicted outages from overly strict policies

### Why eBPF for Falco instead of the kernel module?

The kernel module requires exact kernel header matching and can cause stability issues. The eBPF driver is:

- Safer (runs in userspace sandbox)
- More portable across kernel versions
- Easier to deploy on managed Kubernetes and Minikube
- The direction Falco is moving toward

### Why a custom Scanner API instead of running Trivy directly?

Wrapping Trivy in an API provides:

- **Programmatic access** for CI/CD integration
- **Prometheus metrics** for vulnerability tracking over time
- **Result caching** for dashboard queries
- **Rate limiting** and error handling
- A pattern that mirrors how production security platforms work (e.g., Snyk, Aqua)

---

## 🐛 Troubleshooting Guide

<details>
<summary><b>Falco fails to start (kernel module / eBPF issues)</b></summary>

```bash
# Check Falco pod logs
kubectl logs -n security -l app.kubernetes.io/name=falco

# If using Minikube, ensure the eBPF driver is configured
# The helm-values/falco-values.yaml already sets driver.kind: ebpf

# On some systems, you may need to start Minikube with:
minikube start --driver=docker --memory=6144 --cpus=4
```

</details>

<details>
<summary><b>Kyverno policies not appearing</b></summary>

```bash
# Check Kyverno is running
kubectl get pods -n security -l app.kubernetes.io/name=kyverno

# List all cluster policies
kubectl get cpol

# Check policy reports for violations
kubectl get policyreport -A
kubectl describe policyreport -n default
```

</details>

<details>
<summary><b>OPA Gatekeeper constraints not working</b></summary>

```bash
# Verify Gatekeeper is running
kubectl get pods -n security -l app.kubernetes.io/name=gatekeeper

# Check ConstraintTemplates are established
kubectl get constrainttemplates

# Check Constraints and their violations
kubectl get constraints
kubectl describe k8srequiredlabels require-app-and-owner-labels
```

</details>

<details>
<summary><b>Scanner API returns "Trivy not found"</b></summary>

```bash
# Verify Trivy is installed in the container
kubectl exec -n default deployment/security-scanner -- trivy --version

# Check the Docker image includes Trivy
docker run --rm security-scanner:latest trivy --version

# If missing, rebuild the image — the Dockerfile installs Trivy in the builder stage
docker build --no-cache -t security-scanner:latest .
```

</details>

<details>
<summary><b>Grafana dashboards not showing data</b></summary>

```bash
# Verify Prometheus is scraping the scanner
kubectl port-forward -n security svc/prometheus-operated 9090
# Visit http://localhost:9090/targets — look for security-scanner

# Check dashboard ConfigMaps are labeled
kubectl get configmap -n security -l grafana_dashboard=1

# Verify Grafana sidecar is watching for dashboards
kubectl logs -n security -l app.kubernetes.io/name=grafana -c grafana-sc-dashboard
```

</details>

---

## 📚 Skills Demonstrated

```
Kubernetes Security Engineering
├── ✅ Vulnerability Scanning (Trivy image scan + API wrapper)
├── ✅ Runtime Threat Detection (Falco eBPF + custom rules)
├── ✅ Admission Control (Kyverno ClusterPolicies)
├── ✅ Policy-as-Code (OPA Gatekeeper + Rego ConstraintTemplates)
└── ✅ Security Dashboarding (3 Grafana dashboards)

DevSecOps Practices
├── ✅ Shift-Left Security (scan before deploy)
├── ✅ Container Hardening (non-root, read-only, CAP_DROP ALL)
├── ✅ RBAC (least-privilege ServiceAccount + ClusterRole)
├── ✅ Security Alerting (PrometheusRule CRDs, 9 alert rules)
└── ✅ Compliance Automation (audit mode → enforce promotion)

Platform Engineering
├── ✅ Helm chart authoring (templates, RBAC, SecurityContext)
├── ✅ Multi-tool orchestration (5 Helm releases in 1 script)
├── ✅ Prometheus ServiceMonitor CRDs (auto-discovery)
├── ✅ Structured JSON logging (production standard)
├── ✅ Multi-stage Docker builds (Trivy + Python, minimal image)
└── ✅ Automated deployment scripting (10-step pipeline)
```

---

<div align="center">

**Built with ❤️ by Humesh Deshmukh**

*If this project helped you, please ⭐ the repo!*

[![GitHub followers](https://img.shields.io/github/followers/humeshdeshmukh?style=social)](https://github.com/humeshdeshmukh)

</div>
