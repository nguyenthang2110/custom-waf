# Custom WAF Project - Complete Deployment Guide

## 📦 Project Structure

```
waf-project/
├── cmd/waf/main.go                    # Entry point ✓
├── internal/
│   ├── parser/parser.go               # HTTP Parser ✓
│   ├── normalizer/normalizer.go       # Normalizer ✓
│   ├── engine/
│   │   ├── types.go                   # Data structures ✓
│   │   ├── rule_engine.go             # Rule engine ✓
│   │   ├── transforms.go              # Transforms ✓
│   │   └── matchers.go                # Matchers ✓
│   ├── ratelimit/ratelimit.go         # Rate limiter ✓
│   ├── behavior/detector.go           # Behavior detection ✓
│   ├── decision/decision.go           # Decision engine ✓
│   ├── audit/logger.go                # Audit logger ✓
│   ├── metrics/metrics.go             # Prometheus metrics ✓
│   └── middleware/waf.go              # WAF middleware ✓
├── pkg/config/config.go               # Config loader ✓
├── configs/
│   ├── config.yaml                    # Main config ✓
│   └── rules/all_rules.json           # WAF rules ✓
├── deployments/docker/
│   ├── Dockerfile                     # Docker build ✓
│   └── docker-compose.yml             # Docker compose ✓
├── go.mod                             # Go modules ✓
├── Makefile                           # Build automation ✓
└── README.md                          # Documentation ✓
```

## 🚀 Quick Start

### 1. Prerequisites

```bash
# Install Go 1.21+
curl -OL https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install Docker & Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 2. Setup Project

```bash
# Clone project
git clone https://github.com/yourorg/waf-project
cd waf-project

# Initialize Go modules
go mod init waf-project
go mod tidy

# Create directories
mkdir -p bin configs/rules deployments/docker logs
```

### 3. Build & Run

#### Option A: Native Build

```bash
# Build
make build

# Run
./bin/waf -config configs/config.yaml -rules configs/rules/all_rules.json

# Test
curl http://localhost:8080/api/users?id=1
curl http://localhost:8080/api/users?id=1%27%20UNION%20SELECT  # Should block
```

#### Option B: Docker

```bash
# Build image
make docker

# Run with Docker Compose
docker-compose -f deployments/docker/docker-compose.yml up -d

# View logs
docker-compose logs -f waf

# Stop
docker-compose down
```

## 📋 Configuration

### Main Config (`configs/config.yaml`)

```yaml
server:
  listen: "0.0.0.0:8080"
  read_timeout: 30
  write_timeout: 30
  idle_timeout: 120

upstream:
  url: "http://backend:8000" # Your backend service

parser:
  max_body_size: 10485760 # 10MB

rate_limit:
  requests_per_min: 100
  burst_size: 20

behavior:
  bruteforce_threshold: 5
  bruteforce_window: 300s

decision:
  block_threshold: 10.0 # Block if score >= 10
  challenge_threshold: 5.0 # Challenge if score >= 5

audit:
  log_path: "/var/log/waf/audit.log"
```

### Rule Configuration

Rules are in JSON format at `configs/rules/all_rules.json`. Each rule has:

```json
{
  "id": "WAF-001-SQLI-UNION",
  "enabled": true,
  "metadata": {
    "category": "SQL Injection",
    "severity": "CRITICAL",
    "description": "..."
  },
  "conditions": {
    "targets": ["PATH", "QUERY", "BODY"],
    "methods": ["GET", "POST"]
  },
  "transforms": ["URL_DECODE", "LOWERCASE"],
  "patterns": [
    {
      "type": "REGEX",
      "pattern": "union.*select"
    }
  ],
  "scoring": {
    "anomaly_score": 5,
    "severity_multiplier": 1.5
  }
}
```

## 🧪 Testing

### Unit Tests

```bash
# Run all tests
make test

# Test specific package
go test -v ./internal/parser
go test -v ./internal/engine
go test -v ./internal/normalizer
```

### Integration Tests

```bash
# Test SQLi detection
curl "http://localhost:8080/api?id=1' UNION SELECT * FROM users--"
# Expected: 403 Forbidden

# Test XSS detection
curl "http://localhost:8080/search?q=<script>alert(1)</script>"
# Expected: 403 Forbidden

# Test LFI detection
curl "http://localhost:8080/file?path=../../etc/passwd"
# Expected: 403 Forbidden

# Test legitimate request
curl "http://localhost:8080/api/users?id=123"
# Expected: 200 OK (proxied to backend)
```

### Load Testing

```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Load test
ab -n 10000 -c 100 http://localhost:8080/

# Expected results:
# - Requests per second: 5000+
# - Time per request: < 20ms
# - No failed requests
```

## 📊 Monitoring

### Prometheus Metrics

Access metrics at: `http://localhost:9090/metrics`

**Available metrics:**

- `waf_requests_total{decision="ALLOW|BLOCK|CHALLENGE"}`
- `waf_blocked_total`
- `waf_anomaly_score` (histogram)

### Grafana Dashboard

1. Access Grafana: `http://localhost:3000`
2. Login: admin/admin
3. Add Prometheus datasource: `http://prometheus:9090`
4. Import dashboard with queries:

```promql
# Total requests
rate(waf_requests_total[5m])

# Block rate
rate(waf_blocked_total[5m])

# Average anomaly score
histogram_quantile(0.95, waf_anomaly_score_bucket)
```

### Audit Logs

Logs are in JSON format at `/var/log/waf/audit.log`:

```json
{
  "timestamp": "2025-01-15T10:30:45Z",
  "request_id": "uuid",
  "client_ip": "192.168.1.100",
  "method": "GET",
  "path": "/api/users",
  "decision": "BLOCK",
  "total_score": 15.0,
  "matched_rules": ["WAF-001-SQLI-UNION", "WAF-002-SQLI-BOOLEAN"],
  "latency": "5ms"
}
```

Query logs with `jq`:

```bash
# Top blocked IPs
cat /var/log/waf/audit.log | jq -r 'select(.decision=="BLOCK") | .client_ip' | sort | uniq -c | sort -rn | head -10

# Rules triggering most
cat /var/log/waf/audit.log | jq -r '.matched_rules[]' | sort | uniq -c | sort -rn

# Requests with high anomaly score
cat /var/log/waf/audit.log | jq 'select(.total_score > 10)'
```

## 🔧 Production Deployment

### Kubernetes Deployment

```yaml
# deployments/kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf
spec:
  replicas: 3
  selector:
    matchLabels:
      app: waf
  template:
    metadata:
      labels:
        app: waf
    spec:
      containers:
        - name: waf
          image: waf:latest
          ports:
            - containerPort: 8080
            - containerPort: 9090
          env:
            - name: UPSTREAM_URL
              value: "http://backend-service:8000"
          volumeMounts:
            - name: config
              mountPath: /root/configs
            - name: rules
              mountPath: /root/configs/rules
          resources:
            requests:
              memory: "256Mi"
              cpu: "500m"
            limits:
              memory: "512Mi"
              cpu: "1000m"
      volumes:
        - name: config
          configMap:
            name: waf-config
        - name: rules
          configMap:
            name: waf-rules
---
apiVersion: v1
kind: Service
metadata:
  name: waf-service
spec:
  type: LoadBalancer
  ports:
    - port: 80
      targetPort: 8080
      name: http
    - port: 9090
      targetPort: 9090
      name: metrics
  selector:
    app: waf
```

Deploy:

```bash
kubectl apply -f deployments/kubernetes/deployment.yaml
kubectl apply -f deployments/kubernetes/service.yaml
kubectl apply -f deployments/kubernetes/configmap.yaml
```

### High Availability Setup

```yaml
# HA configuration
apiVersion: apps/v1
kind: Deployment
spec:
  replicas: 5 # Multiple instances
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 1
```

### Auto-scaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: waf-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: waf
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

## 🛡️ Security Best Practices

### 1. Rule Management

```bash
# Test new rules in shadow mode first
# Edit rule: set "enabled": false for testing
# Monitor false positives in logs
# Enable gradually with canary deployment
```

### 2. IP Whitelisting

```yaml
# Add to exceptions in rules
"exceptions":
  { "ips": ["10.0.0.0/8", "172.16.0.0/12"], "paths": ["/health", "/metrics"] }
```

### 3. Rate Limiting Tuning

```yaml
# Adjust based on traffic pattern
rate_limit:
  requests_per_min: 200 # Higher for APIs
  burst_size: 50 # Allow bursts
```

### 4. Regular Updates

```bash
# Update rules monthly
# Subscribe to CVE feeds
# Add new attack patterns
# Test thoroughly before deploy
```

## 📈 Performance Tuning

### Optimize Go Build

```bash
# Build with optimizations
go build -ldflags="-s -w" -o bin/waf cmd/waf/main.go

# Profile CPU
go tool pprof http://localhost:9090/debug/pprof/profile

# Profile memory
go tool pprof http://localhost:9090/debug/pprof/heap
```

### Tune Configuration

```yaml
# Increase for high traffic
parser:
  max_body_size: 1048576 # 1MB (reduce for better perf)

# Reduce rule complexity
# Use simple regex over complex patterns
# Pre-compile patterns (already done)
```

## 🆘 Troubleshooting

### High False Positive Rate

```bash
# Review audit logs
grep "BLOCK" /var/log/waf/audit.log | tail -100

# Identify problematic rules
cat /var/log/waf/audit.log | jq '.matched_rules[]' | sort | uniq -c

# Temporarily disable rule
# Edit rules JSON: "enabled": false

# Add exceptions for legitimate traffic
```

### High Latency

```bash
# Check metrics
curl http://localhost:9090/metrics | grep waf_anomaly_score

# Profile application
go tool pprof http://localhost:9090/debug/pprof/profile

# Optimize rules (reduce regex complexity)
# Increase resources (CPU/memory)
```

### Memory Leaks

```bash
# Monitor memory
docker stats waf

# Profile heap
go tool pprof http://localhost:9090/debug/pprof/heap

# Check goroutines
go tool pprof http://localhost:9090/debug/pprof/goroutine
```

## 📚 Additional Resources

- Architecture documentation: `docs/architecture.md`
- Rule syntax guide: `docs/rule_syntax.md`
- API reference: `docs/api.md`
- Community rules: https://github.com/waf-community/rules

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Add tests
4. Submit pull request

## 📄 License

MIT License - see LICENSE file

---

**🎉 Your WAF is now production-ready!**

For support: support@waf-project.io
