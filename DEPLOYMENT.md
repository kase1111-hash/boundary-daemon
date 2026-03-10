# Deployment & Environment Isolation — Boundary Daemon

**Version:** 1.0.0-beta
**Date:** 2026-03-10

---

## Environment Tiers

| Environment | Purpose | Data | Access |
|-------------|---------|------|--------|
| **dev** | Local development, unit tests | Synthetic / fixture data only | Developer workstation |
| **staging** | Integration tests, pre-release validation | Anonymised copies of production patterns | Restricted to team |
| **prod** | Live agent workloads | Real agent events, real policy decisions | Operators only |

---

## Isolation Requirements

### 1. Network Isolation

```
┌──────────┐      ┌──────────┐      ┌──────────┐
│   dev    │      │ staging  │      │   prod   │
│ 127.0.0.1│      │ VPC/VLAN │      │ VPC/VLAN │
│ no TLS   │      │ TLS req. │      │ TLS req. │
│ optional │      │ internal │      │ mTLS rec.│
└──────────┘      └──────────┘      └──────────┘
     ↑                 ↑                 ↑
  localhost         private net       private net
  only              no public IP      no public IP
```

- **dev:** Health and metrics endpoints bind to `127.0.0.1` (default after
  remediation). No TLS required.
- **staging:** Deploy in an isolated VPC/VLAN. TLS required on all remote
  backends. No public-facing endpoints.
- **prod:** Same as staging, plus mTLS recommended for inter-service
  communication. Network policies (iptables / cloud security groups) restrict
  ingress to known agent IPs.

### 2. Credential Isolation

| Secret | dev | staging | prod |
|--------|-----|---------|------|
| API tokens | Hardcoded test tokens (never real) | Rotated tokens from secrets manager | Rotated tokens from secrets manager |
| Cluster secret | Static test value | Unique per-env, rotated every 30 days | Unique per-env, rotated every 30 days |
| TLS certificates | Self-signed or disabled | Internal CA | Internal CA or public CA |
| `.config_salt` | Generated locally | Unique per-env | Unique per-env, restricted file perms |

**Critical:** Never copy production secrets to staging or dev. Each environment
generates its own credentials independently.

### 3. Configuration Isolation

Use environment-specific config files or environment variables:

```bash
# dev
export BOUNDARY_ENV=dev
export BOUNDARY_HEALTH_HOST=127.0.0.1
export BOUNDARY_METRICS_HOST=127.0.0.1
export BOUNDARY_TLS_ENABLED=false

# staging
export BOUNDARY_ENV=staging
export BOUNDARY_HEALTH_HOST=127.0.0.1
export BOUNDARY_METRICS_HOST=127.0.0.1
export BOUNDARY_TLS_ENABLED=true
export BOUNDARY_TLS_CERTFILE=/etc/boundary/tls/cert.pem
export BOUNDARY_TLS_KEYFILE=/etc/boundary/tls/key.pem

# prod
export BOUNDARY_ENV=prod
export BOUNDARY_HEALTH_HOST=127.0.0.1
export BOUNDARY_METRICS_HOST=127.0.0.1
export BOUNDARY_TLS_ENABLED=true
export BOUNDARY_CLUSTER_SECRET_MAX_AGE_DAYS=30
```

### 4. Data Isolation

- **Event logs** are per-environment. Never aggregate dev/staging logs into
  production SIEM pipelines.
- **Hash chains** are independent per environment. A staging hash chain has no
  relation to production.
- **Policy definitions** may be shared via version control but are loaded
  independently per environment.

---

## Deployment Checklist

### Pre-staging

- [ ] All CRITICAL and HIGH audit findings are remediated
- [ ] TLS enabled on all remote backends
- [ ] API endpoints authenticated (POST /keys, GET /keys)
- [ ] Health/metrics endpoints bound to localhost
- [ ] Cluster secret rotation configured
- [ ] Dev dependencies are NOT installed in the deployment image

### Pre-production

- [ ] All items from pre-staging
- [ ] Penetration test completed against staging
- [ ] SIEM ingestion endpoint uses HTTPS
- [ ] Log retention policy configured
- [ ] Monitoring/alerting for boundary violations
- [ ] Runbook for secret rotation documented
- [ ] Incident response plan covers daemon-specific scenarios
- [ ] Compliance assessment reviewed (see COMPLIANCE.md)

---

## CI/CD Pipeline Stages

```
commit → lint/type-check → unit tests → security scan → build image
                                                            │
                              ┌──────────────────────────────┘
                              ▼
                     deploy to staging → integration tests → manual approval
                                                                    │
                                                                    ▼
                                                          deploy to prod
```

- Staging deploys are automatic on merge to `main`.
- Production deploys require manual approval after staging validation.
- Rollback: keep the previous image tag; redeploy via the same pipeline.
