# Lens: infra — Infrastructure And Pipeline Surface

## Mandate

Even when the application is secure, an exposed **layer underneath it** produces
the same outcome. And the CI environment is the shortest path to production.

## Phase 1 — Map The Surface

```
Glob: "**/Dockerfile*", "**/docker-compose*", "**/*.tf", "**/k8s/**", "**/helm/**"
Glob: "**/.github/workflows/**", "**/.gitlab-ci.yml", "**/nginx*", "**/Caddyfile"
```

## Phase 2 — Attack Tree

### A. Network Exposure *(check this first)*

```
Grep: "0\.0\.0\.0:|ports:|EXPOSE|hostPort|LoadBalancer|publiclyAccessible"
```

Is a database, cache, message queue or monitoring panel bound to a public
interface? Pay particular attention to `5432`, `3306`, `27017`, `6379`, `9200`
and `11211`.

Scenario: `docker-compose exposes 0.0.0.0:5432 -> password brute force -> the whole database`

### B. Privileges Inside The Container

```
Grep: "USER |privileged|CAP_|securityContext|runAsUser|allowPrivilegeEscalation"
```

Without a `USER` instruction the process runs as **root**. `privileged: true` or
`CAP_SYS_ADMIN` is a container escape path.

Also: mounting `docker.sock` gives full control of the host.
```
Grep: "docker\.sock|/var/run/docker"
```

### C. Secrets In Configuration

```
Grep: "PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL" -> in infrastructure files
```

A Kubernetes `Secret` is base64, **not encryption**. Is encryption at rest
enabled? Are SOPS or sealed-secrets in use?

### D. Exploiting The CI Environment *(the least supervised)*

```
Grep: "pull_request_target|workflow_run|secrets\.|if: github\.actor"
Grep: "uses:.*@(main|master|v\d+)$|image:.*:latest"
```

Check:
1. **`pull_request_target`** — are secrets handed to a pull request from a fork?
   This is the classic CI compromise: the attacker opens a pull request and the
   workflow runs their code with your secrets
2. Are secrets available only on protected branches?
3. Is an external action pinned to a mutable tag (`@main`)? Its owner can change
   the contents
4. Is `${{ github.event.* }}` interpolated inside a `run:` block? That is script
   injection
5. Is the runner on a production host? A CI compromise then equals a production
   compromise

### E. TLS And Certificates

```
Grep: "ssl_protocols|ssl_ciphers|tls|listen 80|protocols"
```

Are TLS 1.0 and 1.1 still supported? Is the HTTP-to-HTTPS redirect mandatory? Is
HSTS present? Is internal traffic encrypted (mTLS), or in the clear?

### F. Security Headers

```
Grep: "Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|helmet"
```

Are they set at the reverse proxy or in the application layer?

### G. Resource Limits And Availability

```
Grep: "limits:|resources:|memory|cpu|restart|healthcheck|livenessProbe"
```

Without limits one container consumes the whole host. Without a health check a
broken instance keeps receiving traffic.

### H. Backup And Restore

```
Grep: "backup|dump|pg_dump|snapshot|retention|object-lock|versioning"
```

Do backups exist? **Can they be deleted?** If an identity with production access
can delete the backups, that is a single point of total destruction. Has a restore
been tested?

### I. Terraform And IaC Specifics

```
Grep: "0\.0\.0\.0/0|publicly_accessible|acl\s*=\s*\"public|encrypted\s*=\s*false"
Grep: "\*.*Action|Resource\s*=\s*\"\*\"|AdministratorAccess"
```

A `0.0.0.0/0` security group, a public bucket, an unencrypted disk, a wildcard IAM
permission. Where is the state file stored — encrypted and locked?

### J. Image Provenance

```
Grep: "FROM |image:"
```

Is the base image pinned by digest? `:latest` means a non-reproducible build. Does
it come from an official source?

## Phase 3 — Verification

- [ ] The configuration is used in production (not a dev compose file)
- [ ] The exposure is not compensated for at the network layer (firewall, VPC)
- [ ] The finding is on a real deployment path

## False-Positive Traps

| Trap | Check |
|---|---|
| `docker-compose.yml` is for local development only | Read the file name and the comments |
| The port is closed by the host firewall | Look for the network configuration |
| `USER` is set in the base image | Establish which base image is used |
| The secret is a placeholder supplied by CI | Judge the value |
