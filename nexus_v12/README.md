# Nexus V12 — Privacy-Shielded Reverse Image Search

Fail-closed reverse-image-search control plane for authorized fraud, brand-protection, security-operations, and consented verification workflows.

## Operational components

- **OIDC/JWT:** signature, issuer, audience, expiry and required-claim validation through JWKS.
- **Network boundary:** explicit trusted CIDR allowlist.
- **Abuse controls:** per-subject rate limits plus burst anomaly detection.
- **Preprocessing:** image decode/re-encode removes EXIF and enforces a pixel/byte budget.
- **Audit:** per-query HMAC digest, hashed user identifier, append-only PostgreSQL schema and database trigger preventing UPDATE/DELETE.
- **Retention:** seven-day maximum; encrypted S3 lifecycle policy expires query objects automatically.
- **Storage:** AWS KMS-backed S3, public-access blocking, TLS-only bucket policy and private VPC endpoint baseline.
- **Provider boundary:** only an explicitly configured HTTPS provider whose hostname is allowlisted. No automatic provider discovery, breached datasets, HLR, email tracking, or unrestricted OSINT aggregation.
- **Container hardening:** non-root user, read-only filesystem, dropped Linux capabilities and `no-new-privileges`.
- **CI:** Python compilation/tests and Terraform validation on push/PR.

## Run

1. Copy `.env.example` to `.env` and replace every placeholder with values from the deployment's secret manager.
2. Configure an approved OIDC issuer, audience and JWKS URL.
3. Configure an approved reverse-image provider and add only its hostname to `NEXUS_PROVIDER_ALLOWED_HOSTS`.
4. Set a strong `POSTGRES_PASSWORD` and start the stack with `docker compose -f docker-compose.nexus.yml up --build`.
5. The API listens on `127.0.0.1:8080`; place a TLS 1.3-capable reverse proxy or private ingress in front of it.
6. For AWS, apply `infra/aws/main.tf` with the production VPC and private route-table IDs, then inject the resulting KMS/S3 configuration through the deployment secret manager.

## Request contract

`POST /v1/reverse-image` requires:

- `Authorization: Bearer <OIDC JWT>`
- multipart field `image`
- `X-Purpose-Code`
- `X-Legal-Basis`
- `X-Consent-Confirmed: true` for consent-based identity verification
- `X-Law-Enforcement-Documented: true` for law-enforcement missing-person workflows

The API returns a query hash, timestamp, authorized purpose, vetted-provider matches, confidence, risk classification, retention expiry, and audit event hash. It never returns the query image or biometric representation.

## Security boundary

This repository provides enforceable technical controls; it does not certify legal compliance. Operators must document authorization, jurisdiction, contracts, provider terms, lawful basis, and data-subject procedures before enabling a provider.
