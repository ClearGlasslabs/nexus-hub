# Nexus V12 — Privacy-Shielded Reverse Image Search

A fail-closed orchestration layer for authorized reverse-image-search workflows.

## Security model

- No biometric embeddings or facial templates are generated or persisted.
- EXIF metadata is removed before provider dispatch.
- Audit records contain a per-query digest, not the source image.
- Query salts are ephemeral and are not returned by the service.
- Maximum image retention policy is seven days; the module itself does not persist uploaded images.
- Purpose codes, legal basis, consent, and authorization level are validated before provider execution.
- Providers are injected explicitly; there is no built-in access to breached data, HLR, email tracking, or unrestricted OSINT aggregation.
- API access fails closed without a configured trusted network and verified OIDC deployment boundary.
- The audit chain is tamper-evident and contains a hashed user identifier rather than a raw user ID.

## Provider boundary

`SearchProvider` is intentionally a narrow interface. Production deployments must connect only approved, lawful providers and enforce their terms, robots rules, licensing, jurisdictional requirements, and data-subject controls.

## Important deployment requirement

The repository does **not** claim to provide complete OAuth2/OIDC token validation merely by setting an environment variable. A production deployment must place a standards-compliant OIDC/JWT verifier at the gateway or inject a verified identity context before enabling `/v1/reverse-image`.

The module is a security-oriented foundation, not a legal-compliance certification. Operators remain responsible for applicable biometric/privacy law, contracts, retention schedules, and authorization evidence.
