# ARTEMIS BLUE TEAM — Image Information Protection

ARTEMIS BLUE TEAM is a defensive, local-first image security inspection layer for Nexus V12. It is designed for secure publication, privacy review, compliance, fraud/brand protection, and authorized security operations.

## Security boundary

ARTEMIS does **not** perform facial identification, deanonymization, tracking, endpoint probing, breached-data searches, dark-web searches, credential validation, or unauthorized enrichment. Text embedded in an image is treated as untrusted data, never as policy or instructions.

If authorization is `UNCLEAR` or `REJECTED`, the scanner performs only local classification and fails closed for publication.

## Detection model

The current deterministic engine inspects:

- credential/key markers, JWTs, bearer tokens, cloud token formats, connection strings and webhook URLs;
- high-entropy strings as potential secrets, with values suppressed;
- IP addresses, URLs, ports, UUIDs, hashes and vulnerability identifiers;
- sensitive-document and personal-data indicators supplied by an approved local visual detector;
- face indicators without identity inference;
- QR/barcode indicators without decoding;
- EXIF metadata including GPS, device, timestamp, author and software fields where available.

OCR is intentionally an adapter boundary: an approved local OCR engine may supply text to `ArtemisScanner.scan(..., ocr_text=...)`. No external OCR service is invoked by this package.

## Publication decisions

- `CRITICAL` → `DO_NOT_SHARE`
- `HIGH` → `INTERNAL_ONLY`
- `MEDIUM` → `SHARE_AFTER_REDACTION`
- `LOW` → `SAFE_TO_SHARE` only when authorization is established

The highest-risk finding controls the original image classification.

## Secret handling

ARTEMIS never returns suspected secret values. Reports contain only the secret type, location and remediation. Confirmed exposed credentials should be revoked/rotated through the approved incident-response process. ARTEMIS itself does not test or validate credentials.

## Retention

- Original images: delete after processing by default.
- Temporary derivatives: delete after processing.
- If temporary persistence is unavoidable, infrastructure must enforce encrypted storage and deletion within 24 hours.
- No original may be retained beyond seven days without a documented, time-bound exception.
- Reports default to 30 days and contain a SHA-256 digest plus minimized findings rather than image content.

The scanner does not implement deletion by itself; deployment must wire the lifecycle policy to the storage backend and verify deletion operationally.

## Re-scan requirement

Any redacted derivative must be rendered as the actual publication artifact and scanned again before approval. This prevents redaction failures where text, QR codes, secrets, or identifiers remain recoverable.

## Output contract

`json_report()` emits deterministic JSON matching the ARTEMIS report contract. The contract intentionally excludes raw OCR text, secret values, facial embeddings, biometric templates, and unnecessary PII.

## Operational checklist

1. Authenticate the operator through the Nexus V12 OIDC boundary.
2. Require a documented purpose code and authorization basis.
3. Process locally where feasible.
4. Strip EXIF metadata.
5. Run deterministic secret/PII/infrastructure checks.
6. Apply minimal redaction or block publication.
7. Render the exact proposed publication artifact.
8. Re-scan the rendered artifact.
9. Store only the minimized report and cryptographic hash.
10. Execute and monitor storage deletion controls.
11. Escalate high/critical results to an authorized human reviewer.
