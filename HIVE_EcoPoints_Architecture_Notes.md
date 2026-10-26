# HIVE EcoPoints: database and security notes

## Recommended boundary
Keep EcoPoints as a bounded module with its own schema/database and API. HIVE should pass a trusted authenticated user ID and role; do not trust user IDs or points sent from the browser. Avoid copying the school's entire student profile into EcoPoints.

## Data domains
- Accounts: minimal identity, role, encrypted contact fields, password hash, sessions.
- Activities and proofs: uploaded evidence, review status, points assigned by server.
- Challenges: active campaigns and participants.
- Rewards and redemptions: inventory, costs, request status, fulfillment.
- Audit events and points ledger: append-only operational history.

## Security controls already present in starter
bcrypt password hashes, AES-256-GCM encryption for selected personal fields, HMAC email lookup, hashed session tokens, httpOnly/SameSite cookies, role checks, rate limits, CSRF header check, upload type/header validation, private media access, reviewer view that omits contact fields, and audit entries for major authentication/review actions.

## Still required before a real school deployment
1. Use HTTPS only; set `NODE_ENV=production` and configure `TRUST_PROXY` only if the host proxy is trusted.
2. Use managed PostgreSQL for multi-instance hosting; keep DB credentials least-privileged and use separate staging/production environments.
3. Add school/tenant IDs to records and enforce tenant scoping in every query before onboarding multiple schools.
4. Move reward balance check + stock decrement + redemption + ledger write into one transaction; use idempotency keys for retries.
5. Add admin-only routes/UI to create challenges, manage rewards, and fulfil redemptions. Require verifier/admin authorization on each route.
6. Add malware scanning for uploads, strict content limits, retention/deletion policies, backups and restore tests.
7. Add audit retention, alerts, monitoring, privacy notice/consent where applicable, and independent security review.
8. Do not put `.env`, keys, production DB, uploaded student media, or personal data in the hackathon repository.

This is a stronger prototype baseline, not a security certification. The existing HTML UI was intentionally left unchanged as requested.
