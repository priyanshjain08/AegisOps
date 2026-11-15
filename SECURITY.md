# Security design
- Argon2 password hashing; 15-min JWT access tokens; opaque refresh tokens stored only as SHA-256, rotated on use, reuse of a rotated token revokes all of the user's tokens.
- RBAC via `require(min_role)`; approval/execute need security_admin+. Analysts can request but not approve.
- LLM output is data: schema-validated, evidence IDs checked against real records, ATT&CK IDs allowlisted, actions allowlisted; recommendations become *pending* proposals only.
- Response actions are an allowlist with validated params; the firewall adapter is a simulation; internal/RFC1918 addresses cannot be blocked; no shell execution exists.
- Audit log is append-only by API design (no write/delete routes). It is not cryptographically tamper-evident; use DB-level privileges/WORM storage in production.
- Uploads: size cap, format whitelist, per-record validation. CORS is an explicit origin list. Secrets via env only; `jwt_secret` has no default.
- Known gaps: refresh token in sessionStorage; no per-route login throttling; no MFA; no CSRF concerns because bearer tokens are used, but XSS would expose them.
