# MediTrack: Demo Application (Cloud Security Project)

Flask web application for a medical clinic. It serves as a showcase application: the evaluation focuses on the security of the surrounding AWS infrastructure rather than the application itself.

## Demo Accounts (100% Fictional Data)

Password for all seeded accounts: defined by the `SEED_PASSWORD` variable in the `.env` file (**never hardcode it in source code**).

| Username | Role | MFA | Access |
|---|---|---|---|
| `noor` | Patient | optional | own appointments, notes, documents |
| `mamoun` | Patient | optional | same (own data only) |
| `dr.saber` | Doctor | mandatory | only **noor** (assigned) |
| `dr.tayssir` | Doctor | mandatory | only **mamoun** (assigned) |
| `secretaire` | Secretary | mandatory | everyone's schedule; **no** medical data |
| `admin` | Administrator | mandatory | accounts and care links; **no** medical data |

## Local Testing (Docker)

```bash
docker compose down -v        # start from a clean database
docker compose up --build
# http://localhost:8080
```

**Local MFA code** (`MFA_DEMO=1` in `.env`): the 6-digit code is not emailed; it is printed to the logs. In a second terminal:

```bash
docker compose logs app | grep mfa_code_demo
```

(take the last line, `"code"` field). Demo mode is **for local testing only**: do not enable it on EC2.

## Application Security

- **Authentication**: hashed passwords (`scrypt`), password policy (12 characters, 3 character classes), `HttpOnly`/`SameSite` cookies, 30-minute session lifetime.
- **MFA**: 6-digit one-time code sent directly to the user's email address via **Amazon SES**; expires in 5 min, stored hashed, 3 attempts, rate-limited resend (30 s). Mandatory for doctor, secretary, and admin roles.
- **Account Lockout**: 5 failed attempts → account locked for 15 min; identical error message for unknown account / locked account / wrong password (prevents user enumeration). Unlockable by admin.
- **RBAC**: every route declares its allowed roles; denials are logged (`access_denied`).
- **ABAC**: patient = own data only; doctor = assigned patients only (`care_links` table, managed by admin); denials are logged (`abac_denied`).
- **Separation of Duties**: admin cannot view medical data; secretary cannot either.
- **Web Hardening**: CSRF protection, strict CSP (no `unsafe-inline`), `X-Frame-Options`, `nosniff`, `Cache-Control: no-store`, parameterized SQL queries, upload limits (5 MB, allowed extensions).
- **Container**: non-root user. **S3**: accessed via the EC2 IAM role, no static keys in code.

## Deploying on EC2

```bash
sudo dnf install -y docker && sudo systemctl enable --now docker
cd meditrack && sudo docker build -t meditrack .
sudo docker run -d --name meditrack --restart unless-stopped -p 80:8080 \
  -e DATABASE_URL='postgresql+psycopg2://USER:PASSWORD@RDS-ENDPOINT:5432/meditrack' \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e SEED_PASSWORD='StrongPassword!2026' \
  -e S3_BUCKET='documents-bucket-name' \
  -e SES_SENDER_EMAIL='noreply@yourdomain.com' \
  -e COOKIE_SECURE=1 \
  meditrack
```

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | **mandatory** (app refuses to start without it); must be identical across all workers |
| `DATABASE_URL` | RDS PostgreSQL (if omitted: ephemeral SQLite for initial testing) |
| `S3_BUCKET` / `KMS_KEY_ID` | documents in S3 (SSE-S3 encryption, or SSE-KMS if `KMS_KEY_ID` is set) |
| `SES_SENDER_EMAIL` | verified Amazon SES sender address for delivering MFA codes directly to the user's email |
| `SNS_TOPIC_ARN` | fallback SNS topic (uses `email` `MessageAttributes` so SNS Subscription Filter Policies deliver only to the target user) |
| `MFA_DEMO` | `1` = code written to logs (local testing only) |
| `COOKIE_SECURE` | `1` behind HTTPS (CloudFront / ALB) |
| `LOGIN_MAX_FAILED`, `LOCK_MINUTES`, `MFA_TTL_MIN`, `MFA_MAX_TRIES` | security tuning parameters |

Without `SES_SENDER_EMAIL` **and** without `MFA_DEMO`, MFA-required accounts cannot log in (fail-closed by default).
The EC2 instance needs `ses:SendEmail` permission (via its IAM role), and the sender (plus recipient addresses if SES is in sandbox mode) must be verified in Amazon SES.

## Audit Logs (→ CloudWatch)

One JSON line per event on stdout, for example:

```json
{"ts": "...", "event": "login_failed", "outcome": "failure", "user": "anonymous", "ip": "...", "attempted_user": "admin"}
```

Events: `login`, `login_failed`, `account_locked`, `login_blocked_locked`, `mfa_sent`, `mfa_failed`, `mfa_exhausted`, `mfa_success`, `access_denied`, `abac_denied`, `download_denied`, `csrf_failure`, `upload_document`, `download_document`, `create_medical_note`, `create_user`, `create_care_link`, `password_changed`, etc.

Brute-force detection: CloudWatch *metric filter* on `"login_failed"` (or `"account_locked"`) + alarm → SNS → email.
Ship logs to CloudWatch: Docker log driver `--log-driver=awslogs --log-opt awslogs-group=/meditrack/app --log-opt awslogs-region=us-east-1`.

## Known Limitations (Residual Risks)

- **Email MFA via SES**: weaker than TOTP or passkeys/WebAuthn (target: Cognito + TOTP or WebAuthn).
- No email password reset flow; no antivirus scanning on uploaded files; no application-level rate limiting (handled by WAF and, optionally, nginx).
- The application `admin` role is separate from AWS administration, which uses IAM and AWS Systems Manager Session Manager.
