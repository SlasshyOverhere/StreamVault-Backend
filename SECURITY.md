# Security Policy

## Reporting a Vulnerability

If you discover a security issue, do not open a public GitHub issue.

Report privately using one of these channels:

- GitHub Private Vulnerability Reporting (Security tab)
- Direct private contact to the repository owner on GitHub (title: `SECURITY REPORT`)

Please include:

- A clear description of the issue
- Reproduction steps / proof of concept
- Affected endpoint(s) or file(s)
- Potential impact

## Response Expectations

- Initial acknowledgment target: within 72 hours
- Status update target: within 7 days
- Fix timeline depends on severity and exploitability

## Scope

In scope:

- Authentication and authorization bypass
- Secret exposure
- Injection flaws
- Broken access control
- Replay/rate-limit bypass in AI signed endpoints
- Sensitive data leakage in logs or API responses

Out of scope:

- Denial of service requiring extreme resource abuse
- Vulnerabilities only present in unsupported forks or custom deployments

## Hardening Notes

- Keep production secrets in environment variables only
- Rotate keys immediately if exposure is suspected
- Restrict `CORS_ALLOWED_ORIGINS` in production
- Keep dependency updates enabled (Dependabot)

