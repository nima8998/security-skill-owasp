# A02:2025 — Security Misconfiguration

> Source: OWASP Top 10:2025, https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/ — © OWASP Top 10 Team,
> CC BY 3.0. Condensed and restructured for code auditing; "How to check in code" is added by this skill.

## Summary

Moved up from #5 to #2. Every tested application had some misconfiguration, with more than 719k CWE occurrences. The
rise reflects how much modern software behaviour is driven by configuration. Notable CWEs: CWE-16 Configuration and
CWE-611 XML External Entity (XXE).

## Stats

| CWEs mapped | Max incidence | Avg incidence | Max coverage | Avg coverage | Avg weighted exploit | Avg weighted impact | Total occurrences | Total CVEs |
|---|---|---|---|---|---|---|---|---|
| 16 | 27.70% | 3.00% | 100.00% | 52.35% | 7.96 | 3.97 | 719,084 | 1,375 |

## What it covers

- Missing security hardening anywhere in the stack, or improperly configured cloud permissions.
- Unnecessary features enabled or installed: ports, services, pages, accounts, test frameworks, privileges.
- Default accounts and passwords still active.
- No central error handling, so stack traces or verbose errors reach users.
- New security features disabled or misconfigured after upgrades; insecure settings kept for backward compatibility.
- Insecure settings in app servers, frameworks (Struts, Spring, ASP.NET…), libraries and databases.
- Missing or insecure security headers/directives.
- Without a repeatable, enforced hardening process, risk grows over time.

## How to prevent (checklist)

- [ ] Repeatable, automated hardening so new environments deploy locked down; dev/QA/prod configured identically but with
      different credentials.
- [ ] Minimal platform: remove unused features, components, documentation and samples.
- [ ] Review configuration as part of patch management (including cloud storage permissions such as S3 bucket policies).
- [ ] Segmented architecture (containers, security groups, ACLs) separating components and tenants.
- [ ] Send security directives to clients (security headers).
- [ ] Automate verification of configuration in every environment (manually at least yearly if not automated).
- [ ] Central error handler as a fallback that stops excessive error detail.
- [ ] Prefer identity federation, short-lived credentials or platform roles over static keys/secrets in code, config or
      pipelines.

## Example attack scenarios

1. Sample applications shipped with the app server remain in production; the attacker logs into an admin console with
   unchanged default credentials.
2. Directory listing is enabled; the attacker downloads compiled classes, decompiles them and finds an access-control flaw.
3. Verbose errors (stack traces) reveal component versions with known vulnerabilities.
4. A cloud provider's default sharing settings leave storage open to the internet, exposing sensitive data.

## How to check in code

### Where to look
- Framework settings per environment (`settings.py`, `appsettings*.json`, `application*.yml`, `next.config.*`,
  `config/*.rb`, `.env.example` and how env vars are loaded).
- Server/app bootstrap: middleware for headers, cookies, CORS, error handling, body parsing.
- Container and infrastructure files: `Dockerfile`, `docker-compose*.yml`, Kubernetes manifests, Helm charts,
  Terraform/Bicep/CloudFormation, `vercel.json`, `netlify.toml`, nginx/Apache config.
- XML parsing code (XXE) and any feature toggles for debugging, admin consoles, actuator/metrics endpoints.

### What to verify
- Debug/dev modes cannot be active in production, and the production config is the one actually used.
- Security headers exist where they matter: `Content-Security-Policy`, `Strict-Transport-Security`,
  `X-Content-Type-Options`, `frame-ancestors`/`X-Frame-Options`, `Referrer-Policy`.
- Session/auth cookies set `Secure`, `HttpOnly` and an appropriate `SameSite`.
- Errors go through one handler that logs details and returns a generic message.
- XML parsers disable DTDs/external entities.
- Containers don't run as root or privileged; images don't bake secrets; storage buckets aren't public unless intended.
- Management endpoints (actuator, admin, metrics, GraphQL introspection, Swagger in prod) are disabled or protected.

### Grep starting points
```
DEBUG\s*=\s*True|debug\s*=\s*True|app\.debug|FLASK_DEBUG|APP_DEBUG=true|display_errors
ALLOWED_HOSTS\s*=\s*\[\s*['"]\*|UseDeveloperExceptionPage|customErrors mode="Off"
helmet|Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|x-powered-by
cookie.*(secure|httpOnly|sameSite)|SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE
DocumentBuilderFactory|XMLInputFactory|SAXParser|XmlReader|lxml|resolve_entities|noent|LIBXML_NOENT
management\.endpoints\.web\.exposure\.include|actuator|swagger|introspection
public-read|"Principal"\s*:\s*"\*"|acl\s*=\s*"public|block_public_acls\s*=\s*false
^USER root|privileged:\s*true|0\.0\.0\.0/0|--insecure
admin:admin|password123|changeme|default.?password
```

### Stack-specific signals
- **Django:** `DEBUG = True`, `ALLOWED_HOSTS = ['*']`, `SECRET_KEY` hardcoded, `SECURE_*` settings missing.
- **Flask:** `app.run(debug=True)` (Werkzeug debugger allows code execution if reachable).
- **Express:** no `helmet`, `x-powered-by` enabled, error middleware returning `err.stack`.
- **Spring Boot:** all actuator endpoints exposed; `server.error.include-stacktrace=always`.
- **ASP.NET:** developer exception page outside Development; `customErrors` off; missing HTTPS redirection/HSTS.
- **PHP:** `display_errors=On`, `expose_php=On`.
- **Next.js / Vite:** production source maps; secrets in `NEXT_PUBLIC_*`/`VITE_*` variables (shipped to the browser).

### Common false positives
- Debug flags in dev-only files (`settings/dev.py`, `docker-compose.override.yml`) — confirm prod doesn't load them.
- Headers set by a CDN/reverse proxy outside the repo — list under "Needs verification" rather than as a finding.

## Mapped CWEs (16)

CWE-5 J2EE Misconfiguration: Data Transmission Without Encryption · CWE-11 ASP.NET Misconfiguration: Creating Debug
Binary · CWE-13 ASP.NET Misconfiguration: Password in Configuration File · CWE-15 External Control of System or
Configuration Setting · CWE-16 Configuration · CWE-260 Password in Configuration File · CWE-315 Cleartext Storage of
Sensitive Information in a Cookie · CWE-489 Active Debug Code · CWE-526 Exposure of Sensitive Information Through
Environmental Variables · CWE-547 Use of Hard-coded, Security-relevant Constants · CWE-611 Improper Restriction of XML
External Entity Reference · CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute · CWE-776 Improper
Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') · CWE-942 Permissive Cross-domain Policy
with Untrusted Domains · CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag · CWE-1174 ASP.NET Misconfiguration:
Improper Model Validation

## References

- OWASP Testing Guide — Configuration Management: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README
- OWASP Testing Guide — Testing for Error Codes: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling
- OWASP ASVS 5.0 — V13 Configuration: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md
- NIST SP 800-123 — Guide to General Server Security: https://csrc.nist.gov/publications/detail/sp/800-123/final
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks/
- Amazon S3 bucket discovery and enumeration: https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html
