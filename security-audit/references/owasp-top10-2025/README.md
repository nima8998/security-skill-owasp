# OWASP Top 10:2025 — index for auditors

> Source: OWASP Top 10:2025, https://top10.owasp.org/2025/ — © 2021-2025 OWASP Top 10 Team, licensed under
> Creative Commons Attribution 3.0 Unported (CC BY 3.0). The per-category files in this folder condense and
> restructure the official text for code auditing; the "How to check in code" sections are additions of this
> skill and are not part of the OWASP document.

Read this index once at the start of the audit, then open each category file as you review that category.

| ID | Category | File | Focus in one line | Quick signals to grep first |
|---|---|---|---|---|
| A01 | Broken Access Control | `A01-broken-access-control.md` | Who may do what to which record (incl. IDOR, path traversal, SSRF, CORS, CSRF, open redirect) | `req.params.id`, `findById`, `sendFile`, `redirect(`, `fetch(userUrl)`, `cors(`, routes missing auth middleware |
| A02 | Security Misconfiguration | `A02-security-misconfiguration.md` | Insecure defaults, debug modes, headers, cookies, XXE, cloud/IaC settings | `DEBUG = True`, `debug=True`, `helmet`, `ALLOWED_HOSTS`, `public-read`, `USER root`, XML parsers |
| A03 | Software Supply Chain Failures | `A03-software-supply-chain-failures.md` | Vulnerable, unmaintained or untrusted dependencies; CI/CD and build integrity | lockfiles, `"latest"`, `FROM x:latest`, `uses: x@main`, `curl ... | sh`, `postinstall` |
| A04 | Cryptographic Failures | `A04-cryptographic-failures.md` | Weak hashing/encryption/randomness, TLS validation, key management, secrets | `md5`, `sha1`, `ECB`, `Math.random`, `verify=False`, `rejectUnauthorized: false`, `BEGIN PRIVATE KEY` |
| A05 | Injection | `A05-injection.md` | Untrusted data reaching an interpreter: SQL/NoSQL/OS/ORM/LDAP/EL, XSS, template injection | string-built queries, `exec(`, `shell=True`, `eval(`, `innerHTML`, `dangerouslySetInnerHTML`, `|safe` |
| A06 | Insecure Design | `A06-insecure-design.md` | Missing controls by design: business logic, tenant isolation, uploads, race conditions, client-side enforcement | prices/amounts from `req.body`, `X-User-Id` headers, upload handlers, balance updates without transactions |
| A07 | Authentication Failures | `A07-authentication-failures.md` | Login, sessions, tokens, MFA, reset flows, hardcoded/default credentials | login routes without rate limit, `jwt.verify` options, session regeneration, `password = "`, reset tokens |
| A08 | Software or Data Integrity Failures | `A08-software-or-data-integrity-failures.md` | Unsafe deserialization, unsigned updates/data, untrusted includes, mass assignment, webhook signatures | `pickle.loads`, `yaml.load`, `BinaryFormatter`, `unserialize(`, `create(req.body)`, `<script src` without `integrity` |
| A09 | Security Logging and Alerting Failures | `A09-security-logging-and-alerting-failures.md` | Missing security events, secrets/PII in logs, log injection, no alerting | `console.log(...password/token)`, logging `req.body`/headers, no log on auth failures |
| A10 | Mishandling of Exceptional Conditions | `A10-mishandling-of-exceptional-conditions.md` | Error leaks, swallowed errors, fail-open, missing rollback, unbounded resources | empty `catch {}`, `except: pass`, `err.stack` in responses, `catch → next()` in auth, no body/page limits |

## Mapping a finding to one category

One root cause → one primary category (the most specific one); mention related categories in the text. Overlaps are
common, and a consistent convention makes reports comparable:

- Hardcoded **cryptographic keys / signing secrets** → A04 (CWE-321). Hardcoded **passwords, credentials, default
  accounts** → A07 (CWE-798/259/1392). A **committed `.env`** or secrets in client-shipped config → classify by what the
  secret is (A04 or A07) and mention A02.
- **CORS** that lets untrusted origins read authenticated data → A01 (CWE-942 is mapped under A02; either is defensible,
  be consistent within a report).
- **Stack traces / verbose errors** returned to clients → A10 (CWE-209/550). A missing central error handler as a
  configuration issue → A02.
- **Mass assignment** (CWE-915) → A08. **Path traversal, SSRF, CSRF, open redirect** → A01.
- **Weak password hashing** → A04 (storage), even though it impacts authentication.
- **Missing rate limits** on login/OTP/reset → A07; on business actions (bots, scalping, coupon abuse) → A06; unbounded
  resources (no size/page/time limits) → A10.

## Notes on the source

- A03 lists "CWE-447: Use of Obsolete Function"; the MITRE ID for that name is CWE-477.
- A07 lists CWE-297/298/299 all as "Improper Validation of Certificate with Host Mismatch"; per MITRE, CWE-298 is
  "Improper Validation of Certificate Expiration" and CWE-299 is "Improper Check for Certificate Revocation".
