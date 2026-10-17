# Severity and confidence

Rate every finding on two independent axes. **Severity** says how bad it is if it is real; **confidence** says how sure
you are that it is real. Keeping them apart lets the reader prioritise without you inflating or hiding uncertain issues.

## Severity scale

| Severity | Meaning | Typical examples |
|---|---|---|
| **Critical** | Exploitable remotely with no or trivial preconditions, leading to full compromise: code execution, auth bypass for all users, mass read/write of sensitive data, admin takeover. Fix before the next deploy. | SQL/command injection on a public endpoint; unsafe deserialization of request data; fail-open auth check; live production secret (DB password, cloud key, service-role key) committed to the repo; admin API without authentication |
| **High** | Exploitable by any authenticated user or with modest preconditions; serious impact on other users' data or on integrity. Fix in the current cycle. | IDOR reading/modifying other users' records; stored XSS; SSRF to the internal network or cloud metadata; passwords hashed with MD5/SHA-1 or unsalted; JWT accepted without signature/expiry checks; path traversal reading arbitrary files |
| **Medium** | Real weakness that needs specific conditions, has limited blast radius, or enables a further attack. Plan the fix. | No rate limit on login (brute force); CSRF on state-changing actions; permissive CORS without credentials; stack traces or SQL errors returned to clients; missing CSP on an app that renders user content; sessions not invalidated on logout; reflected XSS that needs user interaction |
| **Low** | Defense-in-depth gap or minor information exposure with no clear exploit path on its own. | Version banners (`X-Powered-By`); cookies without `SameSite` where CSRF is otherwise mitigated; weak-but-not-trivial password policy; mildly sensitive data in admin-only logs; outdated dependency without a known exploitable CVE in the used code path |
| **Info** | Observation or hardening suggestion; not a vulnerability. | MD5 used for cache keys or ETags; recommendation to generate an SBOM; a good control worth keeping |

## How to decide

Think likelihood × impact, then adjust:

1. **Likelihood / exploitability** — Who can reach it (anonymous internet > any logged-in user > admin > local only)?
   How complex is the attack (single request > chained steps > race window)? How easy is it to discover?
2. **Impact** — What does the attacker get: confidentiality, integrity, availability? How much data, and how sensitive
   (credentials, payments, health, PII)? Does it cross users or tenants?
3. **Adjustments**
   - Code reachable only from tests, local scripts or dev tooling → lower one or two levels. Real secrets committed to
     the repository stay high wherever they live, because the repository itself is the exposure.
   - A compensating control exists elsewhere (framework auto-escaping, RLS policy, gateway auth, WAF) → lower, and name
     the control you relied on. If you cannot see that control in the repository, keep the rating and set confidence
     to Low instead.
   - Several medium issues that chain into a serious attack → rate the chain and reference each finding.

A CVSS v4.0 vector is optional; the label above is what the report sorts by.

## Confidence

| Confidence | Use when |
|---|---|
| **High** | You traced attacker-controlled input to the vulnerable sink (or the issue is self-evident, like a committed key) and found no effective control in between. |
| **Medium** | The vulnerable pattern is clear and reachability is likely, but part of the path is indirect (dynamic routing, configuration you can't fully see). |
| **Low** | Plausible, but it depends on runtime or deployment details that are not in the repository. Put these under "Needs verification" unless the potential severity is High or Critical; in that case keep them as findings marked Low confidence. |
