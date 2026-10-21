# Threat modeling for a code audit

A threat model answers four questions (Shostack): *What are we working on? What can go wrong? What are we going to do
about it? Did we do a good job?* In an audit it does two jobs: it tells you **where to look first**, and it tells you
**what is and isn't a vulnerability** in this particular system. The same `eval()` is a critical bug in a web handler
and expected behaviour in a plugin system that runs trusted admin code.

Build it in Step 3, after reconnaissance and before walking the checklists. Keep it short — a page in the report.

## 1. Start from what the project already says

Before writing your own, look for the maintainers' view and treat it as authoritative where it is explicit:

- `SECURITY.md`, `.github/SECURITY.md`, `docs/security*`, `THREAT_MODEL.md`, `threat_model.md`,
  `.oss-scanner/threat_model.md`, a "Security model" page in the docs.
- Statements like "X is trusted", "Y is out of scope", "we treat every DoS as Medium", "do not report Z".

Honour these in severity and exclusions, and say in the report that you did. If something the project excludes
still looks dangerous (for example, a "trusted" input that is actually reachable by anonymous users), report it with
the reason the assumption doesn't hold — that's a finding about the threat model itself.

## 2. Write the model

Use this structure (it mirrors the template used by Anthropic's oss-scanner and the security models of projects such
as Apache Airflow and Gitea):

```markdown
### What the system does and who uses it
One or two sentences. Deployment shape: internet-facing SaaS, internal tool, library, CLI, mobile backend…

### Assets
What an attacker wants: credentials and sessions, PII, payment data, other tenants' data, admin functions,
the server itself (code execution), signing keys, the build pipeline.

### Actors and trust levels  (most → least trusted)
- Operators / deployers — fully trusted (configuration, environment).
- Administrators — trusted for their intended powers; report only what exceeds them.
- Ordinary authenticated users — not trusted beyond their own data and role.
- Users of another tenant / organization.
- Anonymous internet clients.
- Automated sources: webhooks, queues, uploaded files, third-party APIs, LLM output.

### Trust boundaries and entry points
For each boundary: where untrusted data enters (file:line or route), and what control is supposed to stop it.
  Internet → HTTP routes (`routes/*.js`) — auth middleware `requireAuth`
  User content → HTML rendering (`templates/`) — autoescaping
  App → database — ORM / parameterized queries
  App → outbound HTTP (`services/webhook.ts`) — URL allow-list?
  CI → repository secrets (`.github/workflows/`) — permissions block

### Attacker stories
3–6 concrete goals, each tied to a boundary: "an ordinary user reads another tenant's invoices", "an anonymous
client runs code on the server via the import endpoint", "a fork PR exfiltrates the deploy token".

### Severity guidance and exclusions
From the project if it has them; otherwise the defaults below.
```

## 3. Apply STRIDE at each boundary

For every boundary in the model, ask the six STRIDE questions. Each "yes, possibly" becomes a place to look in the
OWASP walk:

| Threat | Property violated | Ask at the boundary | Usually lands in |
|---|---|---|---|
| **S**poofing | Authentication | Can someone act as another user, service or webhook sender? | A07, A08 (webhook signatures) |
| **T**ampering | Integrity | Can data be modified in transit, in storage, or through fields the client shouldn't control? | A08, A06, A04 |
| **R**epudiation | Non-repudiation | Would a malicious action leave a trustworthy audit trail? | A09 |
| **I**nformation disclosure | Confidentiality | Can data cross users/tenants, leak in errors, logs or responses? | A01, A10, A04, A09 |
| **D**enial of service | Availability | Are size, rate, time and recursion bounded? | A10, A06 |
| **E**levation of privilege | Authorization | Can a lower-trust actor reach a higher-trust function or run code? | A01, A05, A08 |

## 4. Default exclusions and down-ratings

Unless the project says otherwise, these are **not reported as vulnerabilities on their own**. Mention them under
*Info* or in the positive/limitations sections when useful — don't drop them silently, and don't inflate them:

- Missing security headers on a JSON-only API that serves no HTML (CSP, X-Frame-Options matter for HTML responses).
- Version banners, `X-Powered-By`, `CHANGELOG` exposure — Low at most.
- Username/email enumeration through login or reset forms — Low unless the threat model makes account existence
  sensitive (e.g. a health or dating service), then Medium.
- Self-XSS that only affects the user who typed the payload, with no way to deliver it to another user.
- Issues that require an already-trusted actor (operator config, admin acting within admin powers, a Dag/plugin author
  in systems where authors are trusted by design). Report them only if they grant *more* than that actor already has.
- Code reachable only from tests, examples, local dev scripts or fixtures, unless shipped or deployed.
- Volumetric DoS (flooding with traffic). Algorithmic DoS from a single small request (ReDoS, zip bombs, unbounded
  pagination) stays in scope.
- A dependency advisory alone, when the vulnerable function is demonstrably not reachable — keep it as Low/Info with
  the reasoning.

## 5. Use the model while auditing

- **Prioritize** the components and boundaries with the most valuable assets and the least trusted actors.
- **Judge reachability** against the actors: "reachable by whom?" is the first question in Step 5.
- **Rate severity** with the attacker's position from the model (anonymous > user > other-tenant user > admin).
- **Write findings as attacker stories** that cross a named boundary — it makes the impact obvious to the reader.

## References

- OWASP Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- OWASP Threat Modeling Manifesto: https://www.threatmodelingmanifesto.org/
- Microsoft STRIDE: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- OWASP ASVS 5.0 — V15 Secure Coding and Architecture: https://github.com/OWASP/ASVS/tree/master/5.0/en
- Anthropic oss-scanner threat model template: https://github.com/anthropics/oss-scanner/blob/main/templates/threat_model.md
