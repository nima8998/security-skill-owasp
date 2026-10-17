# A06:2025 — Insecure Design

> Source: OWASP Top 10:2025, https://top10.owasp.org/2025/A06_2025-Insecure_Design/ — © OWASP Top 10 Team, CC BY 3.0.
> Condensed and restructured for code auditing; "How to check in code" is added by this skill.

## Summary

Down from #4 to #6 as Security Misconfiguration and Supply Chain Failures moved above it. Covers design and
architectural flaws — "missing or ineffective control design" — including business-logic gaps such as undefined or
unwanted state changes. It calls for threat modeling, secure design patterns and reference architectures, and puts
weight on work done before coding: requirements and design.

## Stats

| CWEs mapped | Max incidence | Avg incidence | Max coverage | Avg coverage | Avg weighted exploit | Avg weighted impact | Total occurrences | Total CVEs |
|---|---|---|---|---|---|---|---|---|
| 39 | 22.18% | 1.86% | 88.76% | 35.18% | 6.96 | 4.05 | 729,882 | 7,647 |

## What it covers

- **Design vs implementation:** different root causes, lifecycle stages and fixes. A secure design can still have
  implementation bugs; an insecure design can't be fixed by perfect code, because the needed control never existed.
- **Missing business risk profiling:** without it, teams can't decide what level of security design is needed.
- **Requirements and resources:** confidentiality, integrity, availability and authenticity needs per data asset and
  the expected business logic should be agreed with the business, including exposure and tenant segregation;
  functional and non-functional security requirements defined; security budgeted across the lifecycle.
- **Secure design culture:** continuous threat evaluation, threat modeling in refinement sessions, documented normal and
  failure flows, validated assumptions — secure design is not a tool you add later.
- **Secure SDLC:** secure patterns, "paved road" components, secure libraries, tooling, threat modeling, post-incident
  reviews, security specialists involved from the start (OWASP SAMM can structure this).

## How to prevent (checklist)

- [ ] Establish a secure development lifecycle with AppSec professionals to design security and privacy controls.
- [ ] Maintain a library of secure design patterns / paved-road components.
- [ ] Threat-model critical areas: authentication, access control, business logic, key flows.
- [ ] Use threat modeling as an educational tool.
- [ ] Put security language and controls into user stories.
- [ ] Add plausibility checks at every tier, frontend to backend.
- [ ] Write unit and integration tests proving critical flows resist the threat model — use cases and misuse cases.
- [ ] Separate tiers at system and network level by exposure and protection needs.
- [ ] Isolate tenants by design across all tiers.

## Example attack scenarios

1. Credential recovery based on "security questions" — prohibited by NIST 800-63b, ASVS and the Top 10, because more than
   one person can know the answers; it needs a different design.
2. A cinema chain allows group bookings with a deposit only above fifteen people; an attacker reserves hundreds of seats
   across all cinemas in a few requests, causing large revenue loss.
3. A retailer has no anti-bot protection; scalpers buy all high-end GPUs for resale. Domain rules (e.g. purchases seconds
   after release) and anti-automation could detect and reject them.

## How to check in code

Design flaws rarely match a grep pattern; find them by reading the key flows and asking "what stops a malicious user
here?". Describe each finding as a concrete abuse scenario, not as "the design is weak".

### Flows worth walking end to end
- Money, credits, quotas, discounts, coupons, referrals, inventory, bookings, voting, invitations.
- Account lifecycle: sign-up, email change, password reset/recovery, account deletion, role changes.
- Multi-tenant boundaries: where does the tenant/org id come from on each request?
- File upload and processing pipelines; import/export features.
- Multi-step workflows (checkout, approval chains, onboarding) and their state machine.

### Questions to ask
- **Client-side enforcement (CWE-602):** are prices, totals, discounts, roles, limits or workflow state accepted from the
  client instead of computed/looked up on the server?
- **Trust boundaries (CWE-501/807):** does the server trust headers such as `X-Forwarded-For`, `X-User-Id`, `X-Role`,
  or hidden form fields for security decisions?
- **Limits and anti-automation (CWE-799):** can one user repeat an action unboundedly (bookings, sign-ups, coupon
  redemptions, messages, expensive exports)?
- **Race conditions (CWE-362):** check-then-act on balances/stock/uniqueness without a transaction, row lock, atomic
  update or unique constraint?
- **Workflow enforcement (CWE-841):** can step 3 be called without steps 1–2 (e.g. confirming an order that was never paid)?
- **Uploads (CWE-434/646):** type decided by extension or client MIME only; stored under the web root; executed or
  served inline; no size or count limits; file names used as paths.
- **Credentials and sensitive data by design (CWE-256/311/312/598):** secrets in GET query strings, cleartext storage,
  persistent cookies with sensitive data, sensitive pages cacheable.
- **Security through obscurity (CWE-656):** "hidden" admin URLs or unguessable-looking ids as the only control.
- **Tenant isolation (CWE-653):** shared caches, queues or storage prefixes without tenant scoping.

### Grep starting points
```
(price|amount|total|discount|quantity|balance|credits|role|plan)\b.*(req\.body|request\.(json|form|data)|params\[)
X-Forwarded-For|X-Real-IP|X-User|X-Role|X-Tenant|x-user-id
multer|formidable|busboy|upload|FileField|ImageField|IFormFile|MultipartFile|move_uploaded_file|\.originalname|\.filename
(balance|stock|inventory|credits|seats)\s*(-=|\+=|=\s*\w+\s*[-+])
tenant_?id|org_?id|workspace_?id|company_?id      # check where the value originates
security_question|secret_question|mother.?s.?maiden
```

### Severity guidance
Rate by business impact: free goods, money movement or cross-tenant access → High/Critical; abuse that costs money or
availability (scalping, unlimited bookings) → Medium/High; weak recovery flows → High if they lead to account takeover.

## Mapped CWEs (39)

CWE-73 External Control of File Name or Path · CWE-183 Permissive List of Allowed Inputs · CWE-256 Unprotected Storage
of Credentials · CWE-266 Incorrect Privilege Assignment · CWE-269 Improper Privilege Management · CWE-286 Incorrect User
Management · CWE-311 Missing Encryption of Sensitive Data · CWE-312 Cleartext Storage of Sensitive Information · CWE-313
Cleartext Storage in a File or on Disk · CWE-316 Cleartext Storage of Sensitive Information in Memory · CWE-362
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') · CWE-382 J2EE Bad
Practices: Use of System.exit() · CWE-419 Unprotected Primary Channel · CWE-434 Unrestricted Upload of File with
Dangerous Type · CWE-436 Interpretation Conflict · CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request
Smuggling') · CWE-451 User Interface (UI) Misrepresentation of Critical Information · CWE-454 External Initialization of
Trusted Variables or Data Stores · CWE-472 External Control of Assumed-Immutable Web Parameter · CWE-501 Trust Boundary
Violation · CWE-522 Insufficiently Protected Credentials · CWE-525 Use of Web Browser Cache Containing Sensitive
Information · CWE-539 Use of Persistent Cookies Containing Sensitive Information · CWE-598 Use of GET Request Method With
Sensitive Query Strings · CWE-602 Client-Side Enforcement of Server-Side Security · CWE-628 Function Call with
Incorrectly Specified Arguments · CWE-642 External Control of Critical State Data · CWE-646 Reliance on File Name or
Extension of Externally-Supplied File · CWE-653 Insufficient Compartmentalization · CWE-656 Reliance on Security Through
Obscurity · CWE-657 Violation of Secure Design Principles · CWE-676 Use of Potentially Dangerous Function · CWE-693
Protection Mechanism Failure · CWE-799 Improper Control of Interaction Frequency · CWE-807 Reliance on Untrusted Inputs
in a Security Decision · CWE-841 Improper Enforcement of Behavioral Workflow · CWE-1021 Improper Restriction of Rendered
UI Layers or Frames · CWE-1022 Use of Web Link to Untrusted Target with window.opener Access · CWE-1125 Excessive Attack
Surface

## References

- OWASP Cheat Sheet — Secure Product Design: https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html
- OWASP SAMM — Design: Secure Architecture: https://owaspsamm.org/model/design/secure-architecture/
- OWASP SAMM — Design: Threat Assessment: https://owaspsamm.org/model/design/threat-assessment/
- NIST — Guidelines on Minimum Standards for Developer Verification of Software: https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software
- The Threat Modeling Manifesto: https://threatmodelingmanifesto.org/
- Awesome Threat Modeling: https://github.com/hysnsec/awesome-threat-modelling
