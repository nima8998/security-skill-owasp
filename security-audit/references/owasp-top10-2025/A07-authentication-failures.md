# A07:2025 — Authentication Failures

> Source: OWASP Top 10:2025, https://top10.owasp.org/2025/A07_2025-Authentication_Failures/ — © OWASP Top 10 Team,
> CC BY 3.0. Condensed and restructured for code auditing; "How to check in code" is added by this skill.

## Summary

Stays at #7, renamed to better reflect its 36 CWEs. Standardized frameworks have not pushed it down. Notable weaknesses:
hard-coded passwords and credentials, improper certificate validation, improper authentication and session fixation.

## Stats

| CWEs mapped | Max incidence | Avg incidence | Max coverage | Avg coverage | Avg weighted exploit | Avg weighted impact | Total occurrences | Total CVEs |
|---|---|---|---|---|---|---|---|---|
| 36 | 15.80% | 2.92% | 100.00% | 37.14% | 7.69 | 4.44 | 1,120,673 | 7,147 |

## What it covers

- Automated attacks: credential stuffing with breached pairs, and hybrid "password spray" that mutates breached
  passwords (e.g. incrementing numbers).
- Brute force that isn't throttled or blocked quickly.
- Default, weak or well-known passwords (admin/admin) still accepted.
- Registration with passwords already known to be breached.
- Recovery flows using knowledge-based answers, which can't be made safe.
- Passwords stored in plaintext, reversibly encrypted or weakly hashed (see A04).
- Missing, ineffective or weakly-fallbacked MFA.
- Session identifiers exposed in URLs, hidden fields or other client-readable places.
- Same session identifier reused after login (session fixation).
- Sessions or tokens (especially SSO) not invalidated on logout or inactivity.
- The scope/intended audience of presented credentials not checked.

## How to prevent (checklist)

- [ ] Enforce MFA where possible to stop credential stuffing, brute force and stolen-credential reuse.
- [ ] Encourage password managers.
- [ ] Ship and deploy with no default credentials, especially for admin accounts.
- [ ] Check new/changed passwords against the top 10,000 worst passwords and against breach data (e.g. haveibeenpwned).
- [ ] Follow NIST SP 800-63B §5.1.1 (or another current evidence-based policy) for length and complexity.
- [ ] Don't force periodic rotation; require reset only on suspected compromise.
- [ ] Prevent account enumeration: identical responses for all outcomes ("invalid username or password").
- [ ] Throttle or progressively delay failed logins without enabling denial of service; log failures and alert on attacks.
- [ ] Use a server-side session manager that issues a new high-entropy id at login, keeps it in a secure cookie (never the
      URL), and expires it on logout, idle and absolute timeouts.
- [ ] Prefer a vetted authentication system over a home-made one.
- [ ] Validate credential intent: check JWT `aud`, `iss` and scopes.

## Example attack scenarios

1. Attackers replay breached credentials and predictable variations (Winter2025 → Winter2026); without anti-automation
   the login becomes an oracle confirming valid accounts.
2. Password-only authentication, plus rotation and complexity rules that push users to reuse weak passwords, enables most
   account takeovers; align with NIST 800-63 and require MFA on critical systems.
3. Sessions aren't terminated: a user closes the tab on a shared computer, or SSO survives a single-app logout, and the
   next person using the browser is still logged in.

## How to check in code

### Where to look
- Login, registration, password change, password reset, email change, MFA enrolment/verification, "remember me".
- Session setup (cookie options, store, regeneration), logout handlers, token issuing/refresh/revocation.
- JWT signing/verification options; OAuth/OIDC callback handlers; API key handling.
- Seed data, migrations, fixtures and config files containing users or passwords.
- If auth is delegated (Supabase Auth, Auth0, Cognito, Firebase, Keycloak), review the integration: token verification,
  redirect URLs, which claims are trusted, and how the app maps identities to permissions.

### What to verify
- Rate limiting / lockout / backoff on login, OTP, reset and sign-up endpoints.
- Identical errors and timing for unknown user vs wrong password; reset endpoint doesn't reveal account existence.
- Password policy: minimum length (≥ 8, preferably ≥ 12), no silly maximums, breached-password check if feasible.
- Session id regenerated at login and privilege change; cookie `Secure`/`HttpOnly`/`SameSite`; idle and absolute expiry;
  logout destroys the server-side session or revokes the refresh token.
- JWT: signature verified with a pinned algorithm; `exp` enforced; `aud`/`iss` checked; tokens not in URLs or
  `localStorage` when avoidable.
- Reset tokens: CSPRNG, single-use, short expiry, invalidated after password change; password change asks for the
  current password.
- OAuth: `state` (and PKCE) validated; `redirect_uri` exact-match; ID token validated, not just decoded.
- No hardcoded or default credentials, including in seeds that run in production.

### Grep starting points
```
login|signin|sign_in|authenticate|passport\.authenticate|AuthenticationManager|check_password|password_verify
rate.?limit|express-rate-limit|slowDown|throttle|django-axes|Bucket4j|AspNetCoreRateLimit|lockout
session\.regenerate|cycle_key|rotate.*session|SessionFixation|changeSessionId|session_regenerate_id
jwt\.(sign|verify|decode)|expiresIn|ignoreExpiration|audience|issuer|algorithms|verify_signature
(password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]|admin/admin|defaultPassword|DEFAULT_ADMIN
[?&](token|session|sid|jwt|access_token)=
User not found|Unknown user|Invalid password|wrong password|Email not registered
reset.*token|forgot.?password|uuid\.v1|Date\.now\(\).*token
state=|code_verifier|redirect_uri
```

### Common false positives
- Delegated identity providers already handle hashing, lockout and MFA — focus on the integration, and note provider
  settings (MFA, lockout) as "Needs verification" because they live outside the repo.
- Hardcoded credentials in test fixtures that never run against real systems → Low/Info, unless they are real.

## Mapped CWEs (36)

CWE-258 Empty Password in Configuration File · CWE-259 Use of Hard-coded Password · CWE-287 Improper Authentication ·
CWE-288 Authentication Bypass Using an Alternate Path or Channel · CWE-289 Authentication Bypass by Alternate Name ·
CWE-290 Authentication Bypass by Spoofing · CWE-291 Reliance on IP Address for Authentication · CWE-293 Using Referer
Field for Authentication · CWE-294 Authentication Bypass by Capture-replay · CWE-295 Improper Certificate Validation ·
CWE-297 Improper Validation of Certificate with Host Mismatch · CWE-298 Improper Validation of Certificate Expiration ·
CWE-299 Improper Check for Certificate Revocation · CWE-300 Channel Accessible by Non-Endpoint · CWE-302 Authentication
Bypass by Assumed-Immutable Data · CWE-303 Incorrect Implementation of Authentication Algorithm · CWE-304 Missing
Critical Step in Authentication · CWE-305 Authentication Bypass by Primary Weakness · CWE-306 Missing Authentication for
Critical Function · CWE-307 Improper Restriction of Excessive Authentication Attempts · CWE-308 Use of Single-factor
Authentication · CWE-309 Use of Password System for Primary Authentication · CWE-346 Origin Validation Error · CWE-350
Reliance on Reverse DNS Resolution for a Security-Critical Action · CWE-384 Session Fixation · CWE-521 Weak Password
Requirements · CWE-613 Insufficient Session Expiration · CWE-620 Unverified Password Change · CWE-640 Weak Password
Recovery Mechanism for Forgotten Password · CWE-798 Use of Hard-coded Credentials · CWE-940 Improper Verification of
Source of a Communication Channel · CWE-941 Incorrectly Specified Destination in a Communication Channel · CWE-1390 Weak
Authentication · CWE-1391 Use of Weak Credentials · CWE-1392 Use of Default Credentials · CWE-1393 Use of Default Password

(The OWASP page shows CWE-298 and CWE-299 with CWE-297's name; the names above follow MITRE.)

## References

- OWASP Cheat Sheet — Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Secure Coding Practices: https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
- Have I Been Pwned (breached passwords): https://haveibeenpwned.com/
