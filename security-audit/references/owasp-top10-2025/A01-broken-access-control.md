# A01:2025 — Broken Access Control

> Source: OWASP Top 10:2025, https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ — © OWASP Top 10 Team,
> CC BY 3.0. Condensed and restructured for code auditing; "How to check in code" is added by this skill.

## Summary

Ranked #1 again. Every application in the dataset showed some form of broken access control; it has the most
occurrences in the contributed data and the second-highest number of related CVEs. Access control should keep users
from acting outside their intended permissions; failures lead to unauthorized disclosure, modification or deletion of
data, or business functions run by the wrong people.

## Stats

| CWEs mapped | Max incidence | Avg incidence | Max coverage | Avg coverage | Avg weighted exploit | Avg weighted impact | Total occurrences | Total CVEs |
|---|---|---|---|---|---|---|---|---|
| 40 | 20.15% | 3.74% | 100.00% | 42.93% | 7.04 | 3.84 | 1,839,701 | 32,654 |

## What it covers

- Violating least privilege / deny-by-default: access open to everyone instead of granted to specific roles or users.
- Bypassing checks by tampering with URLs (parameter tampering, forced browsing), internal state, HTML, or API requests.
- Insecure direct object references (IDOR): viewing or editing someone else's record by supplying its identifier.
- APIs missing access control on POST, PUT and DELETE.
- Privilege escalation: acting without being logged in, or as admin while logged in as a regular user.
- Metadata manipulation: replaying or tampering with JWTs, cookies or hidden fields; abusing JWT invalidation.
- CORS misconfiguration letting unauthorized or untrusted origins call the API.
- Forced browsing to authenticated or privileged pages.
- Also mapped here: path traversal, SSRF, CSRF, open redirects, sensitive files under the web root, exposed directory
  listings, insecure temp files (see the CWE list).

## How to prevent (checklist)

- [ ] Deny by default, except for public resources.
- [ ] Implement access control once, centrally, and reuse it everywhere; minimise CORS.
- [ ] Enforce record ownership in the model so users cannot create/read/update/delete arbitrary records.
- [ ] Enforce unique business limits in domain models.
- [ ] Disable directory listing; keep `.git`, metadata and backup files out of web roots.
- [ ] Log access-control failures and alert admins when appropriate (e.g. repeated failures).
- [ ] Rate-limit APIs and controllers to reduce damage from automated tools.
- [ ] Invalidate server-side sessions on logout; keep stateless JWTs short-lived; use refresh tokens with OAuth-standard
      revocation for longer-lived access.
- [ ] Prefer established toolkits/patterns with simple, declarative access control.
- [ ] Include functional access-control tests in unit and integration suites.
- [ ] Enforce access control only in trusted server-side code or serverless APIs, never only in the client.

## Example attack scenarios

1. An unverified `acct` request parameter is passed straight into the SQL query that loads account data; changing it
   returns another customer's account.
2. Admin pages are reachable by requesting their URL directly; an anonymous or non-admin user can load them.
3. All access control lives in front-end JavaScript; the attacker calls the admin API directly with `curl`.

## How to check in code

### Where to look
- Route/controller registration and the middleware chain applied to each route group.
- Handlers that take an identifier from params, query, body or headers and load/modify a record.
- Admin and internal endpoints, background job triggers, webhooks, debug routes.
- File download/upload paths, static file serving, archive extraction.
- Redirects after login/logout, and any outbound HTTP request whose URL comes from input (SSRF).
- CORS and cookie configuration; CSRF protection for cookie-based sessions.
- Database-level policies: Supabase/Postgres RLS, Firebase rules, multi-tenant scoping.
- Front-end code that hides buttons or routes as the only "protection".

### What to verify for every sensitive route
1. **Authentication** is enforced (compare with sibling routes: one route missing the middleware is a classic bug).
2. **Authorization** checks role *and* ownership/tenant on the server, using the identity from the session/token, never
   a user id sent by the client.
3. The query itself is scoped (`where owner_id = currentUser`) rather than fetch-then-forget-to-check.
4. State-changing methods (POST/PUT/PATCH/DELETE) have the same or stricter checks as GET.

### Grep starting points
```
req\.(params|query|body)\.(id|userId|accountId|orgId)      # ids taken from the request
findById|findByPk|findOne\(\{ *id|get_object_or_404|objects\.get\(|repository\.findById
sendFile|send_file|res\.download|readFile\(.*(req|request)\.|open\(.*request\.   # path traversal
\.\./|path\.join\(.*req\.|os\.path\.join\(.*request\.
redirect\(.*(req|request)\.(query|args|params|body)          # open redirect
fetch\(|axios\.|got\(|request\(|requests\.(get|post)|urlopen|HttpClient|WebClient   # SSRF if URL is user-controlled
cors\(|Access-Control-Allow-Origin|allowedOrigins|AllowAnyOrigin
csrf|csurf|CsrfViewMiddleware|ValidateAntiForgeryToken|SameSite
jwt\.decode\(|verify\s*=\s*False|algorithms|ignoreExpiration
isAdmin|role ?===?|hasRole|permission|@PreAuthorize|\[Authorize|\[AllowAnonymous\]|permitAll
express\.static|serveStatic|StaticFiles|autoindex on|Options \+Indexes
enable row level security|create policy|using \(true\)
```

### Stack-specific signals
- **Express / Hono / Fastify:** middleware order; routers mounted without auth; `app.use("*", ...)` leaking into sibling
  sub-apps; handlers that trust `req.body.userId`.
- **Next.js:** route handlers and server actions need their own auth checks; `middleware.ts` matchers that skip paths;
  data fetched with a service-role/admin key on behalf of the user.
- **Django / DRF:** missing `@login_required`/`LoginRequiredMixin`; `permission_classes = [AllowAny]`; querysets not
  filtered by `request.user`.
- **Flask / FastAPI:** routes without `@login_required` or `Depends(current_user)`; ownership checks missing.
- **Spring:** `permitAll()` patterns too broad; missing `@PreAuthorize`; `@RequestParam Long id` loaded without owner check.
- **ASP.NET:** missing `[Authorize]`, stray `[AllowAnonymous]`, policies not applied to minimal APIs.
- **Rails / Laravel:** `skip_before_action :authenticate_user!`; routes outside the `auth` middleware group;
  `Model.find(params[:id])` instead of `current_user.models.find`.
- **Supabase / Firebase:** tables without RLS, policies using `true`, service-role key reachable from the client.

### Common false positives
- Endpoints that are public by design (health checks, public catalog) — confirm with the product intent.
- Ownership enforced at the data layer (RLS, scoped repositories) rather than in the handler — trace it before reporting.
- Checks done by an API gateway or proxy: if its configuration is in the repo, verify it; otherwise list under
  "Needs verification".

## Mapped CWEs (40)

CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') · CWE-23 Relative Path Traversal ·
CWE-36 Absolute Path Traversal · CWE-59 Improper Link Resolution Before File Access ('Link Following') · CWE-61 UNIX
Symbolic Link (Symlink) Following · CWE-65 Windows Hard Link · CWE-200 Exposure of Sensitive Information to an
Unauthorized Actor · CWE-201 Exposure of Sensitive Information Through Sent Data · CWE-219 Storage of File with
Sensitive Data Under Web Root · CWE-276 Incorrect Default Permissions · CWE-281 Improper Preservation of Permissions ·
CWE-282 Improper Ownership Management · CWE-283 Unverified Ownership · CWE-284 Improper Access Control · CWE-285
Improper Authorization · CWE-352 Cross-Site Request Forgery (CSRF) · CWE-359 Exposure of Private Personal Information
to an Unauthorized Actor · CWE-377 Insecure Temporary File · CWE-379 Creation of Temporary File in Directory with
Insecure Permissions · CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak') · CWE-424 Improper
Protection of Alternate Path · CWE-425 Direct Request ('Forced Browsing') · CWE-441 Unintended Proxy or Intermediary
('Confused Deputy') · CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere · CWE-538
Insertion of Sensitive Information into Externally-Accessible File or Directory · CWE-540 Inclusion of Sensitive
Information in Source Code · CWE-548 Exposure of Information Through Directory Listing · CWE-552 Files or Directories
Accessible to External Parties · CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key · CWE-601 URL
Redirection to Untrusted Site ('Open Redirect') · CWE-615 Inclusion of Sensitive Information in Source Code Comments ·
CWE-639 Authorization Bypass Through User-Controlled Key · CWE-668 Exposure of Resource to Wrong Sphere · CWE-732
Incorrect Permission Assignment for Critical Resource · CWE-749 Exposed Dangerous Method or Function · CWE-862 Missing
Authorization · CWE-863 Incorrect Authorization · CWE-918 Server-Side Request Forgery (SSRF) · CWE-922 Insecure Storage
of Sensitive Information · CWE-1275 Sensitive Cookie with Improper SameSite Attribute

## References

- OWASP Proactive Controls C1 — Implement Access Control: https://top10proactive.owasp.org/archive/2024/the-top-10/c1-accesscontrol/
- OWASP ASVS 5.0 — V8 Authorization: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md
- OWASP Testing Guide — Authorization Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README
- OWASP Cheat Sheet — Authorization: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- PortSwigger — Exploiting CORS misconfigurations: https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
- OAuth — Revoking Access: https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/
