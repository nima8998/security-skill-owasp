# OWASP API Security Top 10:2023 — supplementary checklist

> Source: OWASP API Security Top 10:2023, https://owasp.org/API-Security/editions/2023/en/0x11-t10/ — © OWASP
> Foundation, licensed under CC BY-SA 4.0. Condensed for code auditing; the "In code" notes and mappings are
> additions of this skill. As an adaptation, this file is distributed under CC BY-SA 4.0 as well.

Use this file when reconnaissance finds an API: REST controllers, GraphQL schemas/resolvers, gRPC services, RPC-style
server actions, or a mobile/SPA backend. It does not replace the A01–A10 walk; it sharpens it for APIs, where the
client is a program and every field of every request is attacker-controlled. **Report each finding under its
OWASP Top 10:2025 category** (mapping column) and mention the API risk ID in the text.

| ID | Risk | Maps to | In code, look for |
|---|---|---|---|
| API1 | Broken Object Level Authorization (BOLA) | A01 | Handlers that load a record by an ID from the path/query/body (`findById(req.params.id)`, `get_object_or_404(Model, pk=…)`) without scoping the query to the caller (`where: { id, ownerId: user.id }`) or a policy check. Check every verb — GET is often fixed while PUT/DELETE/PATCH are not. GraphQL: resolvers for `node(id:)` and nested fields. |
| API2 | Broken Authentication | A07 | Endpoints missing from the auth middleware list; JWT verification options (algorithms allow-list, `exp`, `aud`, `iss`); API keys in query strings; long-lived tokens without revocation; no rate limit on token/OTP/reset endpoints. |
| API3 | Broken Object Property Level Authorization (BOPLA) | A01 / A08 | **Excessive data exposure**: returning ORM objects or `SELECT *` rows directly (`res.json(user)`) including `password_hash`, `role`, internal flags. **Mass assignment**: `Model.update(req.body)`, `Object.assign(entity, req.body)`, serializers with `fields = '__all__'`, `[Bind]` without an allow-list — lets clients set `role`, `isAdmin`, `balance`, `ownerId`. |
| API4 | Unrestricted Resource Consumption | A10 / A06 | No caps on page size (`limit` from query without max), body size, upload size, array lengths, GraphQL depth/complexity/aliases/batching, regex on user input, outbound calls billed per request (SMS, email, LLM tokens). |
| API5 | Broken Function Level Authorization (BFLA) | A01 | Admin or internal routes (`/admin`, `/internal`, `/debug`, `/v1/users/{id}/role`) protected only by "not linked from the UI"; role checks done in the client; HTTP-method confusion (route protected for POST but not for PUT). |
| API6 | Unrestricted Access to Sensitive Business Flows | A06 | Purchase, sign-up, referral, coupon, reservation, voting, comment flows with no anti-automation (rate limit per account/device, CAPTCHA, step-up, quotas). |
| API7 | Server-Side Request Forgery | A01 | Any outbound request whose URL or host comes from input: webhooks, URL previews, image/PDF fetchers, import-from-URL, OAuth/OIDC discovery. Check for an allow-list, blocking of private/link-local ranges (incl. `169.254.169.254`), redirect handling and DNS rebinding. |
| API8 | Security Misconfiguration | A02 | CORS, verbose errors, missing TLS enforcement, permissive HTTP methods, unnecessary features (GraphQL introspection/playground in production), missing security headers on HTML endpoints. |
| API9 | Improper Inventory Management | A02 | Old API versions still routed (`/v1` next to `/v2` with weaker checks), debug/test endpoints shipped, undocumented routes, OpenAPI spec out of sync with routes, beta hosts sharing production data. |
| API10 | Unsafe Consumption of APIs | A08 / A05 | Data from third-party APIs trusted more than user input: used in queries, rendered as HTML, followed as redirects, deserialized; no TLS validation, timeouts or response-size limits on those calls. |

## Grep starting points

```
# BOLA / BFLA: handlers that load by id
findById\(|findOne\(\{\s*(where:\s*)?\{\s*id|get_object_or_404|\.objects\.get\(pk=|FindAsync\(id|@PathVariable|req\.params\.\w*[iI]d
# BOPLA: mass assignment and over-exposure
update\(req\.body|create\(req\.body|Object\.assign\([^,]+,\s*req\.body|\.\.\.req\.body|fields\s*=\s*['"]__all__|\[Bind\]|permit!|res\.json\(\s*user\b
# Resource consumption
limit\s*=\s*(req|request)\.|parseInt\(req\.query\.(limit|size|per_page)|depthLimit|queryComplexity|introspection:\s*true|graphiql:\s*true|playground
# SSRF
(fetch|axios\.(get|post)|got|request|http\.get|urlopen|requests\.(get|post)|HttpClient\.\w+Async)\(\s*[^'"`)]*(url|uri|href|host|target|callback|webhook)
# Inventory
/v1/|/beta/|/internal/|/debug/|/test/
```

## GraphQL-specific notes

- Authorization must happen in resolvers or a field-level directive, not only at the HTTP layer — a single
  endpoint serves every operation.
- Batching and aliases let one request run thousands of resolver calls (brute force through one HTTP request bypasses
  per-request rate limits).
- Introspection in production is Low on its own; it matters when combined with BFLA (hidden admin mutations).

## References

- OWASP API Security Project: https://owasp.org/API-Security/
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- OWASP Mass Assignment Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP ASVS 5.0 — V4 API and Web Service: https://github.com/OWASP/ASVS/tree/master/5.0/en
