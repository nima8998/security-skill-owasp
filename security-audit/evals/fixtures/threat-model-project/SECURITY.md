# Security policy and threat model

Report vulnerabilities privately to security@tracker.example. Do not open public issues.

## What this project does and where untrusted input enters

A multi-tenant project tracker exposed as a JSON API on the internet. Every request comes from an authenticated user
of some tenant (API token in the `Authorization` header). Tenants are separate customer companies.

## Trust levels

- **Operators** (people with `is_admin = 1`) are our own staff. They are fully trusted, including the ability to run
  code on the server.
- **Users** are trusted only within their own tenant.

## How we rate severity

- Any way for a user of one tenant to read or modify another tenant's data is **Critical**, regardless of the amount
  of data. Tenant isolation is our core promise to customers.
- Denial of service is Medium at most.

## Anything to leave alone

- `/admin/console` executes Python on purpose: it is the operators' maintenance console and is protected by
  `admin_required`. Do not report it as code injection unless a non-operator can reach it.
- Missing browser security headers (CSP, X-Frame-Options, etc.): the service only returns JSON and serves no HTML.
