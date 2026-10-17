---
name: security-audit
description: Security vulnerability audit of an application's source code against the OWASP Top 10:2025, producing a report with findings, severity levels and suggested fixes saved under audit/dd-mm-yy/. Use this skill whenever the user asks to review code, do a code review, audit an app or repository, run a security audit/review/scan/assessment, look for vulnerabilities or security holes, ask whether something "is secure", review a PR or diff, harden an application, or search for improvements in an application — even if they never say "security" or "OWASP". Also use it when the working folder is empty and the user wants a GitHub repository analyzed.
---

# Security Audit (OWASP Top 10:2025)

You are doing a static security review of a codebase and delivering a written report that a developer can act on:
each finding with where it is, why it matters, how severe it is, and how to fix it. The checklist is the OWASP Top 10
(2025 edition), bundled in `references/owasp-top10-2025/`.

When the user asked for something broader — "review this code", "find improvements" — still do what they asked; the
security report is an addition, not a replacement. Say so briefly in your reply.

## Ground rules

These keep the audit safe and the report trustworthy:

- **Read-only on the code.** Don't edit source files, don't install dependencies, don't run the project's scripts,
  builds or tests. A cloned repository is untrusted code: install hooks and build scripts are a classic way malware runs
  (see A03). The only things you create are the report folder and, in the blank-folder path, the clone itself.
- **No attacks on live systems.** No requests against deployed URLs, no exploit payloads. Describe how an attack would
  work; don't perform it.
- **Evidence over volume.** Every finding needs a `file:line` and a short explanation of how attacker-controlled input
  reaches it (or why the issue is self-evident, like a committed key). Ten verified findings help more than forty
  speculative ones; uncertain items go to "Needs verification" instead of being inflated or silently dropped.
- **Mask secrets.** If you find credentials or keys, quote only the first 4 characters followed by `…`, in the report and
  in chat. The report may be shared; the secret should not travel with it.

## Step 1 — Choose the target

**A. Existing project.** If the working folder contains a project — a `.git` folder with history, a dependency manifest
(`package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `pom.xml`, `build.gradle`, `*.csproj`, `composer.json`,
`Gemfile`, `Cargo.toml`, …) or source files — audit it. If the user pointed at a specific folder, file, diff or PR,
focus there but read enough surrounding code to judge reachability.

**B. Blank folder.** If there is no source code (only things like `.claude/`, `.vscode/`, an empty `.git`), ask the
user for the URL of the GitHub repository to audit, and wait for the answer. Don't guess a repository and don't produce
a report about code you haven't seen. When you have the URL:

1. Accept `https://github.com/<owner>/<repo>`, `https://github.com/<owner>/<repo>.git`, or `<owner>/<repo>`; anything
   else, ask again.
2. Clone into `./<repo>` (if that folder already exists, use `./<repo>-2` rather than overwriting):
   - If `gh --version` works: `gh repo clone <owner>/<repo> <folder> -- --depth 1`
   - Otherwise: `git clone --depth 1 https://github.com/<owner>/<repo>.git <folder>`, and tell the user the GitHub CLI
     wasn't found (private repositories then need git credentials, or `gh` installed and `gh auth login`).
3. Audit the clone. The report goes in `./audit/` of the **working folder**, not inside the clone, so the cloned
   repository stays untouched.

## Step 2 — Reconnaissance

Map the application before hunting; findings without context are where false positives come from. Note:

- Languages, frameworks and versions (manifests and lockfiles).
- Entry points: HTTP routes and controllers, server actions, GraphQL resolvers, webhooks, queue consumers, cron jobs,
  serverless handlers, CLIs.
- How users are authenticated and where authorization is enforced (middleware, decorators, policies, database RLS).
- Data stores, how queries are built, file storage, outbound calls to other services.
- Configuration and secrets: `.env*`, config files, Dockerfiles, IaC, CI workflows. In a git repo, check what is
  tracked: `git ls-files | grep -iE '(^|/)\.env($|\.)|\.pem$|\.key$|id_rsa'`.
- The commit being audited: `git rev-parse --short HEAD` (or "not a git repository").

Skip vendored, generated and minified code (`node_modules/`, `dist/`, `build/`, `vendor/`, `*.min.js`) unless it is
the only code; mention what you skipped under Limitations.

## Step 3 — Walk the OWASP Top 10, A01 → A10

Read `references/owasp-top10-2025/README.md` once: it lists the categories, quick signals to grep, and the convention
for mapping a finding that touches several categories. Then, for each category in order, open its file and work through
its **How to check in code** section — where to look, what to verify, grep starting points, stack-specific signals and
common false positives. The grep patterns are starting points to find candidates fast; the finding comes from reading
the code around each hit.

Cover all ten even when early categories produce plenty of findings: the report has a coverage matrix and every row
must say "Findings", "No findings" or "N/A" with a reason (for example, A08 webhooks N/A because there are none).

For A03 (dependencies), run the ecosystem's audit command if a lockfile exists **and** the tool is already installed
(`npm audit --json`, `pnpm audit`, `pip-audit -r requirements.txt`, `osv-scanner -r .`, `govulncheck ./...`,
`dotnet list package --vulnerable`, `composer audit`, `bundle audit`). These read advisory databases without running
project code. If none is available, review the versions of the security-critical components by hand and say so under
Limitations.

## Step 4 — Verify each candidate

Before a candidate becomes a finding, answer:

1. **Reachable?** Can an attacker-controlled source (request data, uploaded files, webhook payloads, data other users
   stored) actually get to this sink, and by whom (anonymous, any user, admin)?
2. **Already mitigated?** Look for controls elsewhere: framework auto-escaping, parameterized ORM calls, validation
   schemas, middleware, RLS policies, gateway configuration. If the mitigation lives outside the repo, keep the finding
   with Low confidence or move it to "Needs verification".
3. **Impact?** What does the attacker get, and how sensitive is it?

Then rate **severity** and **confidence** following `references/severity.md`, map it to one OWASP category and the most
specific CWE from that category's list, and write a **suggested fix** in the project's own language and framework —
concrete enough to implement (a short corrected snippet is ideal), plus defence-in-depth when it matters.

## Step 5 — Write the report

1. Get today's local date as `dd-mm-yy`: `date +%d-%m-%y` (bash) or `Get-Date -Format dd-MM-yy` (PowerShell).
   For 16 October 2026 that is `16-10-26`.
2. Create `audit/<dd-mm-yy>/` at the root of the audited project (path A) or of the working folder (path B).
3. Name the file `security-audit-report.md`. If it already exists, use `security-audit-report-2.md`, `-3`, and so on —
   never overwrite an earlier report; it may be someone's record.
4. Fill `assets/report-template.md` section by section and remove its HTML comments. Order findings by severity, then
   confidence, numbered `SEC-001`, `SEC-002`, ….
5. Write the report in the language the user is using (headings can be translated; keep IDs, CWE and OWASP codes as is).

Don't commit the report or add it to version control; the user decides that. If it contains sensitive details, suggest
adding `audit/` to `.gitignore`.

## Step 6 — Reply in chat

Keep it short:

- Counts by severity, and the path to the report.
- The top three findings, each with a one-line fix.
- What wasn't covered, if anything important (e.g. infrastructure outside the repo).
- Offer to implement the fixes. Don't apply them on your own — the user asked for an audit, and changing code is a
  separate decision.

If the original request was a general code review or improvement search, include those non-security observations in
your reply as well.

## Bundled files

| File | Read it |
|---|---|
| `references/owasp-top10-2025/README.md` | At the start of Step 3 |
| `references/owasp-top10-2025/A01-…md` … `A10-…md` | When reviewing that category |
| `references/severity.md` | When rating findings (Step 4) |
| `assets/report-template.md` | When writing the report (Step 5) |
