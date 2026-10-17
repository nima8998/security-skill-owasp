<!--
  Template for the security-audit skill. Fill every section, keep the headings in this order, and delete these
  HTML comments. Headings may be translated into the user's language. Write "—" for fields that do not apply.
-->
# Security Audit Report — <Project name>

| | |
|---|---|
| **Date** | <dd-mm-yy> |
| **Target** | <absolute path, or GitHub URL + local clone path> |
| **Commit** | <short hash, or "not a git repository"> |
| **Scope** | <whole repository / specific paths / diff or PR> |
| **Method** | Static source review against OWASP Top 10:2025<; tools run, e.g. `npm audit`> |
| **Auditor** | AI agent using the `security-audit` skill |

## 1. Executive summary

<2–5 sentences: overall security posture, the most important risks in plain language, and what to fix first.>

| Critical | High | Medium | Low | Info |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 0 | 0 | 0 | 0 |

## 2. Scope and architecture

- **Stack:** <languages, frameworks, versions>
- **Entry points:** <HTTP routes, handlers, jobs, CLIs reviewed>
- **Authentication / authorization model:** <how users are identified and where permissions are enforced>
- **Data stores and external services:** <databases, storage, third-party APIs>
- **Trust boundaries:** <where untrusted input enters; outbound calls>
- **Excluded:** <anything not reviewed, and why>

## 3. OWASP Top 10:2025 coverage

| ID | Category | Result | Findings |
|---|---|---|---|
| A01 | Broken Access Control | <Findings / No findings / N/A: reason> | <SEC-001, …> |
| A02 | Security Misconfiguration | | |
| A03 | Software Supply Chain Failures | | |
| A04 | Cryptographic Failures | | |
| A05 | Injection | | |
| A06 | Insecure Design | | |
| A07 | Authentication Failures | | |
| A08 | Software or Data Integrity Failures | | |
| A09 | Security Logging and Alerting Failures | | |
| A10 | Mishandling of Exceptional Conditions | | |

## 4. Findings

<!-- One block per finding, ordered by severity (Critical → Info), then by confidence. IDs are sequential. -->

### SEC-001 — <Short, specific title>

| | |
|---|---|
| **Severity** | <Critical / High / Medium / Low / Info> |
| **Confidence** | <High / Medium / Low> |
| **OWASP** | <A0X:2025 Category name> |
| **CWE** | <CWE-NNN: name> |
| **Location** | `<path/to/file.ext:line>`<, further locations> |

**Description.** <What is wrong and why it is a vulnerability in this codebase.>

**Evidence.**

```<language>
<minimal excerpt of the vulnerable code; mask secrets like abcd…>
```

**Impact.** <What an attacker can concretely achieve, and who is able to attempt it.>

**Suggested fix.** <Concrete steps in the project's own language/framework.>

```<language>
<corrected version, when practical>
```

**References.** <OWASP / cheat-sheet links from the category reference file>

## 5. Needs verification and dismissed candidates

| Item | Why it is not a reported finding | How to verify |
|---|---|---|
| <pattern / location> | <compensating control found, unreachable, depends on deployment…> | <what to check> |

## 6. Positive observations

- <Security controls done well that should be kept.>

## 7. Limitations

- Static review only: no dynamic testing and no access to the deployed environment, CI settings or cloud configuration.
- <Tools that were unavailable, files skipped (generated, vendored, minified), etc.>

## 8. Remediation plan

| Priority | Finding(s) | Action | Effort |
|---|---|---|---|
| 1 | <SEC-00X> | <what to do> | <S / M / L> |
