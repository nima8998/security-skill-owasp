# A05:2025 — Injection

> Source: OWASP Top 10:2025, https://top10.owasp.org/2025/A05_2025-Injection/ — © OWASP Top 10 Team, CC BY 3.0.
> Condensed and restructured for code auditing; "How to check in code" is added by this skill.

## Summary

Down from #3 to #5. One of the most tested categories (100% of applications were tested for some form of injection) and
the one with the most CVEs. Cross-site scripting (very frequent, lower impact) and SQL injection (less frequent, high
impact) dominate; the volume of XSS CVEs lowers the category's average impact.

## Stats

| CWEs mapped | Max incidence | Avg incidence | Max coverage | Avg coverage | Avg weighted exploit | Avg weighted impact | Total occurrences | Total CVEs |
|---|---|---|---|---|---|---|---|---|
| 37 | 13.77% | 3.08% | 100.00% | 42.93% | 7.15 | 4.32 | 1,404,249 | 62,445 |

## What it covers

- Untrusted input reaching an interpreter (browser, database, shell, LDAP, expression engine…) and being executed as part
  of a command or query.
- Input not validated, filtered or sanitized.
- Dynamic queries or non-parameterized calls without context-aware escaping.
- Unsanitized input in ORM search parameters, letting attackers extract extra records.
- Hostile data concatenated into queries, commands or stored procedures so it becomes part of the command structure.
- Common forms: SQL, NoSQL, OS command, ORM, LDAP, Expression Language / OGNL, and cross-site scripting (XSS).
- Detect via source review plus automated testing (including fuzzing) of all inputs: parameters, headers, URLs, cookies,
  JSON, SOAP, XML; SAST/DAST/IAST in CI.
- LLM prompt injection is a related class, covered by the OWASP Top 10 for LLM Applications (LLM01:2025).

## How to prevent (checklist)

- [ ] Use a safe API that keeps data separate from commands: parameterized queries, prepared statements, ORMs.
      Stored procedures are not automatically safe if they concatenate input or use dynamic execution.
- [ ] Where separation is impossible, validate input server-side with allow-lists (not a complete defence on its own).
- [ ] For any remaining dynamic query, escape special characters with the target interpreter's escaping syntax.
- [ ] Never accept user-supplied structural elements (table/column names, sort fields) without mapping them through an
      allow-list — they cannot be escaped.
- [ ] Treat hand-written escaping as fragile: small changes can break it.

## Example attack scenarios

1. A SQL string is built by concatenating a URL parameter; changing it rewrites the `WHERE` clause to return every row,
   and potentially modify data or call stored procedures.
2. An HQL (Hibernate) query built with concatenation is bypassed the same way — using an ORM doesn't help when queries
   are built from raw input.
3. A domain parameter is passed to a shell lookup command; appending a command separator runs an extra command that
   reads server files.

## How to check in code

### Where to look
- Every database access: raw SQL, query builders, ORM "raw" escapes, NoSQL query objects built from request bodies.
- Every process execution and every dynamic code evaluation.
- HTML rendering: server templates and client frameworks' "raw HTML" escape hatches; URL attributes (`href`, `src`).
- Template engines rendering user-controlled template strings (SSTI).
- LDAP, XPath, header values, log lines, file names passed to interpreters.
- LLM features: user text concatenated into prompts that can call tools or reach sensitive data.

### Trace source → sink
For each sink, find where its data comes from. Sources: request params/query/body/headers/cookies, uploaded file names
and contents, webhook payloads, database values written earlier by users (stored injection), environment-controlled
values. If an attacker-controlled source reaches the sink without parameterization or correct encoding, it is a finding.

### Grep starting points
```
# SQL built from strings
(query|execute|exec|raw|prepare)\(\s*[`'"].*(\$\{|\+\s*\w|%s|\{\})
`[^`]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY)\b[^`]*\$\{   # template literal with SQL, often stored in a variable first
execute\(f["']|\.format\(.*(SELECT|INSERT|UPDATE|DELETE)|"SELECT .*" ?\+
\.raw\(|\.extra\(|RawSQL|createNativeQuery|createQuery\(.*\+|sequelize\.query|knex\.raw|\$queryRawUnsafe|\$executeRawUnsafe|FromSqlRaw
# OS commands
child_process|exec\(|execSync|spawn\([^)]*shell:\s*true|os\.system|os\.popen|subprocess\.[a-z_]+\([^)]*shell\s*=\s*True
Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process\.Start|system\(|passthru|shell_exec|proc_open|popen
# Code / template evaluation
\beval\(|new Function\(|vm\.run|setTimeout\(\s*['"`]|render_template_string|Template\(.*request|from_string\(|SpEL|OGNL
# XSS sinks
innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|v-html|\[innerHTML\]|bypassSecurityTrust
\|\s*safe|mark_safe|autoescape false|@Html\.Raw|<%-|\{\{\{|th:utext|href=\{.*(user|input|url)
# NoSQL / LDAP / XPath / headers
\$where|\$regex|find\(\s*req\.body|findOne\(\s*req\.body|ldap.*search\(.*\+|xpath.*\+|setHeader\([^)]*req\.
```

### Stack-specific signals
- **React/Vue/Angular:** auto-escape by default; look for `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`,
  `bypassSecurityTrust*`, and `javascript:` URLs in user-controlled `href`.
- **Prisma:** tagged `$queryRaw\`...\`` is parameterized; `$queryRawUnsafe` with interpolation is not.
- **Node + MongoDB:** JSON bodies can carry operators (`{"$ne": null}`) into `find()` — operator injection.
- **Django:** ORM is safe; `raw()`, `extra()`, `cursor.execute` with `%` formatting are not. Templates escape unless `|safe`.
- **Java:** `Statement` with concatenation vs `PreparedStatement`; HQL/JPQL concatenation; SpEL/OGNL evaluation.
- **PHP:** `mysqli_query` with interpolation; `PDO::query` with concatenation; `eval`, `preg_replace` with `/e`.

### Common false positives
- Concatenation of constants or values from a strict allow-list (e.g. sort column mapped through a dictionary).
- Tagged-template SQL helpers (`sql\`...\``) that parameterize automatically — check the library.
- Shell calls with argument arrays and no shell (`execFile`, `subprocess.run([...])`) — still check argument injection
  (CWE-88) such as values starting with `-`.

## Mapped CWEs (37)

CWE-20 Improper Input Validation · CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream
Component ('Injection') · CWE-76 Improper Neutralization of Equivalent Special Elements · CWE-77 Improper
Neutralization of Special Elements used in a Command ('Command Injection') · CWE-78 Improper Neutralization of Special
Elements used in an OS Command ('OS Command Injection') · CWE-79 Improper Neutralization of Input During Web Page
Generation ('Cross-site Scripting') · CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic
XSS) · CWE-83 Improper Neutralization of Script in Attributes in a Web Page · CWE-86 Improper Neutralization of Invalid
Characters in Identifiers in Web Pages · CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument
Injection') · CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') · CWE-90
Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') · CWE-91 XML Injection (aka Blind
XPath Injection) · CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection') · CWE-94 Improper Control of
Generation of Code ('Code Injection') · CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code
('Eval Injection') · CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection') ·
CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page · CWE-98 Improper Control of Filename for
Include/Require Statement in PHP Program ('PHP Remote File Inclusion') · CWE-99 Improper Control of Resource Identifiers
('Resource Injection') · CWE-103 Struts: Incomplete validate() Method Definition · CWE-104 Struts: Form Bean Does Not
Extend Validation Class · CWE-112 Missing XML Validation · CWE-113 Improper Neutralization of CRLF Sequences in HTTP
Headers ('HTTP Response Splitting') · CWE-114 Process Control · CWE-115 Misinterpretation of Output · CWE-116 Improper
Encoding or Escaping of Output · CWE-129 Improper Validation of Array Index · CWE-159 Improper Handling of Invalid Use of
Special Elements · CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') · CWE-493
Critical Public Variable Without Final Modifier · CWE-500 Public Static Field Not Marked Final · CWE-564 SQL Injection:
Hibernate · CWE-610 Externally Controlled Reference to a Resource in Another Sphere · CWE-643 Improper Neutralization of
Data within XPath Expressions ('XPath Injection') · CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax ·
CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language
Injection')

## References

- OWASP Proactive Controls — Secure Database Access: https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database
- OWASP ASVS — V5 Input Validation and Encoding: https://owasp.org/www-project-application-security-verification-standard
- OWASP Testing Guide — SQL Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- OWASP Testing Guide — Command Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
- OWASP Testing Guide — ORM Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection
- OWASP Cheat Sheet — Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- OWASP Cheat Sheet — SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Cheat Sheet — Injection Prevention in Java: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html
- OWASP Cheat Sheet — Query Parameterization: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
- OWASP Automated Threats to Web Applications (OAT-014): https://owasp.org/www-project-automated-threats-to-web-applications/
- PortSwigger — Server-side template injection: https://portswigger.net/kb/issues/00101080_serversidetemplateinjection
- Awesome Fuzzing: https://github.com/secfigo/Awesome-Fuzzing
