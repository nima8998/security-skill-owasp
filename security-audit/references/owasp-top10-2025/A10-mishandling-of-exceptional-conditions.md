# A10:2025 — Mishandling of Exceptional Conditions

> Source: OWASP Top 10:2025, https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/ — © OWASP
> Top 10 Team, CC BY 3.0. Condensed and restructured for code auditing; "How to check in code" is added by this skill.

## Summary

New in 2025. Groups 24 CWEs about improper error handling, logic errors, failing open and related behaviour when software
meets abnormal conditions — previously lumped under vague "code quality". Notable CWEs: CWE-209 error messages with
sensitive information, CWE-234 failure to handle missing parameters, CWE-274 improper handling of insufficient
privileges, CWE-476 NULL pointer dereference, CWE-636 not failing securely ("failing open").

## Stats

| CWEs mapped | Max incidence | Avg incidence | Max coverage | Avg coverage | Avg weighted exploit | Avg weighted impact | Total occurrences | Total CVEs |
|---|---|---|---|---|---|---|---|---|
| 24 | 20.67% | 2.95% | 100.00% | 37.95% | 7.11 | 3.81 | 769,581 | 3,416 |

## What it covers

- Failing to **prevent** an unusual situation, to **detect** it while it happens, or to **respond** well afterwards.
- Causes: weak input validation; error handling placed high in the call stack instead of where errors occur; environmental
  stress (memory, privileges, network); inconsistent handling; unhandled exceptions leaving the system in an unknown state.
- Consequences: logic bugs, overflows, race conditions, fraudulent transactions, and memory/state/resource/timing,
  authentication and authorization problems — affecting confidentiality, integrity or availability.

## How to prevent (checklist)

- [ ] Plan for failure: catch errors where they happen, handle them so the app can recover, show a user-understandable
      message, log, and alert where justified.
- [ ] Add a global exception handler as a safety net for anything missed.
- [ ] Monitor for repeated errors or patterns that suggest probing, and block the source (scripts, bots).
- [ ] Fail closed: if a multi-step transaction fails midway, roll back everything and start over rather than attempting
      partial recovery.
- [ ] Apply rate limits, quotas, throttling and other bounds everywhere — unbounded resources mean poor resilience, DoS,
      brute force and runaway cloud bills.
- [ ] Above a threshold, aggregate identical errors (count + time window) so logging and monitoring keep working (see A09).
- [ ] Strict input validation (with sanitization/escaping where hazardous characters must be accepted).
- [ ] Centralize error handling, logging, monitoring, alerting and the global handler, applied consistently.
- [ ] Define security requirements, threat-model, do secure design reviews, code review/static analysis, and stress,
      performance and penetration testing.
- [ ] Use one exception-handling approach across the organisation to ease review and audit.

## Example attack scenarios

1. File-upload exceptions are caught but resources aren't released; each failure leaks a lock or handle until none remain
   (denial of service).
2. Full database errors are returned to users; the attacker triggers errors on purpose to learn the schema and craft a
   better SQL injection.
3. The attacker disrupts the network in the middle of a debit → credit → log sequence; without a full rollback they can
   drain an account or exploit the race to send funds several times.

## How to check in code

### Where to look
- Global/central error handlers and framework error middleware; unhandled rejection/exception hooks.
- `try/catch` blocks around authentication, authorization, payment, and external calls.
- Multi-write operations (several inserts/updates, external call + DB write) and their transaction boundaries.
- Resource handling: files, streams, DB connections, locks, temp files.
- Request parsing limits, pagination, timeouts, retry loops, recursion and regexes on user input (ReDoS).

### What to verify
- Errors returned to clients are generic; details (stack traces, SQL, file paths, internal hostnames, library versions)
  go only to logs.
- No empty catches or "log and continue" in security-relevant paths; a failed check must deny, not allow.
- Auth/authorization middleware does not call `next()` / return success on exceptions (fail open).
- Multi-step state changes run in a transaction (or use compensating actions) and leave consistent state on failure.
- Resources are released in `finally`/`using`/`with`/`defer`.
- Missing or extra parameters are handled explicitly (an `undefined` role or id must not bypass a check).
- Request body size, upload size, page size, query complexity, and outbound call timeouts are bounded.
- `switch`/`match` statements on security-relevant values have a safe default.

### Grep starting points
```
catch\s*(\(\s*\w*\s*\))?\s*\{\s*\}|except[^:]*:\s*(pass|continue)|rescue\s*=>\s*\w*\s*$|catch \(Exception \w*\)\s*\{\s*\}
res\.(status\(\d+\)\.)?(send|json)\(\s*(err|error|e)\b|err\.stack|error\.message|traceback\.format_exc|printStackTrace|e\.ToString\(\)|getMessage\(\)
catch[^{]*\{[^}]*(next\(\)|return true|return null|allow|isValid\s*=\s*true)
process\.on\(['"](uncaughtException|unhandledRejection)|app\.onError|@ControllerAdvice|UseExceptionHandler|errorhandler
BEGIN|transaction|\$transaction|atomic|commit\(|rollback\(|SaveChanges|unit_of_work
limit:\s*['"]\d+(mb|kb)|MAX_CONTENT_LENGTH|maxFileSize|bodyParser|express\.json\(|client_max_body_size|timeout
new RegExp\(.*(req|input|user)|re\.compile\(.*request
```

### Severity guidance
Fail-open in authentication/authorization → Critical/High. Partial transactions on money or inventory → High.
Stack traces or SQL errors exposed to clients → Low–Medium (higher if they leak secrets). Unbounded resources reachable
anonymously → Medium.

## Mapped CWEs (24)

CWE-209 Generation of Error Message Containing Sensitive Information · CWE-215 Insertion of Sensitive Information Into
Debugging Code · CWE-234 Failure to Handle Missing Parameter · CWE-235 Improper Handling of Extra Parameters · CWE-248
Uncaught Exception · CWE-252 Unchecked Return Value · CWE-274 Improper Handling of Insufficient Privileges · CWE-280
Improper Handling of Insufficient Permissions or Privileges · CWE-369 Divide By Zero · CWE-390 Detection of Error
Condition Without Action · CWE-391 Unchecked Error Condition · CWE-394 Unexpected Status Code or Return Value · CWE-396
Declaration of Catch for Generic Exception · CWE-397 Declaration of Throws for Generic Exception · CWE-460 Improper
Cleanup on Thrown Exception · CWE-476 NULL Pointer Dereference · CWE-478 Missing Default Case in Multiple Condition
Expression · CWE-484 Omitted Break Statement in Switch · CWE-550 Server-generated Error Message Containing Sensitive
Information · CWE-636 Not Failing Securely ('Failing Open') · CWE-703 Improper Check or Handling of Exceptional
Conditions · CWE-754 Improper Check for Unusual or Exceptional Conditions · CWE-755 Improper Handling of Exceptional
Conditions · CWE-756 Missing Custom Error Page

## References

- OWASP MASVS — RESILIENCE category (no link on the source page)
- OWASP Cheat Sheet — Logging: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Cheat Sheet — Error Handling: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
- OWASP ASVS 5.0 — V16.5 Error Handling: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md#v165-error-handling
- OWASP Testing Guide — 4.8.1 Testing for Error Handling: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling
- Microsoft — Best practices for exceptions (.NET): https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions
- Toptal — Clean Code and the Art of Exception Handling: https://www.toptal.com/developers/abap/clean-code-and-the-art-of-exception-handling
- Google for Developers — General error handling rules: https://developers.google.com/tech-writing/error-messages/error-handling
- Real-world example of a mishandled exceptional condition: https://www.firstreference.com/blog/human-error-and-internal-control-failures-cause-us62m-fine/
