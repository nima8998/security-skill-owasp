# A09:2025 — Security Logging and Alerting Failures

> Source: OWASP Top 10:2025, https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/ — © OWASP
> Top 10 Team, CC BY 3.0. Condensed and restructured for code auditing; "How to check in code" is added by this skill.

## Summary

Stays at #9, renamed to stress that logged events need **alerting** to trigger action. Hard to test and thinly
represented in CVE/CVSS data (723 CVEs), but critical for visibility, incident response and forensics. Includes improper
output neutralization for logs (CWE-117), sensitive data in logs (CWE-532) and insufficient logging (CWE-778).

## Stats

| CWEs mapped | Max incidence | Avg incidence | Max coverage | Avg coverage | Avg weighted exploit | Avg weighted impact | Total occurrences | Total CVEs |
|---|---|---|---|---|---|---|---|---|
| 5 | 11.33% | 3.91% | 85.96% | 46.48% | 7.19 | 2.65 | 260,288 | 723 |

## What it covers

- Auditable events (logins, failed logins, high-value transactions) not logged, or logged inconsistently (successes but
  not failures).
- Warnings and errors producing no, inadequate or unclear log messages.
- Log integrity not protected against tampering; logs kept only locally without backup.
- Application and API logs not monitored for suspicious activity.
- Missing or ineffective alert thresholds and escalation; alerts not reviewed in time.
- Penetration tests and DAST scans (Burp, ZAP) not triggering any alert.
- No real-time or near-real-time detection, escalation or alerting of active attacks.
- Sensitive data leaking through logs or alerts visible to users/attackers (see A01), or PII/PHI logged at all.
- Log/monitoring systems open to injection because log data isn't encoded.
- Errors and exceptional conditions missed, so the system never knows (or logs) that something went wrong.
- Missing or outdated alerting use cases; floods of false positives hiding real alerts; missing or outdated playbooks.

## How to prevent (checklist)

- [ ] Log every login, access-control and server-side input-validation failure with enough user context to identify
      suspicious accounts; retain logs long enough for delayed forensics.
- [ ] Log every security control's decision, success or failure.
- [ ] Use a format log-management tools can parse easily (structured logs).
- [ ] Encode log data correctly to prevent injection into logging/monitoring systems.
- [ ] Give high-value transactions an audit trail with integrity controls (e.g. append-only tables).
- [ ] Roll back and restart transactions that throw errors; always fail closed.
- [ ] Alert on suspicious application or user behaviour; give developers guidance, or adopt a system that does it.
- [ ] Define monitoring/alerting use cases and playbooks with DevSecOps and the SOC.
- [ ] Plant honeytokens (fake records or identities); any access is a high-confidence alert.
- [ ] Optionally use behaviour analytics/AI to keep false positives low.
- [ ] Adopt an incident response and recovery plan (e.g. NIST SP 800-61r2 or later) and train developers to recognise and
      report attacks. Tooling examples: OWASP ModSecurity Core Rule Set, ELK stack, commercial observability platforms.

## Example attack scenarios

1. A children's health-plan provider had no logging or monitoring; an outside party reported that records of more than
   3.5 million children had been accessed and modified — possibly for over seven years.
2. A major Indian airline lost more than ten years of passenger data (passports, credit cards) at a third-party cloud
   host, which notified the airline only after a delay.
3. A major European airline suffered a GDPR-reportable breach of more than 400,000 payment records via payment-app
   vulnerabilities and was fined £20 million.

## How to check in code

### Where to look
- Logger setup and conventions (structured vs string logs, levels, destinations, redaction).
- Authentication and authorization code paths: are failures logged? are successes on sensitive actions logged?
- Error handlers and exception paths (see A10): do they log, and what do they include?
- High-value operations (payments, role changes, data exports, deletions): is there an audit trail?
- Any place where request bodies, headers or full objects are logged.

### What to verify
- Security events exist: login success/failure, lockouts, password/MFA changes, access denied, validation failures on
  sensitive endpoints, admin actions — with user id, source IP, timestamp and request id.
- Secrets and personal data are never logged: passwords, tokens, API keys, `Authorization`/`Cookie` headers, full card
  numbers, health data; logging of whole `req.body`/`req.headers` objects is a red flag.
- User-controlled values are logged as structured fields (or with CR/LF neutralized), not concatenated into lines.
- Logs leave the process to a durable destination with retention; alerting hooks exist for repeated failures. Much of
  this lives in infrastructure — if it isn't visible in the repo, record it under Limitations rather than as a finding.

### Grep starting points
```
(console\.(log|info|debug)|logger\.\w+|log\.\w+|print|System\.out\.println|_logger\.Log\w+)\(.*(password|passwd|secret|token|apikey|api_key|authorization|cookie|ssn|card)
logger?\.\w+\(.*req\.(body|headers)|JSON\.stringify\(req\.(body|headers)\)|print\(request\.(data|json|headers)\)
(login|signin|authenticate).*\n(?!.*log)          # read login handlers: is the failure branch logged?
winston|pino|bunyan|morgan|structlog|logging\.getLogger|Serilog|NLog|log4j|slf4j|zap|zerolog
catch\s*\(\w*\)\s*\{\s*\}|except[^:]*:\s*pass     # swallowed errors (also A10)
```

### Severity guidance
Usually Low–Medium. Raise to High when secrets, session tokens or sensitive personal data are written to logs readable
by people or systems that shouldn't have them, or when a high-value system has no security event logging at all.

## Mapped CWEs (5)

CWE-117 Improper Output Neutralization for Logs · CWE-221 Information Loss or Omission · CWE-223 Omission of
Security-relevant Information · CWE-532 Insertion of Sensitive Information into Log File · CWE-778 Insufficient Logging

## References

- OWASP Proactive Controls C9 — Implement Logging and Monitoring: https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/
- OWASP ASVS 5.0 — V16 Security Logging and Error Handling: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- OWASP Cheat Sheet — Application Logging Vocabulary: https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html
- OWASP Cheat Sheet — Logging: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- NIST SP 1800-11 — Recovering from Ransomware and Other Destructive Events: https://csrc.nist.gov/publications/detail/sp/1800-11/final
- NIST SP 1800-25 — Identifying and Protecting Assets Against Ransomware: https://csrc.nist.gov/publications/detail/sp/1800-25/final
- NIST SP 1800-26 — Detecting and Responding to Ransomware: https://csrc.nist.gov/publications/detail/sp/1800-26/final
- Snowflake breach (real-world example): https://www.huntress.com/threat-library/data-breach/snowflake-data-breach
