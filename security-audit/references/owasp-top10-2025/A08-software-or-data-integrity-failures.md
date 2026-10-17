# A08:2025 — Software or Data Integrity Failures

> Source: OWASP Top 10:2025, https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/ — © OWASP Top
> 10 Team, CC BY 3.0. Condensed and restructured for code auditing; "How to check in code" is added by this skill.

## Summary

Stays at #8. Failures to maintain trust boundaries and verify the integrity of software, code and data artifacts — at a
lower level than supply chain failures. The core mistake is assuming updates and critical data are trustworthy without
verifying them. Notable CWEs: CWE-829 Inclusion of Functionality from Untrusted Control Sphere, CWE-915 Improperly
Controlled Modification of Dynamically-Determined Object Attributes (mass assignment), CWE-502 Deserialization of
Untrusted Data.

## Stats

| CWEs mapped | Max incidence | Avg incidence | Max coverage | Avg coverage | Avg weighted exploit | Avg weighted impact | Total occurrences | Total CVEs |
|---|---|---|---|---|---|---|---|---|
| 14 | 8.98% | 2.75% | 78.52% | 45.49% | 7.11 | 4.79 | 501,327 | 3,331 |

## What it covers

- Relying on plugins, libraries, modules, repositories or CDNs from untrusted sources.
- CI/CD pipelines that don't verify integrity, enabling unauthorized access, malicious code or compromise.
- Pipelines that pull code or artifacts from untrusted locations or use them without signature (or equivalent) checks.
- Auto-update that downloads and applies updates without sufficient integrity verification.
- Serialized objects or data that attackers can see and modify (insecure deserialization).

## How to prevent (checklist)

- [ ] Use digital signatures or similar to verify software/data comes from the expected source and wasn't altered.
- [ ] Consume libraries only from trusted repositories (npm, Maven…); high-risk environments: a vetted internal mirror.
- [ ] Require review for code and configuration changes so malicious changes can't slip into the pipeline.
- [ ] Segregate, configure and access-control the CI/CD pipeline to protect integrity through build and deploy.
- [ ] Don't accept unsigned or unencrypted serialized data from untrusted clients without an integrity check or signature
      that detects tampering or replay.

## Example attack scenarios

1. A support subdomain is CNAMEd to a third-party provider; authentication cookies scoped to the parent domain are sent to
   that provider, letting anyone with access to its infrastructure hijack sessions.
2. Routers, set-top boxes and firmware without signed updates can be flashed with malicious images, often unfixable
   until a future version.
3. A developer installs an unsigned package from a random website instead of the official package manager, and it
   contains malicious code.
4. A React front end round-trips serialized Java object state to Spring Boot services; an attacker spots the Java
   serialization signature and uses a deserialization gadget scanner to get remote code execution.

## How to check in code

### Where to look
- Any deserialization of data that crosses a trust boundary: request bodies, cookies, hidden fields, queues, caches,
  files uploaded by users, data from other services.
- Model creation/update from request payloads (mass assignment).
- Webhook receivers (Stripe, GitHub, Slack, payment providers) and their signature verification.
- Cookies or client-held tokens used for security decisions without signing.
- Third-party `<script>`/`<link>` includes; plugin/extension loading; self-update or download-and-execute code.
- Cookie domain scope vs subdomains pointing to third parties.

### What to verify
- No native deserialization (`pickle`, Java `ObjectInputStream`, .NET `BinaryFormatter`, PHP `unserialize`,
  `node-serialize`, unsafe YAML loaders) of untrusted data; use JSON with schema validation instead.
- Writes only accept an allow-list of fields (DTOs, `pick`, serializers with explicit fields, `[Bind]` include lists).
- Webhooks verify the provider's HMAC/signature with a constant-time comparison and reject replays (timestamp window).
- Security-relevant cookies are signed/encrypted server-side, or the server keeps the state.
- CDN assets use Subresource Integrity (`integrity=` + `crossorigin`), or are self-hosted.
- Downloads that are executed or loaded are checksum- or signature-verified.

### Grep starting points
```
pickle\.loads?|cPickle|dill\.loads|marshal\.loads|shelve\.open|jsonpickle\.decode
yaml\.load\((?![^)]*SafeLoader)|yaml\.unsafe_load|Yaml\(\)\.load|new Yaml\(
ObjectInputStream|readObject\(|XMLDecoder|XStream|enableDefaultTyping|@JsonTypeInfo
BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter|TypeNameHandling\.(All|Auto|Objects)
unserialize\(|node-serialize|serialize-javascript.*eval|funcster
\.(create|update|insert|upsert|build|new)\(\s*req\.body|Object\.assign\(\w+,\s*req\.body|\*\*request\.(json|form|data)
fields\s*=\s*['"]__all__['"]|permit!|attr_accessible|\[Bind\]|@ModelAttribute
constructEvent|X-Hub-Signature|x-signature|webhook.*secret|hmac|timingSafeEqual|compare_digest
req\.cookies\.(role|isAdmin|admin|user|plan)|getCookie\(['"](role|admin)
<script[^>]+src=["']https?://|<link[^>]+href=["']https?://[^"']+\.css   # check for integrity=
download.*(exec|spawn|chmod \+x|Start-Process)|urlretrieve.*\.(sh|exe|py)
```

### Common false positives
- `pickle`/native deserialization of data the application itself wrote to a trusted location (no attacker control).
- ORM create calls whose input was already validated and stripped by a schema (Zod, Pydantic, class-validator with
  `whitelist: true`) — check the schema before reporting.

## Mapped CWEs (14)

CWE-345 Insufficient Verification of Data Authenticity · CWE-353 Missing Support for Integrity Check · CWE-426
Untrusted Search Path · CWE-427 Uncontrolled Search Path Element · CWE-494 Download of Code Without Integrity Check ·
CWE-502 Deserialization of Untrusted Data · CWE-506 Embedded Malicious Code · CWE-509 Replicating Malicious Code (Virus
or Worm) · CWE-565 Reliance on Cookies without Validation and Integrity Checking · CWE-784 Reliance on Cookies without
Validation and Integrity Checking in a Security Decision · CWE-829 Inclusion of Functionality from Untrusted Control
Sphere · CWE-830 Inclusion of Web Functionality from an Untrusted Source · CWE-915 Improperly Controlled Modification of
Dynamically-Determined Object Attributes · CWE-926 Improper Export of Android Application Components

## References

- OWASP Cheat Sheet — Software Supply Chain Security: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html
- OWASP Cheat Sheet — Infrastructure as Code Security: https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html
- OWASP Cheat Sheet — Deserialization: https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet
- SAFECode Software Integrity Controls: https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf
- NPR — The untold story of the SolarWinds hack: https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack
- Codecov Bash Uploader compromise: https://about.codecov.io/security-update
- Securing DevOps (Julien Vehent): https://www.manning.com/books/securing-devops
- Insecure Deserialization (Tenendo): https://tenendo.com/insecure-deserialization/
