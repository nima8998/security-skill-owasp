# A04:2025 — Cryptographic Failures

> Source: OWASP Top 10:2025, https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/ — © OWASP Top 10 Team,
> CC BY 3.0. Condensed and restructured for code auditing; "How to check in code" is added by this skill.

## Summary

Down two places to #4. Covers missing cryptography, cryptography that is too weak, leaked keys and related errors. The
most common weaknesses involve weak pseudo-random number generation: broken or risky algorithms, insufficient entropy and
predictable RNGs. Relevant ASVS chapters: V11 Cryptography, V12 Secure Communication, V14 Data Protection.

## Stats

| CWEs mapped | Max incidence | Avg incidence | Max coverage | Avg coverage | Avg weighted exploit | Avg weighted impact | Total occurrences | Total CVEs |
|---|---|---|---|---|---|---|---|---|
| 32 | 13.77% | 3.80% | 100.00% | 47.74% | 7.23 | 3.90 | 1,665,348 | 2,185 |

## What it covers

- Data in transit not encrypted at the transport layer (TLS); the old cost arguments no longer apply.
- Sensitive data (passwords, card numbers, health records, personal data, business secrets) lacking encryption at rest
  or additional application-layer protection, especially under GDPR or PCI DSS.
- Old or weak algorithms/protocols used by default or in legacy code.
- Default keys, weak key generation, key reuse, missing rotation or key management; keys committed to repositories.
- Encryption not enforced (e.g. missing HSTS or other browser directives).
- Server certificates and trust chains not properly validated.
- IVs ignored, reused or not random enough; insecure modes such as ECB; plain encryption where authenticated encryption
  is needed.
- Passwords used directly as keys instead of a password-based key derivation function.
- Non-cryptographic randomness, or a secure seed overridden with a low-entropy one.
- Deprecated hashes (MD5, SHA-1) or non-cryptographic hashes used for security.
- Exploitable crypto error messages or side channels (e.g. padding oracles); forced downgrade or bypass of cryptography.

## How to prevent (checklist)

- [ ] Classify the data the application handles and identify what is sensitive by law, regulation or business need.
- [ ] Keep the most sensitive keys in a hardware or cloud HSM.
- [ ] Use well-vetted cryptographic libraries; never roll your own.
- [ ] Don't keep sensitive data you don't need; tokenise or truncate it (PCI DSS).
- [ ] Encrypt all sensitive data at rest.
- [ ] Use current algorithms, protocols and key sizes with proper key management.
- [ ] Only TLS 1.2+ with forward-secrecy ciphers; drop CBC suites; enforce HTTPS with HSTS; plan quantum-safe key exchange.
- [ ] Disable caching of responses with sensitive data (CDN, web server, application caches such as Redis).
- [ ] Don't use plaintext protocols (FTP, STARTTLS); avoid SMTP for confidential data.
- [ ] Store passwords with a salted, adaptive, work-factor function: Argon2, yescrypt, scrypt or PBKDF2-HMAC-SHA-512
      (bcrypt in legacy systems needs its own guidance).
- [ ] Choose IVs appropriate to the mode (CSPRNG where required); never reuse an IV/nonce with the same key.
- [ ] Use authenticated encryption (e.g. AES-GCM, ChaCha20-Poly1305), not bare encryption.
- [ ] Generate keys with a CSPRNG; derive keys from passwords only via a password KDF.
- [ ] Avoid MD5, SHA-1, CBC mode and PKCS#1 v1.5 padding.
- [ ] Have crypto configuration reviewed by specialists and/or tools; plan post-quantum migration (ENISA: high-risk
      systems by end of 2030).

## Example attack scenarios

1. A site doesn't enforce TLS everywhere or accepts weak ciphers; on a hostile network the attacker downgrades to HTTP,
   steals the session cookie and replays it — or alters data in transit, such as a transfer recipient.
2. Passwords are stored as unsalted or fast hashes; a file-upload flaw leaks the database and the hashes are cracked
   with rainbow tables or GPUs (fast salted hashes fall too).

## How to check in code

### Where to look
- Password storage and verification; user registration and password reset.
- Token, session id, API key, OTP, reset-link and invitation-code generation.
- Encryption/decryption helpers, key loading, KMS usage, JWT signing configuration.
- HTTP/TLS client configuration, database connection strings, SMTP/FTP usage.
- Secrets in source, config files, test fixtures, Dockerfiles, CI files and git history of `.env` files.

### What to verify
- Password hashing uses Argon2/scrypt/bcrypt/PBKDF2 with adequate cost — not MD5/SHA-x, with or without salt.
- Security-relevant randomness uses a CSPRNG (`crypto.randomBytes`/`randomUUID`, `secrets`, `SecureRandom`,
  `RandomNumberGenerator`, `random_bytes`), never `Math.random`/`random`/`Random`/`rand`.
- Symmetric encryption uses an AEAD mode with unique random nonces; keys are not hardcoded, not derived from plain
  passwords, and come from env/KMS.
- TLS verification is never disabled in production code paths.
- JWT secrets are long and random; algorithms are pinned (no `none`, no RS/HS confusion).
- Sensitive data isn't cached or sent over plaintext channels.

### Grep starting points
```
md5|sha1|createHash\(['"](md5|sha1)|hashlib\.(md5|sha1)|MessageDigest\.getInstance\("(MD5|SHA-?1)"|MD5\.Create|SHA1Managed
\b(DES|3DES|RC4|Blowfish)\b|/ECB/|AES/ECB|MODE_ECB|createCipher\(|PKCS1Padding|RSA/ECB/PKCS1
Math\.random|random\.(random|randint|choice)|new Random\(|\brand\(|mt_rand|uniqid
verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|InsecureSkipVerify|CERT_NONE|ServerCertificateValidationCallback|TrustAllCerts
(secret|api[_-]?key|private[_-]?key|token|passwd|password)\s*[:=]\s*['"][^'"]{8,}
-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|sk_live_|ghp_[A-Za-z0-9]{36}|xox[baprs]-
iv\s*=\s*b?['"]|nonce\s*=\s*b?['"]|Buffer\.alloc\(16\)
http://(?!localhost|127\.0\.0\.1)
```
Also run `git ls-files | grep -iE '(^|/)\.env($|\.)|\.pem$|\.key$|id_rsa'` in a git repo to find committed secret files.

### Stack-specific signals
- **Node:** `crypto.createCipher` (MD5-based key derivation, no IV; removed in Node 22 — use `createCipheriv` with an
  AEAD mode); `jsonwebtoken` with short or default secrets.
- **Python:** `random` vs `secrets`; `hashlib.sha256(password)` for passwords; `requests(..., verify=False)`.
- **Java:** `Random` for tokens; `Cipher.getInstance("AES")` defaults to ECB; custom `TrustManager` accepting all.
- **.NET:** `System.Random` for tokens; `RijndaelManaged` with ECB; certificate callbacks returning `true`.
- **PHP:** `md5()`/`sha1()` for passwords instead of `password_hash()`; `rand()`/`mt_rand()` for tokens.

### Common false positives
- MD5/SHA-1 used for non-security purposes (cache keys, ETags, content dedup) → Info at most.
- Test fixtures with obviously fake keys; `.env.example` with placeholders.
- `http://` to localhost or internal docs links.

## Mapped CWEs (32)

CWE-261 Weak Encoding for Password · CWE-296 Improper Following of a Certificate's Chain of Trust · CWE-319 Cleartext
Transmission of Sensitive Information · CWE-320 Key Management Errors (Prohibited) · CWE-321 Use of Hard-coded
Cryptographic Key · CWE-322 Key Exchange without Entity Authentication · CWE-323 Reusing a Nonce, Key Pair in
Encryption · CWE-324 Use of a Key Past its Expiration Date · CWE-325 Missing Required Cryptographic Step · CWE-326
Inadequate Encryption Strength · CWE-327 Use of a Broken or Risky Cryptographic Algorithm · CWE-328 Reversible One-Way
Hash · CWE-329 Not Using a Random IV with CBC Mode · CWE-330 Use of Insufficiently Random Values · CWE-331 Insufficient
Entropy · CWE-332 Insufficient Entropy in PRNG · CWE-334 Small Space of Random Values · CWE-335 Incorrect Usage of Seeds
in Pseudo-Random Number Generator (PRNG) · CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG) · CWE-337
Predictable Seed in Pseudo-Random Number Generator (PRNG) · CWE-338 Use of Cryptographically Weak Pseudo-Random Number
Generator (PRNG) · CWE-340 Generation of Predictable Numbers or Identifiers · CWE-342 Predictable Exact Value from
Previous Values · CWE-347 Improper Verification of Cryptographic Signature · CWE-523 Unprotected Transport of
Credentials · CWE-757 Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade') · CWE-759 Use of a
One-Way Hash without a Salt · CWE-760 Use of a One-Way Hash with a Predictable Salt · CWE-780 Use of RSA Algorithm
without OAEP · CWE-916 Use of Password Hash With Insufficient Computational Effort · CWE-1240 Use of a Cryptographic
Primitive with a Risky Implementation · CWE-1241 Use of Predictable Algorithm in Random Number Generator

## References

- OWASP Proactive Controls C2 — Use Cryptography to Protect Data: https://top10proactive.owasp.org/archive/2024/the-top-10/c2-crypto/
- OWASP ASVS (V11, V12, V14): https://owasp.org/www-project-application-security-verification-standard
- OWASP Cheat Sheet — Transport Layer Protection: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
- OWASP Cheat Sheet — User Privacy Protection: https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html
- OWASP Cheat Sheet — Password Storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP Cheat Sheet — Cryptographic Storage: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Cheat Sheet — HSTS: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- OWASP Testing Guide — Testing for Weak Cryptography: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README
- ENISA — Post-quantum cryptography transition roadmap: https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography
- NIST — First 3 finalized post-quantum encryption standards: https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
