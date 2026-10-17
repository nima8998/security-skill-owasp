# A03:2025 — Software Supply Chain Failures

> Source: OWASP Top 10:2025, https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/ — © OWASP Top 10
> Team, CC BY 3.0. Condensed and restructured for code auditing; "How to check in code" is added by this skill.

## Summary

Voted #1 by half of the community survey respondents. It grew out of "Using Components with Known Vulnerabilities"
(2013) into all failures in how software is built, distributed and updated: vulnerable or malicious third-party code,
tools and dependencies, and weak build pipelines. Few CVEs map to its CWEs (11), but it has the highest average
incidence rate in the contributed data and the highest weighted exploit and impact scores.

## Stats

| CWEs mapped | Max incidence | Avg incidence | Max coverage | Avg coverage | Avg weighted exploit | Avg weighted impact | Total occurrences | Total CVEs |
|---|---|---|---|---|---|---|---|---|
| 6 | 9.56% | 5.72% | 65.42% | 27.47% | 8.17 | 5.23 | 215,248 | 11 |

## What it covers

You are likely vulnerable if:
- Versions of all client- and server-side components (including transitive dependencies) are not tracked.
- Software is vulnerable, unsupported or outdated: OS, servers, DBMS, APIs, runtimes, libraries.
- There is no regular vulnerability scanning or subscription to security bulletins.
- There is no change management across the supply chain: IDEs and extensions, repositories, sandboxes, artifact and
  image registries.
- Supply-chain components are not hardened (access control, least privilege).
- No separation of duties: one person can write code and promote it to production without review.
- Components from untrusted sources can reach or affect production.
- Patching is slow (monthly/quarterly) instead of risk-based and timely.
- Upgraded libraries are not tested for compatibility.
- System configuration is not secured (see A02).
- The CI/CD pipeline is weaker than the systems it builds and deploys.

## How to prevent (checklist)

Component governance:
- [ ] Generate and manage an SBOM centrally; track transitive dependencies.
- [ ] Remove unused dependencies, features, components, files and docs.
- [ ] Continuously inventory component versions (OWASP Dependency-Track, Dependency-Check, retire.js).
- [ ] Monitor CVE/NVD/OSV for used components with SCA/SBOM tools; subscribe to alerts.
- [ ] Obtain components only from official, trusted sources over secure links; prefer signed packages (see A08).
- [ ] Pin deliberately chosen versions; upgrade on purpose.
- [ ] Watch for unmaintained components; migrate, or virtual-patch if migration is impossible.
- [ ] Keep CI/CD, IDEs and developer tooling updated.
- [ ] Use staged/canary rollouts rather than deploying everywhere at once.

Change tracking for: CI/CD settings and pipelines, code repositories, sandboxes, IDEs, SBOM tooling and artifacts,
logging systems, third-party/SaaS integrations, artifact repositories, container registries.

Hardening (with MFA and locked-down IAM):
- [ ] Repositories: no committed secrets, protected branches, backups.
- [ ] Developer workstations: patching, MFA, monitoring.
- [ ] Build servers/CI: separation of duties, access control, signed builds, environment-scoped secrets, tamper-evident logs.
- [ ] Artifacts: provenance, signing, timestamping; promote the same immutable artifact across environments.
- [ ] Infrastructure as code managed through pull requests and version control.

## Example attack scenarios

1. A trusted vendor is compromised and ships malware in an update (SolarWinds 2019, ~18,000 organisations affected).
2. A compromised vendor component behaves maliciously only under specific conditions (Bybit 2025, $1.5B theft via wallet
   software that activated only for the target wallet).
3. A self-propagating npm worm (Shai-Hulud 2025) used post-install scripts to harvest secrets, exfiltrate them to public
   GitHub repositories and republish other packages with stolen npm tokens — over 500 package versions affected.
4. Components run with the application's privileges, so any flaw becomes the app's flaw (Struts 2 RCE CVE-2017-5638,
   Log4Shell CVE-2021-44228).

## How to check in code

### Where to look
- Manifests and lockfiles: `package.json` + `package-lock.json`/`pnpm-lock.yaml`/`yarn.lock`, `requirements*.txt`,
  `pyproject.toml` + `poetry.lock`/`uv.lock`, `go.mod`/`go.sum`, `pom.xml`, `build.gradle`, `*.csproj`/`packages.lock.json`,
  `composer.json`/`composer.lock`, `Gemfile`/`Gemfile.lock`, `Cargo.toml`/`Cargo.lock`.
- CI/CD: `.github/workflows/*`, `.gitlab-ci.yml`, `azure-pipelines.yml`, `Jenkinsfile`, deploy scripts.
- Container images: `FROM` lines, install steps, `curl | sh` patterns.
- Vendored code (`vendor/`, `third_party/`, copied minified libs) and CDN `<script>` tags.

### What to verify
- A lockfile exists and is committed; versions are pinned (no `*`, `latest`, open ranges for critical deps).
- Known-vulnerable versions — run the ecosystem's audit tool **only if it is already available and only in read-only
  mode** (these query advisory databases and do not execute project code):
  `npm audit --json` (needs `package-lock.json`), `pnpm audit`, `yarn npm audit`, `pip-audit -r requirements.txt`,
  `osv-scanner -r .`, `govulncheck ./...`, `bundle audit`, `dotnet list package --vulnerable`, `composer audit`.
  Never run `npm install`/`pip install` or project scripts to make a tool work — install hooks are exactly how supply
  chain malware runs. If no tool is available, review versions of the most security-relevant components manually and
  say so under Limitations.
- Unmaintained or abandoned packages (archived repos, no releases for years, deprecated notices).
- Dependencies fetched from git URLs, plain `http://`, personal forks, or with typosquat-looking names.
- GitHub Actions pinned to a commit SHA (not `@main`/`@v1`) for third-party actions; `pull_request_target` workflows that
  check out PR code; secrets exposed to untrusted workflows; overly broad `permissions:`.
- Base images pinned (digest or specific tag), not `:latest`; official sources.
- Separation of duties and branch protection cannot be seen from the repo — mention as a limitation if relevant.

### Grep starting points
```
"\*"|"latest"|":\s*">=|"\^0\.          # loose versions in package.json
^FROM .*:latest|^FROM [^:@]+$           # unpinned base images
uses:\s*[^@]+@(main|master|v?\d+)\s*$   # actions pinned to mutable refs
pull_request_target|permissions:\s*write-all
curl [^|]*\|\s*(ba)?sh|wget [^|]*\|\s*(ba)?sh|iex\s*\(.*DownloadString
"(pre|post)install"\s*:                 # own lifecycle scripts
git\+https?://|"https?://[^"]+\.tgz"
<script[^>]+src="https?://(?![^"]*integrity)   # CDN scripts (see A08 for SRI)
```

### Common false positives
- Dev-only dependencies used at build time: lower severity, but compromised build tooling still reaches production.
- Advisories for code paths the app never uses: report as Low/Info with the reasoning instead of dropping them.

## Mapped CWEs (6)

CWE-477 Use of Obsolete Function (listed on the OWASP page as "CWE-447") · CWE-1035 2017 Top 10 A9: Using Components
with Known Vulnerabilities · CWE-1104 Use of Unmaintained Third Party Components · CWE-1329 Reliance on Component That
is Not Updateable · CWE-1357 Reliance on Insufficiently Trustworthy Component · CWE-1395 Dependency on Vulnerable
Third-Party Component

## References

- OWASP ASVS — V15 Secure Coding and Architecture: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Cheat Sheet — Dependency Graph SBOM: https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html
- OWASP Cheat Sheet — Vulnerable Dependency Management: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html
- OWASP Dependency-Track: https://owasp.org/www-project-dependency-track/
- OWASP CycloneDX: https://owasp.org/www-project-cyclonedx/
- OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/
- OWASP Virtual Patching Best Practices: https://owasp.org/www-community/Virtual_Patching_Best_Practices
- CVE search: https://www.cve.org · NVD: https://nvd.nist.gov · GitHub Advisory Database: https://github.com/advisories
- Retire.js: https://retirejs.github.io/retire.js/
- SAFECode Software Integrity Controls: https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf
- Glassworm (2025): https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html
- PhantomRaven (2025): https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html
