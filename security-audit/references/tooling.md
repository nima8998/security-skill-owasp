# Automated tools: what is safe to run, and how to triage it

Scanners find candidates faster than reading; they don't find findings. Every hit still goes through Step 5
(reachability, mitigation, impact) before it reaches the report, and the report's *Method* row lists what ran.

## Rule: a tool may read the repository, never run it

The audited code is untrusted. A tool is acceptable only if it **parses** files (source, lockfiles, configs, git
history) and does not build, install, import or execute anything from the repository or its dependencies. Use a tool
only if it is **already installed** — don't install software on the user's machine without asking — and never point a
tool at a live URL.

Two common tools look like readers but are installers in disguise:

- **`pip-audit -r requirements.txt`** — its own documentation says it is "functionally equivalent to
  `pip install -r INPUT`", so it can run arbitrary `setup.py`/build backends of the listed packages. Only use
  `pip-audit -r requirements.txt --no-deps --disable-pip`, which requires every requirement pinned to an exact version
  (`==`) or hashed. Otherwise use `osv-scanner` on the lockfile, or review versions by hand.
- **`dotnet list package --vulnerable`** needs a restore, and a restore evaluates MSBuild project files, which can run
  custom targets from `Directory.Build.props/targets`. Use it only if the user says the project is already restored
  (`obj/project.assets.json` exists); otherwise use `osv-scanner` on `packages.lock.json` or review by hand.

Also avoid anything that **verifies** found secrets against live services (e.g. `trufflehog` without
`--no-verification`): testing a credential is using it.

## Safe-by-default commands

| Purpose | Command (run from the audited root) | Notes |
|---|---|---|
| Dependency advisories, any ecosystem | `osv-scanner scan source -r .` (v2) or `osv-scanner -r .` (v1) | Parses lockfiles; sends package names/versions (not code) to osv.dev. |
| Node | `npm audit --json` / `pnpm audit --json` / `yarn npm audit` | Reads the lockfile; needs one. |
| Python (pinned only) | `pip-audit -r requirements.txt --no-deps --disable-pip` | See above. |
| Go | `govulncheck ./...` | Static call-graph analysis: also tells you whether the vulnerable function is reachable — use that in severity. May download modules. |
| PHP | `composer audit --locked` | Reads `composer.lock`. |
| Ruby | `bundle-audit check` | Reads `Gemfile.lock`. |
| Rust | `cargo audit` | Reads `Cargo.lock`. |
| Secrets, working tree | `gitleaks dir . --redact --no-banner` | `--redact` keeps secrets out of the output. |
| Secrets, git history | `gitleaks git . --redact --no-banner` | Only with full history (not a `--depth 1` clone). Older versions: `gitleaks detect --redact`. |
| Secrets, alternative | `trufflehog filesystem . --no-verification` / `trufflehog git file://. --no-verification` | Never without `--no-verification`. |
| SAST, multi-language | `semgrep scan --config p/default --metrics=off --json` | Rules are downloaded from the registry; code stays local. `--config auto` requires metrics, so prefer a named ruleset (`p/owasp-top-ten`, `p/secrets`, `p/javascript`…). |
| Python SAST | `bandit -r . -f json -q` | |
| Go SAST | `gosec -fmt json ./...` | |
| Rails | `brakeman -q -f json` | |
| IaC, containers, CI | `trivy fs --scanners vuln,secret,misconfig .` / `trivy config .` / `checkov -d .` | Trivy downloads its DB on first run. |
| GitHub Actions | `zizmor --offline .github/workflows` / `actionlint` | zizmor flags template injection, `pull_request_target`, unpinned actions, excessive permissions. |

Exclude vendored and generated folders (`node_modules`, `vendor`, `dist`, `build`, `.venv`) with each tool's ignore
option, or the output drowns in third-party code.

## Manual history checks (no tool needed)

In path A (full history available), secrets removed from the working tree may still be in history:

```bash
git log --all --oneline -- '*.env' '*.pem' '*.key' 'id_rsa*' '*credentials*' '*secret*'
git log --all -p -G '(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|xox[baprs]-|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})' --format='%h %ad %an' --date=short | head -200
```

A secret that ever reached a shared repository is compromised: the fix is **rotate**, then clean history.

## Triage

1. **Deduplicate** tool hits against your own candidates; one root cause → one finding.
2. **Check reachability**: is the vulnerable dependency function or the flagged sink actually called with
   attacker-controlled data? `govulncheck` answers this for Go; for others, grep the import and the call.
3. **Check the context** the tool can't see: framework escaping, middleware, ORM parameterization, test-only code.
4. **Rate with `severity.md`**, not with the tool's label. A "critical" CVE in a dev-only dependency is usually Low.
5. **Record dismissals** in the report's *Needs verification and dismissed candidates* table, with the reason — that
   is what makes a clean result trustworthy.
6. If no tool was available, say so under *Limitations* and describe the manual review you did instead.

## References

- pip-audit security model: https://github.com/pypa/pip-audit#security-model
- OSV-Scanner: https://google.github.io/osv-scanner/
- Gitleaks: https://github.com/gitleaks/gitleaks
- Semgrep CLI reference: https://semgrep.dev/docs/cli-reference
- zizmor (GitHub Actions static analysis): https://docs.zizmor.sh/
- OWASP Source Code Analysis Tools: https://owasp.org/www-community/Source_Code_Analysis_Tools
