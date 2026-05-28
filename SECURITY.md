# Security Policy

## Supported versions

Only the latest deployment of samlguy.com is actively maintained.

---

## Reporting a vulnerability

Please do not open public GitHub issues for security vulnerabilities.

**Preferred:** Use GitHub's private vulnerability reporting — [Report a vulnerability](https://github.com/kellenmurphy/samlguy/security/advisories/new). Reports submitted this way are visible only to the maintainer until a Security Advisory is published.

**Alternate:** Email **me@kellenmurphy.com** if you prefer not to use GitHub.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested remediation

You can expect an acknowledgement within 48 hours and a resolution or status update within 7 days.

---

## Threat model

### Adversaries and assets

| Adversary | Goal | Primary controls |
|---|---|---|
| Malicious paste / shared link | Trigger XSS via crafted SAML or JWT content rendered in the DOM | Svelte's default text escaping, `esc()` in the XML highlighter, CSP (planned) |
| Compromised npm package | Inject malicious code into the build or CI environment | GuardDog, OSV-Scanner, Grype, `npm audit`, SHA-pinned actions, `npm ci` lockfile enforcement |
| Compromised upstream GitHub Action | Substitute malicious CI code via a tampered version tag | All actions pinned to commit SHA, Dependabot rotates pins daily |
| SSRF via OIDC proxy | Use the discovery Worker to reach internal infrastructure | `redirect: 'error'`, 5-second timeout, 100 KB cap, response validation |
| Compromised maintainer account | Push unsigned or unreviewed code to `main` | Required commit signatures, branch protection, CODEOWNERS review, scoped API tokens |
| Information leakage | Exfiltrate SAML assertions or JWT payloads | All decoding is client-side; no server ever receives token content; Worker code logs nothing; `Referrer-Policy: no-referrer` prevents issuer URLs from leaking via outbound navigation |

### Out of scope

- Vulnerabilities in the tokens or assertions themselves — this tool is a decoder, not a validator; it makes no trust decisions on the user's behalf
- Denial-of-service against the OIDC discovery proxy at volume — rate limiting is delegated to Cloudflare's edge

---

## How the application works

Understanding the data flow helps scope what a vulnerability in this project could affect.

### What runs in the browser

All SAML and JWT decoding is entirely client-side. Tokens and assertions are never transmitted to or stored on any server. The full decode path:

1. Input is detected (SAML vs JWT) and parsed in JavaScript
2. SAML: base64-decoded, optionally DEFLATE-inflated, XML parsed with the browser's built-in `DOMParser` (modern browser `DOMParser` ignores DOCTYPE declarations and external entity references entirely — XXE is not a concern in this context)
3. JWT: base64url-decoded in JavaScript, JSON parsed
4. X.509 certificates embedded in SAML are parsed with a custom pure-JavaScript DER/ASN.1 parser
5. Results are rendered in the DOM — nothing leaves the browser
6. Shareable links encode the paste content into the URL fragment (`#...`) using base64url; fragments are never sent to the server by the browser in HTTP requests, so the server never sees the payload

**URL fragment privacy caveats:** The privacy guarantee applies to the server, not to the device or the recipient. Browser history syncs fragments across devices; browser extensions can read them; and sharing a link with another person gives that person the full payload — which is the point, but worth being explicit about. Any future addition of client-side telemetry or error reporting would need to explicitly exclude `window.location.href` to preserve this property. There are no analytics or error-reporting scripts in the current codebase.

**No client-side storage:** The application uses no cookies, no `localStorage`, no `sessionStorage`, and no `IndexedDB`. Nothing the user pastes persists on their device beyond the current browser session. The only persistent representation of a payload is the URL fragment, which is user-controlled.

### What runs server-side

The only server-side code is the OIDC discovery proxy at `/api/discover`, running as a Cloudflare Worker. It:

- Accepts a single `issuer` query parameter
- Validates the issuer is a valid HTTPS URL (non-HTTPS issuers are rejected with HTTP 400)
- Fetches `{issuer}/.well-known/openid-configuration` server-side to avoid browser CORS constraints
- Returns the discovery document JSON to the browser

The Worker does not receive, log, or store any JWT token. It receives only the issuer URL. The Worker code itself logs nothing; Cloudflare's platform logs contain only request metadata (timing, status, the `?issuer=` query string) and never any token content, because no token content is ever sent to the Worker.

**SSRF mitigations in the Worker:**

- **No IP-literal issuers** — the hostname is checked after URL parsing; any IPv4 or IPv6 literal is rejected with 400 before a fetch is attempted
- **Redirects are not followed** — the fetch is made with `redirect: 'error'`; any redirect results in a 502 error
- **5-second timeout** — an `AbortController` cancels the fetch after 5 seconds; a timed-out request returns 504
- **100 KB response cap** — the `Content-Length` header is checked before reading the body, and the body itself is capped at 100,000 bytes; oversized responses are rejected with 502
- **Response validation** — the body must be valid JSON, must be a non-null object, and must contain an `issuer` field (required by RFC 8414); anything else returns 502
- **Origin restriction** — responses include `Access-Control-Allow-Origin: https://samlguy.com`, preventing other browser origins from using the Worker as a free fetch proxy; this does not prevent the outbound request itself, only cross-origin response reads

---

## Supply chain and CI/CD controls

### Action pinning

All GitHub Actions are pinned to a full commit SHA, not a mutable version tag. Version tags can be silently redirected by a compromised upstream repository, substituting malicious code into the pipeline. Pinning by SHA means the exact code reviewed at setup time is the code that runs. Human-readable version numbers are preserved as inline comments.

Current pins in `.github/workflows/ci.yml`:
- `actions/checkout` — SHA-pinned
- `actions/setup-node` — SHA-pinned
- `astral-sh/setup-uv` — SHA-pinned (v8.1.0)
- `cloudflare/wrangler-action` — SHA-pinned
- `codecov/codecov-action` — SHA-pinned
- `github/codeql-action/upload-sarif` — SHA-pinned (v3.28.13)
- `actions/dependency-review-action` — SHA-pinned (v5.0.0)
- `google/osv-scanner-action` reusable workflow — SHA-pinned (v2.3.8)
- `anchore/sbom-action` — SHA-pinned (v0.24.0)
- `anchore/scan-action` — SHA-pinned (v7.4.0)
- `actions/attest-build-provenance` — SHA-pinned (v4.1.0)

Current pins in `.github/workflows/scorecard.yml`:
- `actions/checkout` — SHA-pinned
- `ossf/scorecard-action` — SHA-pinned (v2.4.3)
- `actions/upload-artifact` — SHA-pinned (v7.0.1)
- `github/codeql-action/upload-sarif` — SHA-pinned

Current pins in `.github/workflows/release-please.yml`:
- `googleapis/release-please-action` — SHA-pinned (v4)

Current pins in `.github/workflows/codeql.yml`:
- `actions/checkout` — SHA-pinned
- `github/codeql-action/init` — SHA-pinned (v3.28.13)
- `github/codeql-action/analyze` — SHA-pinned (v3.28.13)

Dependabot is configured to open daily PRs when new versions of these actions are released, keeping SHA rotation low-friction.

### Minimal token permissions

All workflows use explicit `permissions` blocks rather than relying on GitHub's write-all default. The CI workflow sets the following at the workflow level, which serves as the baseline for all jobs:

- `actions: read` — required for the OSV-Scanner reusable workflow (GitHub constrains reusable workflow callers: the calling workflow must include any permissions granted to the called workflow)
- `contents: read`
- `security-events: write` — required for SARIF upload to GitHub Code Scanning across multiple jobs; also needed at workflow level for the OSV-Scanner reusable workflow call

Individual jobs override this baseline to the minimum they require. The deploy job additionally requests `deployments: write` (Cloudflare Pages action), `id-token: write` (OIDC for sigstore attestation), and `attestations: write` (GitHub attestation API). No job can write to the repository, create issues, or make API calls beyond what is explicitly declared.

### No secrets in PR workflows

The deploy job runs only on `push` to `main`, never on `pull_request` events. This prevents a malicious PR from exfiltrating `CLOUDFLARE_API_TOKEN` or `CLOUDFLARE_ACCOUNT_ID` by modifying the workflow file.

The Cloudflare API token stored as a repository secret is scoped to Cloudflare Pages only — it cannot modify DNS records, WAF rules, or other Cloudflare resources.

### Production deploy gate

The deploy job targets a GitHub Environment named `production`. This provides a configuration point for adding manual approval requirements, allowed-branch restrictions, or deployment protection rules in the future without changing any workflow code.

### HTTP security headers

A `_headers` file at the project root is processed by `@sveltejs/adapter-cloudflare` and deployed to every Cloudflare Pages response:

- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` — instructs browsers to use HTTPS exclusively for two years; `preload` makes the domain eligible for inclusion in browser HSTS preload lists
- `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing
- `X-Frame-Options: DENY` — blocks the site from being embedded in an iframe (clickjacking mitigation)
- `Referrer-Policy: no-referrer` — suppresses the `Referer` header on all outbound navigation; prevents token or payload data from leaking via URL referrers if a user clicks an external link
- `Permissions-Policy` — disables camera, microphone, and geolocation access

The adapter additionally appends `Cache-Control: public, immutable, max-age=31536000` on all `/_app/immutable/*` assets and `Cache-Control: no-cache` on mutable app assets.

### Dependency auditing

The CI workflow runs `npm audit --audit-level=moderate` on every push and pull request. The build fails if any moderate, high, or critical vulnerabilities are present in the transitive dependency tree. Dependencies are installed with `npm ci` (not `npm install`), which installs exactly what is recorded in `package-lock.json` and fails if there is any discrepancy — preventing lockfile drift and ensuring reproducible installs.

### Secret scanning

GitHub secret scanning and push protection are both enabled on this repository. Push protection prevents commits containing detected secrets from being accepted by GitHub, including commits from repository owners. This is a server-side control independent of local git configuration.

### Dependabot

Dependabot runs daily for:
- **npm packages** — grouped (Svelte ecosystem together, Cloudflare tools together) to reduce PR noise while keeping everything current. Commits use the `chore(deps)` prefix so routine dependency bumps do not trigger unnecessary patch releases via release-please.
- **GitHub Actions** — separate ecosystem entry, because action dependencies are a supply chain vector that is easy to neglect

### Commit signing

All commits to this repository are signed with an SSH key managed by 1Password. The signing key (`ssh-ed25519`, labeled `wfx6yz`) is registered on GitHub as a signing key, allowing GitHub to display a "Verified" badge on each commit.

Git is configured globally with `gpg.format = ssh` and `commit.gpgsign = true`, so signing is automatic and does not require per-commit flags. The private key never leaves 1Password; signing requests are handled by the 1Password SSH agent.

### CodeQL

A CodeQL workflow runs on every push and pull request to `main`, and weekly on Mondays. It uses the `security-extended` query suite for JavaScript/TypeScript, which covers OWASP Top 10 and additional security patterns beyond the default set. Results are uploaded to GitHub's code scanning dashboard as SARIF findings. The action is SHA-pinned to v3.

### GuardDog

[GuardDog](https://github.com/DataDog/guarddog) (Datadog, Apache 2.0) runs on every push and pull request. It analyzes all packages referenced in `package-lock.json` for behavioral supply chain attack indicators: install/postinstall scripts that should not be present, obfuscated code, high-entropy strings, outbound network calls in lifecycle hooks, and typosquatting patterns. Unlike database-driven scanners, GuardDog detects malicious behavior regardless of whether a CVE has been filed.

GuardDog runs entirely within the CI runner — no data is sent to any external service. Findings are reported as SARIF and uploaded to the GitHub code scanning dashboard. The job must pass before deploy is allowed.

### OSV-Scanner

[OSV-Scanner](https://google.github.io/osv-scanner/) (Google, Apache 2.0) runs on every push and pull request via Google's official reusable workflow. It queries the [Open Source Vulnerabilities](https://osv.dev) database, which aggregates CVE, GitHub Security Advisories (GHSA), and OSV records — a broader set of sources than npm's advisory feed alone. Findings are automatically uploaded to the GitHub code scanning dashboard as SARIF. The job must pass before deploy is allowed.

### SBOM and Grype

On every push and pull request:

- **Syft** ([anchore/sbom-action](https://github.com/anchore/sbom-action), Apache 2.0) generates a Software Bill of Materials in SPDX-JSON format and uploads it as a workflow artifact. This provides an auditable inventory of every package in the build and supports compliance requirements that expect a machine-readable SBOM.

- **Grype** ([anchore/scan-action](https://github.com/anchore/scan-action), Apache 2.0) scans the Syft-generated SBOM for known vulnerabilities at medium severity or higher. Findings are uploaded to the GitHub code scanning dashboard as SARIF. The job must pass before deploy is allowed.

### Dependency Review

The [dependency-review-action](https://github.com/actions/dependency-review-action) runs on pull requests only. It compares the dependency diff introduced by the PR against GitHub's vulnerability database and fails the check if any newly added package carries a moderate or higher CVE. This catches vulnerable dependencies at PR time, before they land in `main`, complementing the full-tree scans that run on push.

### GitHub Code Scanning

All SARIF-producing tools (CodeQL, GuardDog, OSV-Scanner, Grype, OSSF Scorecard) upload their findings to GitHub's code scanning dashboard (Security → Code scanning). This provides a single triage surface across all scanners, with per-file, per-line annotation on pull requests. Each tool registers under its own `category` so findings are de-duplicated and attributable to their source.

### OSSF Scorecard

A [Scorecard](https://securityscorecards.dev) workflow runs weekly and on every push to `main`. It evaluates supply-chain security practices (pinned dependencies, branch protection, token permissions, code review, vulnerability disclosure) and publishes results to the GitHub code scanning dashboard. Results are also published publicly to the OSSF scorecard index.

### Build provenance attestation

The deploy job generates a [SLSA](https://slsa.dev) provenance attestation for the compiled Cloudflare Pages bundle using [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance). The attestation is signed via sigstore's Fulcio CA using the workflow's OIDC identity and recorded in the repository's attestation log. It cryptographically ties the deployed artifact back to the exact workflow run, commit SHA, and repository that produced it.

This means the provenance of every deployed bundle is verifiable: given the artifact, anyone can confirm which commit triggered the build and that it passed through the expected CI pipeline — not a maintainer's local machine or an alternative workflow.

### Branch protection

The `main` branch is protected with the following rules enforced for all contributors including administrators:

- **Required status checks** — `Build & Test`, `GuardDog Supply Chain Scan`, `OSV Scanner / osv-scan`, `SBOM & Grype Scan`, and `Dependency Review` must all pass before any merge is allowed; the branch must be up to date with `main` before merging (strict mode)
- **Required signatures** — every commit merged to `main` must carry a verified cryptographic signature
- **Required pull request review** — at least one approval is required; stale approvals are dismissed on new pushes; code owner review is required
- **No force pushes** — force-pushing to `main` is blocked
- **No branch deletion** — `main` cannot be deleted

### CODEOWNERS

`.github/CODEOWNERS` requires `@kellenmurphy` to approve any pull request that touches any file. This ensures no code is merged without review if collaborators are added in the future.

### Test coverage

The CI workflow enforces test coverage via Vitest and uploads results to Codecov. All modules under `src/lib/` and `src/routes/api/` maintain 100% statement, branch, function, and line coverage. A drop in coverage fails the build.

### Fuzzing

Property-based fuzz tests (`src/lib/fuzz.test.ts`) run against every parser on every CI build using [fast-check](https://github.com/dubzzz/fast-check). The core invariant tested: for any arbitrary input — random strings, arbitrary byte sequences encoded as base64, or malformed base64 — each parser either returns a valid result or throws an `Error` instance. A non-Error throw (string, plain object, `undefined`) is treated as a test failure. This exercises the SAML decoder, JWT decoder, X.509 DER/ASN.1 parser, and generic fallback decoder against inputs they would never receive in normal use.

---

## Versioning and releases

This project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`). Each release is tagged in the repository with a `v`-prefixed version tag (e.g. `v1.0.0`). Tags are signed with the same SSH key used for commit signing.

Since samlguy.com deploys continuously from `main`, the production deployment always reflects the latest tagged release or the commits immediately following it. Security fixes are released as patch versions and deployed immediately on merge to `main`.

---

## License

This project is released under the [MIT License](LICENSE). You are free to use, fork, modify, and distribute the code. The only requirement is that the copyright notice is preserved in copies or substantial portions of the software.

