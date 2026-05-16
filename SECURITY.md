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

## How the application works

Understanding the data flow helps scope what a vulnerability in this project could affect.

### What runs in the browser

All SAML and JWT decoding is entirely client-side. Tokens and assertions are never transmitted to or stored on any server. The full decode path:

1. Input is detected (SAML vs JWT) and parsed in JavaScript
2. SAML: base64-decoded, optionally DEFLATE-inflated, XML parsed with the browser's built-in `DOMParser`
3. JWT: base64url-decoded in JavaScript, JSON parsed
4. X.509 certificates embedded in SAML are parsed with a custom pure-JavaScript DER/ASN.1 parser
5. Results are rendered in the DOM — nothing leaves the browser
6. Shareable links encode the paste content into the URL fragment (`#...`) using base64url; fragments are never transmitted to the server by the browser, so shared links carry the same privacy guarantee as direct paste

### What runs server-side

The only server-side code is the OIDC discovery proxy at `/api/discover`, running as a Cloudflare Worker. It:

- Accepts a single `issuer` query parameter
- Validates the issuer is a valid HTTPS URL (non-HTTPS requests are rejected with HTTP 400)
- Makes a server-side `GET` to `{issuer}/.well-known/openid-configuration` to retrieve the IdP's discovery document (avoiding browser CORS constraints)
- Returns the discovery document JSON to the browser

The Worker does not receive, log, or store any JWT token. It receives only the issuer URL. Outbound requests are only made to `https://` endpoints.

---

## Supply chain and CI/CD controls

### Action pinning

All GitHub Actions are pinned to a full commit SHA, not a mutable version tag. Version tags can be silently redirected by a compromised upstream repository, substituting malicious code into the pipeline. Pinning by SHA means the exact code reviewed at setup time is the code that runs. Human-readable version numbers are preserved as inline comments.

Current pins in `.github/workflows/ci.yml`:
- `actions/checkout` — SHA-pinned
- `actions/setup-node` — SHA-pinned
- `cloudflare/wrangler-action` — SHA-pinned
- `codecov/codecov-action` — SHA-pinned

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

Dependabot is configured to open weekly PRs when new versions of these actions are released, keeping SHA rotation low-friction.

### Minimal token permissions

The CI workflow declares `permissions: contents: read` at the workflow level, restricting the default `GITHUB_TOKEN` to read-only. The deploy job additionally requests `deployments: write` (required by the Cloudflare Pages action) and nothing more. No job can write to the repository, create issues, or make API calls beyond what is explicitly declared.

### No secrets in PR workflows

The deploy job runs only on `push` to `main`, never on `pull_request` events. This prevents a malicious PR from exfiltrating `CLOUDFLARE_API_TOKEN` or `CLOUDFLARE_ACCOUNT_ID` by modifying the workflow file.

The Cloudflare API token stored as a repository secret is scoped to Cloudflare Pages only — it cannot modify DNS records, WAF rules, or other Cloudflare resources.

### Production deploy gate

The deploy job targets a GitHub Environment named `production`. This provides a configuration point for adding manual approval requirements, allowed-branch restrictions, or deployment protection rules in the future without changing any workflow code.

### HTTP security headers

A `_headers` file at the project root is processed by `@sveltejs/adapter-cloudflare` and deployed to every Cloudflare Pages response:

- `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing
- `X-Frame-Options: DENY` — blocks the site from being embedded in an iframe (clickjacking mitigation)
- `Referrer-Policy: no-referrer` — suppresses the `Referer` header on all outbound navigation; prevents token or payload data from leaking via URL referrers if a user clicks an external link
- `Permissions-Policy` — disables camera, microphone, and geolocation access

The adapter additionally appends `Cache-Control: public, immutable, max-age=31536000` on all `/_app/immutable/*` assets and `Cache-Control: no-cache` on mutable app assets.

### Dependency auditing

The CI workflow runs `npm audit --audit-level=high` on every push and pull request. The build fails if any high or critical vulnerabilities are present in the transitive dependency tree.

### Dependabot

Dependabot runs weekly for:
- **npm packages** — grouped (Svelte ecosystem together, Cloudflare tools together) to reduce PR noise while keeping everything current
- **GitHub Actions** — separate ecosystem entry, because action dependencies are a supply chain vector that is easy to neglect

### Commit signing

All commits to this repository are signed with an SSH key managed by 1Password. The signing key (`ssh-ed25519`, labeled `wfx6yz`) is registered on GitHub as a signing key, allowing GitHub to display a "Verified" badge on each commit.

Git is configured globally with `gpg.format = ssh` and `commit.gpgsign = true`, so signing is automatic and does not require per-commit flags. The private key never leaves 1Password; signing requests are handled by the 1Password SSH agent.

### CodeQL

A CodeQL workflow runs on every push and pull request to `main`, and weekly on Mondays. It uses the `security-extended` query suite for JavaScript/TypeScript, which covers OWASP Top 10 and additional security patterns beyond the default set. Results are uploaded to GitHub's code scanning dashboard as SARIF findings. The action is SHA-pinned to v3.

### OSSF Scorecard

A [Scorecard](https://securityscorecards.dev) workflow runs weekly and on every push to `main`. It evaluates supply-chain security practices (pinned dependencies, branch protection, token permissions, code review, vulnerability disclosure) and publishes results to the GitHub code scanning dashboard. Results are also published publicly to the OSSF scorecard index.

### Branch protection

The `main` branch is protected with the following rules enforced for all contributors including administrators:

- **Required status checks** — the `Build & Test` CI job must pass before any merge is allowed; the branch must be up to date with `main` before merging (strict mode)
- **Required signatures** — every commit merged to `main` must carry a verified cryptographic signature
- **Required pull request review** — at least one approval is required; stale approvals are dismissed on new pushes; code owner review is required
- **No force pushes** — force-pushing to `main` is blocked
- **No branch deletion** — `main` cannot be deleted

### CODEOWNERS

`.github/CODEOWNERS` requires `@kellenmurphy` to approve any pull request that touches any file. This ensures no code is merged without review if collaborators are added in the future.

### Test coverage

The CI workflow enforces test coverage via Vitest and uploads results to Codecov. All library modules (`src/lib/`) maintain 100% statement, branch, function, and line coverage. A drop in coverage fails the build.

### Fuzzing

Property-based fuzz tests (`src/lib/fuzz.test.ts`) run against every parser on every CI build using [fast-check](https://github.com/dubzzz/fast-check). The core invariant tested: for any arbitrary input — random strings, arbitrary byte sequences encoded as base64, or malformed base64 — each parser either returns a valid result or throws an `Error` instance. A non-Error throw (string, plain object, `undefined`) is treated as a test failure. This exercises the SAML decoder, JWT decoder, X.509 DER/ASN.1 parser, and generic fallback decoder against inputs they would never receive in normal use.

---

## Versioning and releases

This project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`). Each release is tagged in the repository with a `v`-prefixed version tag (e.g. `v1.0.0`). Tags are signed with the same SSH key used for commit signing.

Since samlguy.com deploys continuously from `main`, the production deployment always reflects the latest tagged release or the commits immediately following it. Security fixes are released as patch versions and deployed immediately on merge to `main`.

---

## License

This project is released under the [MIT License](LICENSE). You are free to use, fork, modify, and distribute the code. The only requirement is that the copyright notice is preserved in copies or substantial portions of the software.

---

## Out of scope

- Vulnerabilities in tokens or assertions pasted by users — the tool is a decoder, not a validator; it does not make trust decisions on behalf of the user
- Denial of service against the OIDC discovery proxy via large volumes of requests (rate limiting is delegated to Cloudflare)
