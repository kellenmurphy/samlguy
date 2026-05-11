# Security Policy

## Supported versions

Only the latest deployment of samlguy.com is actively maintained.

---

## Reporting a vulnerability

Please do not open public GitHub issues for security vulnerabilities.

Report via email to: **samlguy@kellenmurphy.com**

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

Dependabot is configured to open weekly PRs when new versions of these actions are released, keeping SHA rotation low-friction.

### Minimal token permissions

The CI workflow declares `permissions: contents: read` at the workflow level, restricting the default `GITHUB_TOKEN` to read-only. The deploy job additionally requests `deployments: write` (required by the Cloudflare Pages action) and nothing more. No job can write to the repository, create issues, or make API calls beyond what is explicitly declared.

### No secrets in PR workflows

The deploy job runs only on `push` to `main`, never on `pull_request` events. This prevents a malicious PR from exfiltrating `CLOUDFLARE_API_TOKEN` or `CLOUDFLARE_ACCOUNT_ID` by modifying the workflow file.

The Cloudflare API token stored as a repository secret is scoped to Cloudflare Pages only — it cannot modify DNS records, WAF rules, or other Cloudflare resources.

### Production deploy gate

The deploy job targets a GitHub Environment named `production`. This provides a configuration point for adding manual approval requirements, allowed-branch restrictions, or deployment protection rules in the future without changing any workflow code.

### Dependency auditing

The CI workflow runs `npm audit --audit-level=high` on every push and pull request. The build fails if any high or critical vulnerabilities are present in the transitive dependency tree.

### Dependabot

Dependabot runs weekly for:
- **npm packages** — grouped (Svelte ecosystem together, Cloudflare tools together) to reduce PR noise while keeping everything current
- **GitHub Actions** — separate ecosystem entry, because action dependencies are a supply chain vector that is easy to neglect

### CODEOWNERS

`.github/CODEOWNERS` requires `@kellenmurphy` to approve any pull request that touches any file. This ensures no code is merged without review if collaborators are added in the future.

### Test coverage

The CI workflow enforces test coverage via Vitest and uploads results to Codecov. All library modules (`src/lib/`) maintain 100% statement, branch, function, and line coverage. A drop in coverage fails the build.

---

## Out of scope

- Vulnerabilities in tokens or assertions pasted by users — the tool is a decoder, not a validator; it does not make trust decisions on behalf of the user
- Denial of service against the OIDC discovery proxy via large volumes of requests (rate limiting is delegated to Cloudflare)
