# samlguy.com — SAML & JWT Decoder

## Project Overview

A clean, fast, identity-community-focused decoder tool for SAML assertions and JWTs. Lives at **samlguy.com**. Built as a learning project and genuine community resource — think jwt.io but for the full modern IAM stack.

The core value prop: paste whatever messy thing you grabbed from a log file, a network tab, or a browser plugin, and the tool figures out what it is and decodes it cleanly. No more manually stripping RelayState params or fighting with double-encoded URLs.

---

## Tech Stack

- **Framework**: SvelteKit (latest)
- **Deployment**: Cloudflare Pages with `@sveltejs/adapter-cloudflare`
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Package manager**: npm

Server routes (SvelteKit API routes) run as Cloudflare Workers automatically via the adapter. No separate infrastructure needed.

---

## Scaffold Instructions

```bash
npm create svelte@latest samlguy
# Choose: Skeleton project, TypeScript, Tailwind
cd samlguy
npm install
npm install -D @sveltejs/adapter-cloudflare
```

Update `svelte.config.js` to use the Cloudflare adapter:

```js
import adapter from '@sveltejs/adapter-cloudflare';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default {
    preprocess: vitePreprocess(),
    kit: {
        adapter: adapter()
    }
};
```

---

## Features to Build

### 1. SAML Decoder (build first)

**Input handling — this is the most important UX piece:**

The input box should accept any of the following and figure out what to do:

- A raw base64+deflate blob (HTTP-Redirect binding)
- A raw base64 blob (HTTP-POST binding)
- A query string: `SAMLRequest=<blob>&RelayState=...`
- A full URL containing a SAMLRequest parameter
- A raw HTTP log line (e.g. copied from an access log) containing a SAMLRequest — strip the HTTP method, path prefix, status code, etc. and extract just the parameter

Key detail: **always parse out RelayState as a separate labeled field** rather than including it in the decode attempt. This is the #1 failure mode on existing tools.

Handle double URL-encoding gracefully (`%252F` etc.) — iteratively URL-decode until the value inflates cleanly.

**Output to display:**

- Pretty-printed, syntax-highlighted XML
- Parsed summary panel showing key fields:
    - Issuer
    - NameID (value + Format)
    - Destination
    - AssertionConsumerServiceURL
    - InResponseTo (if present)
    - Binding type detected (Redirect vs POST)
    - RelayState (shown separately)
- **Timestamp math**: for `NotBefore`, `NotOnOrAfter`, `SessionNotOnOrAfter`, `AuthnInstant` — show the raw value AND a human-readable relative label ("expired 3 hours ago", "valid for 5 minutes", "active")
- **Certificate extraction**: if a `<ds:X509Certificate>` is present, decode it and show subject, issuer, expiration, and whether it's currently valid
- **Attribute statements**: clean table of released attributes and values

### 2. JWT Decoder (build second)

Same smart input handling — accept a raw JWT or a Bearer token header like `Authorization: Bearer <token>`.

**Output:**

- Header and payload decoded and pretty-printed
- Signature algorithm flagged — call out `alg: none` explicitly as dangerous; note weak vs strong algorithms
- Timestamp math same as SAML: `iat`, `exp`, `nbf` shown with relative human-readable labels
- Scope claim parsed into a readable list if present
- **OIDC Discovery integration** (see below)

### 3. OIDC Discovery (SvelteKit server route)

When a JWT is decoded and an `iss` claim is present, show a button or auto-trigger a fetch to:

```
GET /api/discover?issuer=<iss value>
```

This SvelteKit API route proxies a request to `<iss>/.well-known/openid-configuration` server-side (avoiding CORS issues from the browser) and returns the IdP metadata.

Display the discovery result alongside the decoded JWT — highlight whether the token's `aud`, `alg`, and other claims are consistent with what the IdP advertises.

Route lives at `src/routes/api/discover/+server.ts`.

### 4. Shareable Links

Encode the pasted payload into the URL fragment (`#`) so it never hits the server. A "Copy link" button generates a URL that reopens the tool with the payload pre-loaded. Useful for async troubleshooting with colleagues.

---

## Suggested Route Structure

```
src/routes/
  +layout.svelte         # nav, shared chrome
  +page.svelte           # landing / SAML decoder (default tab)
  jwt/
    +page.svelte         # JWT decoder
  api/
    discover/
      +server.ts         # OIDC discovery proxy
```

Or use tabs on a single page route — either approach is fine.

---

## Decode Logic (pure TS modules)

Keep decode logic in `src/lib/` as framework-agnostic TypeScript so it's testable independently of Svelte:

```
src/lib/
  saml.ts       # input detection, URL-decode, base64, inflate, XML parse
  jwt.ts        # split, base64url decode, parse header/payload
  cert.ts       # X.509 decode from base64 DER
  time.ts       # timestamp math and relative label helpers
```

For SAML inflate: use the `pako` library (`npm install pako`) for deflate/inflate in the browser.
For XML: use the built-in `DOMParser` — no additional dependency needed.
For X.509: `@peculiar/x509` is a good lightweight option.

---

## Deployment

- Connect the GitHub repo to **Cloudflare Pages**
- Build command: `npm run build`
- Output directory: `.svelte-kit/cloudflare`
- Point **samlguy.com** DNS to the Cloudflare Pages deployment (update from the current forward to kellenmurphy.com)

---

## Tone & Branding

The site should feel like it was made by someone who actually works in IAM, not a generic SaaS tool. Lean into the samlguy.com name a little — it can have some personality without being a joke.

Take visual inspiration from kellenmurphy.com: clean, minimal, typographically confident, personal without being flashy. No loud colors or gradients. The kind of thing where the design gets out of the way and lets the tool do the talking.

- Dark mode as default, with a light mode toggle if desired
- Monospace font for decoded output (XML, JWT JSON, certificate details)
- Sans-serif for UI chrome — something clean like Inter or IBM Plex Sans
- Muted color palette — use accent color sparingly, maybe for highlighted fields like NameID or exp
- A small, understated footer credit: "Made with ♥ by Kellen "The SAML Guy" Murphy" linking to kellenmurphy.com

The identity community will appreciate a tool that clearly understands their workflows and doesn't look like a marketing site.

---

## Repository Security Setup

### Dependabot

Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
    - package-ecosystem: 'npm'
      directory: '/'
      schedule:
          interval: 'weekly'
      open-pull-requests-limit: 10
      groups:
          svelte:
              patterns:
                  - 'svelte*'
                  - '@sveltejs/*'
          cloudflare:
              patterns:
                  - '@cloudflare/*'
                  - 'wrangler'

    - package-ecosystem: 'github-actions'
      directory: '/'
      schedule:
          interval: 'weekly'
      open-pull-requests-limit: 5
```

Grouping related deps (Svelte, Cloudflare) means fewer noisy PRs while still keeping things current. The `github-actions` ecosystem entry is important — action dependencies are a supply chain vector people often miss.

### Security Policy

Create `SECURITY.md` at the repo root:

```markdown
# Security Policy

## Supported Versions

Only the latest deployment of samlguy.com is actively maintained.

## Reporting a Vulnerability

Please do not open public GitHub issues for security vulnerabilities.

Report vulnerabilities via email to: samlguy@kellenmurphy.com

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested remediation

You can expect an acknowledgment within 48 hours and a resolution or status
update within 7 days.

## Scope

samlguy.com is a client-side decoding tool. All SAML and JWT payloads are
processed in the browser and are never transmitted to or stored on any server,
with the exception of the OIDC discovery proxy endpoint (/api/discover), which
accepts only an issuer URL parameter and makes outbound fetch requests on
the user's behalf.
```

### Branch Protection

Configure on GitHub under Settings → Branches for `main`:

- Require pull request before merging (at least 1 approval if collaborators are added later)
- Require status checks to pass before merging (wire up the CI job below)
- Require branches to be up to date before merging
- Do not allow bypassing the above settings
- Block force pushes

### CI/CD with GitHub Actions

Create `.github/workflows/ci.yml`. Key security principles applied:

- **Pin all actions to a full commit SHA**, not a mutable tag — tags can be moved by a compromised upstream
- **Minimal permissions** — declare only what each job actually needs
- **No secrets in PR workflows** — deploy only from `main`, never from PRs (prevents secret exfiltration via malicious PRs)
- **Environment protection** — use a GitHub Environment called `production` for the deploy job so it requires explicit approval if you want a manual gate

```yaml
name: CI/CD

on:
    push:
        branches: [main]
    pull_request:
        branches: [main]

permissions:
    contents: read

jobs:
    test:
        name: Build & Test
        runs-on: ubuntu-24.04
        permissions:
            contents: read
        steps:
            - name: Checkout
              uses: actions/checkout@<PIN TO FULL SHA>

            - name: Setup Node
              uses: actions/setup-node@<PIN TO FULL SHA>
              with:
                  node-version: 20
                  cache: 'npm'

            - name: Install dependencies
              run: npm ci

            - name: Audit dependencies
              run: npm audit --audit-level=high

            - name: Type check
              run: npm run check

            - name: Build
              run: npm run build

    deploy:
        name: Deploy to Cloudflare Pages
        runs-on: ubuntu-24.04
        needs: test
        if: github.ref == 'refs/heads/main' && github.event_name == 'push'
        environment: production
        permissions:
            contents: read
            deployments: write
        steps:
            - name: Checkout
              uses: actions/checkout@<PIN TO FULL SHA>

            - name: Setup Node
              uses: actions/setup-node@<PIN TO FULL SHA>
              with:
                  node-version: 20
                  cache: 'npm'

            - name: Install dependencies
              run: npm ci

            - name: Build
              run: npm run build

            - name: Deploy to Cloudflare Pages
              uses: cloudflare/wrangler-action@<PIN TO FULL SHA>
              with:
                  apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
                  accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
                  command: pages deploy .svelte-kit/cloudflare --project-name=samlguy
```

**Important**: Replace each `<PIN TO FULL SHA>` with the actual commit SHA for the action version you want. Find them on each action's GitHub releases page. Claude Code can help with this — ask it to look up and pin the current SHA for each action when setting up the workflow.

Store `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` as GitHub repository secrets (Settings → Secrets and variables → Actions). The Cloudflare API token should be scoped to Cloudflare Pages only — not a global token.

### CODEOWNERS

Create `.github/CODEOWNERS`:

```
* @kellenmurphy
```

Simple for a solo project but establishes the pattern and ensures any future collaborators require your review.

---

## Out of Scope (for now)

- Signature validation (requires the IdP's public key — could be a future feature via metadata fetch)
- SAML metadata parsing (separate tool idea)
- User accounts / saved history
