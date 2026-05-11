# samlguy.com — SAML & JWT Decoder

## Project overview

A clean, fast, identity-community-focused decoder tool for SAML assertions and JWTs. Lives at **samlguy.com**. Aimed at IAM practitioners in higher education, research, and federated identity — particularly the InCommon/Internet2 community, Shibboleth IdP operators, and anyone debugging SAML flows or JWT tokens professionally.

The core UX premise: paste whatever messy thing you grabbed from a log file, a network tab, or a proxy tool, and the tool figures out what it is and decodes it cleanly. No binding-type dropdowns, no manual RelayState stripping, no fighting with double-encoded URLs.

---

## Tech stack

- **Framework**: SvelteKit 2 with Svelte 5 (runes API: `$state`, `$derived`, `$effect`, `$props`)
- **Deployment**: Cloudflare Pages + Workers via `@sveltejs/adapter-cloudflare`
- **Language**: TypeScript (strict)
- **Styling**: Tailwind CSS 4
- **Package manager**: npm
- **Testing**: Vitest 4 with v8 coverage provider, jsdom + happy-dom environments
- **CI**: GitHub Actions with SHA-pinned actions, Codecov integration
- **Linting**: typescript-eslint + eslint-plugin-svelte

---

## What's built

### Single-page auto-detect decoder (`src/routes/+page.svelte`)

A single `<textarea>` input. The `detect()` function determines whether the input is a JWT (three-part dot-separated base64url, or starts with `Authorization: Bearer`) or SAML (everything else). A debounced `$effect` drives decoding on a 300ms timer.

The page handles:
- Multiple SAML messages in one paste (`decodeAllSaml` scans for all `SAMLRequest`/`SAMLResponse` params)
- Generic fallback decoding (`decodeAllGeneric`) for non-SAML base64/XML/JSON blobs
- Lazy-loaded cert decoding via dynamic `import('$lib/cert')` to avoid blocking first render

### SAML decode library (`src/lib/saml.ts`)

`decodeSaml(raw)` / `decodeAllSaml(raw)` — full input detection pipeline:

1. **`extractSamlParam`** — tries URL parse, HTTP log line regex, colon-format (`SAMLRequest: <value>`), raw query string, fallback to raw value. Extracts RelayState separately.
2. **`extractQueryString`** — handles full URLs, HTTP GET log lines, raw `?`-prefixed strings, bare `SAMLRequest=` strings.
3. **`decodeValue`** — iterative URL-decode (handles `%252F` etc.), base64 normalize (standard ↔ base64url), try DEFLATE-inflate (HTTP-Redirect), try plain base64 (HTTP-POST), fail with a clear error.
4. **`parseSummary`** — extracts all summary fields from the parsed DOM using namespace-aware `getElementsByTagNameNS`. Handles encrypted assertions/NameIDs, signing cert extraction (only from `ds:Signature`, not encryption key certs), attribute statements, timestamps.
5. **`prettyPrintXml`** — custom indenting printer (no external XML library).

### JWT decode library (`src/lib/jwt.ts`)

`decodeJwt(input)` — strips `Bearer` prefix, splits on `.`, base64url-decodes header and payload, returns typed `JwtDecodeResult` with:
- `isAlgNone` / `isWeakAlg` flags
- `timestamps` object (`iat`, `exp`, `nbf` as `JwtTimestamp` with `date`, `label`, `expired`)
- `scopes` array (handles both `scope` string and `scp` array claim variants)

### X.509 certificate parser (`src/lib/cert.ts`)

**Pure custom DER/ASN.1 parser — no external library.** (`@peculiar/x509` is in package.json but is unused and should be removed.) Parses: subject DN, issuer DN, validity dates (both UTCTime and GeneralizedTime), serial number, and key algorithm (RSA with bit length, EC with named curve). Handles unknown OIDs gracefully.

### Time helpers (`src/lib/time.ts`)

`relativeLabel(date)` — returns human-readable relative strings ("just expired", "3 hours ago", "in 5 minutes", "active"). `isExpired(date)` — boolean check.

### Generic fallback decoder (`src/lib/generic.ts`)

`decodeAllGeneric(raw)` — scans input for base64 blobs and attempts decode, returns content type classification (XML, JSON, text) for display. Shown when SAML decode fails and SAML-specific errors shouldn't be surfaced.

### OIDC discovery proxy (`src/routes/api/discover/+server.ts`)

Cloudflare Worker. Accepts `?issuer=<url>`, validates HTTPS, fetches `{issuer}/.well-known/openid-configuration`, returns the discovery document. Rejects non-HTTPS issuers with HTTP 400. **The API is deployed but the JWT UI does not yet call it** — wiring up the UI is a planned feature.

### InfoTip component (`src/lib/InfoTip.svelte`)

Hover tooltip on every summary field. Renders a small `?` button; on hover/focus, calculates the button's `getBoundingClientRect()` and renders the tooltip using `position: fixed` to escape the `overflow-hidden` card containers (absolute positioning would be clipped). The tooltip resets `uppercase`, `tracking-wider`, and `font-semibold` via `normal-case tracking-normal font-normal` to handle inheriting from section header spans.

### Explanations (`src/lib/explanations.ts`)

All tooltip text externalized as `FIELD_EXPLANATIONS: Record<string, string>` with dotted-namespace keys (`saml.binding`, `jwt.algorithm`, `saml.ts.notOnOrAfter`, etc.). Also exports `SAML_TS_KEY` to map dynamic SAML timestamp labels (from `parseSummary`) to their explanation keys. Designed to be i18n-ready — a translation is just an alternate implementation of the same record shape.

---

## Test coverage

100% statements, branches, functions, and lines across all `src/lib/` modules. Achieved via:
- `/* v8 ignore next */` directives on defensive null-guards that are unreachable in valid DER/XML (never in `parseName`, `parseKeyAlg`, etc.)
- Carefully crafted DER certificate fixtures (single-line base64, length divisible by 4 — jsdom's `atob()` is strict, unlike Node's `Buffer.from()`)
- Test cases for every edge path: UTCTime year ≥ 50, EC with no curve OID, RSA modulus without leading zero, unknown DN attribute OIDs, all SAML timestamp variants, JWT non-string alg, etc.
- `explanations.test.ts` verifies every key used in the UI has a non-empty explanation, and that `SAML_TS_KEY` has no dangling references

Run with: `npm run coverage`

---

## Architecture decisions

**Single page, no routing** — JWT was briefly planned as a separate `/jwt` route; collapsed into the same page with auto-detection. Simpler, less navigation friction.

**Custom X.509 DER parser** — wrote a pure-JS parser rather than using `@peculiar/x509` to eliminate the dependency. The parser handles the cases we actually encounter in SAML signing certs (RSA, EC, both time formats, standard DN attributes + unknown OID fallback).

**`position: fixed` tooltips** — the summary cards use `overflow-hidden rounded-lg` for styling. `absolute`-positioned children are clipped by `overflow: hidden` ancestors. `position: fixed` elements escape this and are not clipped, at the cost of needing JS to compute the viewport coordinates on hover.

**Debounced reactive decoding** — a 300ms `$effect` timer rather than a form submit or button click. Provides instant feedback on paste without thrashing during continuous typing.

**Generic fallback** — if SAML decode fails and the input contains base64 or JSON, `decodeAllGeneric` tries to decode what it can and display it, rather than just showing an error. Useful for pasting partially-encoded or non-SAML content.

**Namespace-aware XML parsing** — all SAML element lookups use `getElementsByTagNameNS` with the correct URNs. This handles documents that use non-standard namespace prefixes, which is common in the wild.

---

## Planned features

### High priority
- **OIDC Discovery UI** — the `/api/discover` endpoint is live; the JWT results panel needs a "Fetch discovery" button (or auto-trigger when `iss` is present). Should surface `issuer`, `jwks_uri`, `authorization_endpoint`, supported algs/scopes, and flag any inconsistencies with the decoded token's claims.
- **Shareable links** — encode the paste content into the URL fragment (`window.location.hash`). A "Copy link" button generates a URL that reopens the tool with the payload pre-loaded. Fragment never hits the server. Useful for async troubleshooting with colleagues.

### Medium priority
- **SAML signature validation** — fetch the IdP's SAML metadata (by EntityID or URL), extract the signing cert, and verify `<ds:Signature>` using the Web Crypto API. Display verified/unverified status prominently.
- **Light mode toggle** — dark mode is current default; add a toggle with `localStorage` persistence.
- **XML syntax highlighting** — color-code element names, attribute names, and values in the XML `<pre>` block. Could use a small tokenizer or a lightweight library like `highlight.js` scoped to XML.

### Lower priority / ideas
- **SAML metadata parsing** — accept EntityDescriptor XML, display SP/IdP metadata in a structured way (ACS URLs, NameID formats, signing certs, attribute requirements)
- **JWT JWKS validation** — after OIDC discovery, fetch `jwks_uri` and attempt to verify the JWT signature using the matching key
- **i18n** — `explanations.ts` is already structured for this; add a locale switcher and alternate record implementations

---

## Code quality rules

Before any structural refactor on a file >300 LOC, remove dead props, unused exports, and debug logs. Commit separately.

After any significant change, run:
```bash
npx tsc --noEmit && npx eslint . --quiet && npm run coverage
```
All three must pass before reporting work complete.

ESLint config note: `svelte/no-navigation-without-resolve` is configured with `ignoreLinks: true` because samlguy.com deploys at the root with no base path, making `resolve()` unnecessary for plain `href="/"` links.

---

## Branding & tone

The site should feel like it was made by someone who actually works in IAM. Lean into the samlguy.com name — it can have personality without being a joke.

- Dark mode as default
- Monospace font for decoded output (XML, JWT JSON, certificate details)
- Sans-serif for UI chrome
- Muted color palette; accent color used sparingly (status badges, expired timestamps)
- Footer: "Made with ♥ by Kellen 'The SAML Guy' Murphy" linking to kellenmurphy.com
- No loud colors, no gradients, no marketing copy — the tool does the talking

The identity community will appreciate a tool that clearly understands their workflows.

---

## Deployment

- **Cloudflare Pages** — connected to this GitHub repo; merges to `main` auto-deploy
- Build command: `npm run build`
- Output directory: `.svelte-kit/cloudflare`
- Cloudflare Worker API routes deploy automatically alongside the Pages site via the adapter
- `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` stored as GitHub repository secrets; token is scoped to Cloudflare Pages only
