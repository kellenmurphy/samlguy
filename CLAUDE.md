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
4. **`parseSummary`** — extracts all summary fields from the parsed DOM using namespace-aware `getElementsByTagNameNS`. Handles encrypted assertions/NameIDs, signing cert extraction (only from `ds:Signature`, not encryption key certs), attribute statements, timestamps, and `authnContext`/`requestedAuthnContext` class references.
5. **`prettyPrintXml`** — custom indenting printer (no external XML library). Long opening tags (>100 chars) are wrapped via `wrapOpenTag`/`splitAttrs` helpers, aligning continuation lines to the first attribute column.
6. **`STATUS_DESCRIPTIONS`** / **`STATUS_SPEC_URLS`** — maps all 23 SAML 2.0 status code URNs to human-readable descriptions and links to the SAML Core spec PDF.
7. **`AUTHN_CONTEXT_LABELS`** / **`AUTHN_CONTEXT_SPEC_URLS`** — maps SAML AuthnContext Class Reference URIs (OASIS, REFEDS, RAF, NIST) to short display labels and spec links.

### SAML metadata library (`src/lib/metadata.ts`)

**Pure DOM parsing, no external library** (same philosophy as `saml.ts`). Routed ahead of the SAML-message decode path in `+page.svelte`.

1. **`isMetadata(raw)`** — regex check that the first element (after an optional BOM, XML prolog, and comments) is `EntityDescriptor` or `EntitiesDescriptor`, with any namespace prefix.
2. **`parseMetadata(raw)`** — parses the first `EntityDescriptor` into a structured `EntityMetadata` (entity ID, `validUntil`, `cacheDuration`, `mdrpi` registration authority, `mdattr` entity categories, organization, contacts, and `idp`/`sp` `RoleDescriptor`s). Single-entity scope: when wrapped in an `EntitiesDescriptor` aggregate it returns the first entity plus an `aggregateCount` so the UI can show a "first of N" banner. Throws on invalid XML or no `EntityDescriptor`.
3. Per role it extracts protocol support, signing flags (`WantAuthnRequestsSigned` / `AuthnRequestsSigned` / `WantAssertionsSigned`), `KeyDescriptor` certs (signing/encryption, decoded via the shared `cert.ts` parser), NameID formats, SSO/SLO/ACS endpoints (binding, location, index, default), `shibmd:Scope`, SP `RequestedAttribute`s (friendly names via `attributes.ts`), and `mdui:UIInfo` display info.
4. **`BINDING_LABELS`** / **`ENTITY_CATEGORY_LABELS`** / **`ENTITY_CATEGORY_SPEC_URLS`** — map binding URNs (incl. legacy Shibboleth 1.0 / SimpleSign) and entity-category URIs (R&S, CoCo, SIRTFI, Registered-by-InCommon, …) to short labels and spec links, same shape as the `saml.ts` label maps. **`entityCategoryKind(uri)`** coarsely classifies a category (`rs` / `coco` / `assurance` / `access` / `registration` / `other`) so the UI can colour badges by type.

### SAML metadata health checks (`src/lib/metadata-checks.ts`)

`checkMetadata(result, rawXml)` returns a list of `MetadataCheck { severity, title, detail }` for the federation problems that are detectable from a single pasted document: expired / expiring / missing / unparseable `validUntil`; metadata that carries no document-level `ds:Signature` or is signed with SHA-1; certificates pasted with PEM armor (`-----BEGIN CERTIFICATE-----`); roles with no certificate or no signing cert; plaintext (HTTP) endpoints; `entityID` whitespace or trailing-slash mismatches; misspelled entity-category URIs via a `MISSPELLED_CATEGORIES` map (e.g. `refeds.org/sirtf` → `sirtfi`); and lingering SAML 1.x / Shibboleth 1.0 protocol support. It re-parses `rawXml` only to detect the document signature (which `parseMetadata` does not model). Checks needing the partner's side (entityID/ACS mismatch, attribute release) or a network round-trip (reachable logos, the "cert cliff", refresh Content-Type) are deliberately out of scope. Rendered as a "Health Checks" panel above the entity summary in `+page.svelte`.

### JWT decode library (`src/lib/jwt.ts`)

`decodeJwt(input)` — strips `Bearer` prefix, splits on `.`, base64url-decodes header and payload, returns typed `JwtDecodeResult` with:
- `isAlgNone` / `isWeakAlg` flags
- `timestamps` object (`iat`, `exp`, `nbf` as `JwtTimestamp` with `date`, `label`, `expired`)
- `scopes` array (handles both `scope` string and `scp` array claim variants)

### X.509 certificate parser (`src/lib/cert.ts`)

**Pure custom DER/ASN.1 parser — no external library.** Parses: subject DN, issuer DN, validity dates (both UTCTime and GeneralizedTime), serial number, and key algorithm (RSA with bit length, EC with named curve). Handles unknown OIDs gracefully.

### Time helpers (`src/lib/time.ts`)

`relativeLabel(date)` — returns human-readable relative strings ("just expired", "3 hours ago", "in 5 minutes", "active"). `isExpired(date)` — boolean check.

### Generic fallback decoder (`src/lib/generic.ts`)

`decodeAllGeneric(raw)` — scans input for base64 blobs and attempts decode, returns content type classification (XML, JSON, text) for display. Shown when SAML decode fails and SAML-specific errors shouldn't be surfaced.

### OIDC discovery proxy (`src/routes/api/discover/+server.ts`)

Cloudflare Worker. Accepts `?issuer=<url>`, validates HTTPS, fetches `{issuerUrl.href}/.well-known/openid-configuration`, returns the discovery document. Rejects non-HTTPS issuers with HTTP 400. Called from the JWT results panel when `iss` is present — surfaces issuer match and supported algorithm checks against the decoded token.

### InfoTip component (`src/lib/InfoTip.svelte`)

Hover tooltip on every summary field. Renders a small `?` button; on hover/focus, calculates the button's `getBoundingClientRect()` and renders the tooltip using `position: fixed` to escape the `overflow-hidden` card containers (absolute positioning would be clipped). The tooltip resets `uppercase`, `tracking-wider`, and `font-semibold` via `normal-case tracking-normal font-normal` to handle inheriting from section header spans.

### Shareable link codec (`src/lib/hash.ts`)

`encodePayload(s)` — UTF-8 encodes a string, base64url-encodes the bytes (no padding). `decodePayload(s)` — reverses this. Used in `+page.svelte`: on `onMount`, reads `window.location.hash`, decodes it into the textarea input (wrapped in try/catch for malformed hashes). The "Copy link" button calls `encodePayload(input)` and writes `origin + pathname + '#' + encoded` to the clipboard. The hash fragment is never sent to the server.

### XML syntax highlighter (`src/lib/xml-highlight.ts`)

`highlightXml(xml: string): string` — character-by-character tokenizer that converts raw XML into HTML with `<span>` elements for syntax coloring. No external library. Handles: `<?...?>` prologs, `<!--...-->` comments, closing tags, opening tags with attributes, self-closing tags, and text content. Private helpers: `esc()`, `localName()`, `elSpan()`, `highlightAttrs()`, `highlightOpenTag()`.

`XML_ELEMENT_TIPS` — 43 known SAML element names (assertion, protocol, `ds:`, `xenc:` namespaces) mapped to tooltip descriptions. Known elements get `class="xml-el xml-el-tip" data-el="LocalName"` so the `+page.svelte` `onmouseover` handler can surface contextual tooltips via delegated events. Unknown elements get `class="xml-el"` only.

Dark/light mode colors for the highlight classes are defined in a `<style>` block in `+page.svelte` using `:global()` selectors (Tailwind can't statically analyze class names produced by `{@html}`).

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

**Custom XML tokenizer (no external library)** — `xml-highlight.ts` is a hand-rolled character scanner rather than wrapping `highlight.js` or similar. Keeps the bundle lean and gives precise control over which elements get `data-el` attributes for tooltip delegation. The same "no external library" philosophy as the X.509 DER parser.

---

## Planned features

### Medium priority
- **SAML signature validation** — fetch the IdP's SAML metadata (by EntityID or URL), extract the signing cert, and verify `<ds:Signature>` using the Web Crypto API. Display verified/unverified status prominently.
- **JWT JWKS validation** — after OIDC discovery, fetch `jwks_uri` and attempt to verify the JWT signature against the matching key.

### Lower priority / ideas
- **MDQ discovery** — fetch an entity's metadata from InCommon's MDQ service by EntityID and feed it into the metadata view (`src/lib/metadata.ts`)
- **REFEDS entity category checker** — cross-check an SP's `RequestedAttribute`s against entity categories already parsed by the metadata view
- **i18n** — `explanations.ts` is already structured for this; add a locale switcher and alternate record implementations

---

## Commit message conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Release-please reads commit messages to determine version bumps and populate `CHANGELOG.md`. Every commit to `main` (directly or via PR merge) must follow this format:

```
type(scope): short description

Optional body explaining why, not what.
```

### Types and their effects

| Type | Version bump | Changelog section |
|------|-------------|-------------------|
| `feat` | minor (1.x.0) | Features |
| `fix` | patch (1.0.x) | Bug Fixes & Dependencies |
| `perf` | patch | Performance |
| `security` | none (display only) | Security — use `fix` if a bump is needed |
| `docs` | none | Documentation (visible) |
| `chore` | none | Miscellaneous (hidden) |
| `ci` | none | CI/CD (hidden) |

Breaking changes: add `!` after the type (`feat!:` or `fix!:`) **or** include a `BREAKING CHANGE:` footer. Either triggers a major bump (x.0.0).

### Scope (optional)

Scope goes in parentheses: `fix(deps):`, `feat(saml):`, `ci(release):`. Dependabot is configured to produce `fix(deps):` for npm updates and `chore(ci):` for Actions updates — both fit the changelog config automatically.

### Commits that don't trigger changelog entries

Commits that don't match any of the above types (e.g. `Add something` with no type prefix) are ignored by release-please entirely — no bump, no changelog entry. Always use a type prefix.

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
- Header logo: `<saml:Guy/>` — `<` and `/>` in default text color, `saml:` in muted neutral-500
- Footer: "Made with ♥ by The SAML Guy" linking to kellenmurphy.com
- No loud colors, no gradients, no marketing copy — the tool does the talking

The identity community will appreciate a tool that clearly understands their workflows.

---

## Deployment

- **Cloudflare Pages** — connected to this GitHub repo; merges to `main` auto-deploy
- Build command: `npm run build`
- Output directory: `.svelte-kit/cloudflare`
- Cloudflare Worker API routes deploy automatically alongside the Pages site via the adapter
- `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` stored as GitHub repository secrets; token is scoped to Cloudflare Pages only
