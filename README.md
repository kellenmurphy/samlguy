<div align="center">

# `<saml:Guy/>`
**[*samlguy.com*](https://samlguy.com) — A SAML assertion and JWT decoder for the IAM community.**

[![CI](https://github.com/kellenmurphy/samlguy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kellenmurphy/samlguy/actions/workflows/ci.yml) [![codecov](https://codecov.io/gh/kellenmurphy/samlguy/graph/badge.svg)](https://codecov.io/gh/kellenmurphy/samlguy) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12859/badge)](https://www.bestpractices.dev/projects/12859)

</div>

Paste whatever messy thing you grabbed from a log file, a network tab, or a browser plugin and the universal identity decoder at [samlguy.com](https://samlguy.com) figures out what it is and decodes it — no pre-processing, no binding-type dropdowns, no manually stripping RelayState first.

SAML assertions get a full summary panel with binding type, message type, status code (with human-readable explanation and spec link), issuer, NameID, timestamps with relative labels, attribute statement table, signing certificate details, AuthnContext class with label and assurance-level tooltip, and syntax-highlighted pretty-printed XML with per-element hover tips. JWTs get header and payload decoded with algorithm safety flags, timestamps, scope badges, and an OIDC discovery flow that surfaces issuer metadata and algorithm match status. Paste a SAML **`EntityDescriptor`** and it's parsed into a structured view — roles, certificates, endpoints, NameID formats, requested attributes, entity categories, and contacts.

Think [jwt.io](https://jwt.io), but for the full modern IAM stack — built by someone who actually works in identity, for everyone else who does too.


## Who is it for?

[samlguy.com](https://samlguy.com) is built by an IAM practitioner, for the IAM practitioner community: identity architects and engineers at universities, research institutions, and other organizations participating in federated identity like **[InCommon](https://incommon.org)** and **[eduGAIN](https://edugain.org/)**, and the broader R&E Trust & Identity community. 

If you run a Shibboleth IdP, debug SAML flows for a living, or spend time staring at raw base64 blobs in Fiddler or a browser DevTools network tab — this tool belongs in your bookmarks.

But it's not just SAML! It's equally useful for OAuth 2.0 / OIDC work. Access tokens and ID tokens from Okta, Microsoft Entra ID, Ping, Keycloak, or any standards-compliant authorization server can be pasted directly and decoded with full claim and timestamp analysis.

## Features

**Input** — paste just about anything: raw base64+DEFLATE or base64 blob, query string, full URL, raw HTTP log line, JWT, or `Authorization: Bearer` header. Multiple SAML messages in one paste are handled. RelayState is always extracted separately; double URL-encoding is unwound automatically. `ctrl-a` in your logs and paste away — it'll make sense of it. An **Examples** button loads any of 11 pre-built, dynamically-generated payloads (SAMLResponse, SAMLRequest, IdP/SP metadata, JWT, Authorization header, query string, and full redirect URL) as one-click starting points.

**SAML** — binding type, message type, status with human-readable description and spec link, issuer, NameID, timestamps with relative labels ("expired 3 hours ago"), AuthnContext class reference with friendly label and assurance-level tooltip (OASIS, REFEDS, RAF, NIST), attribute table with **InCommon attribute annotations** (R&S and eppn-scoped/unscoped badges from an embedded attribute registry; friendly names filled in even when the assertion omits them), signing cert details (key algorithm, validity), and syntax-highlighted XML with hover tips on all known SAML element names.

**SAML metadata** — paste an `EntityDescriptor` (or a single entity from an `EntitiesDescriptor` aggregate) and it's parsed into a structured view: entity ID, registration authority, `validUntil` with a relative label, and colour-coded **entity category badges** (Research & Scholarship, SIRTFI, Code of Conduct, Registered-by-InCommon, …) linked to their spec pages. Each IdP/SP role lists its signing requirements, SSO/SLO/ACS endpoints with human-readable binding labels and default/index flags, supported NameID formats, `shibmd:Scope`, and signing/encryption certificates decoded with the same X.509 parser as assertions. SP roles show their **requested attributes** with friendly names and required/optional flags; MDUI display info, organization, and contacts are surfaced too — alongside the syntax-highlighted XML. A **health-checks** panel flags the common federation footguns that are detectable from the document itself: expired/missing `validUntil`, unsigned metadata or a SHA-1 signature, certificates pasted with PEM headers, missing signing certs, plaintext (HTTP) endpoints, entityID whitespace/trailing-slash mismatches, misspelled entity-category URIs (e.g. `refeds.org/sirtf`), and lingering SAML 1.x support. Entity-category badges are colour-coded by kind and link out to their REFEDS / GÉANT / federation specifications.

**JWT** — algorithm with safety flags (`alg: none` danger badge, HMAC weak badge), claims summary, timestamps with relative labels, scope/scp badge list, raw JSON header and payload. OIDC discovery fetches the issuer's `.well-known/openid-configuration` server-side (Cloudflare Worker, avoids CORS) and checks algorithm support against the token's `alg`. Accepts bare JWTs, `Bearer <token>`, or full `Authorization: Bearer <token>` header lines.

**Everything else** — contextual `?` tooltips on every field covering the SAML spec, JWT/OIDC standards, and trust fabric conventions. Shareable links base64url-encode the input into the URL fragment — never sent to the server. Dark mode default with `localStorage` persistence.


## Privacy & Security

**All SAML and JWT payloads are decoded entirely in your browser.** Nothing you paste is ever transmitted to or stored on any server. The only network request the tool makes on your behalf is the OIDC discovery proxy described above, which receives only an issuer URL, not the token itself.

See [SECURITY.md](SECURITY.md) for the full vulnerability disclosure policy and a description of the security controls in this project.


## Local development

```bash
git clone https://github.com/kellenmurphy/samlguy.git
cd samlguy
npm install
npm run dev
```

The dev server starts at `http://localhost:5173`.

```bash
npm run check       # svelte-check + tsc type checking
npm run lint        # eslint
npm run test        # vitest single run
npm run test:watch  # vitest in watch mode
npm run coverage    # vitest with v8 coverage report
npm run build       # production build
npm run preview     # preview production build locally
```


## Project structure

```
src/
  lib/
    saml.ts             # input detection, URL-decode, base64, inflate, XML parse, summary extraction
    metadata.ts         # SAML metadata parser: EntityDescriptor roles, certs, endpoints, categories
    metadata-checks.ts  # static health checks: expiry, signing, cert hygiene, endpoints, entityID
    jwt.ts              # JWT decode: base64url, header/payload, alg flags, timestamps, scopes
    cert.ts             # X.509 DER/ASN.1 parser: subject, issuer, key algorithm, validity
    time.ts             # timestamp math and relative label helpers
    generic.ts          # fallback decoder for unrecognized base64/JSON/XML blobs
    hash.ts             # base64url encode/decode for shareable URL fragments
    xml-highlight.ts    # custom XML tokenizer: syntax-colored HTML spans + element tooltips
    attributes.ts       # InCommon attribute registry: R&S categories, eppn-scoped detection
    examples.ts         # 11 dynamically-generated example payloads (SAML, metadata, JWT, URLs)
    explanations.ts     # externalized hover tooltip text for all summary fields
    InfoTip.svelte      # hover tooltip component
  routes/
    +layout.svelte      # nav, shared chrome, dark mode
    +page.svelte        # main decoder — auto-detects SAML vs JWT
    api/
      discover/
        +server.ts      # OIDC discovery proxy (Cloudflare Worker)
    privacy/
      +page.svelte      # privacy policy
.github/
  workflows/ci.yml      # CI/CD: build, test, coverage, deploy
  dependabot.yml        # weekly dependency updates for npm and Actions
  CODEOWNERS
```


## Deployment

[samlguy.com](https://samlguy.com) is deployed using Cloudflare Pages. Every merge to `main` triggers an automatic build and deploy via GitHub Actions — but only after the test and coverage jobs pass. Build command: `npm run build`, output directory: `.svelte-kit/cloudflare`.


## What's Planned

- **Diff view** — paste two assertions side-by-side and highlight what changed; most useful for attribute table and timestamp diffs when debugging why a second login attempt looks different
- **MDQ discovery** — "Discover" button on the SAML Issuer row fetches the IdP's metadata from InCommon's MDQ service (`https://mdq.incommon.org/entities/{entityID}`) and feeds it into the metadata view — no aggregate download needed; optional MDQ base URL for other federations (eduGAIN, etc.)
- **SAML signature validation** — verify `<ds:Signature>` against the signing cert retrieved via MDQ (or from the pasted metadata); show a verified/failed badge
- **SP-initiated flow simulator** — given an EntityID, construct and encode a valid AuthnRequest URL for testing IdP behavior without a real SP; note: unsigned only (most IdPs accept this, some require signed requests)
- **JWT JWKS validation** — after OIDC discovery, fetch `jwks_uri` and verify the JWT signature against the matching key
- **REFEDS entity category checker** — given an EntityID (via MDQ), check whether the IdP's attribute release policy would likely cover the SP's requested attributes; builds on the entity-category and requested-attribute parsing already in the metadata view


## Contributing

This started as a personal passion project for [The SAML Guy](https://kellenmurphy.com) to mess with a nifty tech stack (Svelte). Bug reports and suggestions are welcome via [GitHub Issues](https://github.com/kellenmurphy/samlguy/issues). See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines. For security vulnerabilities, please follow the [responsible disclosure process](SECURITY.md) rather than opening a public issue.


## License

[MIT](LICENSE) — free to use, modify, and distribute. Attribution appreciated but not required.