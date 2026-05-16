<div align="center">

# `<saml:Guy/>`
**[*samlguy.com*](https://samlguy.com) — A SAML assertion and JWT decoder for the IAM community.**

[![CI](https://github.com/kellenmurphy/samlguy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kellenmurphy/samlguy/actions/workflows/ci.yml) [![codecov](https://codecov.io/gh/kellenmurphy/samlguy/graph/badge.svg)](https://codecov.io/gh/kellenmurphy/samlguy) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12859/badge)](https://www.bestpractices.dev/projects/12859)

</div>

Paste whatever messy thing you grabbed from a log file, a network tab, or a browser plugin and the universal identity decoder at [samlguy.com](https://samlguy.com) figures out what it is and decodes it — no pre-processing, no binding-type dropdowns, no manually stripping RelayState first.

SAML assertions get a full summary panel with binding type, message type, status code (with human-readable explanation and spec link), issuer, NameID, timestamps with relative labels, attribute statement table, signing certificate details, AuthnContext class with label and assurance-level tooltip, and syntax-highlighted pretty-printed XML with per-element hover tips. JWTs get header and payload decoded with algorithm safety flags, timestamps, scope badges, and an OIDC discovery flow that surfaces issuer metadata and algorithm match status.

Think [jwt.io](https://jwt.io), but for the full modern IAM stack — built by someone who actually works in identity, for everyone else who does too.


## Who is it for?

[samlguy.com](https://samlguy.com) is built by an IAM practitioner, for the IAM practitioner community: identity architects and engineers at universities, research institutions, and other organizations participating in federated identity like **[InCommon](https://incommon.org)** and **[eduGAIN](https://edugain.org/)**, and the broader R&E Trust & Identity community. 

If you run a Shibboleth IdP, debug SAML flows for a living, or spend time staring at raw base64 blobs in Fiddler or a browser DevTools network tab — this tool belongs in your bookmarks.

But it's not just SAML! It's equally useful for OAuth 2.0 / OIDC work. Access tokens and ID tokens from Okta, Microsoft Entra ID, Ping, Keycloak, or any standards-compliant authorization server can be pasted directly and decoded with full claim and timestamp analysis.

## Features

**Input** — paste just about anything: raw base64+DEFLATE or base64 blob, query string, full URL, raw HTTP log line, JWT, or `Authorization: Bearer` header. Multiple SAML messages in one paste are handled. RelayState is always extracted separately; double URL-encoding is unwound automatically. `ctrl-a` in your logs and paste away — it'll make sense of it.

**SAML** — binding type, message type, status with human-readable description and spec link, issuer, NameID, timestamps with relative labels ("expired 3 hours ago"), AuthnContext class reference with friendly label and assurance-level tooltip (OASIS, REFEDS, RAF, NIST), attribute table, signing cert details (key algorithm, validity), and syntax-highlighted XML with hover tips on all known SAML element names.

**JWT** — algorithm with safety flags (`alg: none` danger badge, HMAC weak badge), claims summary, timestamps with relative labels, scope/scp badge list, raw JSON header and payload. OIDC discovery fetches the issuer's `.well-known/openid-configuration` server-side (Cloudflare Worker, avoids CORS) and checks algorithm support against the token's `alg`.

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
    jwt.ts              # JWT decode: base64url, header/payload, alg flags, timestamps, scopes
    cert.ts             # X.509 DER/ASN.1 parser: subject, issuer, key algorithm, validity
    time.ts             # timestamp math and relative label helpers
    generic.ts          # fallback decoder for unrecognized base64/JSON/XML blobs
    hash.ts             # base64url encode/decode for shareable URL fragments
    xml-highlight.ts    # custom XML tokenizer: syntax-colored HTML spans + element tooltips
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

- **InCommon attribute annotations** — flag attributes in the attribute table as InCommon Baseline Eligible, R&S, or REFEDS RAF/eppn-scoped; a clear differentiator vs generic SAML tools
- **Diff view** — paste two assertions side-by-side and highlight what changed; most useful for attribute table and timestamp diffs when debugging why a second login attempt looks different
- **SAML metadata parsing** — parse `EntityDescriptor` XML into a structured view: signing certs, ACS URLs, NameID formats, supported bindings, contacts
- **MDQ discovery** — "Discover" button on the SAML Issuer row fetches the IdP's metadata from InCommon's MDQ service (`https://mdq.incommon.org/entities/{entityID}`) — no aggregate download needed; optional MDQ base URL for other federations (eduGAIN, etc.)
- **SAML signature validation** — verify `<ds:Signature>` against the signing cert retrieved via MDQ; show a verified/failed badge
- **SP-initiated flow simulator** — given an EntityID, construct and encode a valid AuthnRequest URL for testing IdP behavior without a real SP; note: unsigned only (most IdPs accept this, some require signed requests)
- **JWT JWKS validation** — after OIDC discovery, fetch `jwks_uri` and verify the JWT signature against the matching key
- **REFEDS entity category checker** — given an EntityID (via MDQ), show which entity categories apply and whether the IdP's attribute release policy would likely cover them; requires MDQ + metadata parsing


## Contributing

This started as a personal passion project for [The SAML Guy](https://kellenmurphy.com) to mess with a nifty tech stack (Svelte). Bug reports and suggestions are welcome via [GitHub Issues](https://github.com/kellenmurphy/samlguy/issues). For security vulnerabilities, please follow the [responsible disclosure process](SECURITY.md) rather than opening a public issue.


## License

[MIT](LICENSE) — free to use, modify, and distribute. Attribution appreciated but not required.