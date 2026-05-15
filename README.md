# samlguy

**SAML assertion and JWT decoder for the IAM community.**

Visit [samlguy.com](https://samlguy.com) — paste whatever messy thing you grabbed from a log file, a network tab, or a browser plugin and the tool figures out what it is and (attempts to) decode it.

Think jwt.io, but for the full modern IAM stack — built by someone who actually works in identity, for everyone else who does too.

---

## Who it's for

samlguy.com is aimed at the IAM practitioner community: identity architects and engineers at universities, research institutions, and other organizations participating in federated identity frameworks like **InCommon**, the **research and education (R&E) trust fabric**, and the broader Internet2 community. If you run a Shibboleth IdP, debug SAML flows for a living, or spend time staring at raw base64 blobs in Fiddler or a browser DevTools network tab — this tool belongs in your bookmarks.

It's equally useful for OAuth 2.0 / OIDC work. Access tokens and ID tokens from Okta, Microsoft Entra ID, Ping, Keycloak, or any standards-compliant authorization server can be pasted directly and decoded with full claim and timestamp analysis.

---

## Features

### Smart input detection

A single input box accepts anything. No pre-processing, no choosing a binding type from a dropdown, no manually stripping RelayState before pasting:

- Raw base64+DEFLATE blob (HTTP-Redirect binding)
- Raw base64 blob (HTTP-POST binding)
- Query string: `SAMLRequest=<blob>&RelayState=...`
- Full URL containing a SAML parameter
- Raw HTTP log line — strips method, path, status code, and extracts the parameter
- Raw JWT or `Authorization: Bearer <token>` header
- Multiple SAML messages in a single paste (e.g., a log excerpt spanning several flows)

RelayState is always extracted and displayed as a separate labeled field, never mixed into the decode attempt. This is the most common failure mode on other tools. Double URL-encoding (`%252F` etc.) is handled via iterative decode until the value is stable.

---

### SAML decoder

**Summary panel:**
Binding type, message type, status (Success / failure with badge), Issuer, Destination, ACS URL, NameID (value + format), InResponseTo, RelayState, encryption flags

**Timestamp math:**
`NotBefore`, `NotOnOrAfter`, `SessionNotOnOrAfter`, `AuthnInstant`, `SubjectConfirmation NotOnOrAfter` — raw ISO value plus a human-readable relative label ("expired 3 hours ago", "valid for 5 minutes", "in the future")

**Signing certificate:**
Subject, issuer, key algorithm (RSA-2048, EC P-256, etc.), validity dates, and current valid/expired status — decoded from the raw DER in `<ds:X509Certificate>` with no external dependencies

**Attribute statements:**
Clean table of all released attributes with name, friendly name, and values

**Pretty-printed XML:**
Full assertion XML, indented and copyable

---

### JWT / OIDC decoder

**Summary panel:**
Algorithm (with danger badge for `alg: none`, weak badge for HMAC), token type, key ID, issuer, subject, audience, JWT ID

**Timestamp math:**
`iat`, `exp`, `nbf` — ISO value plus human-readable relative label and expired/active status

**Scopes:**
`scope` or `scp` claim parsed into individual tokens displayed as badges

**Raw JSON:**
Header and payload pretty-printed; "Copy token" button copies the full raw token

---

### Contextual help

Every field in every summary panel has a **?** hover tooltip explaining what the field means and why it matters — covering the SAML specification, JWT/OIDC standards, OAuth 2.0 scopes, and common trust fabric conventions. Tooltip text is externalized in `src/lib/explanations.ts` for easy editing and future translation.

---

### OIDC Discovery

When working with a JWT, the `/api/discover` endpoint (a Cloudflare Worker) accepts an issuer URL and fetches the corresponding `.well-known/openid-configuration` server-side, avoiding CORS constraints. The route validates that the issuer uses HTTPS before making any outbound request.

---

## Privacy

**All SAML and JWT payloads are decoded entirely in your browser.** Nothing you paste is ever transmitted to or stored on any server. The only network request the tool makes on your behalf is the OIDC discovery proxy described above, which receives only an issuer URL, not the token itself.

See [SECURITY.md](SECURITY.md) for the full vulnerability disclosure policy and a description of the security controls in this project.

---

## Tech stack

| | |
|---|---|
| Framework | SvelteKit 2 with Svelte 5 (runes) |
| Language | TypeScript |
| Styling | Tailwind CSS 4 |
| Deployment | Cloudflare Pages + Workers (`@sveltejs/adapter-cloudflare`) |
| SAML inflate | `pako` |
| X.509 parsing | Custom pure-JS DER/ASN.1 parser (zero external dependencies) |
| Testing | Vitest with v8 coverage — 100% statement, branch, function, and line coverage on all library modules |

---

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

---

## Project structure

```
src/
  lib/
    saml.ts             # input detection, URL-decode, base64, inflate, XML parse, summary extraction
    jwt.ts              # JWT decode: base64url, header/payload, alg flags, timestamps, scopes
    cert.ts             # X.509 DER/ASN.1 parser: subject, issuer, key algorithm, validity
    time.ts             # timestamp math and relative label helpers
    generic.ts          # fallback decoder for unrecognized base64/JSON/XML blobs
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

---

## Deployment

Connected to Cloudflare Pages. Every merge to `main` triggers an automatic build and deploy via GitHub Actions — but only after the test and coverage jobs pass. Build command: `npm run build`, output directory: `.svelte-kit/cloudflare`.

---

## What's planned

### Near-term

- **SAML error decoder** — human-readable explanations for `<samlp:Status>` codes and `StatusMessage` values ("RequesterError / NoAuthnContext — your IdP couldn't satisfy the requested AuthnContext"); already parsed, just needs a lookup table
- **AuthnContext decoder** — render `<saml:AuthnContextClassRef>` URNs as friendly labels with tooltips covering assurance levels, REFEDS MFA, RAF, and the most common `PasswordProtectedTransport` / `Kerberos` / `TimeSyncToken` values
- **InCommon attribute annotations** — flag attributes in the attribute table as InCommon Baseline Eligible, R&S, or REFEDS RAF/eppn-scoped; your differentiator vs generic SAML tools
- **Shareable links** — encode the pasted payload into the URL fragment (`#`) so it never hits the server; a "Copy link" button lets you pre-load a decoder view to share with colleagues
- **XML syntax highlighting** — color-code element names, attributes, and values in the pretty-printed XML block

### Medium-term

- **Diff view** — paste two assertions side-by-side and highlight what changed; most useful for attribute table and timestamp diffs when debugging why a second login attempt looks different
- **SAML metadata parsing** — parse `EntityDescriptor` XML into a structured view: signing certs, ACS URLs, NameID formats, supported bindings, contacts
- **MDQ discovery** — "Discover" button on the SAML Issuer row fetches the IdP's metadata from InCommon's MDQ service (`https://mdq.incommon.org/entities/{entityID}`) — no aggregate download needed; optional MDQ base URL for other federations (eduGAIN, etc.)
- **SAML signature validation** — verify `<ds:Signature>` against the signing cert retrieved via MDQ; show a verified/failed badge
- **SP-initiated flow simulator** — given an EntityID, construct and encode a valid AuthnRequest URL for testing IdP behavior without a real SP; note: unsigned only (most IdPs accept this, some require signed requests)
- **JWT JWKS validation** — after OIDC discovery, fetch `jwks_uri` and verify the JWT signature against the matching key

### Longer-term

- **REFEDS entity category checker** — given an EntityID (via MDQ), show which entity categories apply and whether the IdP's attribute release policy would likely cover them; requires MDQ + metadata parsing


---

## Contributing

Primarily a personal project and community resource, but bug reports and suggestions are welcome via [GitHub Issues](https://github.com/kellenmurphy/samlguy/issues). For security vulnerabilities, please follow the [responsible disclosure process](SECURITY.md) rather than opening a public issue.

---

## License

[MIT](LICENSE) — free to use, modify, and distribute. Attribution appreciated but not required beyond keeping the copyright notice.

---

Made with ♥ by [The SAML Guy](https://kellenmurphy.com)
