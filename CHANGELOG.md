# Changelog

## [1.0.0](https://github.com/kellenmurphy/samlguy/releases/tag/v1.0.0) (2026-05-16)

### Features

* Smart input detection — paste raw base64+DEFLATE (HTTP-Redirect), raw base64 (HTTP-POST), query strings, full URLs, HTTP log lines, or `Authorization: Bearer` headers; the tool figures out what it is
* SAML decoder with summary panel (binding, message type, status, issuer, destination, ACS URL, NameID, InResponseTo, RelayState, encryption flags), timestamp math, signing certificate details (subject, issuer, key algorithm, validity), attribute statement table, and pretty-printed XML
* JWT / OIDC decoder with algorithm warnings (`alg: none` danger, HMAC weak badge), timestamp analysis, scope display, and raw header/payload JSON
* X.509 certificate parser — pure DER/ASN.1 implementation, no external library; handles RSA, EC, UTCTime, GeneralizedTime, and unknown OIDs
* OIDC Discovery — Discover button on the `iss` field fetches `.well-known/openid-configuration` server-side via Cloudflare Worker; surfaces issuer match, supported algorithms, JWKS URI, and endpoint URLs
* Shareable links — Copy link button encodes the current input into the URL fragment (`#`); the fragment never reaches the server
* InfoTip contextual help tooltips on every summary field, covering SAML spec, JWT/OIDC standards, OAuth 2.0 scopes, and common federation conventions
* Light / dark mode toggle with `localStorage` persistence
* Privacy policy page

### Bug Fixes & Dependencies

* Fix overscroll background flash on mobile
* Fix coverage reporters: configure lcov output in vitest config rather than CLI flag
* Fix devalue and svelte audit vulnerabilities
* Bump all dependencies to latest

### Security

* OSSF Scorecard workflow — weekly evaluation of supply-chain security practices, results published to GitHub code scanning dashboard
* CodeQL advanced setup — `security-extended` query suite on every push and PR to `main`
* SHA-pinned GitHub Actions across all workflows
* Commit signing via SSH key (1Password agent); all commits to `main` carry verified signatures
* Property-based fuzz tests (fast-check) covering all parsers: SAML decoder, JWT decoder, X.509 DER/ASN.1 parser, generic fallback decoder
* SECURITY.md: vulnerability reporting via GitHub private advisory; full disclosure of data flow, supply chain controls, branch protection, and fuzzing approach

### Documentation

* MIT license
