# Changelog

## [1.1.1](https://github.com/kellenmurphy/samlguy/compare/samlguy-v1.1.0...samlguy-v1.1.1) (2026-05-16)


### Bug Fixes & Dependencies

* **ci:** trigger CI via label instead of workflow dispatch ([347af49](https://github.com/kellenmurphy/samlguy/commit/347af49faceba4257637f24055b49aa26d875c2a))
* **ci:** trigger CI via label; bump dev deps ([9ec17d9](https://github.com/kellenmurphy/samlguy/commit/9ec17d9bd43f5486df1df9b73efa763a20bdf368))
* **deps:** bump dev dependencies to latest ([7fc3a22](https://github.com/kellenmurphy/samlguy/commit/7fc3a22cf3d9c9f81bb964b093eaf11925ca0a69))

## [1.1.0](https://github.com/kellenmurphy/samlguy/compare/samlguy-v1.0.0...samlguy-v1.1.0) (2026-05-16)


### Features

* add release-please for automated changelog and GitHub releases ([74ff54f](https://github.com/kellenmurphy/samlguy/commit/74ff54f10c1328b81630a285dada4b0767a14555))


### Bug Fixes & Dependencies

* automate release PR approval, merge, and CI trigger ([8dd5876](https://github.com/kellenmurphy/samlguy/commit/8dd5876cb77590857b8d2d8bb7a6f442a0e633ff))
* automate release PR approval, merge, and CI trigger ([9e7f2f3](https://github.com/kellenmurphy/samlguy/commit/9e7f2f3ff30e45a9781d26630ca2eac61ec8d6aa))
* **ci:** add --repo flag to gh commands in release-please workflow ([e464d81](https://github.com/kellenmurphy/samlguy/commit/e464d81027a025b419d039a6de602c75d4f5aaf3))
* **ci:** add --repo flag to gh commands in release-please workflow ([5a4131d](https://github.com/kellenmurphy/samlguy/commit/5a4131d4dd096daab615e9dd4c489deb2c42b4f8))
* release automation, security headers, and doc updates ([3d2c15e](https://github.com/kellenmurphy/samlguy/commit/3d2c15ed31f149c83d34a91de63f539af27adad1))
* release automation, security headers, and doc updates ([d390500](https://github.com/kellenmurphy/samlguy/commit/d3905008857a066dcdb90aa723bf31562f220bc9))

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
