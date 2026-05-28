# Contributing to samlguy

Thanks for your interest. samlguy is a focused tool for the IAM/identity community, so contributions that serve that audience are most welcome.

## Before you start

For anything beyond a small bug fix, open an issue first to discuss the change. This avoids wasted effort if the direction doesn't fit the project's scope.

**Security vulnerabilities:** do not open a public issue. See [SECURITY.md](SECURITY.md) for the disclosure process.

## Development setup

```bash
git clone https://github.com/kellenmurphy/samlguy.git
cd samlguy
npm install
npm run dev
```

Requires Node 20+.

## Standards

- **TypeScript strict mode** — no `any`, no type assertions without justification
- **Test coverage** — all `src/lib/` and `src/routes/api/` modules must maintain 100% statement, branch, function, and line coverage; run `npm run coverage` to check
- **Lint** — `npm run lint` must pass with no errors
- **Commit messages** — follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `chore:`, etc. Release notes are generated from commit messages.

## Submitting a PR

1. Fork the repo and create a branch from `main`
2. Make your changes, add or update tests
3. Run `npx tsc --noEmit && npm run lint && npm run coverage` — all must pass
4. Open a pull request with a clear description of what changed and why
5. All CI checks must pass before review

## What fits this project

- Improvements to SAML, JWT, or X.509 parsing accuracy
- New identity protocol support (OIDC, WS-Fed, SCIM, etc.)
- Accessibility and usability improvements
- Documentation improvements
- Bug fixes

## What probably doesn't fit

- General-purpose web app features unrelated to identity
- External service integrations that require sending token data off-device
- Changes that weaken the client-side-only privacy guarantee
