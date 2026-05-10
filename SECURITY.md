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
