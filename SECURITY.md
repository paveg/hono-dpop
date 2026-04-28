# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x | Yes |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report security issues via [GitHub Security Advisories](https://github.com/paveg/hono-dpop/security/advisories/new).

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You can expect an initial response within 72 hours. We will work with you to understand and address the issue before any public disclosure.

## Scope

This policy covers the `hono-dpop` npm package. Vulnerabilities in dependencies should be reported to the respective maintainers.

## Cryptographic Considerations

This middleware verifies asymmetric signatures from untrusted clients. If you discover a parsing or verification issue that could lead to:

- Accepting a forged proof
- Bypassing `jti` replay protection
- Accepting a non-asymmetric or `none` algorithm
- Timing leaks during key/proof comparison

…please prioritize disclosure via the channel above.
