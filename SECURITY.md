# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.0.1-SNAPSHOT (main branch) | :white_check_mark: |

## Reporting a Vulnerability

Security issues should be reported directly to the repository maintainers through confidential security advisories or designated security contact channels.
Do NOT open public GitHub issues for security vulnerabilities.

### Responsible Disclosure Guidelines
- Provide reproducible steps and environment details.
- Synthetic proof-of-concept data only: never use live production data, real malware, or EICAR strings.
- Allow adequate time for remediation before any public disclosure.

## Security Controls Overview
- Server-side validation and authorization on every endpoint.
- Content Security Policy (two headers, `script-src 'self'`, no nonce), `nosniff`, `frame-ancestors 'none'`, and secure cookie flags.
- Cryptographic integrity verification via HMAC-SHA256 audit chaining.
- Safe error handling with correlated UUID identifiers.
