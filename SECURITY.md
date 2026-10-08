# Security Policy

## Reporting a vulnerability

Please report security issues in injectlab privately. Do not open a public issue.

- Email: **admin@opsbreak.com**
- Or use GitHub private vulnerability reporting:
  [Report a vulnerability](https://github.com/Opsbreak/injectlab/security/advisories/new)

Please include the affected version or commit, steps to reproduce, and what impact you think the
issue has. A minimal scenario or payload file that triggers the problem is very helpful.

## What to expect

- We acknowledge reports within **3 business days**.
- We will keep you informed while we investigate and work on a fix.
- We follow **coordinated disclosure**: we agree on a disclosure date with you, publish a fix and
  an advisory, and credit you unless you prefer to stay anonymous.

## Scope

In scope: vulnerabilities in injectlab itself, for example

- attacker-controlled payload or model output escaping the HTML report's escaping (XSS),
- a mock tool or the runner causing real side effects (network calls, command execution),
- secrets from target configuration (API keys) leaking into results, transcripts or reports.

Out of scope: prompt-injection weaknesses in third-party models or applications you test with
injectlab. Report those to the vendor of the affected system.

## Supported versions

Security fixes are made on the latest release.
