# Security

## Reporting a problem

Report vulnerabilities through GitHub private vulnerability reporting: the repository's **Security** tab, then **Report a vulnerability**. Do not open a public issue for a security problem.

Include what you found, how to reproduce it, and what it could expose. Never include real credentials, tenant IDs, or customer data in a report.

## Scope

In scope: the scripts in this repository, for example a way to make a write happen without `--yes`, send a token to a host outside the allowlist, follow a redirect, retry a write that may have taken effect, or print a secret.

Out of scope: Sophos products and APIs. Report those to Sophos.

## If a secret leaks

Rotate the Sophos API credential on the Sophos Central API credentials page. Fusion execution logs cannot be deleted, so a secret that reached a log stays there: rotation is the only fix.
