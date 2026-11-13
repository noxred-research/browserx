# Security policy

We take the security of BrowserX and of the people who run it seriously. This page says which versions are supported, how to report a vulnerability, what you can expect from us, and what is in and out of scope.

> **Intended use.** BrowserX is infrastructure for operating browsers and network egress that you own or are permitted to operate. Use it only on systems and services you own or are authorized to automate. See [Responsible use](#responsible-use).

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier than 0.1.0 | No |

BrowserX is pre-1.0. Only the latest 0.1.x release (and the `main` branch) receives security fixes. The distribution is the source repository and tagged source releases. No binaries, container images, hosted service or crates.io packages are published, so there are no other artifacts to patch. The Dockerfile and Compose file in [`docker/`](docker) are for development and evaluation: do not expose a container started from them to a network you do not control.

### Automated security checks

The [security workflow](.github/workflows/security.yml) checks locked dependencies against current Rust advisories, scans all fetched Git history for secrets and audits workflow configuration on main-branch pushes, weekly and on manual dispatch. On pull requests it rejects added dependencies with known high-severity vulnerabilities, and on `main` it runs the OpenSSF Scorecard. [CodeQL](.github/workflows/codeql.yml) analyzes Rust and GitHub Actions on authorized pull requests, main-branch pushes, weekly and on manual dispatch. Dependency review, Scorecard and CodeQL publish results only while the repository is public. These checks run only for code owners (see [`.github/CODEOWNERS`](.github/CODEOWNERS)); they reduce risk and do not replace review.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a suspected vulnerability.** Report it privately through GitHub private vulnerability reporting for `noxred-research/browserx`:

1. Open <https://github.com/noxred-research/browserx/security/advisories/new>, or go to the repository's **Security** tab and choose **Report a vulnerability**.
2. Describe the affected component (HTTP API, CDP relay, scheduler, egress forwarder, snapshot storage, runtime, CLI) and the version or commit, the impact, and steps or a proof of concept that reproduce the problem. A minimal reproduction against a local worker is ideal.
3. Do not include live credentials, real personal data, working lease tokens, snapshot key files or captured third-party content in the report.

If the private reporting option is not offered on the repository, open a public issue that asks for a private channel and contains no technical details.

## What to expect

These are commitments for good-faith reports of issues in scope. Times are in business days.

| Step | Target |
| --- | --- |
| Acknowledge receipt | within 3 days |
| Initial assessment: confirmed, needs more information, or not a vulnerability | within 10 days |
| Status updates while the report is open | at least every 14 days |
| Fix or mitigation, and a coordinated disclosure date | within 90 days of the initial assessment; sooner for actively exploited issues |

We will keep you informed, agree on a disclosure date with you, and credit you in the published advisory unless you ask to remain anonymous. This project does not run a bug bounty. If we cannot meet a target we will tell you why.

## Safe harbor

We consider security research carried out in good faith under this policy to be authorized, and we will not pursue or support legal action against you for it. Good faith means that you:

- test only against your own deployment of BrowserX, never against someone else's systems or data;
- make a reasonable effort to avoid privacy violations, data destruction and interruption or degradation of services;
- access only as much data as needed to demonstrate the issue, and stop and report if you encounter personal data or credentials;
- give us a reasonable time to fix the issue before you disclose it, and do not disclose it publicly until we have agreed a date or the 90-day target has passed without a response;
- do not use social engineering, physical attacks, denial of service or spam.

This safe harbor covers the BrowserX project only. It does not authorize testing of upstream proxies, of third-party sites that a deployment's browsers visit, of the services of GitHub or other platforms, or of anyone else's deployment; those have their own terms. If you are unsure whether an activity is covered, ask first, privately.

## Scope

**In scope:** code in this repository, its build and CI configuration, and the deployment files under `docker/`. Findings that bypass a control described below are in scope even when they need a particular configuration. Examples:

- **Authentication and authorization.**
  - A way to call a `/v1` route, attach to the CDP relay or release a session without a valid API key and, where required, lease token.
  - Acting on another owner's session: reading, attaching to, renewing, handing off, snapshotting or releasing it, or listing it.
  - A lease token that keeps working after handoff or release, or relay connections that survive the generation change.
  - Bypassing the generation fencing so that a stale controller can act on a lease that moved on.
- **Relay scoping.** Under shared-browser isolation, any way for a session to reach another session's browser context, targets or storage, or to run a command the scoped relay refuses (`Target.createBrowserContext`, `Browser.close`, `SystemInfo.*` and so on). Context isolation is documented as not being a hostile multi-tenant boundary, so reports must show a breach of the *documented* filtering, not a browser-level escape.
- **Egress controls.** A way to make the forwarder dial a private, loopback, link-local, carrier-grade NAT, cloud metadata or other address its policy refuses, including through DNS rebinding, redirects, alternative IP spellings or IPv6 embeddings; or a way to reach the network from a browser without going through the forwarder.
- **Secret handling.** Leakage of API keys, lease tokens, proxy passwords or snapshot key material into logs, metrics, error bodies, API responses, command lines or environment of the browser beyond what the documentation states.
- **Snapshot and profile storage.** Reading or forging snapshots without the key, swapping sealed snapshots between profiles or versions, files created with wider permissions than documented, profile directories shared between two browsers, or erasure that leaves data behind.
- **Resource limits.** Bypassing owner quotas, the admission queue bounds, message-size limits or forwarder limits so that one client exhausts the worker.
- **Supply chain.** Weaknesses in the build, container, workflow or dependency configuration.

**Out of scope:**

- vulnerabilities in third-party dependencies, including Chromium, that have no BrowserX-specific exploit path (report those upstream; dependency advisories are checked in CI);
- findings that require an operator to deliberately grant a credential, a token, filesystem access to `state_dir` or a network position to an attacker;
- what a target site does with traffic from browsers a worker runs, and the behavior of upstream proxies;
- malicious behavior of a client that holds a valid lease on a **dedicated** browser: it controls a real browser by design;
- plaintext transport on listeners an operator exposes without TLS termination, which the documentation tells operators to avoid;
- denial of service by volume against a deployment that does not use the limits the documentation tells operators to configure;
- the development defaults of the files in `docker/`;
- reports from automated scanners without a demonstrated impact, and social engineering of maintainers;
- abuse of BrowserX by third parties against systems you operate. We cannot act on deployments we do not run; report that activity to the operator or hosting provider concerned.

## What BrowserX handles

Knowing what a deployment holds helps you judge impact and protect it.

- **API keys (`bxk_...`)** are stored as SHA-256 digests only, in the configuration, and are shown once at creation.
- **Lease tokens (`bxt_...`)** are stored as SHA-256 digests in the lease registry and returned once. A token also appears in the `cdp_url` of its session, so treat that URL as a secret and keep request paths of `/cdp/` out of proxy logs. BrowserX itself never logs them.
- **Snapshots** hold session cookies and `localStorage`. They are encrypted with AES-256-GCM before they reach disk; the key lives in a separate key file (mode `0600`). Anyone who has both can read them.
- **Profile directories** are ordinary Chromium profiles, unencrypted, readable by the worker's user. They contain cookies, storage and caches.
- **Proxy passwords** of a session are held in the lease registry (needed to recover the session) and are write-only through the API.
- **Browsers** execute whatever pages their clients open, with the privileges of the worker's user. Isolate workers accordingly.

See [isolation and security](docs/design/isolation-and-security.md) for the threat model.

## Responsible use

BrowserX gives automation clients real browsers and network egress. Use it only where you have the right to: your own sites and test environments, services whose owners and terms permit automation, and upstream proxies you are entitled to use. Do not use it to attack or overload third parties, to access systems or data you are not authorized to access, to evade a site's protections, or for anything unlawful where you operate. This is the project's intended-use policy and a condition of support and community participation; the [AGPL-3.0-only](LICENSE) license itself is unchanged.

The project enforces parts of this in code: the egress forwarder refuses non-public destinations by default, quotas and queues bound what one owner can consume, and the relay scopes shared sessions. These controls reduce harm; they do not verify that you are authorized. Misuse of BrowserX is not covered by this policy, is not covered by the safe harbor above, and is your responsibility.

## Disclosure

After a fix is released, the advisory is published through GitHub Security Advisories with credit to the reporter unless the reporter asks to remain anonymous.
