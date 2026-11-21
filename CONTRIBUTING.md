# Contributing to BrowserX

Thank you for considering a contribution. This guide covers how the project is organized, what a change must satisfy, and how a pull request is reviewed.

By contributing you agree that your contribution is licensed under the project license, [GNU AGPL version 3 only](LICENSE) (`AGPL-3.0-only`). There is no contributor license agreement and no DCO sign-off requirement. Do not submit code you do not have the right to license under the AGPL.

Security vulnerabilities are **not** reported through issues or pull requests; follow [SECURITY.md](SECURITY.md). Everyone taking part in the project is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Intended use and what we accept

BrowserX is AI/LLM-native browser infrastructure for authorized security research: it operates browsers and network egress that you own or are permitted to operate, and AI agents may watch, drive and explain it within limits an operator sets. Contributions must fit that purpose. We will decline changes that:

- add capabilities aimed at evading a site's protections, hiding abuse, or attacking third parties;
- weaken, bypass or add exceptions to authentication, lease-token handling, snapshot encryption, the scoped relay of shared browsers or the egress destination policy;
- ship real credentials, cookies, harvested data, captured third-party content or exploit payloads in code, fixtures or tests;
- make claims about how a website will treat a browser that BrowserX runs;
- let a model authorize anything: scope, capabilities, leases, recovery and egress decisions stay deterministic code, and no model may sit in the data path;
- remove or weaken the scope checks, untrusted-content marking, secret redaction or audit log of the MCP server.

Test only against local services and systems you own. See [Responsible use](README.md#responsible-use-and-security).

## Choose your path

| If you want to | Start here |
| --- | --- |
| Report a bug or request a feature | Open an issue with the matching form; search existing issues first |
| Ask how to use or deploy BrowserX | The [docs](docs/README.md), then the question form |
| Fix a typo or improve documentation | A pull request against `docs/` or the README; no issue needed |
| Change scheduler, recovery, persistence, relay or egress behavior | Open an issue first, then follow the [contribution flow](#contribution-flow) |
| Run the worker locally | [Getting started](docs/guides/getting-started.md) |
| Operate or deploy BrowserX | [Operations](docs/guides/operations.md) |

## Where to start

- Read the [architecture](docs/design/architecture.md), [sessions and leases](docs/design/sessions-and-leases.md) and the [configuration reference](docs/guides/configuration.md).
- The workspace is split into crates by responsibility; the table in the architecture page says which crate owns what. A change normally stays inside one crate, plus `browserx-core` when a contract changes.
- Open an issue before starting a large change so the approach can be agreed first. Small fixes and documentation corrections can go straight to a pull request.

## Development setup

- **Rust toolchain.** The version in [`rust-toolchain.toml`](rust-toolchain.toml); `rustup` installs it automatically.
- **C compiler.** SQLite is built into the binary by a Cargo build script.
- **Chromium (optional).** The tests that drive a real browser look for an executable in `BROWSERX_CHROMIUM_PATH`, then for `chromium`, `chromium-browser`, `google-chrome`, `google-chrome-stable` and `chrome` on `PATH`. When none is found they print a line starting with `SKIP:` and pass, so a green run without a browser proves less than a run with one. Run them against a browser before you change runtime, recovery, persistence or relay code.
- **Build.** `cargo build --workspace`.

## Checks to run before opening a pull request

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 ci/lint-provenance.py
python3 ci/check-docs-links.py
cargo deny --locked check licenses advisories bans sources
```

`ci/lint-provenance.py` is the public-tree hygiene gate. It checks a hashed rule set (`ci/provenance-hashes.txt`) so that the repository never has to spell the names it must not contain, and it rejects absolute developer paths, references to internal design records and e-mail addresses that are not obviously synthetic. It prints `file:line: [rule]` without the matched text. `ci/lint-provenance.py --history` applies the same rules to every fetched ref, commit message, tag and file version, and requires commit identities to be account handles with a GitHub noreply address (set your commit name to your handle). `ci/check-docs-links.py` checks that relative links and anchors in Markdown files resolve.

To run the tests against a real browser:

```sh
BROWSERX_CHROMIUM_PATH=/path/to/chromium cargo test --workspace --locked -- --nocapture
```

or `ci/run-browser-tests.sh /path/to/chromium`, which also fails if a browser test still skips.

If you touch `.github/workflows/`, also run `actionlint` and `zizmor .github/workflows`.

## Coding standards

All Rust follows the workspace lints in [`Cargo.toml`](Cargo.toml). On top of those:

- **No `unsafe`** (`unsafe_code = "forbid"`). Do not add exceptions.
- **No `unwrap`, `expect` or `panic!`** in non-test code. Return typed errors. Test modules may allow them locally.
- **Errors.** Library crates return the typed `browserx_core::Error` (or a crate error that converts into it) with lowercase messages without trailing punctuation. `anyhow` is for process wiring in the binary. Never put a secret into an error message.
- **Ownership and allocation.** Prefer borrowing to cloning, `&[T]` to `&Vec<T>`, `&str` to `&String`. Avoid avoidable allocation on the relay and forwarder paths.
- **Async.** Never hold a lock across `.await`. Channels and queues are bounded. Long-lived tasks take a cancellation signal and are supervised. Blocking work goes through `spawn_blocking`.
- **Leases.** Every lease mutation is load, modify, compare-and-swap on the expected generation. Do not write a lease any other way.
- **Logging.** Use structured `tracing` fields. Never log API keys, lease tokens, proxy credentials, cookies, snapshot contents or the path of the `/cdp/` route.
- **Public API.** Document public items and add a `//!` module comment.
- **Boring design.** Prefer a small direct implementation to a new abstraction, and delete code you replace.

## Tests

- Tests are deterministic and use no external network. Use loopback fixtures: a local TCP server for pages, a fake runtime for scheduler tests, a fake upstream proxy for egress tests.
- A behavior change needs a test that fails without it. A bug fix needs a regression test.
- Tests that need Chromium detect it and skip with a printed `SKIP:` note otherwise; they must never fail merely because no browser is installed.
- Test credentials are obviously synthetic. Do not commit key-shaped values that a scanner would flag: build them at runtime from split parts, with a comment that they are canaries. `gitleaks` runs in CI with detectors for `bxt_` lease tokens and `bxk_` API keys.
- Never commit snapshot key files, browser profiles or recorded traffic.
- **Fuzzing.** `fuzz/` is a cargo-fuzz workspace of its own, excluded from the main workspace, with one target per parser of untrusted input (request bodies of the HTTP API, identifiers, the forwarder's request and reply heads, proxy routes) and a small seed corpus under `fuzz/corpus/<target>/`. `cargo check --manifest-path fuzz/Cargo.toml --all-targets` builds the targets on stable, and a crash input replays on stable with `cargo run --manifest-path fuzz/Cargo.toml --bin <target> < <input>`. To fuzz, run `cargo install cargo-fuzz`, then `cargo +nightly fuzz run <target> corpus/<target>` from `fuzz/`. The `fuzz-short` CI job runs every target for 60 s on a pull request. A crash is a bug in the product code: fix it there, add a regression test, and keep the input as a seed.

## Documentation

Update the relevant page under [`docs/`](docs/README.md) and add a [`CHANGELOG.md`](CHANGELOG.md) entry under `[Unreleased]` for user-visible behavior, configuration, API, CLI, metric or format changes. Config keys have one reference, the [configuration reference](docs/guides/configuration.md); do not describe the same key in two places. Documentation describes BrowserX as it is: do not reference the history of the code, internal planning material or other projects. `ci/lint-provenance.py` enforces the identifier rules.

## Format and schema changes

The lease database carries a migration table, snapshots carry a plaintext `format_version`, and the snapshot key file carries a version. Changes are forward-only: add a migration or bump a version instead of editing a shipped one, and keep readers refusing formats newer than they understand. Never edit a migration that has been released.

## Contribution flow

1. Fork the repository and create a branch from `main` whose name describes the change.
2. Reproduce the current behavior before editing, and add or update tests for the successful path and the relevant failures.
3. Make focused commits. A pull request should do one thing, with the smallest change that satisfies the tests.
4. Run the [checks](#checks-to-run-before-opening-a-pull-request) locally.
5. Open a pull request and fill in the template: why the change is needed, what behavior changed, the exact checks you ran, and any safety, configuration or format impact.
6. A code owner reviews the pull request. Expect requests for tests, documentation, or a narrower scope. Do not bypass a failing check; fix it, or describe an unrelated failure precisely enough for a reviewer to reproduce it.

Keep credentials, local environment files, browser profiles and generated secrets out of commits and pull requests.

### Continuous integration for external pull requests

Pull-request CI runs only when the actor, rerun actor and pull-request author are individual code owners, and the head branch belongs to this repository. The gate reads the wildcard rule from [`.github/CODEOWNERS`](.github/CODEOWNERS) on the trusted default branch. For external contributions, including forks, a maintainer runs the checks above and reports the results on the pull request. A green local run from you does not replace that review.

Once a contribution is approved, a maintainer opens an integration pull request from a branch in this repository that contains the contributor's commits unchanged, plus any conflict resolution or review follow-ups as separate commits. CI runs on that branch. `main` takes squash merges only, so the squashed commit credits the contributor with a `Co-authored-by` trailer, and the maintainer closes the original pull request with a link to the merged one. Maintainers update dependencies and base images by hand through the same path; no bot opens update pull requests. An update to a GitHub Action also needs the new commit SHA added to the repository's allowed-actions list before it merges, or every workflow run fails to start.

The [security workflow](.github/workflows/security.yml) checks current Rust advisories, all fetched Git history for secrets and workflow configuration on main-branch pushes, weekly and on manual dispatch; on pull requests it reviews added dependencies for known vulnerabilities, and on `main` it runs the OpenSSF Scorecard. [CodeQL](.github/workflows/codeql.yml) scans Rust and GitHub Actions on authorized pull requests, main-branch pushes, weekly and on manual dispatch. Dependency review, Scorecard and CodeQL upload results only once the repository is public. Every workflow requires an owner actor and rerun actor.

The CI runner hosts do not provide a browser for the job user, so the default test job runs the real-browser tests in their skip mode. The `browser` job in the [CI workflow](.github/workflows/ci.yml) is opt-in: a maintainer runs the workflow manually with `run_browser_tests` enabled and `chromium_path` set to a Chromium executable on the runner host.

These workflow gates are defense in depth, not a sandbox: a pull request can change its own workflow. The repository settings are the authoritative control: workflows from forks need maintainer approval for every external contributor, Actions run only SHA-pinned allowlisted actions with a read-only default token, and `main` accepts only squash-merged pull requests with an approving code-owner review, resolved review threads and a green, up-to-date `required` check.

**Maintainer rule: never approve a workflow run from a fork without first reading that pull request's diff of `.github/` and of the CI scripts it runs.** The authorization gate lives in a file the pull request can edit, so approving the run executes whatever the diff says on the project's runners. See [SECURITY.md](SECURITY.md#maintainer-rules).

## Getting help

- Questions: the [docs](docs/README.md), then the question issue form.
- Bugs and feature ideas: the matching issue form.
- Security: [SECURITY.md](SECURITY.md), never a public issue.
- Conduct concerns: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Conduct

Be respectful and assume good faith. Discussions stay technical. Maintainers may close issues or pull requests that are abusive, off-topic or unsafe to run. The full policy is in the [Code of Conduct](CODE_OF_CONDUCT.md).
