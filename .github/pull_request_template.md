## What and why

<!-- One paragraph: the change and the reason. Link the issue it closes. -->

## How it was verified

<!-- Exact commands and their result, e.g. `cargo test -p browserx-pool`. -->

## Checklist

- [ ] I have read the [contributing guide](https://github.com/noxred-research/browserx/blob/main/CONTRIBUTING.md) and agree to the [Code of Conduct](https://github.com/noxred-research/browserx/blob/main/CODE_OF_CONDUCT.md)
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and the affected tests pass
- [ ] `python3 ci/lint-provenance.py` and `python3 ci/check-docs-links.py` pass
- [ ] Config keys, API routes, CLI commands, metrics or error codes that changed are updated in `docs/`, and `CHANGELOG.md` has an `[Unreleased]` entry
- [ ] Lease, snapshot or database format changes are versioned and forward-only; no shipped migration or format version was edited
- [ ] No change to authentication, lease token handling, snapshot encryption, the scoped CDP relay or egress destination checks, or the change is called out above with its tests
- [ ] No credentials, cookies, real personal data or captured third-party content in code, tests or fixtures
