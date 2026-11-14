# Third-party notices

BrowserX itself is licensed under [AGPL-3.0-only](LICENSE). This file describes the third-party material that the repository contains or that a build of it links. Their licenses are separate from the BrowserX license and are not changed by it.

This inventory was compiled from the repository tree and each item's own metadata. It is not legal advice.

## Rust dependencies

BrowserX vendors no third-party source code. All Rust dependencies are fetched from crates.io at build time and pinned in [`Cargo.lock`](Cargo.lock); the workspace crates are `publish = false`.

The set of licenses a dependency may carry is enforced in CI by `cargo deny` using [`deny.toml`](deny.toml). The allowed licenses are Apache-2.0 (also with the LLVM exception), MIT, MIT-0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, MPL-2.0, CC0-1.0, BSL-1.0 and CDLA-Permissive-2.0. A dependency under any other license fails the build.

To list the licenses of the dependencies of a build, run `cargo deny list` or `cargo metadata`, and keep the license texts that a distribution of a binary requires.

## Native components linked into the binary

The following native components are built from source by Cargo build scripts and linked into the `browserx` binary. Retain the licenses of the components in the actual distribution.

| Component | Crate (version in `Cargo.lock`) | Used by | License |
| --- | --- | --- | --- |
| SQLite | `libsqlite3-sys` (bundled) | the lease registry | SQLite is public domain; the Rust bindings are MIT |
| ring | `ring` | rustls cryptography | Apache-2.0 AND ISC, with the licenses of its bundled sources in the crate |
| AWS-LC | `aws-lc-sys` (through `aws-lc-rs`) | rustls cryptography provider | ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause, with the licenses of its bundled sources in the crate |
| LZ4 | `lz4-sys` | record batch compression support of the Kafka client | BSD-2-Clause for the library; the Rust bindings are MIT |

## Data embedded in the binary

| Material | Crate (version in `Cargo.lock`) | License |
| --- | --- | --- |
| Root certificate store data | `webpki-roots` | CDLA-Permissive-2.0 |

## Browser

BrowserX does not bundle, download or redistribute a browser. It launches a Chromium executable that you install or point it to, under that executable's own license and terms. The Dockerfile in [`docker/`](docker) installs a Chromium package from the base image's distribution repositories; the license of that package applies to the resulting image.

## Container base images

The container build in [`docker/`](docker) starts from the public `rust` (build stage) and `debian` (runtime stage) base images and installs distribution packages, among them Chromium, `curl`, `tini` and font packages. Their licenses apply to images you build; maintainers update the base image tags by hand, and the notices of the base image and installed packages are available inside the image under `/usr/share/doc`.

## Documentation and assets

The banner and architecture diagrams under [`docs/assets/`](docs/assets) are original works of this project and are covered by the repository license. The [Code of Conduct](CODE_OF_CONDUCT.md) is adapted from the Contributor Covenant, version 2.1, which is licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).
