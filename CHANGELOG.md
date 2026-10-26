# Changelog

## Unreleased

## v0.5.0 (26 Oct 2026)

### Added

- V034 Reinitialization (sealevel-attacks class 4). Flags a raw `AccountInfo` or `UncheckedAccount` that a handler reads with Borsh and writes back through `try_borrow_mut_data` with no initialized flag, discriminator or empty data check. Quiet for `#[account(init)]`, typed accounts, read only handlers and any handler that checks `is_initialized`, `discriminator`, `data_is_empty()` or `lamports() == 0`. Benchmark: sealevel `4-initialization/insecure` is now flagged, `secure` and `recommended` stay quiet for V034.
- V033 Vulnerable anchor-lang Version. When you scan a directory, `Cargo.toml` and `Cargo.lock` are checked for anchor-lang 1.0.0 or 1.0.1. In those releases `Program<'info, System>` accepts any executable account (RUSTSEC-2026-0144, CVE-2026-45137), fixed in 1.0.2. A lock file that resolves a fixed version silences the `Cargo.toml` finding. Older versions and 1.0.0 release candidates are not flagged. https://rustsec.org/advisories/RUSTSEC-2026-0144

## v0.4.0 (23 Oct 2026)

### Added
- V032 Precompile Offsets Not Checked. Flags a program that reads an Ed25519 or Secp256k1 precompile instruction back from the instructions sysvar and never checks the signature, public key and message instruction indexes. Without those checks an entry can name one key while the runtime verified another signature, so one real signature can count as several approvals. This is the class behind the Rain card program loss on Solana (about $1.1M, August 2026). Quiet when all three index fields are named, or when there are three or more compares against `u16::MAX`. https://blog.verichains.io/p/rain-hack-analysis-ed25519-signature
- `--format sarif` for GitHub code scanning. SARIF 2.1.0 with one rule per detector, fix text, CWE tags, a `security-severity` score, repo relative paths, and line independent fingerprints. With `--output <dir>` it writes `anchor-sentinel.sarif`. The SARIF builder existed in the library but was not reachable from the CLI.

## v0.3.1 (21 Oct 2026)

### Added
- V031 Manual Close Without Cleanup (sealevel-attacks class 9). Flags a handler that sets an account's lamports to zero (`**acc.lamports.borrow_mut() = 0`, `try_borrow_mut_lamports`, `sub_lamports(acc.lamports())`) and never clears the data, reassigns the owner, shrinks the account or calls `.close(...)`. Follows `let a = acc.to_account_info()` aliases. Quiet for `close = target`, partial withdrawals, and any handler that zeroes data, assigns, reallocs or closes. Background: Anchor 0.30 dropped the closed account discriminator, so data cleanup or `close =` is what matters now.
- V030 Type Cosplay. Flags raw `AccountInfo` or `UncheckedAccount` fields read by hand with Borsh (`try_from_slice`, `deserialize`) and no discriminator check. Quiet for typed `Account<T>`, `try_deserialize`, and manual discriminator compares.

### Fixed
- V030 no longer flags a handler that checks a custom `discriminant` enum on the deserialized account (the sealevel-attacks `3-type-cosplay/secure` false positive).

## v0.3.0 (19 Oct 2026)

### Added
- V028 Duplicate Mutable Accounts. Flags two mutable `Account<'info, T>` fields of the same type with no check that they are different accounts. It stays quiet when a constraint or the handler compares the keys (`a.key() != b.key()`, `require_keys_neq!`), for `init` fields, token and mint pairs, and pairs with different static seed prefixes. A field marked `dup` gets a higher confidence finding, because it opts out of Anchor's own check. Anchor 1.0 rejects duplicate mutable `Account` fields by default; older versions do not.
- V029 Unchecked Sysvar Address (sealevel-attacks class 10). Flags a raw `AccountInfo` or `UncheckedAccount` named like a sysvar (`rent`, `clock`, `instructions`, anything with `sysvar` in the name) when nothing ties it to the real sysvar address. Quiet for `Sysvar<'info, T>` fields, `address = ...` constraints, key comparisons to a `sysvar::...::ID`, and the checked readers (`from_account_info`, `load_instruction_at_checked`, `load_current_index_checked`, `get_instruction_relative`). The instructions sysvar is rated High, the others Medium. Background: the 2022 Wormhole Solana loss came from a forged instructions sysvar.

### Changed
- `cargo clippy --all-targets -- -D warnings` is clean on Rust 1.99.
- Added CI that runs clippy and the tests on every push and pull request.

## v0.2.1 (11 Oct 2026)

### Fixed
- `diff` matched findings by line number, so adding a few lines above a finding showed every finding as both new and fixed. It now matches by detector, file and title.
- V025 accepts a manual program ID comparison (for example `if ctx.accounts.token_program.key != &spl_token::ID`) before the CPI, like V006.

## v0.2.0 (11 Oct 2026)

Accuracy, output and packaging release. Work done 11 Oct 2026.

### Fixed
- Findings from AST-based detectors (V001, V002, V003, V004, V006) now report the real line number. They used to report line 0.
- `--format json` and `--format github` output is now clean on stdout. The banner and status lines go to stderr, so the JSON parses and CI can read the annotations.
- GitHub annotations escape newlines, commas and colons and include the detector ID in the title.
- V001 no longer flags an account that the handler checks with `.is_signer`.
- V002 no longer flags an account whose `ctx.accounts.<name>.owner` is compared in the handler.
- V006 no longer flags a raw `invoke` in a handler that compares the program account to a hardcoded program ID.
- V004 no longer calls `user.key()` seeds "static" (token spacing broke the check).
- V008 reported `Pubkey::find_program_address` twice, and missed `expected_bump != bump` as a check. Both fixed.
- V021 now reads `seeds` from the parsed `#[account(...)]` attribute, so multi-line attributes are understood.
- Results are deduped to one finding per detector, file and line.
- Two stale unit tests fixed. `cargo test`: 44 passing.

### Added
- BENCHMARK.md: results against coral-xyz/sealevel-attacks (4 of 11 classes detected, 1 partial, 6 missed; the target finding no longer fires on any hand-fixed version, it did on 4 of 4 before). Script in `benchmarks/sealevel-attacks.sh`.
- Prebuilt binaries on the GitHub release: Linux x86_64 (static, musl) and macOS arm64, built and smoke tested by a new release workflow (`.github/workflows/release.yml`).
- Unit tests for the manual check helpers.

### Changed
- README rewritten: detector table matches `anchor-sentinel list` (26 detectors), real sample output, quick install, every scan flag, PoC scaffold notes, limitations.
- `License` renamed to `LICENSE` with the standard GPL-3.0 text.
- `target/` and `.DS_Store` are no longer tracked; added `.gitignore`. (Git history still contains the old build files.)

## v0.1.0 (3 to 4 Jan 2026)

Initial release: CLI (`scan`, `diff`, `init`, `list`), detectors V001 to V027, taint analysis, CFG and global program context engines, TypeScript PoC generator, terminal/JSON/Markdown/GitHub output.
