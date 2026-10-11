# Changelog

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
