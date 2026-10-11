# Benchmark: coral-xyz/sealevel-attacks

[sealevel-attacks](https://github.com/coral-xyz/sealevel-attacks) is the standard set of Solana bug examples from the Anchor team. It has 11 bug classes. Each class has an `insecure` program, a `secure` program (fixed by hand in the handler) and a `recommended` program (fixed with Anchor constraints). Class 9 has two extra insecure variants.

This is a small, honest benchmark. It shows what Anchor-Sentinel catches today and what it misses.

- Repo commit tested: `24555d0` (sealevel-attacks main, depth 1)
- Anchor-Sentinel: v0.2.0
- Date: 11 Oct 2026
- Reproduce: `benchmarks/sealevel-attacks.sh path/to/anchor-sentinel`

## Headline

| | v0.1.0 detectors | v0.2.0 |
|---|---|---|
| Bug classes where the target bug is flagged on the insecure program | 4 of 11 (+1 partial) | 4 of 11 (+1 partial) |
| Of those, target finding still raised on the hand-fixed `secure` program (false positive) | 4 of 4 | **0 of 4** |
| Target finding still raised on the `recommended` program | 0 of 4 | 0 of 4 |
| Fixed programs (secure + recommended, 22 total) with zero findings | 8 | **11** |
| Total findings on the 22 fixed programs | 47 | **36** |
| Total findings on the 13 insecure programs | 30 | 27 |

"v0.1.0 detectors" means the v0.1.0 detector logic with only the line-number and JSON output fixes applied, so the two runs can be compared.

The v0.2.0 gains come from five fixes made after the first run: V001, V002 and V006 now recognise manual `is_signer`, owner and program ID checks; V008 no longer double reports and recognises `expected_bump != bump`; V021 reads multi-line `seeds` constraints; results are deduped per detector and line.

## Per class

Detected = the right detector fires on the vulnerable account or call, at the right line.

| # | Bug class | Insecure: target bug flagged? | Secure: fix recognised? | Recommended: fix recognised? |
|---|---|---|---|---|
| 0 | Signer authorization | Yes, V001 line 16 | Yes (v0.1.0: no, V001 still fired) | Yes |
| 1 | Account data matching | Partial. V002 flags the unchecked `token` account (line 20) as a missing owner check. The data mismatch itself is not modelled | n/a. V002 still fires, correctly: this secure version adds the data check but still has no owner check | Yes |
| 2 | Owner checks | Yes, V002 line 24 | Yes (v0.1.0: no) | Yes |
| 3 | Type cosplay | **Missed.** No discriminator check detector. (v0.1.0 raised a wrong V002 here even though the owner is checked; now gone) | n/a | n/a |
| 4 | Initialization (reinit) | **Missed.** V002/V024 fire on other things, not the reinit | n/a | n/a |
| 5 | Arbitrary CPI | Yes, V006 line 11 | Yes (v0.1.0: no, V006 fired twice) | Yes |
| 6 | Duplicate mutable accounts | **Missed.** No detector for this class | n/a | n/a |
| 7 | Bump seed canonicalization | Yes, V008 line 11 | Yes (v0.1.0: no, V008 fired twice) | Yes |
| 8 | PDA sharing | **Missed.** V021 fires on all three versions alike, so it gives no signal for shared seeds | n/a | n/a |
| 9 | Closing accounts (3 insecure variants) | **Missed** on all 3. No detector for zeroing data / closed discriminator | n/a | n/a |
| 10 | Sysvar address checking | **Missed.** V002 skips accounts named like sysvars (`rent`) | n/a | n/a |

Score: 4 detected, 1 partial, 6 missed.

## Raw output (v0.2.0)

Detector ID and line for every finding. `-` means no findings.

```
0-signer-authorization/insecure                  V001:16 V002:16 V021:16
0-signer-authorization/recommended               -
0-signer-authorization/secure                    V002:20 V021:20
1-account-data-matching/insecure                 V002:20
1-account-data-matching/recommended              -
1-account-data-matching/secure                   V002:23
10-sysvar-address-checking/insecure              -
10-sysvar-address-checking/recommended           -
10-sysvar-address-checking/secure                -
2-owner-checks/insecure                          V002:24
2-owner-checks/recommended                       -
2-owner-checks/secure                            -
3-type-cosplay/insecure                          -
3-type-cosplay/recommended                       -
3-type-cosplay/secure                            -
4-initialization/insecure                        V002:31 V024:14
4-initialization/recommended                     V013:18
4-initialization/secure                          V002:30 V024:17
5-arbitrary-cpi/insecure                         V001:33 V002:31 V002:32 V002:33 V006:11 V009:11 V010:12 V021:33
5-arbitrary-cpi/recommended                      V009:31 V010:11 V024:11
5-arbitrary-cpi/secure                           V001:36 V002:34 V002:35 V002:36 V009:14 V010:15 V021:36
6-duplicate-mutable-accounts/insecure            -
6-duplicate-mutable-accounts/recommended         -
6-duplicate-mutable-accounts/secure              -
7-bump-seed-canonicalization/insecure            V008:11
7-bump-seed-canonicalization/recommended         V004:29 V013:22 V024:10
7-bump-seed-canonicalization/secure              -
8-pda-sharing/insecure                           V009:35 V010:13 V021:20 V021:21 V024:13
8-pda-sharing/recommended                        V004:28 V009:43 V010:16 V021:29 V024:16
8-pda-sharing/secure                             V009:38 V010:16 V021:23 V021:24 V024:16
9-closing-accounts/insecure-still-still          V002:39 V024:14
9-closing-accounts/insecure-still                V002:39 V024:13
9-closing-accounts/insecure                      V002:24 V024:10
9-closing-accounts/recommended                   V001:19 V002:19
9-closing-accounts/secure                        V002:59 V002:64 V002:65 V024:13 V024:45
```

## Noise on fixed programs

36 findings remain on the 22 fixed programs. Some are true (for example 1-secure and 4-secure really have no owner check on a raw `AccountInfo`). Most are noise. By detector:

| Detector | Findings on fixed programs | Note |
|---|---|---|
| V002 Missing owner check | 10 | Fires on raw `AccountInfo` even when only the key is read or the account is passed to the token program |
| V024 Account used without validation | 7 | Noisy, flags `transfer_ctx` helper calls and signers |
| V021 Unverified seeds | 5 | Name based (`vault`, `pool`, `authority`), flags non-PDA accounts |
| V009 CPI reentrancy | 4 | Fires on any CPI; reentrancy into the caller is rare on Solana |
| V010 Unchecked transfer amount | 4 | Style level |
| V001, V004, V013 | 2 each | |

## What this means

- The core first-pass checks work: missing signer, missing owner, arbitrary CPI, bump canonicalization. With v0.2.0 they no longer fire once the bug is fixed by hand.
- Six classes have no detector yet: type cosplay, reinitialization, duplicate mutable accounts, PDA sharing, account closing, sysvar address. These are the roadmap.
- V009, V010, V021 and V024 need tuning or a lower default severity. Use `--exclude` or `--severity` to cut noise today.
- This is static analysis. It is a first pass, not an audit.
