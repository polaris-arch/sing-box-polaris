# Audit remediation status

## Current K2 remaining CI remediation

Last tested source: commit `e4df75e43c76c83aa35a9b9fe9f8eb8eeafe61a4`, tree `f923292171fe1d9354d4c47fed8cc322652728fc`. All ten lint jobs now report only 14 unique staticcheck findings. Previous modernize/gci/gofumpt/unused findings disappeared, the owned-format gate passed, and Linux/macOS ordinary tests passed. Windows ordinary tests now report only two cleanup DACL restoration failures; the earlier native enumeration and JSON fixture failures disappeared. Patch tests separately failed at CLONE_NEWNET creation without runner capability. The contract workflow and all other nine selfcheck jobs, including iOS/Android and cross-platform libraries, completed successfully for K2. None of these results certify the changed source below.

The current six Go files correct golangci-specific statement-local suppression of thirteen proper-name ST1005 diagnostics, retain the deliberate STUN field projection instead of an unsafe suggested whole-struct conversion, and add regression coverage. Windows fixture cleanup uses symmetric requested rights and verifies the restored protected DACL; stage/access/control diagnostics avoid exposing SID/SDDL. Production ACL policy and both security-rejection tests remain intact. The exact reason Windows refused the earlier restoration is not claimed proven; the next actual run must decide.

All 92 current owned Go files passed the official formatter's --diff fixed point. The tool-build Go1.27.0 versus CI Go1.27.2 difference and local gci module-discovery warning remain documented. Current lint/product CI has not run. The user explicitly authorized this batch disposable GitHub Linux runner to execute only the common/netns test binary with sudo -n. The workflow binds that entry to fixed same-repository PR #2, its expected branch and actual checked-out source (including only the exact event merge with matching head parent/tree); a polaris-main push must equal that same head commit. Read-only API failure never elevates. Other source identities retain the original unprivileged test path; no test is skipped or counted as passed. Other package tests and compilation remain unprivileged. No host sysctl/AppArmor setting changes. This is distinct from the earlier Windows SYSTEM authorization. The new gate has not executed yet.

The following K1 and reconstruction sections are retained as historical snapshots, not evidence for current bytes.

## Historical K1 CI remediation

Last tested source: commit `918198714a6ef8a7661e0c566761a0c0892fb53a`, tree `40e4fbc23ae827f3e001d84610ce95b2cb4a7981`. That CI was not green: all 10 lint platforms failed (149 unique findings), self-check stopped at formatting, and Windows product tests failed. Linux/macOS tests and the contract workflow passed only for K1.

The current 71 source/helper changes have passed independent static review. They address all known lint findings, Windows native enumeration admission, typed construction-test fixtures, and formatter diagnostic output. Existing lint gates and stable Windows/Tailscale error strings are retained; 13 precise proper-name ST1005 directives are documented. No current-tree product test or lint PASS is claimed.

Official golangci-lint2.15.0 formatting write and subsequent --diff both exited0, with empty diff. The official local binary was built with Go1.27.0, whereas CI uses Go1.27.2. Local gci module discovery was unavailable; complete warning/output evidence was retained. This is a formatting fixed point with environment caveats, not CI certification. A fresh single unified CI campaign remains required.

The source inventory retains earlier ownership/baseline entries, updates affected hashes and includes all current remediation files. It excludes itself and this status document to avoid hash self-reference. No predicted final commit or old success receipt is relabeled as current evidence.

## Historical reconstruction snapshot

The following original finding table and integration notes record the preceding source reconstruction. Their product-validation labels are historical; the current state and remaining validation requirements are stated above.

## Original 45 findings

| Finding | Owner | Implementation / validation status |
|---|---|---|
| H-F1 | hot | Rebuilt; partition static review closed; product validation not run |
| BC1 | windows | Rebuilt; partition static review closed; product validation not run |
| N1 | libraries | Rebuilt; partition static review closed; product validation not run |
| PC1 | runtime | Rebuilt; partition static review closed; product validation not run |
| S1 | libraries | Rebuilt; partition static review closed; product validation not run |
| STORE-RC1 | libraries | Rebuilt; partition static review closed; product validation not run |
| STORE-RC2 | libraries | Rebuilt; partition static review closed; product validation not run |
| 04-C1 | runtime | Rebuilt; partition static review closed; product validation not run |
| CE-B1 | libraries | Rebuilt; partition static review closed; product validation not run |
| CE-R1 | libraries | Rebuilt; partition static review closed; product validation not run |
| CE-R2 | libraries | Rebuilt; partition static review closed; product validation not run |
| N2 | libraries | Rebuilt; partition static review closed; product validation not run |
| N3 | libraries | Rebuilt; partition static review closed; product validation not run |
| N4 | libraries | Rebuilt; partition static review closed; product validation not run |
| OB-R1 | libraries | Rebuilt; partition static review closed; product validation not run |
| OB-R2 | libraries | Rebuilt; partition static review closed; product validation not run |
| PH1 | runtime | Rebuilt; partition static review closed; product validation not run |
| RC3 | libraries | Rebuilt; partition static review closed; product validation not run |
| RC4 | libraries | Rebuilt; partition static review closed; product validation not run |
| BC2 | runtime | Rebuilt; partition static review closed; product validation not run |
| PH2 | runtime | Rebuilt; partition static review closed; product validation not run |
| RM05-1 | runtime | Rebuilt; partition static review closed; product validation not run |
| RM05-2 | runtime | Rebuilt; partition static review closed; product validation not run |
| WH1 | windows | Rebuilt; partition static review closed; product validation not run |
| HOT-APP-F1 | hot | Rebuilt; partition static review closed; product validation not run |
| HOT-APP-F2 | hot | Rebuilt; partition static review closed; product validation not run |
| UIP-03 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| UIP-04 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| UIP-05 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| D-01 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| D-02 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| D-03 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| NA-01 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| NA-02 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| NA-04 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| NA-05 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| BC3 | runtime | Rebuilt; partition static review closed; product validation not run |
| BC4 | runtime | Rebuilt; partition static review closed; product validation not run |
| CUSTODY-RC1 | runtime | Rebuilt; partition static review closed; product validation not run |
| NA-03 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| PC3 | windows | Rebuilt; partition static review closed; product validation not run |
| PH3 | runtime | Rebuilt; partition static review closed; product validation not run |
| RC5 | libraries | Rebuilt; partition static review closed; product validation not run |
| UIP-01 | delivery-ui | Rebuilt; partition static review closed; product validation not run |
| UIP-02 | delivery-ui | Rebuilt; partition static review closed; product validation not run |

O02 was previously completed and is not reopened or included in these 45.

## Additional required scope

- testing-merge: rebuilt persisted static integrity verified awaiting dual parent commit. Preserve full dfb803 testing ancestry; recover official sing-tun9ffa source baseline, local patch tree and exact two binding JSONs; verify original source archives, not old hashes alone.
- kernel-ci-repair: baseline preserved. Retain all 7baae CI repairs and governance ancestry; final remove only dots-protocol-codegen.yml and dots-baseline-materialize.yml.
- app-main-merge: five real main blobs verified awaiting dual parent commit. Integrate five README files from 51587; final parents82db and51587. Read actual blobs and verify; current compare confirms3 unique main commits, net5README.
- candidate-ci-formatter: source static review closed real candidate sha pending. Actual candidate JSON only after true kernel commit; same-repository batch PR-only candidate mode, ordinary PR formal; cheap format and existing native chain preserved; formatter allowlist rederived from rebuilt manifest.
- windows-system-acceptance: source static review closed execution not run. User approved fresh SYSTEM and PrebuildUserDomain paths; wire candidate Windows job to one build; do not claim execution success.
- source-metadata: identities refreshed pending metadata review. Legacy fork-source-fingerprint-v1 collector unchanged/historical-only; current native_release_index→upstream-native receipt/assets→App reviewed-kernel-source-v1/source_policy/upstream-release chain retained. New actual source/asset identity required; never relabel historical receipts.
- durable-integration: owner sources admitted final code only snapshot readback required. Every owner increment first persisted to Library, materialized back and SHA256 checked; only verified packages admitted. Final complete freeze likewise persisted and read back before root remote writes. Two governance branches only; no main/tag writes or product gates.

The final kernel commit must exist before candidate-source.json is materialized. This source-only App snapshot intentionally omits that file. Formal release-contract source/assets remain bound to their existing release until actual new release inputs are available. Candidate acceptance is not formal release evidence.

The legacy fork-source-fingerprint-v1 collector remains historical-only and unsupported for the current source. Use the existing scripts/ci/native_release_index.py producer, upstream-native receipts/assets and App polaris-reviewed-kernel-source-v1 source policy chain. Historical receipt bytes and introducedCommit references are unchanged.
