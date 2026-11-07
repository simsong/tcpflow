# tcpflow 1.7.0 CI/CD analysis and implementation specification

Evidence collected November 6, 2026. This records the pre-implementation diagnosis. The resulting implementation and operational procedure are described in CI_CD.md; no tag or release is created by preparing these changes.

## Baselines and ownership

| Repository | Local revision | Current remote main | Relevant working-tree state |
| --- | --- | --- | --- |
| tcpflow | b1479db14b1604e00d35c2d39566c54e8b1785d0, master | 191b4e0b4627261a8a5177e2f9e477ec389c01cd | Clean; local master is behind main |
| bulk_extractor | b6b43e749d59a71e61992580f5ad18f68313a8bf, main | e86383947ee016c825599887334cacf011736abf | Local edits to AGENTS.md and doc/RELEASE_NOTES.md; read-only reference |
| mail-archiver | ba0af6c5f31826ca2917e50c29fb103318ba9b34, codex/signed-installer-labels | ba0af6c5f31826ca2917e50c29fb103318ba9b34 | Six local website/test edits; read-only reference. GitHub redirects this repository to email-collection-toolkit |

Use tcpflow origin/main, not the old local master, as the implementation baseline: main includes recent security and portability fixes. Its Autoconf version is 1.6.2; the local checkout says 1.6.1, README says 1.5.0, and the root CMake project says 1.4.6. Synchronize maintained version declarations to 1.7.0 and explicitly document Autotools as the CI/release build path. The CMake tree also contains obsolete source paths, so changing its version alone does not establish a working CMake build.

## Existing checks

| Capability | tcpflow current main | bulk_extractor current main | mail-archiver current main |
| --- | --- | --- | --- |
| Trigger policy | Every branch push plus main-target PRs; duplicates runs for branches with PRs | main pushes and PRs; most code jobs skip draft PRs; documentation path exclusions | Non-main branch pushes; changed-file gate; explicit release-candidate trigger |
| Native compilation | macOS and Ubuntu latest, C++17 despite workflow title saying C++14 | macOS latest, Ubuntu 22.04/latest; Debian Bookworm compile-only container | Python/Rust/macOS checks with pinned native dependencies |
| BSD | FreeBSD and OpenBSD VM builds and checks | Not in inspected workflow set | Not an applicable reference |
| Functional checks | Autotools make check; packet reconstruction and PDF tests, plus optional external-corpus scripts | Native unit/integration tests and make distcheck | Static, Rust, Python and browser checks; packaging/runtime checks |
| AddressSanitizer | Absent | PR-only Ubuntu 22.04 debug tests | No corresponding C++ application sanitizer suite |
| ThreadSanitizer | Absent | PR-only Ubuntu latest dedicated shared-state/thread-safety test | No corresponding C++ application sanitizer suite |
| UndefinedBehaviorSanitizer | Absent | Configure option exists; not invoked by inspected CI jobs | No corresponding C++ application sanitizer suite |
| Static analyzer | None in inspected workflow | Monthly/manual Coverity Scan | Python/Rust-specific static tooling |
| Other C++ static analyzers | Absent | No clang-tidy, Clang Static Analyzer, cppcheck, or CodeQL jobs found | Not a substitute for C++ analysis |
| Coverage | Legacy shell script rebuilds/tests then invokes obsolete Codecov Bash uploader; contains a hard-coded token; uses gcov-9 | Dedicated lcov collection and Codecov action | Different-language coverage is not a direct build recipe |
| Source distribution | No automated distcheck/release job | make distcheck; source artifact uploaded | Source distributions validated before release assembly |
| Windows runtime | No workflow | MinGW static EXE, import allowlist, native Windows behavior tests | Built package installation, relocation/runtime, signature checks |
| Snap | Absent | Strict core22 package, amd64/arm64 builds and installed-package test | Not applicable |

Preserve tcpflow's BSD coverage. Avoid copying bulk_extractor's draft-PR exclusions: the requested draft must receive meaningful CI. Choose main pushes plus PRs to prevent duplicate ordinary branch CI; tag builds should be coordinated by the release workflow rather than independently rebuilding identical release artifacts in several workflows.

The requested full set of bulk_extractor analyzers is currently Coverity. Additional Clang Static Analyzer, clang-tidy, cppcheck and CodeQL would broaden coverage beyond that baseline and are awaiting scope clarification. ASan, TSan and UBSan should each run as a distinct supported configuration; ASan and TSan cannot be combined. Instrument C and C++ compilation and linking, validate option values and incompatible combinations, and exercise real tests. Do not copy the reference macro literally: it treats even an explicit --disable option as enabling a sanitizer and only appends flags to CXXFLAGS.

TSan requires actual concurrent work. tcpflow's ordinary packet processing does not provide the same thread-pool coverage as bulk_extractor; add a substantive concurrency test for its existing shared atomic histogram/set and mutex primitives, with assertions on totals and insertion semantics. Also run the packet regressions in instrumented builds, without pretending that sequential execution establishes concurrency coverage. Runtime inability to initialize a sanitizer must fail visibly, not be converted into a passing result.

## Test and distribution boundaries

- tests/test-subs.sh infers build paths from a few srcdir values and hard-codes a distcheck layout. Out-of-tree builds and a real distcheck must verify and repair this boundary.
- test-multifile.sh requires a file under /corp and exits zero when missing. test-iptree.sh and test-chroot.sh also exit zero without their optional packet capture. A green make check therefore does not prove these behaviors were exercised. Mark skips honestly and add repository-contained fixtures for required release behavior.
- Several tests use the same output-directory names. Keep existing checks serial unless test isolation is repaired; adding make -j to tests can create races unrelated to the sanitizer's target.
- The source-distribution manifest lists only a few PCAPs, while the PDF test loops over whichever PCAPs are available. A distribution can therefore test less than a checkout. Include the required corpus and test helpers explicitly and verify the generated archive's real build/test/install/uninstall path.
- The legacy Windows configuration disables real libpcap and uses be13_api/pcap_fake.cpp. Consequently Windows is offline-PCAP-only unless a separate capture-driver integration is added. It does not support the native libpcap filter/live-capture feature set. The fallback reader must receive malformed/truncated-length tests before release; signing an executable does not prove parser correctness.
- Optional Cairo affects PDF tests; a Windows build that omits it must have a deliberate test selection and documented feature boundary. Native/Snap release builds should retain supported packet/PDF functionality.

## Release comparison

bulk_extractor's v* tag starts source, Windows and release/Snap workflows. Its assembly script retrieves successful workflow artifacts for the release commit, combines tar.gz/EXE/Snaps and SHA256SUMS, and creates a draft GitHub Release. Its Snap workflow tests installed strict-confinement packages on amd64/arm64. Optional Store upload is a separate protected job and silently leaves packages unpublished without credentials. The inspected Windows workflow verifies PE format and DLL dependencies and tests on Windows, but does not apply Authenticode signing. Its release source should therefore not be described as satisfying the signed-EXE request.

mail-archiver supplies the stronger signing/publishing precedent. A preflight verifies the tag points at a commit already on main and agrees with the application version; release jobs consume an immutable commit. Azure login uses GitHub OIDC with a protected windows-signing environment; Artifact Signing applies SHA-256 with RFC3161 timestamps. Signature verification includes trust/publisher checks. Tested installers and source archives are assembled with checksums, staged in a complete draft, then published. Its successful release workflow is evidence this mechanism works for that repository, not that tcpflow already has Azure access.

Proposed tcpflow graph:

1. Validate annotated v1.7.0-style release tag, exact configure.ac/CMake version agreement, tag-to-event-SHA agreement, and main ancestry. Resolve one immutable source commit.
2. Run required correctness jobs on that source revision using reusable workflows/Makefile targets; enforce successful checks before publishing.
3. Build the Autotools source tar.gz with make distcheck. Build and install/test native amd64 and arm64 strict Snaps. Build the agreed Windows x64 artifact and execute PCAP reconstruction checks on Windows.
4. In a tag-restricted protected signing job, use Azure OIDC, sign and timestamp the agreed EXE(s), verify trusted Authenticode signatures and expected publisher, and repeat the installed/runtime test. Never fall back to an unsigned release when signing is missing or fails.
5. Download only this release run's tested artifacts, verify the expected asset set and version/architecture names, generate SHA256SUMS after signing, and create a complete release. Whether it remains draft or publishes automatically must follow the user's choice. Reruns must not overwrite a different commit's assets or mutate an existing public release silently.
6. Optional Snap Store publication is a separate explicit choice and requires tcpflow package ownership and Store credentials. Producing a .snap GitHub asset needs no Store login.

A standalone signed tcpflow64.exe most closely matches bulk_extractor. If the user wants an installer EXE, choose a maintained installer system, sign both the contained executable and outer installer, install silently in CI, and test the installed binary. This is an additional artifact/consumer distinction, not a change in filename alone.

## Verified execution evidence

- tcpflow main 191b4e0: https://github.com/simsong/tcpflow/actions/runs/41738124281 succeeded; native macOS/Ubuntu and both BSD jobs succeeded. This is baseline evidence, not evidence for any proposed changes.
- bulk_extractor e863839: recent main native/Windows/Codecov runs succeeded. The latest monthly Coverity run failed while downloading its build tool, before capture/upload: https://github.com/simsong/bulk_extractor/actions/runs/41276721176 . Do not copy that configuration and claim effective analysis without a successful new scan.
- bulk_extractor latest release v2.2.0 contains source tar.gz, Windows EXE, amd64/arm64 Snaps and SHA256SUMS.
- tcpflow latest published release is the older tcpflow-1.6.1 tag with only tcpflow-1.6.1.tar.gz. The new v* convention must be documented.
- mail-archiver release at ba0af6c succeeded: https://github.com/simsong/email-collection-toolkit/actions/runs/41903844842 . Its separate website deployment also succeeded; tcpflow does not need an unrelated website deployment.

## Prerequisites and current blockers

The active gh identity is simsong-agent. GitHub reports pull=true and push=false on tcpflow; repository secrets/variables and collaborator permissions cannot be inspected with that access. Do not switch to the personal account. The tcpflow origin uses github.com directly; publication must retain/use the established github-codex authentication alias and verify it authenticates the agent separately from commit signing.

Azure settings exist in the bulk_extractor reference repository, but tcpflow needs its own scoped configuration and an OIDC federation subject matching its repository and protected environment. Configuration presence is not proof of Azure role assignment, certificate-profile access, tag restrictions, or hosted-runner connectivity. These must be checked before declaring signed releases operational. CodeQL needs GitHub code-scanning permissions if included. Store publication requires separate ownership/credentials if selected.

Autoconf/Automake, LLVM 21 analyzer tools and MinGW are installed locally. Local Boost/libpcap prerequisites were not found in the inspected Homebrew locations. Docker's Colima socket is unavailable. Finch is installed but its VM is stopped. Start an existing supported Linux VM or obtain missing native dependencies before claiming local builds. A Linux container can validate Linux builds and cross-compilation, but it does not establish hosted TSan support, Windows installation, Snap confinement, Azure signing or GitHub release correctness.

## Active-work coordination requiring approval

Open PRs observed against main 191b4e0:

- #285 fix/ubsan, 48b39d15b4ed1f36d07acf691464f7f558954142: packs be13::tcphdr and avoids memcpy(NULL,0) in iptree.h. Directly relevant to a new UBSan gate.
- #284 fix/tso-zero-ip-len: src/tcpdemux.cpp and tests/Makefile.am, new TSO test.
- #282 fix/w-multiple-r: src/tcpflow.cpp and tests/Makefile.am, new packet-output test.
- #281 feat/relinquish-numeric-ids-213: privilege handling, tests/Makefile.am, man page.
- #283 remove-scan-python: CMake/Automake files, tcpflow sources and man page.
- #278 patch-1: man-page corrections; largely independent unless documentation integration touches those lines.

The app's available chat inventory showed this as the active tcpflow task; it does not establish absence of external contributors. The pr-to-ready active-work gate requires approval before potentially conflicting branch creation/edits. Proposed coordination: branch from current origin/main, leave these PRs unmerged, avoid bundling their unrelated behavior, preserve their tests when integrating later, and repair only evidenced defects needed for required checks. Await the user's decision before editing.

## Acceptance evidence required after implementation

Record baseline, complete diff, task-owned new files, exact candidate and up to three shared review/fix rounds. Run Makefile validation; obtain the required independent Sol High completion review and Astra High pre-push review on the same candidate. Verify agent identity/signature before commit/push. Open a draft PR and request Copilot through the review API. Track current-head CI and review results, fix valid findings, and hand off honestly. No tag, merge, public release, Snap Store upload, or access-policy change is authorized merely to get a passing test.

Subsequent user decisions: use current main; incorporate only PR #285; ship a signed standalone x64 EXE; produce amd64/arm64 Snaps on GitHub only; include the proposed additional analyzers. Agent Write access was granted. The user authorized publication after approval and merge. On November 7 the user excluded Coverity and approved reuse of email-collection-toolkit's Azure identity and public signing profile with a separate tcpflow environment federation. The implementation therefore uses Clang Static Analyzer, clang-tidy, cppcheck and CodeQL without a Coverity workflow or credential requirement. Signing-service access still requires verification through GitHub CI.
