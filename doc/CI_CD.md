# CI and release procedure

Autotools is the supported path. `make -f Makefile.ci bootstrap native` builds
and runs the packet/PDF and concurrent atomic-container regressions. Each mode
uses a separate directory under `.build/`; `make -f Makefile.ci distcheck`
tests a real source distribution, including its installation and uninstallation.
Run `make -f Makefile.ci test-ci check-workflows` for release-policy tests,
actionlint and shellcheck. The three historical tests requiring `/corp` or
`nitroba.pcap` report SKIP when their external fixtures are absent.

## Correctness

The PR and main workflow calls reusable correctness, Windows and Snap workflows.
Draft PRs receive the same tests. Main pushes and PR updates each run once;
ordinary feature-branch pushes do not independently duplicate those checks.
Tag pushes run only the release orchestration, which calls the same reusable
workflows. No workflow uses `pull_request_target` to execute PR code.

Native builds and distribution checks cover Ubuntu 22.04, Ubuntu 24.04 and
macOS 15. Debian Bookworm is compile-only; FreeBSD and OpenBSD retain native VM
tests. OpenBSD retains the three preexisting unsupported-PCAP exclusions.

`asan`, `tsan` and `ubsan` instrument C, C++ and executable linking, and execute
the real regressions. ASan and TSan cannot be combined. TSan additionally
exercises shared histogram and set operations from eight contending threads.
Its disposable Ubuntu runner lowers `vm.mmap_rnd_bits` to 28 to leave space for
the sanitizer's shadow mapping. A runtime startup failure remains a failed job.

`clang-analyzer` performs a clean build under scan-build; `clang-tidy` and
`cppcheck` use Bear's real compilation database. Clang analyzer findings fail
their jobs. Cppcheck error-severity findings fail its job; warning, performance
and portability advice is retained in XML reports. Its separate offline-reader
executable is analyzed independently of the incompatible libpcap ABI model.
Cppcheck uses its Boost/POSIX/OpenSSL models instead of parsing installed
dependency headers. Its derived database retains project/configuration include
paths; the original database is built unchanged before analysis.
Cppcheck explicitly includes the generated `config.h` so older supported
versions analyze the configured build. Clang-tidy disables only the blanket
Annex K deprecation warning for standard C memory functions; path-sensitive
memory and bounds checks remain enabled.
CodeQL captures a manual C/C++ build and also analyzes Python and Actions,
preserving the existing default setup's language coverage. It uploads
security-extended results to GitHub Code Scanning.
Disable GitHub's repository-level CodeQL default setup
before using this workflow: GitHub rejects advanced-analysis uploads while
default setup is enabled, and running both duplicates analysis.
Coverage collects lcov data from a fresh instrumented
build and uploads through the supported Codecov action, without an embedded
token or downloaded shell uploader.

Coverity is excluded by project policy. Static analysis uses Clang Static
Analyzer, clang-tidy, cppcheck and CodeQL; no Coverity credentials are required.

For Linux validation on macOS, start the configured engine, then run
`make -f Makefile.ci container-image container-check CHECK='bootstrap native'`.
The source mount is read-only and copied into a disposable container. This does
not copy Git metadata, build caches or existing release artifacts. It does
not establish Windows runtime, GitHub OIDC or installed Snap correctness.

## Package behavior

The Windows job pins vcpkg and builds static Boost ICL, OpenSSL, zlib and TRE with
MinGW. `make -f Makefile.ci windows-deps` prepares the same static prefix locally;
pass its absolute path as `WINDOWS_DEPS` to the `windows` target. A PE32+ check
and system-DLL allowlist reject an unexpected runtime DLL.
The executable is then run on Windows against ordinary and VLAN PCAP fixtures;
IPv4, VLAN and IPv6 reconstructed hashes and parsed DFXML must match. Windows
uses underscores for colons in generated address/MAC/timestamp filename components.
It intentionally supports
offline PCAP processing through the bundled reader. Live capture, BPF filters,
Wi-Fi decoding and Cairo PDFs are not included in this Windows configuration.

Each Snap is built natively, installed with strict confinement, and run on a
checked-in packet capture. CI verifies reconstructed bytes, DFXML and a PDF.
Users can install GitHub downloads with `sudo snap install --dangerous FILE`.
Connect `tcpflow:home` for ordinary files, `tcpflow:removable-media` for external
media, and `tcpflow:network-control` only when live capture is needed. Snap
Store publication is deliberately absent.

## Signing prerequisites

Set the non-secret `AZURE_*` variables and exact `WINDOWS_PUBLISHER` listed in
README.md. Configure the `windows-signing` GitHub environment to accept only
release tags matching `v*`, not arbitrary branches. The Azure application must
have an OIDC federated credential for this repository's exact environment
subject and `api://AzureADTokenExchange` audience, and the Artifact Signing
Certificate Profile Signer role scoped to the intended public certificate
profile. Check the repository's OIDC customization: do not assume its subject
matches another repository's immutable-subject format.

Only the signing job requests `id-token: write`. It logs into Azure without a
stored private key, signs with SHA-256 and an RFC3161 timestamp, checks public
trust and the exact publisher with Windows and SignTool, then reruns the PCAP
tests against the signed bytes. Missing configuration, denied service access,
an unsigned executable, a missing timestamp or a failed runtime test prevents
release publication. Configured variables alone are not proof of signing access.

## Release sequence

After review, successful CI and the human merge, create an annotated tag matching
the source version, for example `git tag -s v1.7.0 -m 'tcpflow 1.7.0'`, then push
that exact tag. The workflow requires an annotated tag, exact Autoconf/CMake
version agreement, tag/event-commit agreement and ancestry on `origin/main`.
Signed tags are recommended; annotation and ancestry are enforced by CI.

The release run builds and tests its own artifacts. It never searches for the
latest successful build from another commit. Native distribution checks supply
`tcpflow-1.7.0.tar.gz`; the Windows and Snap jobs supply the tested binary and
both architectures. Signing waits for all correctness/package jobs to pass.
The final asset set is:

- `tcpflow-1.7.0.tar.gz`
- `tcpflow64.exe` (public Authenticode signature and timestamp)
- `tcpflow_1.7.0_amd64.snap`
- `tcpflow_1.7.0_arm64.snap`
- `SHA256SUMS`, calculated after signing

Assembly rejects missing, empty and unexpected assets. It creates a complete
draft, downloads the draft assets and verifies their checksums, then publishes.
If a release already exists for that tag, the job stops without replacing it.
If a job fails after draft creation, inspect and retain the draft for diagnosis;
do not blindly delete a public release or move a published tag to retry.

Never infer readiness from an earlier revision. Verify the current PR's native,
sanitizer, analyzer, package and review results. After tagging, verify the actual
release workflow, downloaded checksums, public signature and expected assets.
