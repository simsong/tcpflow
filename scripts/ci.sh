#!/usr/bin/env bash
# Run tcpflow's checks through the same commands locally and in GitHub CI.
# Each mode has its own out-of-tree Autotools build and diagnostic reports.
# Native and instrumented builds run the real packet and concurrency tests.
# Static analyzers inspect compiler commands, not guessed include paths.
# Windows cross-builds are checked for non-system DLL imports before upload.
set -euo pipefail
source_root=$(cd "$(dirname "$0")/.." && pwd)
mode=${1:?check mode required}
build_root=${CI_BUILD_ROOT:-"$source_root/.build"}
jobs=${CI_JOBS:-2}
build="$build_root/$mode"
mkdir -p "$build"
cd "$source_root"
[[ -f configure ]] || bash bootstrap.sh
cd "$build"
configure_args=(--quiet)
case "$mode" in
    asan) configure_args+=(--without-o3 --enable-address-sanitizer);;
    tsan) configure_args+=(--without-o3 --enable-thread-sanitizer);;
    ubsan) configure_args+=(--without-o3 --enable-undefined-sanitizer);;
    coverage)
        export CFLAGS='-g -O0 --coverage' CXXFLAGS='-g -O0 --coverage' LDFLAGS=--coverage
        configure_args+=(--without-opt);;
    clang-analyzer|clang-tidy)
        export CC=clang CXX=clang++
        if [[ "$(uname -s)" = Darwin ]]; then
            SDKROOT=$(xcrun --show-sdk-path)
            export SDKROOT CPPFLAGS="${CPPFLAGS:-} -isysroot $SDKROOT"
            export LDFLAGS="${LDFLAGS:-} -isysroot $SDKROOT"
        fi
        configure_args+=(--without-o3);;
    windows)
        : "${WINDOWS_DEPS:?WINDOWS_DEPS must name a static MinGW dependency prefix}"
        export CPPFLAGS="-I$WINDOWS_DEPS/include" LDFLAGS="-L$WINDOWS_DEPS/lib"
        export PKG_CONFIG_LIBDIR="$WINDOWS_DEPS/lib/pkgconfig"
        export LIBS
        LIBS=$(pkg-config --libs --static openssl zlib)
        configure_args+=(--host=x86_64-w64-mingw32 --enable-cairo=false --disable-wifi --without-cap-ng);;
    native|distcheck|cppcheck|codeql-build) ;;
    *) echo "Unknown check mode: $mode" >&2; exit 2;;
esac
"$source_root/configure" "${configure_args[@]}"
case "$mode" in
    clang-analyzer)
        make clean
        scan-build --status-bugs -o reports make -j"$jobs" analyzer-build
        ;;
    clang-tidy|cppcheck)
        make clean
        bear -- make -j"$jobs" analyzer-build
        if [[ "$mode" = clang-tidy ]]; then
            run-clang-tidy -p . -j "$jobs" -warnings-as-errors='clang-analyzer-*'
        else
            # Use the tool's Boost/POSIX models for external libraries. Preserve
            # project/config include paths; compile the original database first.
            jq --arg source "$source_root" --arg build "$build" \
                'map(.arguments |= map(select((startswith("-I/") | not) or startswith("-I" + $source) or startswith("-I" + $build))))' \
                compile_commands.json > cppcheck-commands.json
            # The standalone reader test and libpcap use intentionally distinct
            # ABI types in separate executables; do not merge their CTU models.
            # Older cppcheck versions need the generated configuration explicit.
            cppcheck --project=cppcheck-commands.json --library=boost,posix,openssl --enable=warning,performance,portability \
                --include="$build/config.h" \
                --inline-suppr --check-level=exhaustive --suppress=missingIncludeSystem \
                -i"$source_root/src/be13_api/pcap_fake.cpp" -i"$source_root/tests/test_pcap_fake.cpp" \
                --xml --xml-version=2 --output-file=cppcheck.xml
            cppcheck --project=cppcheck-commands.json --library=boost,posix,openssl --enable=warning,performance,portability \
                --include="$build/config.h" \
                --inline-suppr --check-level=exhaustive --suppress=missingIncludeSystem \
                --file-filter='*pcap_fake*' --xml --xml-version=2 --output-file=cppcheck-reader.xml
            cat cppcheck.xml cppcheck-reader.xml
            # Keep all advisory diagnostics, but gate on actual error severity.
            if grep -q 'severity="error"' cppcheck.xml cppcheck-reader.xml; then exit 1; fi
        fi
        ;;
    distcheck)
        make -j"$jobs" all
        make distcheck
        ;;
    windows)
        make -j"$jobs" all
        exe=src/tcpflow.exe
        file "$exe" | grep -q 'PE32+ executable'
        x86_64-w64-mingw32-objdump -p "$exe" | sed -n 's/^[[:space:]]*DLL Name: //p' | sort -u > dll-imports.txt
        test -s dll-imports.txt
        if grep -Eiv '^(ADVAPI32|BCRYPT|CRYPT32|DBGHELP|GDI32|KERNEL32|msvcrt|PSAPI|SHELL32|USER32|USERENV|WS2_32|ucrtbase|api-ms-win-crt-[a-z0-9-]+)\.dll$' dll-imports.txt; then
            echo 'Windows binary requires a DLL outside the system allowlist' >&2
            exit 1
        fi
        mkdir -p "$source_root/dist"
        cp "$exe" "$source_root/dist/tcpflow64.exe"
        ;;
    codeql-build) make -j"$jobs" all;;
    *)
        make -j"$jobs" all
        # The historical shell regressions share output names; keep them serial.
        make -j1 check || { cat src/test-suite.log tests/test-suite.log 2>/dev/null; exit 1; }
        if [[ "$mode" = coverage ]]; then
            lcov --capture --directory . --output-file coverage.info
            lcov --remove coverage.info '/usr/*' --output-file coverage.filtered.info
            lcov --list coverage.filtered.info
        fi
        ;;
esac
