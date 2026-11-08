#!/usr/bin/env bash
# Validate tcpflow release identity and the exact final asset set.
# Preflight binds an annotated version tag to one commit already on main.
# Assembly accepts only tested source, signed Windows and architecture Snaps.
# Checksums are generated after signing and verified before publication.
# This helper never pushes tags, grants access or publishes a release itself.
set -euo pipefail
mode=${1:?mode required}
tag=${2:?release tag required}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected vMAJOR.MINOR.PATCH tag' >&2; exit 2; }
version=${tag#v}
case "$mode" in
    preflight)
        commit=${3:?immutable commit required}
        [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo 'Expected full immutable commit SHA' >&2; exit 2; }
        test "$(git cat-file -t "refs/tags/$tag")" = tag
        test "$(git rev-parse "refs/tags/$tag^{commit}")" = "$commit"
        test "$(git rev-parse HEAD)" = "$commit"
        git diff --quiet
        git diff --cached --quiet
        git merge-base --is-ancestor "$commit" refs/remotes/origin/main
        actual=$(sed -n 's/^AC_INIT(TCPFLOW, \([^,]*\),.*/\1/p' configure.ac)
        test "$actual" = "$version"
        grep -Fxq "project(tcpflow VERSION $version LANGUAGES CXX C)" CMakeLists.txt
        printf 'commit=%s\nversion=%s\n' "$commit" "$version"
        ;;
    assets)
        directory=${3:?asset directory required}
        cd "$directory"
        expected=("tcpflow-$version.tar.gz" tcpflow64.exe "tcpflow_${version}_amd64.snap" "tcpflow_${version}_arm64.snap")
        for asset in "${expected[@]}"; do test -s "$asset"; done
        # Refuse accidental logs, unsigned candidates or a second architecture.
        shopt -s nullglob dotglob
        files=(*)
        test "${#files[@]}" -eq 4
        tar -tzf "${expected[0]}" > archive-contents.txt
        grep -Fxq "tcpflow-$version/configure" archive-contents.txt
        rm archive-contents.txt
        sha256sum "${expected[@]}" > SHA256SUMS
        sha256sum -c SHA256SUMS
        ;;
    *) echo "Unknown release mode: $mode" >&2; exit 2;;
esac
