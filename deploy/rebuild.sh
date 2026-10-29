#!/usr/bin/env bash
# Builds a published release again from its tag and says whether the result is
# the file GitHub published, byte for byte.
#
#   deploy/rebuild.sh <version> [linux-x86_64 | linux-arm64 | all]
#
# For example `deploy/rebuild.sh 0.14.0`. It needs git, curl and Docker, and
# nothing of ours: no account, no key, no token. It checks out the tag into a
# directory of its own, builds the archive with that tag's own
# `deploy/release-build.sh` in the container the release was built in, and
# compares the result with the line for it in the release's SHA256SUMS.
#
# Without an archive named, it builds the one for this machine's processor,
# which is the quick one. Docker can build the other through emulation, much
# more slowly: `all` builds both.
#
# The attestation on a release is GitHub saying which commit and workflow made
# each file. This is the check that does not need GitHub to be telling the
# truth: if the bytes you build from the tag are the bytes published, the
# published program is that source, whoever built it.
#
# Linux archives only. macOS and Windows are not yet reproducible on another
# machine, and deploy/README.md says why.

set -euo pipefail

repository=${CAIRN_REPOSITORY:-https://github.com/cairnchain/cairn}

# What a run that matched has shown, and what it has not: the archives it
# rebuilt are known to be the source, and nothing else in SHA256SUMS is. It
# said a download whose hash is in SHA256SUMS was known to be the source,
# having rebuilt one Linux archive of five: a SHA256SUMS published beside a
# swapped macOS archive carries the right Linux line all the same.
what_was_checked() {
  local names=$1 work=$2 version=$3 name
  echo "Known now to be what v$version's source builds:"
  for name in $names; do
    echo "  cairn-$name.tar.gz"
  done
  echo "Every other archive in SHA256SUMS is not checked by this. For those, the"
  echo "check is the attestation:"
  echo "  gh attestation verify <the archive you downloaded> --repo cairnchain/cairn"
  echo "Copy SHA256SUMS out of $work into the folder you downloaded to:"
  echo "$work is a temporary directory, which this machine may clear."
  echo "Then, in that folder, check one of the archives above against it with:"
  for name in $names; do
    echo "  grep 'cairn-$name.tar.gz\$' SHA256SUMS | shasum -a 256 -c -"
  done
}

if [ "${1:-}" = "--say-what-was-checked" ]; then
  # For the test that holds the sentence above to what was rebuilt.
  what_was_checked "$2" "$3" "$4"
  exit 0
fi

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <version> [linux-x86_64 | linux-arm64 | all]" >&2
  exit 2
fi
version=${1#v}
which=${2:-}
if [ -z "$which" ]; then
  case "$(uname -m)" in
    aarch64 | arm64) which=linux-arm64 ;;
    *) which=linux-x86_64 ;;
  esac
fi
case "$which" in
  all) names="linux-x86_64 linux-arm64" ;;
  linux-x86_64 | linux-arm64) names=$which ;;
  *)
    echo "$which is not a Linux archive; this rebuilds linux-x86_64, linux-arm64 or all" >&2
    exit 2
    ;;
esac

for tool in git curl docker; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "this needs $tool, which is not installed" >&2
    exit 1
  fi
done

work=$(mktemp -d "${TMPDIR:-/tmp}/cairn-rebuild.XXXXXX")
echo "working in $work"

curl -fsSL -o "$work/SHA256SUMS" \
  "$repository/releases/download/v$version/SHA256SUMS"
git -c advice.detachedHead=false clone --quiet --depth 1 \
  --branch "v$version" "$repository" "$work/source"
if [ ! -f "$work/source/deploy/release-build.sh" ]; then
  echo "v$version was released before releases could be rebuilt, and its tag has no deploy/release-build.sh to build with" >&2
  exit 1
fi

# The date inside the archive is the tagged commit's, which is what the
# release used.
SOURCE_DATE_EPOCH=$(git -C "$work/source" log -1 --format=%ct HEAD)
export SOURCE_DATE_EPOCH

status=0
for name in $names; do
  archive="cairn-$name.tar.gz"
  bash "$work/source/deploy/release-build.sh" "$name" "$version" "$work/built"
  published=$(awk -v f="$archive" '$2 == f || $2 == "*" f {print $1}' "$work/SHA256SUMS")
  if command -v sha256sum >/dev/null 2>&1; then
    built=$(sha256sum "$work/built/$archive" | cut -d' ' -f1)
  else
    built=$(shasum -a 256 "$work/built/$archive" | cut -d' ' -f1)
  fi
  echo
  echo "$archive"
  echo "  published  ${published:-(not in SHA256SUMS)}"
  echo "  built      $built"
  if [ -n "$published" ] && [ "$published" = "$built" ]; then
    echo "  the same: the published archive is what v$version's source builds"
  else
    echo "  DIFFERENT: the published archive is not what this machine built from v$version"
    status=1
  fi
done

echo
echo "The archives built are in $work/built."
if [ "$status" -eq 0 ]; then
  what_was_checked "$names" "$work" "$version"
fi
exit "$status"
