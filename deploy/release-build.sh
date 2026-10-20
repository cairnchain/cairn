#!/usr/bin/env bash
# Builds one release archive, the way the release does and the way anyone
# checking a release does: `.github/workflows/build.yml` runs this for every
# archive it publishes, and `deploy/rebuild.sh` runs it to make the same
# archive again from a tag.
#
#   deploy/release-build.sh <archive name> <version> <directory to write to>
#
# The archive name is one of the five a release publishes, without its
# extension: linux-x86_64, linux-arm64, macos-apple-silicon, macos-intel,
# windows-x86_64.
#
# The point is that the same commit gives the same bytes, on any machine, so
# that a published binary can be checked against the source rather than
# taken on GitHub's word. Each thing below is here because two builds of one
# commit differed without it, or because it is a path or a time that differs
# from one machine to the next and would end up inside the archive.
#
# The Linux archives are built inside one container image named by its digest
# rather than its tag, so the compiler, the linker, the C compiler and its
# libraries, tar and gzip are the same bytes on every machine that builds
# them, now and years from now. That is what makes them reproducible anywhere
# Docker runs. macOS and Windows have no such image: their linkers and system
# libraries come with the machine, so those archives are as deterministic as
# this file can make them, and no more (deploy/README.md says which match).

set -euo pipefail

# rust:1.89.0-slim-bookworm, the index digest, which covers both the amd64 and
# the arm64 image. It has to carry the toolchain `rust-toolchain.toml` pins,
# and the build stops below if it does not, so moving the toolchain moves this
# line in the same change.
BUILDER=docker.io/library/rust:1.89.0-slim-bookworm@sha256:d7fc7de78bb8c1469933aeecbf801314d30d7d6e9f0578bba4cfa285bfa37fe6

# The musl C library and the wrapper that compiles against it, which `blake3`
# needs for its assembly and C. Named to the version, so a Debian update can
# never change what goes into a binary without this line changing. Debian
# keeps only the newest version of a package in its archive, so when the
# version named here has gone from it, the packages are taken from Debian's
# snapshot of the day the image was made, which keeps every version for good.
MUSL_PACKAGES="musl=1.2.3-1 musl-dev=1.2.3-1 musl-tools=1.2.3-1"
DEBIAN_SNAPSHOT=20250908T000000Z

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <archive name> <version> <directory to write to>" >&2
  exit 2
fi
name=$1
version=$2
out=$3

case "$name" in
  linux-x86_64) target=x86_64-unknown-linux-musl platform=linux/amd64 ;;
  linux-arm64) target=aarch64-unknown-linux-musl platform=linux/arm64 ;;
  macos-apple-silicon) target=aarch64-apple-darwin ;;
  macos-intel) target=x86_64-apple-darwin ;;
  windows-x86_64) target=x86_64-pc-windows-msvc ;;
  *)
    echo "no release archive is called $name" >&2
    exit 2
    ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$root"

# The time every file in the archive is dated, and what a C compiler is told
# the date is: the release commit's, so it is the same on every machine and
# on every day the commit is built again.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct HEAD)
fi
export SOURCE_DATE_EPOCH

case "$target" in
  *linux*)
    if [ -z "${CAIRN_IN_BUILDER:-}" ]; then
      # The checkout is read only inside, and the build goes to a directory of
      # the container's own, so nothing left over from an earlier build on
      # this machine can end up in this one. The files written back are given
      # to whoever ran this, not to the container's root.
      exec docker run --rm --platform "$platform" \
        -e CAIRN_IN_BUILDER=1 \
        -e SOURCE_DATE_EPOCH \
        -e "OWNER=$(id -u):$(id -g)" \
        -v "$root:/cairn:ro" \
        -v "$out:/out" \
        -w /cairn \
        "$BUILDER" \
        bash deploy/release-build.sh "$name" "$version" /out
    fi
    export CARGO_TARGET_DIR=/build
    export DEBIAN_FRONTEND=noninteractive
    # shellcheck disable=SC2086
    if ! { apt-get update -qq && apt-get install -y -qq --no-install-recommends $MUSL_PACKAGES; } >/dev/null; then
      echo "$MUSL_PACKAGES are no longer in Debian's archive; taking them from its snapshot of $DEBIAN_SNAPSHOT"
      sed -i \
        -e "s|^URIs: http://deb.debian.org/debian\$|URIs: http://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT|" \
        -e "s|^URIs: http://deb.debian.org/debian-security\$|URIs: http://snapshot.debian.org/archive/debian-security/$DEBIAN_SNAPSHOT|" \
        /etc/apt/sources.list.d/debian.sources
      apt-get -o Acquire::Check-Valid-Until=false update -qq >/dev/null
      # shellcheck disable=SC2086
      apt-get install -y -qq --no-install-recommends $MUSL_PACKAGES >/dev/null
    fi
    ;;
esac

# The toolchain is the one `rust-toolchain.toml` names, to the patch version,
# and nothing else: a different compiler is a different binary.
pinned=$(awk -F'"' '/^channel[[:space:]]*=/{print $2; exit}' rust-toolchain.toml)
rustup show active-toolchain >/dev/null
running=$(rustc --version | awk '{print $2}')
if [ "$running" != "$pinned" ]; then
  echo "rust-toolchain.toml pins $pinned and this machine compiles with $running" >&2
  exit 1
fi
rustup target add "$target" >/dev/null

# Where the checkout, the downloaded crates and the toolchain sit is written
# into a program wherever it names a source file, which is every message a
# panic or a failed assertion prints. Those three paths differ from machine to
# machine, so each is written as a fixed name instead.
native() {
  # A Windows compiler is handed Windows paths, and only matches those.
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s' "$1"
  fi
}
cargo_home=${CARGO_HOME:-$HOME/.cargo}
sysroot=$(rustc --print sysroot)
flags=(
  "--remap-path-prefix=$(native "$cargo_home")=/cargo"
  "--remap-path-prefix=$(native "$sysroot")=/rustc"
  "--remap-path-prefix=$(native "$root")=/cairn"
)
# Microsoft's linker writes the time it ran into every program's header and a
# fresh identifier into the record that names its debug file. Those twenty
# bytes were all that differed between two builds of one commit. /Brepro has
# it write a hash of the program's contents in both places instead.
case "$target" in
  *windows-msvc) flags+=("-Clink-arg=/Brepro") ;;
esac
# Cargo splits this variable on one character no path contains, unlike
# RUSTFLAGS, which it splits on spaces.
CARGO_ENCODED_RUSTFLAGS=$(IFS=$'\x1f'; printf '%s' "${flags[*]}")
export CARGO_ENCODED_RUSTFLAGS

# --locked so the release is built from the dependency versions in Cargo.lock
# and not from whatever resolved newest this morning.
cargo build --release --locked --target "$target" \
  --bin cairnd --bin cairn-wallet --bin cairn-explorer

# The folder carries the version; the archive does not, so the link on the
# website never has to be edited again.
target_dir=${CARGO_TARGET_DIR:-target}
folder="cairn-${version}-${name}"
stage=$(mktemp -d)
mkdir "$stage/$folder"
suffix=""
case "$target" in
  *windows*) suffix=".exe" ;;
esac
for program in cairnd cairn-wallet cairn-explorer; do
  cp "$target_dir/$target/release/${program}${suffix}" "$stage/$folder/"
done
# Every file copied here from the repository is in the list of paths the
# release decision in release.yml compares, or a change to it is never
# released.
cp LICENSE-MIT LICENSE-APACHE "$stage/$folder/"
cp deploy/DOWNLOAD.txt "$stage/$folder/README.txt"
printf '%s\n' "$version" > "$stage/$folder/VERSION"

# An archive records, for every file, its name, its owner, its permissions and
# its date, in the order the disk hands them over. Each of those is whatever
# the machine happened to have, so each is set: the order sorted, the owner
# nobody's in particular, the permissions the ones a program and a document
# need, and the date the commit's.
chmod 0755 "$stage/$folder"
chmod 0755 "$stage/$folder"/cairnd* "$stage/$folder"/cairn-wallet* "$stage/$folder"/cairn-explorer*
chmod 0644 "$stage/$folder"/LICENSE-MIT "$stage/$folder"/LICENSE-APACHE "$stage/$folder/README.txt" "$stage/$folder/VERSION"
case "$target" in
  *windows*)
    archive="cairn-${name}.zip"
    python "$root/deploy/release-zip.py" "$stage" "$folder" "$out/$archive"
    ;;
  *)
    archive="cairn-${name}.tar.gz"
    # GNU tar, which is the one that can sort and fix every field. macOS ships
    # another one and has GNU's as `gtar`.
    tar=tar
    if command -v gtar >/dev/null 2>&1; then
      tar=gtar
    fi
    if ! "$tar" --version 2>/dev/null | grep -q 'GNU tar'; then
      echo "the archive needs GNU tar, which this machine does not have as tar or gtar" >&2
      exit 1
    fi
    # gzip -n so the archive's own name and date are not written into it.
    "$tar" --create --format=gnu --sort=name \
      --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -C "$stage" "$folder" | gzip -n > "$out/$archive"
    ;;
esac
rm -rf "$stage"

if [ -n "${OWNER:-}" ]; then
  chown "$OWNER" "$out/$archive"
fi
(cd "$out" && sha256sum "$archive" 2>/dev/null || shasum -a 256 "$archive")
