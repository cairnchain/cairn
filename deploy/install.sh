#!/bin/sh
#
# Installs a Cairn seed node on a Debian or Ubuntu server.
#
# Run it as root on a machine that has nothing else of yours on it:
#
#     curl -fsSL <this file> -o install.sh
#     less install.sh          # read it before running it, always
#     sh install.sh
#
# It builds from source rather than fetching a binary, so what runs is what
# you can read. That takes a few minutes and a little memory; see the note
# about swap below if the build is killed partway.
#
# A seed node mines nothing and holds no key. If this machine were taken
# tomorrow, there would be nothing on it to steal.

set -eu

NETWORK="${NETWORK:-testnet-2}"
PORT="${PORT:-9944}"
SEED="${SEED:-}"
REPO="${REPO:-https://github.com/cairnchain/cairn}"
SRC="/usr/local/src/cairn"
DATA="/var/lib/cairn"

say() { printf '\n== %s\n' "$1"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "run this as root" >&2
    exit 1
fi

say "Packages"
apt-get update -qq
apt-get install -y -qq git curl build-essential pkg-config

say "Rust"
if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain 1.89.0
fi
# rustup installs for the invoking user; make it findable for this script.
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

say "Source"
before=none
if [ -d "$SRC/.git" ]; then
    before=$(git -C "$SRC" rev-parse HEAD)
    branch=$(git -C "$SRC" symbolic-ref --short HEAD 2>/dev/null || echo main)
    git -C "$SRC" fetch --quiet origin
    git -C "$SRC" reset --hard --quiet "origin/$branch"
else
    rm -rf "$SRC"
    git clone --quiet "$REPO" "$SRC"
fi
after=$(git -C "$SRC" rev-parse HEAD)
echo "at $(git -C "$SRC" rev-parse --short HEAD) $(git -C "$SRC" log -1 --format=%cd --date=short)"

# A shell reads its script as it goes, so the update just fetched is not the
# one running: this script has already been read from the file it overwrote.
# If the installer itself moved, hand over to the new one rather than carry on
# with instructions that are now out of date.
if [ "${CAIRN_INSTALLER_REEXEC:-}" != "1" ] && [ "$before" != "none" ] &&
   [ "$before" != "$after" ] &&
   ! git -C "$SRC" diff --quiet "$before" "$after" -- deploy/install.sh; then
    echo "the installer changed; running the new one"
    CAIRN_INSTALLER_REEXEC=1
    export CAIRN_INSTALLER_REEXEC
    exec sh "$SRC/deploy/install.sh"
fi

say "Build"
# Nothing to do here when only the deployment files moved, which is why this
# step can finish in a fraction of a second and still be correct.
# A small server can run out of memory linking with optimisation on. If this
# step is killed, add swap and run the script again:
#
#     fallocate -l 2G /swapfile && chmod 600 /swapfile
#     mkswap /swapfile && swapon /swapfile
#
( cd "$SRC" && cargo build --release --bin cairnd )
install -m 0755 "$SRC/target/release/cairnd" /usr/local/bin/cairnd

say "User and directory"
if ! id cairn >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin cairn
fi
mkdir -p "$DATA"
chown cairn:cairn "$DATA"
chmod 0750 "$DATA"

say "Service"
UNIT=/etc/systemd/system/cairnd.service
cp "$SRC/deploy/cairnd.service" "$UNIT"

# The unit ships with the defaults; rewrite the line if this run asked for
# something else, so every server ends up with a unit that says what it does.
if [ "$NETWORK" != "testnet-2" ] || [ "$PORT" != "9944" ] || [ -n "$SEED" ]; then
    ARGS="--network $NETWORK --data $DATA --listen 0.0.0.0:$PORT --status 60"
    for peer in $SEED; do
        ARGS="$ARGS --seed $peer"
    done
    # Collapse the shipped multi-line ExecStart into one line with our
    # arguments, leaving every hardening directive untouched.
    awk -v args="$ARGS" '
        /^ExecStart=/ { print "ExecStart=/usr/local/bin/cairnd " args; skip = 1; next }
        skip && /\\$/ { next }
        skip { skip = 0; next }
        { print }
    ' "$SRC/deploy/cairnd.service" > "$UNIT"
fi

systemctl daemon-reload
systemctl enable cairnd
# restart rather than start: on an update the service is already running, and
# `enable --now` would leave the old binary in place while reporting success.
# An operator would then believe a fix was applied when it was not.
systemctl restart cairnd

say "Firewall"
if command -v ufw >/dev/null 2>&1; then
    ufw allow "$PORT"/tcp >/dev/null
    echo "opened $PORT/tcp"
else
    echo "no ufw here; open $PORT/tcp however this machine does it"
fi

say "Done"
# What is actually running, so an update can be told from a no-op.
echo "commit   $(git -C "$SRC" rev-parse --short HEAD)"
echo "started  $(systemctl show -p ActiveEnterTimestamp --value cairnd)"
systemctl --no-pager --lines=6 status cairnd || true
cat <<NOTE

The node is running and will come back on its own after a reboot or a crash.

  what it is doing     journalctl -u cairnd -f
  stop it              systemctl stop cairnd
  start it again       systemctl start cairnd
  update it            sh install.sh

Publish this machine as <its public address>:$PORT so others can start from
it. Nothing else about it needs to be public, and nothing on it is worth
stealing: a seed node mines nothing and holds no key.
NOTE
