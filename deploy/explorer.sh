#!/bin/sh
#
# Puts the Cairn explorer on a public address, behind a certificate.
#
# The explorer is a node that also serves the website: the chain in public,
# and an explanation of it written for readers who know nothing, something, or
# everything. It holds no key, mines nothing, and reads the chain like any
# other node.
#
# Run it as root, after install.sh has run on the same machine:
#
#     sudo env DOMAIN=explorer.example.org sh explorer.sh
#
# DOMAIN is what the certificate is issued for, and it has to already point at
# this machine. Without one the site is served over plain HTTP, which is fine
# to look at and wrong to publish: a page saying who owns what must not be
# alterable by anything between here and the reader.

set -eu

NETWORK="${NETWORK:-testnet-3}"
PORT="${PORT:-9945}"
HTTP="${HTTP:-127.0.0.1:8080}"
SEED="${SEED:-}"
DOMAIN="${DOMAIN:-}"
REPO="${REPO:-https://github.com/cairnchain/cairn}"
SRC="/usr/local/src/cairn"
DATA="/var/lib/cairn-explorer"

say() { printf '\n== %s\n' "$1"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "run this as root" >&2
    echo "with sudo, pass the settings through env, since sudo clears them:" >&2
    echo "  sudo env DOMAIN=... SEED=... sh $0" >&2
    exit 1
fi

echo "network  $NETWORK"
echo "seeds    ${SEED:-none}"
if [ -n "$DOMAIN" ]; then
    echo "domain   $DOMAIN, with a certificate"
else
    echo "domain   none, so plain HTTP on port 80"
fi

say "Source"
if [ -d "$SRC/.git" ]; then
    branch=$(git -C "$SRC" symbolic-ref --short HEAD 2>/dev/null || echo main)
    git -C "$SRC" fetch --quiet origin
    git -C "$SRC" reset --hard --quiet "origin/$branch"
else
    rm -rf "$SRC"
    git clone --quiet "$REPO" "$SRC"
fi
echo "at $(git -C "$SRC" rev-parse --short HEAD)"

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

say "Build"
( cd "$SRC" && cargo build --release --bin cairn-explorer )
install -m 0755 "$SRC/target/release/cairn-explorer" /usr/local/bin/cairn-explorer

say "User and directory"
# The same unprivileged user a node runs as, since neither holds anything.
if ! id cairn >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin cairn
fi
mkdir -p "$DATA"
chown cairn:cairn "$DATA"
chmod 0750 "$DATA"

say "Service"
UNIT=/etc/systemd/system/cairn-explorer.service
if [ "$NETWORK" != "testnet-3" ] || [ "$PORT" != "9945" ] ||
   [ "$HTTP" != "127.0.0.1:8080" ] || [ -n "$SEED" ]; then
    ARGS="--network $NETWORK --data $DATA --listen 0.0.0.0:$PORT --http $HTTP"
    for peer in $SEED; do
        ARGS="$ARGS --seed $peer"
    done
    awk -v args="$ARGS" '
        /^ExecStart=/ { print "ExecStart=/usr/local/bin/cairn-explorer " args; skip = 1; next }
        skip && /\\$/ { next }
        skip { skip = 0; next }
        { print }
    ' "$SRC/deploy/cairn-explorer.service" > "$UNIT"
else
    cp "$SRC/deploy/cairn-explorer.service" "$UNIT"
fi
systemctl daemon-reload
systemctl enable cairn-explorer
systemctl restart cairn-explorer

say "Certificate and proxy"
# Caddy rather than a certificate managed by hand: it asks for one, renews it,
# and redirects HTTP to HTTPS, none of which is worth writing again here. The
# explorer itself speaks no TLS and never will; serving a website is not what
# the protocol is for, and one program that does one thing is easier to read.
if ! command -v caddy >/dev/null 2>&1; then
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl || true
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" \
        > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
fi

if [ -n "$DOMAIN" ]; then
    SITE="$DOMAIN"
else
    SITE=":80"
fi

cat > /etc/caddy/Caddyfile <<CADDY
# Written by explorer.sh. The explorer serves plain HTTP on loopback; this
# holds the certificate and is the only thing listening on the outside.
$SITE {
    reverse_proxy $HTTP

    # The site loads nothing from anywhere else, so nothing else is allowed.
    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options nosniff
        Referrer-Policy no-referrer
        -Server
    }
}
CADDY

systemctl restart caddy

say "Firewall"
if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
    ufw allow "$PORT"/tcp >/dev/null
    echo "opened 80/tcp, 443/tcp, $PORT/tcp"
else
    echo "no ufw here; open 80, 443 and $PORT however this machine does it"
fi

say "Done"
grep '^ExecStart=' "$UNIT"
systemctl --no-pager --lines=5 status cairn-explorer || true
if [ -n "$DOMAIN" ]; then
    echo
    echo "The site is at https://$DOMAIN/ once the certificate is issued,"
    echo "which takes a few seconds the first time. Watch it with:"
    echo "  journalctl -u caddy -f"
else
    echo
    echo "The site is at http://<this machine>/ over plain HTTP."
    echo "Set DOMAIN and run this again to put a certificate in front of it."
fi
