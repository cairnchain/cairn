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
#     sudo env DOMAIN=cairnchain.org sh explorer.sh
#
# DOMAIN is what the certificate is issued for, and it has to already point at
# this machine. Without one, on a first run, the site is served over plain
# HTTP, which is fine to look at and wrong to publish: a page saying who owns
# what must not be alterable by anything between here and the reader.
#
# The same command updates the machine later, and takes no settings with it.
# One this run does not name is read back off the machine, the domain
# included, so an update keeps the certificate the site already has. Naming a
# setting changes it. Naming it empty puts it back to the default it ships
# with. Everything else on the unit's command line, such as `--keep`, is
# carried as it stands.

set -eu

REPO="${REPO:-https://github.com/cairnchain/cairn}"
SRC="/usr/local/src/cairn"
DATA="/var/lib/cairn-explorer"
UNIT=/etc/systemd/system/cairn-explorer.service
CADDYFILE=/etc/caddy/Caddyfile
BIN=/usr/local/bin/cairn-explorer

say() { printf '\n== %s\n' "$1"; }

# What is already on this machine is the only record of what it was told to
# do, so a setting this run does not name is read back out of it rather than
# reset to the default. A re-run that says nothing changes nothing, which
# matters most for DOMAIN: dropping it takes the certificate off a published
# site and leaves it answering in plain HTTP.
#
# An unset variable and an empty one are different things here. Unset says
# nothing about a setting. Empty says put it back to the default.

# A unit's ExecStart as one line: this script writes one line, and the file it
# ships with wraps the same command across several.
unit_line() {
    awk '/^ExecStart=/ {
        line = $0
        while (sub(/\\$/, "", line)) { getline more; line = line " " more }
        print line
        exit
    }' "$1"
}

# One argument out of the installed line, or all of them where it repeats, as
# --seed does.
carried() {
    found=""
    take=""
    for word in $INSTALLED; do
        if [ -n "$take" ]; then
            found="$found $word"
            take=""
        elif [ "$word" = "--$1" ]; then
            take=1
        fi
    done
    echo "${found# }"
}

# Every other argument of the installed line, as it stands and in its order,
# for the reason `install.sh` gives beside the same lines: an update that
# rebuilt the line from its own settings dropped a `--keep` or anything else
# an operator had added by hand, and said only what it had kept.
the_rest() {
    rest=""
    program=1
    skip=""
    for word in $INSTALLED; do
        if [ -n "$program" ]; then
            program=""
        elif [ -n "$skip" ]; then
            skip=""
        else
            case "$word" in
                --network | --data | --listen | --http | --seed) skip=1 ;;
                *) rest="$rest $word" ;;
            esac
        fi
    done
    echo "${rest# }"
}

# The domain is not in the unit; the Caddyfile is where it is written down.
# The first site block is the one this script wrote, and :80 is what it writes
# when there is no domain, which is to say no domain carried.
carried_domain() {
    [ -f "$CADDYFILE" ] || return 0
    site=$(sed -n 's/^\([^ #][^ ]*\) {$/\1/p' "$CADDYFILE" | head -n 1)
    if [ "$site" != ":80" ]; then
        echo "$site"
    fi
}

# Named by this run, else carried, else the default. It assigns rather than
# prints, because KEPT has to outlive the call and a command substitution is
# a subshell.
KEPT=""
resolve() {
    eval "named=\${$1+named}; passed=\${$1-}"
    if [ -n "$named" ]; then
        value="${passed:-$3}"
    elif [ -n "$2" ]; then
        value="$2"
        KEPT="$KEPT $1"
    else
        value="$3"
    fi
    eval "$1=\$value"
}

# What this run will write, settled from what it was told and what the
# installed line says.
the_settings() {
    listen=$(carried listen)
    # A first guess only. Whatever this sets is put to `cairn-explorer
    # --check` below and replaced by the name the build gives if it is
    # refused, so a retired name here costs a line of output and nothing
    # else. It is not asked from the build at this point because the build
    # is not built yet.
    resolve NETWORK "$(carried network)" testnet-6
    resolve PORT "${listen##*:}" 9945
    resolve HTTP "$(carried http)" 127.0.0.1:8080
    resolve SEED "$(carried seed)" ""
    resolve DOMAIN "$(carried_domain)" ""
    # Not settings this script is told. The directory and the address to
    # listen on are whatever the installed line says, and the defaults on a
    # first install.
    data=$(carried data)
    DATADIR=${data%% *}
    DATADIR=${DATADIR:-$DATA}
    ADDRESS=${listen%:*}
    ADDRESS=${ADDRESS:-0.0.0.0}
    REST=$(the_rest)
}

# The line this machine will run: what this run settled, and everything else
# the installed line carried.
the_line() {
    line="--network $NETWORK --data $DATADIR --listen $ADDRESS:$PORT --http $HTTP"
    if [ -n "$REST" ]; then
        line="$line $REST"
    fi
    for peer in $SEED; do
        line="$line --seed $peer"
    done
    echo "$line"
}

# The shipped unit with this machine's line in it, collapsed from the several
# lines it ships on into one, and with the directory that line names as the
# one place the explorer may write. Every other directive is left as it ships.
write_unit() {
    awk -v bin="$BIN" -v args="$ARGS" -v data="$DATADIR" '
        /^ExecStart=/ { print "ExecStart=" bin " " args; skip = /\\$/; next }
        skip { skip = /\\$/; next }
        /^ReadWritePaths=/ { print "ReadWritePaths=" data; next }
        { print }
    ' "$1"
}

# What a build calls a network, or nothing where it does not know the name.
name_of() {
    (cd / && "$1" --check --network "$2" 2>/dev/null) | awk '/^network/ {print $2; exit}'
}

# A test network gets retired when a rule has to change, and its name stays
# written in the unit file of every machine that was running it. Carrying a
# setting forward is right until the build stops accepting it, and then it is
# a service that will not start. The explorer itself is asked, since it is the
# only thing that knows which names this build has.
settle_the_network() {
    if (cd / && "$1" --check --network "$NETWORK") >/dev/null 2>&1; then
        return 0
    fi
    # Asked, not written down, for the reason `install.sh` carries beside the
    # same lines: the day testnet-6 is retired, a rescue that hands back
    # `testnet-6` hands back a retired network, which is what the check above
    # exists to catch. The build says which name is current on the first line
    # of `--check`.
    fallback=$( (cd / && "$1" --check 2>/dev/null) | awk '/^network/ {print $2; exit}')
    if [ -z "$fallback" ]; then
        echo "network  $NETWORK is not a network this build knows, and this build" >&2
        echo "         would not say which one is. Nothing is installed." >&2
        exit 1
    fi
    echo "network  $NETWORK is not a network this build knows, so $fallback is used"
    echo "         instead. Name one explicitly to choose another."
    NETWORK=$fallback
}

# The whole line, put to the build before anything on this machine changes,
# for the reason `install.sh` gives: a PORT or a SEED the explorer refuses
# installed a service that restarted five times and stopped.
check_the_line() {
    # Unquoted on purpose: this is a list of arguments and not one argument.
    # shellcheck disable=SC2086
    if ! "$1" --check $ARGS >/dev/null 2>&1; then
        echo "cairn-explorer refuses the line this would install, so nothing is" >&2
        echo "installed:" >&2
        echo "  $ARGS" >&2
        # shellcheck disable=SC2086
        "$1" --check $ARGS >&2 || true
        exit 1
    fi
}

# Moves the chain and the index of a network this machine is leaving out of the
# way of the one it is joining, and keeps them, for the reason `install.sh`
# gives beside the same lines.
set_aside() {
    if [ ! -d "$1" ] || [ -z "$(ls -A "$1")" ]; then
        return 0
    fi
    kept="$1.$2"
    if [ -e "$kept" ]; then
        kept="$kept.$(date +%Y%m%d%H%M%S)"
    fi
    systemctl stop cairn-explorer 2>/dev/null || true
    if ! mv "$1" "$kept"; then
        systemctl start cairn-explorer 2>/dev/null || true
        echo "data     $1 holds $2's chain and this machine is moving to $3, and it" >&2
        echo "         could not be moved aside to $kept. Nothing else is changed;" >&2
        echo "         move or empty it yourself and run this again." >&2
        exit 1
    fi
    mkdir -p "$1"
    echo "data     $2's chain is kept in $kept: an explorer on $3 starts from nothing"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "run this as root" >&2
    echo "with sudo, pass the settings through env, since sudo clears them:" >&2
    echo "  sudo env DOMAIN=... SEED=... sh $0" >&2
    exit 1
fi

INSTALLED=""
if [ -f "$UNIT" ]; then
    INSTALLED=$(unit_line "$UNIT")
fi

# What the loops above cannot carry faithfully: quoting, which would split a
# word differently from systemd, a variable or specifier systemd would expand,
# or a pattern the shell would.
case "$INSTALLED" in
    *\"* | *\'* | *\\* | *\$* | *%* | *\** | *\?* | *\[*)
        echo "the installed unit's command line has something this script cannot" >&2
        echo "carry as it stands:" >&2
        echo "  $INSTALLED" >&2
        echo "write it without quotes, variables or patterns, and run this again." >&2
        exit 1
        ;;
esac

the_settings

# The network the directory holds, in the words of the build that is running
# it, asked before that build is replaced, for the reason `install.sh` gives.
WAS=""
named=$(carried network)
named=${named%% *}
if [ -n "$named" ]; then
    if [ -x "$BIN" ]; then
        WAS=$(name_of "$BIN" "$named")
    fi
    WAS=${WAS:-$named}
fi

case "$DATADIR" in
    /*) ;;
    *)
        echo "the installed unit keeps its chain in $DATADIR, which is not a full" >&2
        echo "path; write it as one and run this again." >&2
        exit 1
        ;;
esac

echo "network  $NETWORK"
echo "listen   $ADDRESS:$PORT"
echo "data     $DATADIR"
echo "http     $HTTP"
echo "seeds    ${SEED:-none}"
if [ -n "$DOMAIN" ]; then
    echo "domain   $DOMAIN, with a certificate"
else
    echo "domain   none, so plain HTTP on port 80"
fi
if [ -n "$KEPT" ]; then
    echo "kept     ${KEPT# }, which this run did not name"
fi
if [ -n "$REST" ]; then
    echo "carried  $REST, as the installed unit had it"
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
# --locked so a seed node is built from the dependency versions in Cargo.lock,
# the same ones the checks ran against. release.yml already says this about the
# binaries it publishes; the machines that build from source were resolving
# whatever cargo decided at the time.
( cd "$SRC" && cargo build --release --locked --bin cairn-explorer )
BUILT="$SRC/target/release/cairn-explorer"

say "Service"
# Everything the new build is asked, it is asked here, before it is installed
# and before anything the running explorer depends on is touched: a refusal
# below leaves this machine exactly as it was.
settle_the_network "$BUILT"
NOW=$(name_of "$BUILT" "$NETWORK")
ARGS=$(the_line)
check_the_line "$BUILT"

# The same unprivileged user a node runs as, since neither holds anything.
if ! id cairn >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin cairn
fi
if [ -n "$WAS" ] && [ "$WAS" != "$NOW" ]; then
    set_aside "$DATADIR" "$WAS" "$NOW"
fi
mkdir -p "$DATADIR"
chown cairn:cairn "$DATADIR"
chmod 0750 "$DATADIR"

install -m 0755 "$BUILT" "$BIN"
write_unit "$SRC/deploy/cairn-explorer.service" > "$UNIT"
systemctl daemon-reload
systemctl enable cairn-explorer
# A unit that failed its last five starts is refused a sixth until its
# interval has passed, a start asked for by hand included. This is the run
# that has just mended whatever failed, so the count is cleared first.
systemctl reset-failed cairn-explorer 2>/dev/null || true
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

WWW=""
if [ -n "$DOMAIN" ]; then
    SITE="$DOMAIN"
    # An apex like cairnchain.org gets www.cairnchain.org pointed back at it,
    # because people type it. A name that is already a subdomain does not.
    if [ "$(echo "$DOMAIN" | tr -cd '.' | wc -c)" -eq 1 ]; then
        WWW="www.$DOMAIN"
    fi
else
    SITE=":80"
fi

cat > "$CADDYFILE" <<CADDY
# Written by explorer.sh. The explorer serves plain HTTP on loopback; this
# holds the certificate and is the only thing listening on the outside.

# Caddy waits forever for a request head by default, on the reasoning that a
# slow caller may be an honest one on a bad line. That is the right default
# for a general server and the wrong one here: the explorer behind this
# answers every reader from an index already in memory, so a head that has
# taken ten seconds to arrive is not a slow reader, and a few dozen of them
# are how a public site is taken down from a laptop. The explorer enforces the
# same bound on its own side for a node published without anything in front of
# it; this is the half that applies to cairnchain.org.
{
    servers {
        timeouts {
            read_header 10s
            read_body 30s
            idle 2m
        }
    }
}

$SITE {
    reverse_proxy $HTTP

    # The site loads nothing from anywhere else, so nothing else is allowed.
    # Said here rather than only in a comment: a page that fetched a script
    # from somewhere could be made to show a balance that is not the chain's,
    # and the reader would have no way to tell. The one exception is the
    # favicon, which is drawn inline as a data URI rather than fetched.
    header {
        Content-Security-Policy "default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options nosniff
        Referrer-Policy no-referrer
        -Server
    }
}
CADDY

# One address for the site. A second name that answers the same pages is a
# second thing to keep a certificate for and a second address for a link to
# be written with, so it redirects rather than serves.
if [ -n "$WWW" ]; then
    cat >> "$CADDYFILE" <<CADDY

$WWW {
    redir https://$DOMAIN{uri} permanent
}
CADDY
fi

# A bad config here takes the public site off the air, and the restart is
# where that would happen. Checked first, so a mistake in this file leaves the
# server that is already running exactly where it was.
if command -v caddy >/dev/null 2>&1 && ! caddy validate --config "$CADDYFILE" >/dev/null 2>&1; then
    echo "the Caddyfile this script wrote does not validate, so caddy was not" >&2
    echo "restarted and the site is still being served as it was:" >&2
    caddy validate --config "$CADDYFILE" >&2
    exit 1
fi
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
# An explorer that cannot start stops within a second or two, and what follows
# spoke of a site being served whether or not it was.
sleep 3
running=""
if systemctl is-active --quiet cairn-explorer; then
    running=1
fi
systemctl --no-pager --lines=5 status cairn-explorer || true
if [ -z "$running" ]; then
    cat <<NOTE

The explorer is not running. What it said as it stopped is above, and all of
it is in the journal:

  what it said         journalctl -u cairn-explorer -n 50
NOTE
    exit 1
fi
echo
if [ -n "$DOMAIN" ]; then
    echo "The site is at https://$DOMAIN/ once the certificate is issued,"
    echo "which takes a few seconds the first time. Watch it with:"
    echo "  journalctl -u caddy -f"
    if [ -n "$WWW" ]; then
        echo "https://$WWW/ redirects to it."
    fi
else
    echo "The site is at http://<this machine>/ over plain HTTP."
    echo "Name a domain and run this again to put a certificate in front of it."
fi
cat <<NOTE

  what it is doing     journalctl -u cairn-explorer -f
  update it            sh explorer.sh

The update line takes no settings: this machine keeps the ones it already
has, the domain among them, and every other argument on the unit's command
line. Naming one changes it, and naming it empty puts it back to the default,
which is the only way a setting goes back on its own:

  change the domain    sudo env DOMAIN=example.org sh explorer.sh
  back to plain HTTP   sudo env DOMAIN= sh explorer.sh
NOTE
