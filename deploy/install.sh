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
# It needs no address to start from: the ones a node begins with are written
# into the program. SEED still works, and names a peer to try first.
#
# The same command updates the machine later, and takes no settings with it.
# One this run does not name is read back off the machine, so an update keeps
# the network, the port, the seeds and the mining address the node already
# had. Naming a setting changes it. Naming it empty puts it back to the
# default it ships with. Everything else on the unit's command line, such as
# `--keep all`, `--archive` or another `--data`, is carried as it stands.
#
# It builds from source rather than fetching a binary, so what runs is what
# you can read. That takes a few minutes and a little memory; see the note
# about swap below if the build is killed partway.
#
# A seed node holds no key. If this machine were taken tomorrow, there would be
# nothing on it to steal. It can still be asked to mine, with MINE set to a
# public key: what a miner needs is the address rewards are paid to, never the
# key that spends them.

set -eu

REPO="${REPO:-https://github.com/cairnchain/cairn}"
SRC="/usr/local/src/cairn"
DATA="/var/lib/cairn"
UNIT=/etc/systemd/system/cairnd.service
BIN=/usr/local/bin/cairnd

say() { printf '\n== %s\n' "$1"; }

# The installed unit is the only record of what this machine was told to do:
# NETWORK, PORT, SEED and MINE are written down nowhere else. So a setting
# this run does not name is read back out of it rather than reset to the
# default. An update that says nothing changes nothing, which is what makes
# the update line printed at the end safe to follow.
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

# Every other argument of the installed line, as it stands and in its order.
#
# This script used to write the line from the four settings it carries and
# nothing else, so an update dropped whatever an operator had added by hand
# and said only what it had kept. `--keep all` went back to a gigabyte and the
# next round of upkeep deleted the blocks it had been keeping, `--data` went
# back to /var/lib/cairn and started a chain from nothing beside the one the
# node had, `--listen` opened on every interface, and `--archive` stopped.
# Only what the line is rebuilt from is left out here: the four settings, the
# address `--listen` names, and the directory `--data` names.
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
                --network | --data | --listen | --seed | --mine) skip=1 ;;
                *) rest="$rest $word" ;;
            esac
        fi
    done
    echo "${rest# }"
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
    # A first guess only. Whatever this sets is put to `cairnd --check`
    # below and replaced by the name the build gives if it is refused, so a
    # retired name here costs a line of output and nothing else. It is not
    # asked from the build at this point because the build is not built
    # yet.
    resolve NETWORK "$(carried network)" testnet-6
    resolve PORT "${listen##*:}" 9944
    resolve SEED "$(carried seed)" ""
    # A public key to pay block rewards to. Mining needs the address money
    # goes to and nothing else: the key that spends it never leaves the
    # machine that holds it, so this stays true even here, where nothing
    # worth stealing may sit.
    resolve MINE "$(carried mine)" ""
    # Not settings this script is told. The directory and the address to
    # listen on are whatever the installed line says, and the defaults on a
    # first install.
    data=$(carried data)
    DATADIR=${data%% *}
    DATADIR=${DATADIR:-$DATA}
    ADDRESS=${listen%:*}
    ADDRESS=${ADDRESS:-0.0.0.0}
    if [ -n "$INSTALLED" ]; then
        REST=$(the_rest)
    else
        REST="--status 60"
    fi
}

# The line this machine will run: what this run settled, and everything else
# the installed line carried.
the_line() {
    line="--network $NETWORK --data $DATADIR --listen $ADDRESS:$PORT"
    if [ -n "$REST" ]; then
        line="$line $REST"
    fi
    for peer in $SEED; do
        line="$line --seed $peer"
    done
    if [ -n "$MINE" ]; then
        line="$line --mine $MINE"
    fi
    echo "$line"
}

# The shipped unit with this machine's line in it, collapsed from the several
# lines it ships on into one, and with the directory that line names as the
# one place the node may write. Every other directive is left as it ships.
write_unit() {
    awk -v bin="$BIN" -v args="$ARGS" -v data="$DATADIR" '
        /^ExecStart=/ { print "ExecStart=" bin " " args; skip = /\\$/; next }
        skip { skip = /\\$/; next }
        /^ReadWritePaths=/ { print "ReadWritePaths=" data; next }
        { print }
    ' "$1"
}

# What a build calls a network, or nothing where it does not know the name.
# Asked from the root directory, so that a cairn-data/cairn.conf wherever this
# script was started from cannot answer for the name.
name_of() {
    (cd / && "$1" --check --network "$2" 2>/dev/null) | awk '/^network/ {print $2; exit}'
}

# A test network gets retired when a rule has to change, and its name stays
# written in the unit file of every machine that was running it. Carrying a
# setting forward is right until the build stops accepting it, and then it is
# a service that will not start. The node itself is asked, since it is the
# only thing that knows which names this build has.
#
# Only a refusal of the line is taken to mean the name is gone. `cairnd` exits
# 2 for a command line it will not read and 1 for a start that failed, and
# this took any failure for the first, so something else going wrong handed
# the machine another network in silence.
settle_the_network() {
    refused=0
    (cd / && "$1" --check --network "$NETWORK") >/dev/null 2>&1 || refused=$?
    if [ "$refused" -eq 0 ]; then
        return 0
    fi
    if [ "$refused" -ne 2 ]; then
        echo "network  cairnd --check --network $NETWORK failed for a reason other than" >&2
        echo "         the name, so nothing is installed. It said:" >&2
        (cd / && "$1" --check --network "$NETWORK") >&2 || true
        exit 1
    fi
    # Asked, not written down. This said `NETWORK=testnet-6`, which is the
    # same shape of mistake the check above it exists to catch: the day
    # testnet-6 is retired, the line that rescues a machine from a retired
    # network hands it a retired network. The build is the only thing that
    # knows which name is current, and it says so on the first line of
    # `--check`.
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

# The whole line, put to the build before anything on this machine changes.
#
# Only MINE was checked here, by hand, and nothing else this script writes
# into the unit: a PORT or a SEED the node refuses installed a service that
# restarted five times and stopped, and then this script died at the firewall
# with the unit already enabled. `--check` reads the line the way a start
# would, `cairn.conf` included, and starts nothing.
check_the_line() {
    # Unquoted on purpose: this is a list of arguments and not one argument.
    # shellcheck disable=SC2086
    if ! "$1" --check $ARGS >/dev/null 2>&1; then
        echo "cairnd refuses the line this would install, so nothing is installed:" >&2
        echo "  $ARGS" >&2
        # shellcheck disable=SC2086
        "$1" --check $ARGS >&2 || true
        exit 1
    fi
}

# Moves the chain a network this machine is leaving out of the way of the one
# it is joining, and keeps it.
#
# A reset changes the network and nothing else, and a node started on the old
# one's directory either set every block aside on its first start, because
# none of them is on the new chain, or refused to start at all over a
# ledger.dat of the old network, five times and then for good. Neither was
# said. The old chain is kept beside the new directory for anyone who wants
# it, and the settings in it go along to the new one.
set_aside() {
    if [ ! -d "$1" ] || ! ls -A "$1" | grep -qvx 'cairn.conf'; then
        return 0
    fi
    kept="$1.$2"
    if [ -e "$kept" ]; then
        kept="$kept.$(date +%Y%m%d%H%M%S)"
    fi
    # Stopped first: a node still running would go on writing files by name,
    # and they would land in the new directory.
    systemctl stop cairnd 2>/dev/null || true
    if ! mv "$1" "$kept"; then
        systemctl start cairnd 2>/dev/null || true
        echo "data     $1 holds $2's chain and this machine is moving to $3, and it" >&2
        echo "         could not be moved aside to $kept. Nothing else is changed;" >&2
        echo "         move or empty it yourself and run this again." >&2
        exit 1
    fi
    mkdir -p "$1"
    if [ -f "$kept/cairn.conf" ]; then
        cp -p "$kept/cairn.conf" "$1/cairn.conf"
    fi
    echo "data     $2's chain is kept in $kept: a node on $3 starts from nothing"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "run this as root" >&2
    echo "with sudo, pass the settings through env, since sudo clears them:" >&2
    echo "  sudo env SEED=... MINE=... sh $0" >&2
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
        echo "write it without quotes, variables or patterns, or move the setting" >&2
        echo "into cairn.conf in the data directory, and run this again." >&2
        exit 1
        ;;
esac

the_settings

# The network the directory holds, in the words of the build that is running
# it, asked before that build is replaced. A name is not enough: `testnet`
# names whichever test network is current, so the same word in the unit can
# be the network the chain is on today and another one after the update.
WAS=""
named=$(carried network)
named=${named%% *}
if [ -n "$named" ]; then
    if [ -x "$BIN" ]; then
        WAS=$(name_of "$BIN" "$named")
    fi
    WAS=${WAS:-$named}
fi

# MINE=off said stop mining before an empty value said it for every setting.
if [ "$MINE" = "off" ]; then
    MINE=""
fi

# A key that is not a key produces a service that will not start, and systemd
# reports that as a failure to launch rather than as a bad argument. Asked
# here as well as by `--check` below, because this is before the build.
if [ -n "$MINE" ]; then
    case "$MINE" in
        *[!0-9a-fA-F]* | "")
            echo "MINE is not a public key: $MINE" >&2
            exit 1
            ;;
    esac
    if [ "${#MINE}" -ne 64 ]; then
        echo "MINE should be 64 hex characters, this is ${#MINE}" >&2
        echo "get it with: cairn-wallet address <your key file>" >&2
        exit 1
    fi
fi

case "$DATADIR" in
    /*) ;;
    *)
        echo "the installed unit keeps its chain in $DATADIR, which is not a full" >&2
        echo "path; write it as one and run this again." >&2
        exit 1
        ;;
esac

# Said early, so a run that lost a setting on its way through sudo is obvious
# before anything is built rather than after it is running, and so that what
# was kept rather than chosen is said out loud.
echo "network  $NETWORK"
echo "listen   $ADDRESS:$PORT"
echo "data     $DATADIR"
echo "seeds    ${SEED:-none given, the written-in ones are used}"
if [ -n "$MINE" ]; then
    echo "mining   to $MINE"
else
    echo "mining   off"
fi
if [ -n "$KEPT" ]; then
    echo "kept     ${KEPT# }, which this run did not name"
fi
if [ -n "$INSTALLED" ] && [ -n "$REST" ]; then
    echo "carried  $REST, as the installed unit had it"
fi

say "Packages"
# A refresh that reports errors is common and usually harmless: an older
# release whose backports have been archived says so every time, while the
# packages below live in the main repository and install fine. Failing here
# would stop an installation for a reason that has nothing to do with it.
if ! apt-get update -qq; then
    echo "apt-get update reported errors; carrying on with what is available"
fi
apt-get install -y -qq git curl build-essential pkg-config || true

# What actually matters is whether the tools are here.
missing=
for tool in git curl cc; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    echo "missing:$missing" >&2
    echo "install them and run this again; on Debian or Ubuntu that is" >&2
    echo "  apt-get install git curl build-essential pkg-config" >&2
    exit 1
fi

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
# --locked so a seed node is built from the dependency versions in Cargo.lock,
# the same ones the checks ran against. release.yml already says this about the
# binaries it publishes; the machines that build from source were resolving
# whatever cargo decided at the time.
( cd "$SRC" && cargo build --release --locked --bin cairnd )
BUILT="$SRC/target/release/cairnd"

say "Service"
# Everything the new build is asked, it is asked here, before it is installed
# and before anything the running node depends on is touched: a refusal below
# leaves this machine exactly as it was.
settle_the_network "$BUILT"
NOW=$(name_of "$BUILT" "$NETWORK")
ARGS=$(the_line)
check_the_line "$BUILT"

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
write_unit "$SRC/deploy/cairnd.service" > "$UNIT"

systemctl daemon-reload
systemctl enable cairnd
# A unit that failed its last five starts is refused a sixth until its
# interval has passed, a start asked for by hand included. This is the run
# that has just mended whatever failed, so the count is cleared first.
systemctl reset-failed cairnd 2>/dev/null || true
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
# What is actually running, so an update can be told from a no-op and a
# setting that went missing is visible without reading the unit file.
echo "commit   $(git -C "$SRC" rev-parse --short HEAD)"
echo "started  $(systemctl show -p ActiveEnterTimestamp --value cairnd)"
grep '^ExecStart=' "$UNIT"
# A node that cannot start stops within a second or two. The note below said
# it was running whether or not it was, read the moment after the restart.
sleep 3
running=""
if systemctl is-active --quiet cairnd; then
    running=1
fi
systemctl --no-pager --lines=6 status cairnd || true
if [ -z "$running" ]; then
    cat <<NOTE

The node is not running. What it said as it stopped is above, and all of it
is in the journal:

  what it said         journalctl -u cairnd -n 50
NOTE
    exit 1
fi
cat <<NOTE

The node is running and will come back on its own after a reboot or a crash.

  what it is doing     journalctl -u cairnd -f
  stop it              systemctl stop cairnd
  start it again       systemctl start cairnd
  update it            sh install.sh

The update line takes no settings: this machine keeps the ones it already
has, and every other argument on the unit's command line. Naming a setting
changes it, and naming it empty puts it back to the default, which is the
only way a setting goes back on its own:

  change two           sudo env NETWORK=devnet PORT=9955 sh install.sh
  put them back        sudo env NETWORK= PORT= sh install.sh
  stop mining          sudo env MINE= sh install.sh

Publish this machine as <its public address>:$PORT so others can start from
it. Nothing else about it needs to be public, and nothing on it is worth
stealing: a seed node holds no key, and one that mines holds only the address
its rewards are paid to.
NOTE
