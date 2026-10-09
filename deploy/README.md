# Running a Cairn seed node

A seed node is an address people can start from. It validates the chain like
any other node and holds no key. If the machine were taken tomorrow there
would be nothing on it to steal, which is why a seed should be a machine with
nothing else of yours on it.

Everything here targets Debian or Ubuntu with systemd, which is what almost
every rented server runs.

## The short version

On each server, as root. A minimal cloud image has no `git`, and the installer
cannot fetch itself, so that one package comes first:

```
apt install -y git
git clone https://github.com/cairnchain/cairn /usr/local/src/cairn
sh /usr/local/src/cairn/deploy/install.sh
```

Read `install.sh` before running it. It is short and it says what it does. It
installs everything else it needs, including Rust.

Nothing has to be said about where to start: the addresses a node begins with
are written into the program, in `crates/cairn-net/src/seeds.rs`, exactly as
the first block is. A machine unpacked anywhere finds the network by itself,
and after one conversation it keeps its own book of addresses.

`SEED` still exists, and names a peer to try instead of that list. It is what
the very first machine of a new network needs, and what a private network
needs. If you reach root through `sudo`, pass it with `sudo env`, because
`sudo` clears the environment and a setting that goes missing produces a node
that runs correctly and does the wrong thing:

```
sudo env SEED=203.0.113.10:9944 sh /usr/local/src/cairn/deploy/install.sh
```

## The name

`seed.cairnchain.org` is the one starting point written into every program.
It should carry an `A` record for each machine that is worth starting from,
and a node tries all of them.

That is where redundancy lives, and it is deliberate that it lives there and
not in the source. Adding an entry point is a line in the zone file, taking
one away is deleting that line, and neither asks anybody to download anything
again. No address is written into the program: an address is a machine
somebody rents today and somebody else rents in two years, and a list of them
in public source would send every fresh node in the world knocking on a
stranger's door.

The one thing this costs is that a network with a single name has a single
person who could lose it. The answer is not a fallback address, which would
be blocked as easily as the name; it is a second name that somebody else
owns, and it goes into `crates/cairn-net/src/seeds.rs` the day somebody else
runs a node worth starting from.

## What the script does

It installs Rust, builds `cairnd` from source, creates a `cairn` system user
with no shell, puts the data directory at `/var/lib/cairn`, installs a systemd
unit, starts it, and opens the port if `ufw` is present.

It builds rather than downloading a binary, so what runs on your server is
what you can read in the repository. That costs a few minutes.

**If the build is killed partway**, the machine ran out of memory linking.
Small servers often do. Add swap and run the script again:

```
fallocate -l 2G /swapfile && chmod 600 /swapfile
mkswap /swapfile && swapon /swapfile
```

## What it needs from the machine

| | |
| --- | --- |
| Processor | one core is plenty; a seed does not mine |
| Memory | 1 GB to run, 2 GB to build comfortably |
| Disk | 20 GB leaves years of room |
| Network | one inbound TCP port, 9944 by default |

## The one rule about these machines

**No wallet key ever goes on a seed node.** Not to test with, not to hold a
balance on. A seed is a public address that strangers connect to, and the
whole reason it can be exposed without worry is that there is nothing on it
worth taking.

Mining does not break this rule, because a miner is told the address rewards
are paid to and nothing more. The key that spends them stays wherever you keep
it. Set `MINE` to an address, as `cairn-wallet address <key file>` prints it,
and the node will mine to it:

```
MINE="<address>" sh /usr/local/src/cairn/deploy/install.sh
```

A node set to mine waits until it has a peer it reached itself, and until the
chain has stopped arriving, before it builds a block, and says so in the
journal. A block mined
with nobody to hand it to starts a chain of that machine's own, and past the
depth a node will undo, that machine could never follow the network again.

On a test network at least one machine has to keep mining, or the chain
stands still and nobody can try anything. On a real network this would be a
poor arrangement, because the entry points people start from would also be
the machines producing blocks. Two servers is what this network has, so for
now one of them does both.

## Watching it

```
journalctl -u cairnd -f
```

A healthy node prints a line a minute:

```
[00:04:00] height 41  stored 41  peers 3  known 5  cold 0  work 5637144576
```

`height` is how many blocks it has and `stored` is how many are on the disk:
on a healthy node they are the same, and only the second survives a restart.
`peers` is how many nodes it is talking to. `known` is how many addresses it
has learned about. If `peers` stays at zero on a machine that was given a
seed, the port is not open.

## Where to put them

Two or three servers, and it matters that they are **not** all at the same
host or in the same country. A network whose entry points all sit in one data
centre has one place to fail and one place to lean on. Two hosts in two
countries is a meaningful difference for a few euros a month.

## Restarting, updating, stopping

```
systemctl restart cairnd
systemctl stop cairnd
sh /usr/local/src/cairn/deploy/install.sh   # rebuilds and restarts
```

`install.sh` reads the settings this machine already has back out of its unit
file, so an update takes none of them with it: `NETWORK`, `PORT`, `SEED` and
`MINE` come back as they were. It prints what it kept, so a setting that went
missing on its way through `sudo` is visible before anything is built.

The unit is not the only place a node reads settings from: `cairnd` also
reads `cairn.conf` in its data directory, and the command line wins over it.
The update writes `--network` and `--listen` on every line, so those two
belong on the command line and not in the file; the seeds of both are used.
Before it installs anything, the update prints what the new build reads from
the line and the file together, which is what the node will do.

Every other argument on the unit's command line is carried as it stands, so a
`--keep all`, an `--archive`, a `--data` on another disk or a `--listen` on one
address (`[::]:9944` for every IPv6 one included) survives an update, and the
unit is allowed to write wherever `--data` points. What is not carried is a
directive added to the unit itself, because the unit is written fresh from
the one in this directory: put such a directive in a drop-in with
`systemctl edit cairnd`, which an update never touches.

The command line is the exception, and belongs in the unit, where the update
reads it and writes it back. A drop-in that sets `ExecStart` runs instead of
it, so an update would carry the settings of a line that does not run, and
print that line as the one running. The update refuses while a drop-in sets
`ExecStart`, names the file, and changes nothing. The same holds for the
explorer's unit and `explorer.sh`.

Before anything on the machine changes, the new build is asked whether it
would run the line the update is about to install. A line it refuses is
printed with the reason and nothing is installed.

Naming a setting changes it. Naming it empty puts it back to the default it
ships with, which is the one way a setting goes back on its own:

```
sudo env PORT=9955 sh /usr/local/src/cairn/deploy/install.sh   # keeps the rest
sudo env PORT= sh /usr/local/src/cairn/deploy/install.sh       # back to 9944
sudo env MINE= sh /usr/local/src/cairn/deploy/install.sh       # stop mining
```

A node that was mining therefore keeps mining, which is what a test network
lives on: a miner that quietly stopped is how one goes still without anybody
noticing. Stopping it is `MINE=`, said out loud, and nothing else. It writes
`--mine off` on the command line, which also stops a key named in
`cairn.conf`, and later updates carry it until `MINE` names an address again.

When the network changes, because it was named or because the new build no
longer has the old one, the old network's chain is moved aside to
`/var/lib/cairn.<old network>` and the new network starts from an empty
directory, with the same `cairn.conf`. A chain from one network is of no use
to a node on another, and starting on it either discards it block by block or
does not start at all. Delete the old directory once nobody wants it.

The same happens when the network keeps its name and its first block changes,
which is what minting it again at its opening does (below): the chain from the
old first block is moved aside to `/var/lib/cairn.<network>-<the first twelve
characters of that block>`. A node of one minting refuses a directory of the
other and changes nothing on it, so this is what lets it start.

A node killed outright, or a server that loses power, comes back on its own:
the data directory lock is held by the kernel on an open file and is released
when the process dies, however it dies. Nothing has to be cleaned up by hand.
A node that cannot start is tried five times, thirty seconds apart, which is
long enough for a name server that is slow to answer after a reboot, and then
left stopped; `journalctl -u cairnd` says why.

## Opening a network

A network's first block is written into the program, and its timestamp is
where the difficulty's schedule starts: every minute a network opens after
that timestamp is a block asked less than the network's real rate, down to
nearly nothing, for whoever mines first. No server can run the block before a
build carrying it is merged and installed. So the block is dated at an opening
announced ahead and minted before it, and every node opens the chain by itself
at that moment. In order:

1. **Choose the opening**, in UTC, far enough ahead for everything below: the
   review of the pull request and its checks, the merge, the release's own
   checks and build, which take about two hours from the merge, and an
   install on every server. Half a day is comfortable. Announce it.
2. **Mint the first blocks**, on the branch that ships the network, from the
   repository:

   ```
   cargo run --release -p cairn-ledger --example remint -- --opens-at 2026-10-06T18:00:00Z
   ```

   It refuses a time already past, says how far ahead the opening is, dates
   the test network's first block at it, and writes it into every place that
   pins it. Then settle by hand the lines it lists as still calling a block
   provisional: the paragraph above `TESTNET_8` in
   `crates/cairn-ledger/src/genesis.rs` and the status in `README.md`. A
   release refuses to go out while either still says provisional.
3. **Merge** the pull request into `main` once its checks pass. That is what
   releases: the version in `Cargo.toml` has no release yet, so `release.yml`
   checks, builds and publishes that commit.
4. **Install on every server**, the seeds and the miner, with `install.sh`, and
   `explorer.sh` where the explorer runs, as soon as the merge is on `main`.
   They build from source and need not wait for the release. A directory of
   the network's previous first block is set aside as above. Each node starts
   with no chain and says when the network opens, in `journalctl -u cairnd`.
5. **The network opens by itself** at the announced time. Each node lays the
   first block down ten target times before it, which is as far ahead of its
   clock as any block may stand. A node installed with `MINE` builds nothing
   on it until the opening itself, by its own clock. In the meantime it says
   so in `journalctl -u cairnd`, and it mines from the opening on. Nothing has
   to be done on the day. A server installed after the opening joins as any
   node does.

## Putting the explorer on a public address

The explorer is a node that also serves the website: the chain in public, and
an explanation of it for readers who know nothing, something, or everything.
It holds no key and mines nothing, like a seed, and it can share a machine
with one.

It needs a name that already points at the machine, because a page saying who
owns what has to arrive unaltered, and that means a certificate:

```
sudo env DOMAIN=cairnchain.org sh /usr/local/src/cairn/deploy/explorer.sh
```

That builds the explorer, runs it on loopback, installs Caddy in front of it,
and asks for a certificate. A bare name like `cairnchain.org` also gets
`www.cairnchain.org` redirected to it, because people type it. On a first run
with no `DOMAIN` the site is served over plain HTTP, which is fine for looking
at and wrong for publishing.

`explorer.sh` keeps its settings the way `install.sh` does, the domain among
them and every other argument on its unit's command line: running it again for
a new build leaves the certificate where it is, and `DOMAIN=` is what takes a
site back to plain HTTP. A change of network moves the old chain and index
aside to `/var/lib/cairn-explorer.<old network>` the same way, and so does a
network minted again.

No seed has to be named: the addresses a node starts from are written into
the program.

Unlike a plain node, the explorer keeps the whole cold set and an index from
owners to their notes. That is a cost which grows with the chain, and it is
here on purpose: it is exactly the cost the protocol refuses to put on the
program everybody runs.

## What this network is

`testnet-8` is a test network. Its money is worth nothing, it is meant to be
worth nothing, and the network will be reset. When it is, every balance on it
disappears and nothing carries over. Say so to anyone you invite.
