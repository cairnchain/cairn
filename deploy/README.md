# Running a Cairn seed node

A seed node is an address people can start from. It validates the chain like
any other node and holds no key. If the machine were taken tomorrow there
would be nothing on it to steal, which is why a seed should be a machine with
nothing else of yours on it.

Everything here targets Debian or Ubuntu with systemd, which is what almost
every rented server runs.

## The short version

On each server, as root. If you reach root through `sudo`, pass the settings
with `sudo env`, because `sudo` clears the environment and a setting that goes
missing produces a node that runs correctly and does the wrong thing:

```
sudo env SEED=203.0.113.10:9944 sh /usr/local/src/cairn/deploy/install.sh
```

Otherwise:

```
git clone https://github.com/cairnchain/cairn /usr/local/src/cairn
sh /usr/local/src/cairn/deploy/install.sh
```

Read `install.sh` before running it. It is short and it says what it does.

The first server starts alone. Every later one should be told about an
earlier one, so the network is connected from the first minute:

```
SEED="203.0.113.10:9944" sh /usr/local/src/cairn/deploy/install.sh
```

After that they find each other on their own: a node asks its peers who else
they know, so one address is enough to join and none at all to rejoin.

A machine that is not one of the first will not need `SEED` at all. The
addresses in `crates/cairn-net/src/seeds.rs` are written into every program,
so anything unpacked anywhere finds the network by itself. Those entries are
what the names below have to resolve to.

## The names

`seed.cairnchain.org` and `seed2.cairnchain.org` are what the program looks
up first, and each should have an `A` record pointing at one of these
machines. The raw addresses are written in beside them, so a node still
starts when a name cannot be resolved; the names are there so a machine can
be replaced by editing a zone file rather than by publishing a release.

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
it. Set `MINE` to a public key and the node will mine to it:

```
MINE="<public key>" sh /usr/local/src/cairn/deploy/install.sh
```

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
[00:04:00] height 41  peers 3  known 5  cold 0  work 5637144576
```

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

`install.sh` rewrites the service file from the environment it is given, so
whatever `SEED` and `MINE` were set to on the last run is what the unit says.
Pass them again on an update, or edit `/etc/systemd/system/cairnd.service`.

A node killed outright, or a server that loses power, comes back on its own:
the data directory lock is held by the kernel on an open file and is released
when the process dies, however it dies. Nothing has to be cleaned up by hand.

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
`www.cairnchain.org` redirected to it, because people type it. Without
`DOMAIN` the site is served over plain HTTP, which is fine for looking at and
wrong for publishing.

No seed has to be named: the addresses a node starts from are written into
the program.

Unlike a plain node, the explorer keeps the whole cold set and an index from
owners to their notes. That is a cost which grows with the chain, and it is
here on purpose: it is exactly the cost the protocol refuses to put on the
program everybody runs.

## What this network is

`testnet-3` is a test network. Its money is worth nothing, it is meant to be
worth nothing, and the network will be reset. When it is, every balance on it
disappears and nothing carries over. Say so to anyone you invite.
