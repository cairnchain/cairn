# Running a Cairn seed node

A seed node is an address people can start from. It validates the chain like
any other node, mines nothing, and holds no key. If the machine were taken
tomorrow there would be nothing on it to steal, which is why a seed should be
a machine with nothing else of yours on it.

Everything here targets Debian or Ubuntu with systemd, which is what almost
every rented server runs.

## The short version

On each server, as root:

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

**No wallet key ever goes on a seed node.** Not to mine with, not to test
with. A seed is a public address that strangers connect to, and the whole
reason it can be exposed without worry is that there is nothing on it worth
taking. Mine from your own machine if you want to mine.

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

A node killed outright, or a server that loses power, comes back on its own:
the data directory lock is held by the kernel on an open file and is released
when the process dies, however it dies. Nothing has to be cleaned up by hand.

## What this network is

`testnet-2` is a test network. Its money is worth nothing, it is meant to be
worth nothing, and the network will be reset. When it is, every balance on it
disappears and nothing carries over. Say so to anyone you invite.
