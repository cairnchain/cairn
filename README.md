# Cairn

A blockchain designed so that a full validating node costs the same to run in
thirty years as it does today.

Every existing chain grows its validation cost with its own usage, so the
longer it succeeds the fewer people can afford to verify it, and validation
drifts into data centres. Cairn holds the ledger as a fixed size commitment
instead of a growing database: a bounded working set lives in every node, and
everything that has not moved in a long time lives only in the commitment and
is spent by presenting a proof. Nothing is ever destroyed, expired, or charged
rent.

The paper is `docs/cairn-whitepaper.html`. What the field has already done
with this problem, and where Cairn stands against it, is in
`docs/cairn-prior-art.html`; the working design notes are in
`docs/cairn-design.html`.

Review is the contribution most wanted right now, and the paper says plainly
what it borrows and what limit it accepts.

## Status

Pre-alpha, and running in public. `testnet-3` has been up since 27 August 2026
on two seed nodes at two hosts in two countries. Its money is worth nothing,
is meant to be worth nothing, and the network will be reset.

There is no mainnet. A network exists once its first block does, and that one
will be mined in the open on the day it is announced.

The protocol is complete and runs end to end: notes and transactions, the
accumulator that replaces the state database, the two tiers, proof of work with
a difficulty that retargets in a handful of blocks, the fork choice, atomic
reorganisation, and syncing between nodes over TCP.

A node keeps its chain on disk and replays it on start, and finds its peers by
asking the ones it already has, so it needs one address to join a network and
none at all to rejoin one.

There is a node and there is a wallet, and money moves between people on a
network running on one machine. Every consensus rule is settled, including the
two that were open longest: the hot set holds 131072 notes, measured at roughly
68 MB so that a phone can hold it, and the reward halves every two years until
it reaches a floor it then keeps forever.

A node keeps the hot set in full and the cold set as sixty four hashes, so what
it costs to validate does not grow with the chain. It also lets go of any block
too deep to be undone, and of the branch behind it: what it holds in memory is
the stretch a reorganisation could still reach, and one identifier every 1024
heights before that, which is 492 kB over thirty years.

On disk it keeps the ledger those blocks add up to, which is a fixed size, and
a bounded amount of recent blocks for peers a little behind. Everything older
is dropped. What it does keep for good is the headers, at 182 bytes each, and
the forest they make: 129 MB a year, against 50 GB a year for Bitcoin and 200
for Ethereum. That is what lets any node show a newcomer which chain carries
the most work, which is in turn what stops joining a chain from depending on
anyone volunteering to carry its history.

An archivist keeps the whole cold set and is the only party that can rebuild
the proof of a note whose owner lost theirs. That service costs a set that
grows, it is chosen rather than paid for, and the network runs without it.

A wallet keeps its own proofs current out of what every block already carries,
so it spends a fallen note without asking anyone. Money moves between people
across a set no node holds.

Every header commits to two things beyond its own block: the work behind the
whole chain, and every header that came before it, held as sixty four hashes
like the cold set. What they buy is the only way to join this chain without
downloading all of it. Someone starting from nothing draws 512 old headers
against accumulated work rather than height, checks each is really where it
claims to be in the tip's own commitment, and works out what stands behind the
tip without reading the millions in between. Then they are handed the ledger.
Twelve megabytes for a thirty year chain, against 2 067 GB of reading.

Any node can answer, because the headers and the forest they make are kept on
disk by every node at 182 bytes each. Joining does not depend on anyone
volunteering to carry the history.

Those fields had to be in the header from the first day: changing the shape of
a header invalidates every block already mined, so a chain that ever carries
value can never gain one.

Each network starts from a block written into the source, so two nodes that
have never met are on the same chain by construction and neither has to take a
stranger's word for where the story begins.

A block holds 128 kilobytes, which is about 686 ordinary payments, or eleven a
second. That number decides three things at once and is small because of the
first two: a node holds the blocks it could still reorganise away, so it is
134 MB of memory every node must have; it sets how fast the hot set turns over
and with it how long a fallen note stays spendable without a proof; and it is
how many people can be paid in a minute.

| Network | Starts from | Opens at | Block time |
| --- | --- | --- | --- |
| `testnet-3` | `0000001b9876...` | 1787820378 | 60 s |
| `devnet` | `00000139ffc6...` | 1787820357 | 5 s |
| `mainnet` | not made yet | | |

There is an explorer, which is a node that also serves a website: the chain in
public, and an explanation of it written at three levels for readers who know
nothing, something, or everything. It keeps an index from owners to their
notes, which is the growing cost the protocol refuses to put on validators and
is exactly why it lives in a separate program nobody has to run.

A node survives being treated badly. It holds a bounded number of connections,
a bounded share of them from any one address, and lets go of a peer that opens
a frame and stops talking rather than waiting on it forever. Undo records,
known-bad blocks and dead branches are all bounded, so nothing an anonymous
peer does decides how much memory this node spends. The data directory is held
by a lock the operating system releases when the process ends, so a machine
that loses power comes straight back up.

A rule can change without the chain being thrown away. A change names the
height it takes effect at, and blocks below it go on being judged by the rule
that judged them, so nothing already mined becomes invalid and no balance is
destroyed. Nobody votes on it: the height is in the software, and miner
signalling is refused for the reason proof of stake is. A node that reaches a
height whose rules it does not have says which version it needs and stops,
rather than treating every updated peer as a liar and following whoever did not
update either.

What is left before a network worth trusting: a proof of the sampling bound,
which is ours and unreviewed, an outside audit, and enough people running nodes
that no single one of them matters.

## Getting it

Programs for macOS, Linux and Windows are on the
[releases page](https://github.com/cairnchain/cairn/releases/latest), with a
`SHA256SUMS` file beside them. They are built in public by GitHub from a
tagged commit, and each one carries an attestation saying which commit and
which workflow produced it:

```
gh attestation verify <the archive> --repo cairnchain/cairn
```

That asks GitHub rather than us, which is the point. Your operating system
will still warn you, because these programs carry no paid certificate. The
check above is worth more than one.

Then run it:

```
cairnd
```

The addresses it starts from are written into the program, exactly as the
first block is, so a node that was just unpacked finds the network on its own.
`--seed <address>` starts somewhere else instead, replacing that list. To put
one of those addresses on a machine of your own, `deploy/` has an installer
and the notes that go with it. On a bare server that is three lines:

```
apt install -y git
git clone https://github.com/cairnchain/cairn /usr/local/src/cairn
sh /usr/local/src/cairn/deploy/install.sh
```

## Layout

| Crate | Contents |
| --- | --- |
| `cairn-primitives` | Domain separated hashing, checked amounts, canonical encoding, Merkle roots |
| `cairn-crypto` | Ed25519 keys and signatures, with canonical encoding and weak key rejection |
| `cairn-accumulator` | The sparse Merkle tree a node holds in place of the ledger, and its proofs |
| `cairn-ledger` | Notes, transactions, blocks, the two tiers, and the consensus rules |
| `cairn-chain` | The block tree, the fork choice, and reorganisation |
| `cairn-net` | The wire protocol, block propagation, syncing over TCP, and peer discovery |
| `cairn-store` | The append only block log a node replays on start |
| `cairn-node` | `cairnd`, a node |
| `cairn-wallet` | the wallet: a library that holds the key, and `cairn-wallet` on top of it |
| `cairn-http` | the small HTTP server and JSON writer the wallet and the explorer share |
| `cairn-explorer` | `cairn-explorer`, a node that indexes the chain and serves `web/` |

The website itself is in `web/`, kept out of the protocol crates. It is plain
HTML, CSS and JavaScript with no build step and no framework, compiled into the
explorer binary, so what is served is what was written.

## Running it

```
cargo build --release
```

Make a key, and start a node that mines to it on a throwaway network:

```
./target/release/cairn-wallet new alice.key
./target/release/cairnd --network devnet --data node \
    --mine $(./target/release/cairn-wallet address alice.key)
```

From another terminal, open the wallet. It joins the network as a node of its
own and verifies the chain before it answers anything, so it needs its own
directory:

```
./target/release/cairn-wallet open alice.key \
    --network devnet --data wallet --seed 127.0.0.1:9944
```

That prints an address to open in a browser: the balance, the address to be
paid at, a form to spend from, and where the money sits. It is served on the
loopback and nowhere else, the address carries a secret drawn for that run, and
a request naming another host or carrying another page's origin is refused. The
key stays in the process that read it; nothing the browser holds can sign.

The same things without a browser, for scripts and for servers:

```
./target/release/cairn-wallet balance alice.key \
    --network devnet --data wallet --seed 127.0.0.1:9944

./target/release/cairn-wallet send alice.key --to <public key> \
    --amount 12.5 --fee 0.25 \
    --network devnet --data wallet --seed 127.0.0.1:9944
```

Everything that touches money lives in the library, and both of those are faces
on top of it. That is what makes a native application on a phone a matter of
writing a face rather than writing spending a second time.

Watch the same network in a browser, with the explorer alongside the node:

```
./target/release/cairn-explorer --network devnet --data explorer \
    --seed 127.0.0.1:9944
```

It prints the address to open, `http://127.0.0.1:8080/` unless told otherwise.
The site holds no key and signs nothing; spending needs the wallet above.

`devnet` is the same rules with a five second block time and a hot set small
enough to watch notes fall. Consensus rules come from the network name and
cannot be set one at a time: two nodes differing on any of them would build
separate chains while believing they were on the same one.

## Building

```
cargo test --workspace
cargo clippy --workspace --all-targets
```

Runnable demonstrations, each showing or measuring one part of the design:

```
cargo run -p cairn-ledger --example walkthrough        money moving, end to end
cargo run --release -p cairn-accumulator --example scale     what a node stores
cargo run -p cairn-chain --example partition          two chains meeting again
cargo run --release -p cairn-net --example network       nodes finding each other
cargo run --release -p cairn-net --example gossip          a block crossing a room
cargo run --release -p cairn-ledger --example history      the cost of arriving late
cargo run --release -p cairn-ledger --example collapse   losing most of the miners
cargo run --release -p cairn-ledger --example sampled_start   catching a forged chain
cargo run --release -p cairn-ledger --example blocksize    what a block may take
cargo run --release -p cairn-chain --example weight    what a node holds in memory
cargo run --release -p cairn-chain --example window     what a full block costs held
cargo run --release -p cairn-chain --example archivist   what each role carries
cargo run --release -p cairn-ledger --example footprint      what a hot note costs
cargo run --release -p cairn-accumulator --example proving   what proving costs
cargo run --release -p cairn-crypto --example verify   what a signature costs
```

## How this is built

The workspace denies `unsafe`, panicking helpers, unchecked arithmetic, and
slice indexing. Consensus code takes the current time as an argument rather
than reading a clock, and holds no iteration order that varies between
processes.

Anything that decides whether two nodes agree is written so it can be tested
without a network: the sync layer takes messages and returns messages, and the
transport under it decides nothing.

The dependency tree is deliberately small. There is no asynchronous runtime: a
node keeps tens of connections rather than thousands, so one reader thread and
one writer thread per peer costs nothing and leaves far less to audit inside a
process people are being asked to run.

Every number an anonymous peer gets to choose is capped, and every table one
can fill is bounded. A reorganisation deeper than `MAX_REORG_DEPTH` is refused
rather than kept possible by holding undo records forever; that is a local
safety policy, not a consensus rule, and it is written down as such.

What a node must hold to validate is capped by the rules: 68 MB of hot notes
and, in the worst case the rules allow, 233 MB of blocks it could still have to
undo. Neither grows with the chain.

One cost does grow, and it is small and named: the headers, at 129 MB a year.
A node keeps them so that anyone can join through it. Keeping every block, and
archiving every note that ever fell out of the hot set, are the two costs that
grow without bound, and both are chosen work the network does not depend on.
`cargo run --release -p cairn-chain --example archivist` prints all four.

## Licence

MIT or Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.

Contributions are welcome, and reviews of the protocol more than anything
else. The parts most worth an outside eye are the two tiers in
`crates/cairn-ledger/src/state.rs`, the accumulator in
`crates/cairn-accumulator/src/forest.rs`, and the consensus rules in
`crates/cairn-ledger/src/validation.rs`.
