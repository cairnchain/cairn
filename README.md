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

Pre-alpha, and running in public. `testnet-2` has been up since 27 August 2026
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
107 MB so that a phone can hold it, and the reward halves every two years until
it reaches a floor it then keeps forever.

A node keeps the hot set in full and the cold set as sixty four hashes, so what
it costs to run does not grow with the chain. An archivist keeps the whole cold
set and is the only party that can rebuild a proof for someone who lost theirs.

A wallet keeps its own proofs current out of what every block already carries,
so it spends a fallen note without asking anyone. Money moves between people
across a set no node holds.

Every header commits to two things beyond its own block: the work behind the
whole chain, and every header that came before it, held as sixty four hashes
like the cold set. Neither changes what a node does today. What they buy is the
only way to join this chain without downloading all of it: someone starting
from nothing can be handed a sample of old headers, check each is really where
it claims to be, and work out what stands behind the tip without reading the
millions in between. That is roughly three hundred kilobytes and the hundred
megabytes of state, against the tens of gigabytes it takes to read everything.

The mechanism that uses them is not written yet. The fields are, because they
could not have been added later: changing the shape of a header invalidates
every block already mined, so a chain that ever carries value can never gain
one.

Each network starts from a block written into the source, so two nodes that
have never met are on the same chain by construction and neither has to take a
stranger's word for where the story begins.

| Network | Starts from | Opens at | Block time |
| --- | --- | --- | --- |
| `testnet-2` | `0000001b9876...` | 1787820378 | 60 s |
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

What is left before a network worth trusting: the sampling protocol that uses
the header commitments, an outside audit, and enough people running nodes that
no single one of them matters.

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

Join the network with either seed:

```
cairnd --seed 213.32.69.172:9944 --seed 92.222.100.238:9944
```

To run one of those addresses yourself, `deploy/` has an installer and the
notes that go with it.

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
| `cairn-wallet` | `cairn-wallet`, a wallet that is itself a node |
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

From another terminal, read what that key holds and pay someone with it. The
wallet joins the network as a node of its own and verifies the chain before it
answers, so it needs its own directory:

```
./target/release/cairn-wallet balance alice.key \
    --network devnet --data wallet --seed 127.0.0.1:9944

./target/release/cairn-wallet send alice.key --to <public key> \
    --amount 12.5 --fee 0.25 \
    --network devnet --data wallet --seed 127.0.0.1:9944
```

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

One cost still grows with the chain: a node holds every block of the followed
branch in memory, which is the history rather than the validation state. What
a node must hold to validate is capped and always will be; what it currently
holds to serve its own history is not. The header commitment is what makes it
possible to stop holding it, and that work is named in the design document
rather than left for someone to discover.

## Licence

MIT or Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.

Contributions are welcome, and reviews of the protocol more than anything
else. The parts most worth an outside eye are the two tiers in
`crates/cairn-ledger/src/state.rs`, the accumulator in
`crates/cairn-accumulator/src/forest.rs`, and the consensus rules in
`crates/cairn-ledger/src/validation.rs`.
