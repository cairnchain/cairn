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

The design document is `docs/cairn-design.html`.

## Status

Pre-alpha. There is no released binary and no public network.

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

What is left is the other half of that: a wallet that keeps and refreshes its
own proofs, so it can spend a note that has fallen without asking anyone. Then
a public testnet.

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

`devnet` is testnet's rules with a five second block time. Consensus rules come
from the network name and cannot be set one at a time: two nodes differing on
any of them would build separate chains while believing they were on the same
one.

## Building

```
cargo test --workspace
cargo clippy --workspace --all-targets
```

Five runnable demonstrations, each showing one part of the design:

```
cargo run -p cairn-ledger --example walkthrough
cargo run --release -p cairn-accumulator --example scale
cargo run -p cairn-chain --example partition
cargo run --release -p cairn-net --example network
cargo run --release -p cairn-net --example gossip
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

## Licence

MIT or Apache-2.0, at your option.
