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

Pre-alpha. There is no network, no consensus, and no released binary. What
exists is the ledger core: notes, transactions, blocks, and the rules that
connect one block to the next.

The accumulator that makes the whole design work is not implemented yet. The
state commitment is currently recomputed from the full note set, which is
correct but does not scale. It sits behind `LedgerState::projected_state_root`
and the `NoteResolver` trait, which are the two seams it will replace, and the
block header field it fills is already final.

## Layout

| Crate | Contents |
| --- | --- |
| `cairn-primitives` | Domain separated hashing, checked amounts, canonical encoding, Merkle roots |
| `cairn-crypto` | Ed25519 keys and signatures, with canonical encoding and weak key rejection |
| `cairn-ledger` | Notes, transactions, blocks, state, and the consensus rules |

## Building

```
cargo test --workspace
cargo clippy --workspace --all-targets
cargo run -p cairn-ledger --example walkthrough
```

The workspace denies `unsafe`, panicking helpers, unchecked arithmetic, and
slice indexing. Consensus code takes the current time as an argument rather
than reading a clock.

## Licence

MIT or Apache-2.0, at your option.
