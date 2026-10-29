---
title: Cairn, for reviewers
language: en
stylesheet: cairn-whitepaper.css
strap:
  Where the claims are, how to check each one yourself, what this project
  has already got wrong, and where we most expect to be wrong still.
byline: For release 0.14.0, 29 October 2026
byline: [github.com/cairnchain/cairn](https://github.com/cairnchain/cairn)
byline: Every command below was run against that release before publishing
abstract: How this was made
---

# For reviewers

Thank you for looking. This page is for someone who knows the field and has
an afternoon.

Cairn's code, documents and tests were written by an AI model (Claude),
directed by one person who does not program. Every audit so far was done by
AI models too: many of them, adversarial and enumerative, and they found real
defects, some of them serious, which are listed below with the pull request
that fixed each. No human outside the project has reviewed any of it before
you. Please weigh everything here accordingly, and assume nothing has been
checked by a person.

## The design in five sentences

Every node holds a hot set of notes capped by consensus rule at 131 072
notes, about 68 MB. Older notes live in an append-only Merkle forest (the
Utreexo construction) carried as at most 64 roots, and are spent with an
inclusion proof the spender supplies, checked against the roots as they stand
now. A note that just fell out of the hot set stays spendable with no proof
for a grace window of 64 blocks, at most 8 192 notes. Every place a transfer
takes in the hot set destroys a fixed place price of 6 000 pebbles, so pushing
notes out costs whoever does it. A newcomer joins from a FlyClient-style
sample of the header chain and a ledger handed over by a peer, weighed rather
than replayed.

The paper is [the whitepaper](https://cairnchain.org/whitepaper); the
protocol, byte for byte, is [the specification](https://cairnchain.org/specification);
what is defended and what is not is [the threat model](https://cairnchain.org/threat-model).

## The three questions we most want answered

1. **The sampling bound** (whitepaper, "Sampled verification"). 4 096 draws,
   measured to hold against a forger up to at least 42.96% of the world's
   work (published as 40%), with a guarantee of about 633 blocks of depth.
   Measured, not proved, over the placement families in
   `crates/cairn-ledger/examples/adversarial_placement.rs` and
   `crates/cairn-ledger/examples/searching_for_a_break.rs`; the draw itself
   is `crates/cairn-ledger/src/sampling.rs`. The first version was wrong by
   a factor of 2<sup>122</sup>, and the paper says how. Is there a strategy
   outside those families, or an input the prover controls that we missed?
2. **A forged burial from an old fork point.** The difficulty is ASERT
   anchored at the first block, so the time elapsed since an old fork point
   is real and free to declare, and no difficulty rule prices a rewrite from
   far back. What prices it is the weighing and the refusal of a tip more
   than 32 times below the hardest header of its run, which puts a tip at
   no less than 2^18.9 hashes on testnet-8
   (`crates/cairn-ledger/tests/the_price_of_a_seed.rs`). Naive forgeries
   from fork points one hour, twenty-eight hours and ten days old are
   refused (`crates/cairn-ledger/tests/audit_a_burial_from_three_fork_ages.rs`).
   An optimally built one has not been built. A handed-over ledger on its
   own does accept a forged burial, by design: the weighing is the gate
   (`crates/cairn-ledger/tests/audit_forged_join.rs` says why).
3. **The thesis against Christ and Bonneau** (whitepaper, "The limit that
   applies, and where Cairn falls"). Cairn takes the proof-update side of
   their dilemma on purpose. Does a hot set capped by consensus rule change
   who bears the proof-update rate, as the paper claims, or only how it is
   described?

If you have more time: the place price against a flood of the hot set, the
tie band in the fork choice, and ASERT anchored at the first block with a
bound of four per block.

## Where to look in the code

The two tiers are `crates/cairn-ledger/src/state.rs`, the forest
`crates/cairn-accumulator/src/forest.rs`, the consensus rules
`crates/cairn-ledger/src/validation.rs`, the difficulty
`crates/cairn-ledger/src/pow.rs`, the handover
`crates/cairn-ledger/src/handover.rs`, and the fork choice and reorganisation
`crates/cairn-chain/src/lib.rs`. How a node picks whom to follow when it
arrives is `crates/cairn-net/src/node.rs`.

## Checking a claim yourself

Everything below runs from a clone at the tag `v0.14.0`, with the Rust
toolchain `rust-toolchain.toml` pins, which `rustup` installs by itself. Each
was run on that tag on 29 October 2026 and passed, in about a minute or less
on a laptop, building included, once the first one had built the workspace.

<div class="tablewrap">
  <table>
    <thead><tr><th>Claim</th><th>Where it is checked</th></tr></thead>
    <tbody>
      <tr><td>The node's memory and disk bounds the README and paper publish</td><td><code>cargo test -p cairn-explorer --test published_figures</code></td></tr>
      <tr><td>What grows without bound, and by how much a year</td><td><code>cargo run --release -p cairn-chain --example archivist</code></td></tr>
      <tr><td>The sampling count and the share it holds to</td><td><code>cargo run --release -p cairn-ledger --example adversarial_placement</code></td></tr>
      <tr><td>The wider search for a placement that breaks the bound</td><td><code>cargo run --release -p cairn-ledger --example searching_for_a_break</code></td></tr>
      <tr><td>Which check refuses which forgery</td><td><code>cargo test -p cairn-ledger --test audit_where_the_forgery_is_caught</code></td></tr>
      <tr><td>The price of a seed, and what it costs an honest chain</td><td><code>cargo test --release -p cairn-ledger --test the_price_of_a_seed -- --nocapture</code></td></tr>
      <tr><td>A forged burial from fork points of three ages</td><td><code>cargo test -p cairn-ledger --test audit_a_burial_from_three_fork_ages</code></td></tr>
      <tr><td>A handed-over ledger alone accepts a forged burial</td><td><code>cargo test -p cairn-ledger --test audit_forged_join</code></td></tr>
      <tr><td>The retarget against an independent ASERT reference</td><td><code>cargo test -p cairn-ledger --test the_difficulty_follows_the_clock</code></td></tr>
      <tr><td>A flood of the hot set: cost and duration</td><td><code>cargo run --release -p cairn-chain --example flood</code></td></tr>
      <tr><td>The specification, as test vectors built from it alone</td><td><code>cargo test -p cairn-ledger --test audit_the_specification</code></td></tr>
    </tbody>
  </table>
</div>

`cargo test --workspace` runs everything, which takes a while. To run the
programs themselves on the live test network, [the testnet
page](https://cairnchain.org/testnet) has the commands.

## Where this project has been wrong

Listed because a reviewer should know the kind of mistake this process
makes. Each was found in-house, by an AI audit, a lab test or the live test
network, and fixed with a test that fails without the fix. These are the ones
rated critical or high, one line each; findings that were the same defect
share a line. The audit reports themselves are not published.

Before pull requests were used, in the design phase:

- The sampling bound, first version: 512 draws and 45.7%, derived for a
  uniform draw; the real draw left a forger 2<sup>-5.8</sup> instead of
  2<sup>-128</sup>.
- Borrowed weight: the sampling was sound about how much work a chain carried
  and said nothing about whether the tip stood at its end.
- Proofs were accepted against any of the last 32 states; removing a note
  through an old path folded nothing, and the note could be spent again.
  Every node agreed, so nothing forked.

Since, by pull request:

- The number of halvings the draw spreads over came from a height the prover
  states, which let a forger buy halvings with invented work
  ([#1](https://github.com/cairnchain/cairn/pull/1)).
- A fresh node on a network whose first block is pinned never joined by
  handover ([#244](https://github.com/cairnchain/cairn/pull/244)).
- A forged body held first for a side-branch block kept a node off the
  heavier branch ([#244](https://github.com/cairnchain/cairn/pull/244)).
- The specification did not say how a signature is verified, where Ed25519
  verifiers differ ([#246](https://github.com/cairnchain/cairn/pull/246)).
- A peer's frame, transfer or block request was decoded or read before its
  allowance was charged, so a greeted peer bought seconds of processor per
  message, and one join answer was built per asker
  ([#242](https://github.com/cairnchain/cairn/pull/242)).
- Timestamps the rules accepted from a minority could make the chain run at
  half speed ([#237](https://github.com/cairnchain/cairn/pull/237)).
- A path let go of on a running ledger was not put back by a reorganisation,
  so the node refused a valid block
  ([#237](https://github.com/cairnchain/cairn/pull/237)).
- The documents priced seed grinding at the tip's own work, when a tip at
  the floor cost one nonce ([#237](https://github.com/cairnchain/cairn/pull/237),
  then [#255](https://github.com/cairnchain/cairn/pull/255), which holds a tip
  to the hardest header of its run).
- A block from a second un-updated peer got that peer refused as
  misbehaving ([#243](https://github.com/cairnchain/cairn/pull/243)).
- A node's inbound slots could be held for good by strangers that behaved,
  and every per-host rule keyed on the exact address, so one IPv6 machine
  passed them all ([#243](https://github.com/cairnchain/cairn/pull/243)).
- The start-up replay deleted valid blocks on a refusal that was about the
  reader, and an archivist lost every leaf at its first restart
  ([#236](https://github.com/cairnchain/cairn/pull/236)).
- A node that missed one block from a peer it took as its equal stopped
  following the best chain ([#240](https://github.com/cairnchain/cairn/pull/240)).
- A heavier branch of full blocks parting less than a batch below the tip
  was never taken ([#251](https://github.com/cairnchain/cairn/pull/251)).
- A wallet's node told a stranger which key it followed
  ([#249](https://github.com/cairnchain/cairn/pull/249)).
- Wallet accounting after a reorganisation: notes kept that the losing
  branch paid, movements below a trimmed log shown as taken back, undone
  payments left in the account
  ([#248](https://github.com/cairnchain/cairn/pull/248)).
- A payment `send` handed over was forgotten by the next command and could be
  sent twice, and `send` built payments from a chain it had not finished
  reading ([#238](https://github.com/cairnchain/cairn/pull/238)).
- A payment a block carried could be called unpaid, with "send it again",
  which could pay the payee twice; and a restored account could be rewound by
  its own node catching up ([#254](https://github.com/cairnchain/cairn/pull/254)).
- The wallet called its key file the only copy and named nothing about
  `history.dat`, so a restore from the key lost every note that had fallen
  cold, and an unreadable account was written over
  ([#233](https://github.com/cairnchain/cairn/pull/233)).
- A wallet counted two silent sockets as two peers and said it had caught up
  ([#256](https://github.com/cairnchain/cairn/pull/256)).
- The block log took any refused read for its end and cut every later block,
  and the explorer showed a balance of nought past the money ceiling
  ([#230](https://github.com/cairnchain/cairn/pull/230)).
- The explorer answered "no such transaction" for one it had located, and
  showed a stopped node under a sentence promising recovery
  ([#234](https://github.com/cairnchain/cairn/pull/234)).
- The documents said an unspent note shows no key, while the wallet paid its
  change back to the address whose key a spend had just published
  ([#265](https://github.com/cairnchain/cairn/pull/265)).
- The difficulty was a moving average until a stranger mined 80 blocks in two
  minutes on testnet-7 and the network nearly stopped for 33 hours
  ([#278](https://github.com/cairnchain/cairn/pull/278)).
- About 4 096 junk side blocks claiming difficulty 1 made a node drop an
  honest heavier branch, and the side store's bounds broke after a failed
  switch ([#281](https://github.com/cairnchain/cairn/pull/281)).
- 62 reused addresses kept a newcomer off the honest chain for ever, and a
  node killed outright lost its anchors
  ([#282](https://github.com/cairnchain/cairn/pull/282)).
- The gate that held a newcomer for the choice of chain read the height the
  peer wrote into its own handshake, so one peer could put a newcomer on a
  false chain; critical ([#296](https://github.com/cairnchain/cairn/pull/296)).
- A heavier branch handed over past 32 MiB of side blocks lost its top block
  as each one landed ([#295](https://github.com/cairnchain/cairn/pull/295)).
- A stranger with one address more than a list held kept a newcomer off the
  honest chain, and a wallet that opened none of its first four archivist
  dials stopped looking ([#294](https://github.com/cairnchain/cairn/pull/294),
  [#296](https://github.com/cairnchain/cairn/pull/296)).
- The wallet told a person left on an abandoned branch to delete
  `pending.dat`, its only record of payments in flight
  ([#292](https://github.com/cairnchain/cairn/pull/292)).
- A miner whose every connection lost the duplicate tie never mined, live on
  testnet-8 ([#298](https://github.com/cairnchain/cairn/pull/298)).
- A node never asked for a branch parting more than 72 blocks below its tip,
  so a fork 73 to 1 024 deep was legal and impossible to read; live on
  testnet-8 ([#300](https://github.com/cairnchain/cairn/pull/300)).
- A peer the choice asked to read was followed past the depth a node undoes
  with its claimed work never checked, so one visitor could put a newcomer on
  a worthless chain for good; critical
  ([#306](https://github.com/cairnchain/cairn/pull/306)).
- A restarted miner's wait for a heavier chain was spent by the first peer it
  reached, whatever that peer claimed
  ([#305](https://github.com/cairnchain/cairn/pull/305)).

An audit of everything that changed since 14 October was started on
29 October 2026; what it finds will be added here.

## What is known and open

Found while checking this page, on 29 October 2026, and not yet explained:
a program that reads testnet-8 from its first block, a new explorer or
`cairn-wallet recover`, stops at block 1 152; the explorer says nothing, and
`recover` says the one peer it reached that keeps every block sent nothing
more.

These are stated in the documents and not fixed:

- **A stall a stranger can still cause.** The time a newcomer gives one
  peer's read of its chain is bounded, at 543 s on testnet-8
  ([#310](https://github.com/cairnchain/cairn/pull/310)), but the bound is per
  connection: a stranger holding N connections can hold a newcomer up to N
  times that before the honest chain is read. A stall, not a capture.
- **Only the Linux releases can be rebuilt byte for byte on another
  machine** (`deploy/rebuild.sh`,
  [#309](https://github.com/cairnchain/cairn/pull/309)). The macOS and
  Windows archives are built twice on GitHub and compared, but their linkers
  and system libraries come with the machine; `deploy/README.md` says which
  match.
- **R4, the optimal forged burial from an old fork point**, the second
  question above. A lab attempt to build the cheapest one was not finished,
  and the question is left to outside review.
- **A fake archivist** that answers for a chain and never sends the blocks
  costs a recovery a minute per batch when it is the only peer that could
  serve them.

[The open questions](https://cairnchain.org/open-questions) lists what the
project has decided not to decide yet: privacy, post-quantum signatures, who
archivists are and who pays them, the difficulty variants set aside, and fee
estimation. The whitepaper's "Limitations" section is the list of what the
design does not do.

## Telling us

In the discussion thread, or as an issue on
[GitHub](https://github.com/cairnchain/cairn/issues). A vulnerability goes by
[SECURITY.md](https://github.com/cairnchain/cairn/blob/main/SECURITY.md).
Everything found will be fixed, tested and credited.
