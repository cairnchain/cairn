---
title: Cairn Threat Model
language: en
stylesheet: cairn-whitepaper.css
strap:
  What this project defends, against whom, and what it knowingly leaves
  open, row by row against the code it ships.
byline: Revision of 26 September 2026
byline: [github.com/cairnchain/cairn](https://github.com/cairnchain/cairn)
byline: Held to the repository by a test, which checks every path it names
abstract: How to read this
---

# Cairn threat model

The first model was written on 30 August 2026, in French and outside the
repository, against a commit three hundred and twenty eight commits older
than this revision. On 25 September it was read again row by row against the
code, and nineteen of its thirty seven rows turned out to be contradicted or
qualified by what had been found since. A model a reader cannot reach and
nobody keeps in step is the same kind of claim as a figure nothing holds, so
this one lives beside the code and moves with it.

Each row names a threat, what stands in its way and where, the test that
holds that, and what is left. What is left is written as the identifiers of
the findings that show it, from the audit wave of 25 and 26 September 2026:
`NN-Fk` is a defect, `NN-Ik` an improvement and `NN-Qk` a question. An empty
residue means the mitigation holds as far as anybody has looked, which is not
the same as holding. Every file this document names is checked to exist by
`crates/cairn-explorer/tests/site.rs`, and every item named beside a file is
checked to appear in it, so a row that points at code which has moved fails a
test rather than standing.

## What is defended

In order of how bad a failure would be.

<div class="scroll">
  <table>
    <thead><tr><th>Asset</th><th>What stands in the way</th><th>Held by</th><th>Left open</th></tr></thead>
    <tbody>
      <tr><td>Money: no pebble created or destroyed outside the rules</td><td>the coinbase cap and the running supply in the state root, <code>crates/cairn-ledger/src/validation.rs</code>, <code>CoinbaseOverpay</code>; <code>crates/cairn-ledger/src/state.rs</code>, <code>supply_after</code>; the ceiling, <code>crates/cairn-primitives/src/amount.rs</code>, <code>MAX_MONEY</code></td><td><code>crates/cairn-ledger/tests/audit_emission.rs</code>, <code>crates/cairn-ledger/tests/audit_supply_and_overflow.rs</code></td><td></td></tr>
      <tr><td>Funds: nothing spent without its key, nothing spent twice</td><td>strict verification, <code>crates/cairn-crypto/src/lib.rs</code>, <code>verify_strict</code>; keys outside the prime order subgroup refused, <code>is_torsion_free</code>; a cold note emptied in place</td><td><code>crates/cairn-crypto/tests/audit_the_verification_rule.rs</code>, <code>crates/cairn-crypto/tests/audit_a_key_nobody_holds.rs</code></td><td></td></tr>
      <tr><td>Agreement: two honest nodes reach the same state</td><td>commit and revert through one replay, <code>crates/cairn-ledger/src/state.rs</code>, <code>fn revert</code>; the handover held field by field, <code>crates/cairn-ledger/src/handover.rs</code>, <code>pub fn accept</code></td><td><code>crates/cairn-ledger/tests/invariants.rs</code>, <code>crates/cairn-ledger/tests/handover.rs</code></td><td>09-F1, 05-F1, 05-F2, 07-F1</td></tr>
      <tr><td>Availability: no message anyone can send stops a node</td><td>a frame ceiling before any allocation, <code>crates/cairn-net/src/wire.rs</code>, <code>MAX_FRAME_BYTES</code>; a per-peer allowance, <code>crates/cairn-net/src/sync.rs</code>, <code>ALLOWANCE</code>; a connection ceiling, <code>crates/cairn-net/src/node.rs</code>, <code>MAX_PEERS</code></td><td><code>crates/cairn-net/tests/hostile_peer.rs</code>, <code>crates/cairn-net/tests/fuzz_wire.rs</code></td><td>13-F1, 16-F1, 16-F2, 16-F3, 14-F1, 15-F1, 04-F1</td></tr>
      <tr><td>A newcomer's start: nobody below the honest majority puts one on a false chain</td><td>the sampled weighing, <code>crates/cairn-ledger/src/sampling.rs</code>, <code>pub const SAMPLES</code>, the count taken from the age the tip claims against the reader's clock; a fresh draw priced by holding the tip to its run, <code>crates/cairn-ledger/src/sampling.rs</code>, <code>pub const MOST_FALL</code></td><td><code>crates/cairn-ledger/tests/audit_the_bound.rs</code>, <code>crates/cairn-ledger/tests/the_price_of_a_seed.rs</code></td><td>12-F1</td></tr>
      <tr><td>Privacy: the software adds nothing to what the chain shows</td><td>by decision the chain is public, amounts and owners included; what the software must not do is tell anyone more than that</td><td></td><td>38-F1, 38-F2, 38-F3, 38-F4, 38-F5, 44-I7</td></tr>
      <tr><td>The rules and their schedule: they change only as the source says, and visibly</td><td>a rule changes at a height written into the build, <code>crates/cairn-ledger/src/validation.rs</code>, <code>version_at</code>; a node past its schedule says so and stops, <code>crates/cairn-node/src/main.rs</code>, <code>rules_running_out</code>; nobody votes</td><td><code>crates/cairn-ledger/tests/audit_rule_change.rs</code>, <code>crates/cairn-chain/tests/audit_rule_change.rs</code></td><td>05-F1, 05-F2, 44-I1</td></tr>
    </tbody>
  </table>
</div>

The 30 August model put privacy outside the model, as a property a public
chain does not have. That was the wrong row. The chain is public by decision,
and the open questions paper says what it shows; but a wallet that tells a
peer which notes are its own, or a node that advertises the address of the
phone it runs on, spends privacy the protocol never asked for. That is a
failure of the software, and the model counts it as one.

It also said governance was none. There is no key, no vote and no authority,
and that part holds. But whoever writes the build decides the rules and the
height they change at, and the release is published by a workflow; that is a
party, and it is in the table of actors below.

## Who acts

<div class="scroll">
  <table>
    <thead><tr><th>Actor</th><th>What it can do</th><th>What stands in the way</th><th>Left open</th></tr></thead>
    <tbody>
      <tr><td>A user</td><td>sign transfers of its own notes</td><td>every input signed over the network, the version, the identifier, the index and the note spent, <code>crates/cairn-ledger/src/transaction.rs</code>, <code>fn message</code></td><td></td></tr>
      <tr><td>A miner</td><td>order a block, date it within bounds, claim the reward and fees, fill its own block space for free</td><td>the retarget, the median of past times and the drift a reader allows, <code>crates/cairn-ledger/src/validation.rs</code>, <code>max_timestamp_drift</code>; the coinbase cap; the eviction cap, <code>max_evictions_per_block</code></td><td>04-F1, 04-F2, 44-F1</td></tr>
      <tr><td>A majority miner</td><td>rewrite recent history, censor, spend twice deep</td><td>nothing: it is the assumption. A node will not undo past <code>crates/cairn-chain/src/lib.rs</code>, <code>MAX_REORG_DEPTH</code>, which is a local policy tied to the burial and the maturity</td><td></td></tr>
      <tr><td>A miner with a third to a half of the work</td><td>earn more than its share by withholding blocks, as on every Nakamoto chain; try to mislead a newcomer's start</td><td>selfish mining is untreated, and the only lever taken is keeping the branch already followed at equal work; the start is bounded at the share the papers publish, measured and not proved</td><td>06-F2, 44-I4</td></tr>
      <tr><td>A hostile peer</td><td>send malformed or costly messages, poison an address book, try to eclipse a node</td><td>the frame ceiling and allowance above; a ceiling on connections from any one address, <code>crates/cairn-net/src/node.rs</code>, <code>MAX_PER_HOST</code>; a bounded share of the book per address group, <code>crates/cairn-net/src/book.rs</code>, <code>MAX_PER_GROUP</code></td><td>14-F1, 14-F2, 13-F1, 08-F1</td></tr>
      <tr><td>An adversary on the path</td><td>read every message, delay or withhold blocks, eclipse a node without any Sybil</td><td>nothing on the wire is private or bound to a peer; what it cannot do is forge, since every block needs work and every transfer a signature. Transport privacy is a decision not yet taken</td><td>44-I3, 38-F3</td></tr>
      <tr><td>An operator</td><td>control a node's disk, its clock and its settings</td><td>a node replays its block log at start and validates it again rather than trusting its own disk; the clock is read for the drift a block may run ahead and nothing else</td><td>05-F2, 11-F2, 21-F1, 25-F1</td></tr>
      <tr><td>The maintainer and the release</td><td>decide the rules and their heights; publish the binaries people run</td><td>every action pinned by hash; a provenance attestation, <code>.github/workflows/release.yml</code>, <code>attestations</code>; reproducible bytes; a schedule visible in the source months before its height. Nothing bounds what a schedule may change</td><td>28-F1, 28-F2, 28-F3, 27-F2, 44-I1</td></tr>
      <tr><td>An archivist</td><td>serve paths for fallen notes; stay silent; watch who asks; vanish</td><td>every answer is folded against roots the asker's own node worked out, so it cannot lie; <code>crates/cairn-net/src/message.rs</code>, <code>GetProofs</code>. A wallet offline past its node's retention depends on one, which is the design's stated cost, and the archive's durability is not yet the software's</td><td>37-F1, 38-F1, 38-F4, 20-F1, 44-I2</td></tr>
      <tr><td>The seed operator</td><td>see every first contact and every wallet session; hand a newcomer only addresses it chooses</td><td>one name, <code>crates/cairn-net/src/seeds.rs</code>, <code>seed.cairnchain.org</code>; the sampling makes any chain it shows checkable, so the harm is eclipse and observation rather than a false chain</td><td>38-F5, 14-Q3, 44-I6</td></tr>
      <tr><td>Absent by design</td><td>no validator set, no admin key, no checkpoint, no oracle, no bridge</td><td>none of them exists in the source, so none of them is a surface</td><td></td></tr>
    </tbody>
  </table>
</div>

## What is assumed

<div class="scroll">
  <table>
    <thead><tr><th>Assumption</th><th>If it is false</th><th>Held by</th><th>Left open</th></tr></thead>
    <tbody>
      <tr><td>Most of the work is honest</td><td>history is rewritten, and a newcomer can be misled</td><td>the root assumption of proof of work; nothing holds it</td><td>12-F1</td></tr>
      <tr><td>Clocks are roughly right</td><td>a node refuses valid blocks or takes future ones, a drift local to it while the median holds</td><td><code>crates/cairn-ledger/tests/retarget_timewarp.rs</code>, <code>crates/cairn-chain/tests/clock_skew.rs</code></td><td>04-F1, 06-F1, 07-Q1</td></tr>
      <tr><td>Each network's first block is written into the build</td><td>a newcomer believes whichever first block a peer hands it</td><td><code>crates/cairn-ledger/src/validation.rs</code>, <code>for_network</code>; <code>crates/cairn-ledger/tests/network_rules.rs</code></td><td></td></tr>
      <tr><td>The sampling bound holds</td><td>a forger below half the work puts a newcomer on its chain</td><td><code>crates/cairn-ledger/tests/audit_the_bound.rs</code></td><td>06-F2, 12-F1</td></tr>
      <tr><td>Undoing a block is the exact inverse of applying it</td><td>after a reorganisation a node's state root parts from the network's, with no attacker needed</td><td><code>crates/cairn-ledger/tests/invariants.rs</code>, <code>crates/cairn-chain/tests/audit_a_reorganisation_is_the_inverse.rs</code></td><td>09-F1, 11-F1, 11-F2, 11-F3, 17-F1</td></tr>
      <tr><td>A handed ledger is the ledger a node would have built</td><td>a node started from one follows another chain</td><td><code>crates/cairn-ledger/tests/handover.rs</code>, <code>crates/cairn-ledger/tests/audit_forged_join.rs</code></td><td>07-F1, 16-F3</td></tr>
      <tr><td>The hot set never passes its capacity</td><td>the one bound the whole design rests on is not a bound</td><td><code>crates/cairn-ledger/src/state.rs</code>, <code>plan_evictions</code>; <code>crates/cairn-ledger/tests/tiers.rs</code></td><td>44-F1</td></tr>
      <tr><td>The operating system's randomness is there and good</td><td>keys are guessable; there is no weaker fallback for a key, so a failure is an error</td><td><code>crates/cairn-crypto/src/lib.rs</code>, <code>random_bytes</code></td><td></td></tr>
      <tr><td>Arithmetic does not wrap in a release build</td><td>an unchecked sum wraps where a checked one refuses</td><td><code>Cargo.toml</code>, <code>overflow-checks = true</code>, with unchecked arithmetic denied in every crate</td><td>31-F3</td></tr>
    </tbody>
  </table>
</div>

### The three assumptions that would stop the project

The 30 August model named three of these as the ones whose failure ends the
project rather than costs it something, because each one false is a
disagreement between honest nodes. Where each stands now:

1. **The sampling bound.** Then: a derivation of 512 samples, unreviewed and
   unmeasured. Now: 4 096 samples, the adversary's best placement measured,
   the count taken from the age a tip claims against a clock the reader
   holds, a tip held to the run below it so that a fresh draw costs work,
   and the whole stated as a conjecture rather than a theorem. It was broken
   once by this project and mended. Still open: 12-F1.
2. **Undo is the exact inverse of apply.** Then: held by debug assertions on
   the length of the hot set, and nothing in a release build. Now: held by
   property tests over random sequences and forks, and by a test that undoes
   every block of a chain and compares roots. Still open: 09-F1, and 11-F1 to
   11-F3 on the node-local structures around it.
3. **A handed ledger is exact.** Then: held by the state root and the chain
   of recent headers. Now: held field by field, with every refusal named by a
   test, and tied to the chain that was weighed by the run of headers between
   the ledger and the tip. Still open: 07-F1 and 16-F3.

None of the three has the shape it had on 30 August, and none is closed.

## Where it can be reached

<div class="scroll">
  <table>
    <thead><tr><th>Surface</th><th>What stands in the way</th><th>Held by</th><th>Left open</th></tr></thead>
    <tbody>
      <tr><td>The peer protocol</td><td>every message capped at decode; an allowance per peer</td><td><code>crates/cairn-net/tests/protocol.rs</code>, <code>crates/cairn-net/tests/fuzz.rs</code></td><td>13-F1, 16-F1, 16-F2, 16-F3, 14-F1, 14-F2, 15-F1</td></tr>
      <tr><td>The wallet's page</td><td>served on the loopback, behind a secret drawn for the run, refusing another host or origin; it moves money, <code>crates/cairn-wallet/src/serve.rs</code>, <code>/api/send</code>; a body read only for a POST and capped, <code>crates/cairn-http/src/http.rs</code>, <code>MAX_BODY_BYTES</code></td><td><code>crates/cairn-wallet/tests/page.rs</code>, <code>crates/cairn-http/tests/fuzz_request.rs</code></td><td>22-F1, 24-F1, 24-F6</td></tr>
      <tr><td>The explorer</td><td>public by design, read only, bounded per request</td><td><code>crates/cairn-explorer/tests/answers.rs</code></td><td>25-F1, 26-F1</td></tr>
      <tr><td>The pool</td><td>bounded in count and in bytes, conflicts refused, a fee floor asked again when the state moves, <code>crates/cairn-chain/src/lib.rs</code>, <code>MAX_POOL_BYTES</code></td><td><code>crates/cairn-chain/tests/pool.rs</code></td><td>21-F3</td></tr>
      <tr><td>A wallet as a node</td><td>a wallet joins the network as a node of its own, listening, <code>crates/cairn-wallet/src/lib.rs</code>, <code>0.0.0.0:0</code>; every cost a greeted peer can impose lands on the device the design exists for</td><td></td><td>38-F2, 16-F1, 13-F1, 14-F1, 44-I5</td></tr>
      <tr><td>The sampled start</td><td>new, and the part of the design with no deployed precedent in this form</td><td><code>crates/cairn-ledger/tests/sampling.rs</code>, <code>crates/cairn-ledger/tests/audit_the_bound.rs</code></td><td>06-F2, 12-F1</td></tr>
      <tr><td>The two tiers and cold proofs</td><td>new; a proof is checked against the forest as it stands and nothing older, <code>crates/cairn-accumulator/src/forest.rs</code>, <code>pub fn verify</code>; a fallen note stays spendable without a proof for a window, <code>crates/cairn-ledger/src/state.rs</code>, <code>GRACE_BLOCKS</code></td><td><code>crates/cairn-ledger/tests/tiers.rs</code>, <code>crates/cairn-ledger/tests/cold_spends.rs</code></td><td>44-F1, 21-Q2</td></tr>
      <tr><td>Files read back from disk</td><td>every record framed and checked; the block log validated again at start</td><td><code>crates/cairn-store/tests/fuzz_record_framing.rs</code>, <code>crates/cairn-store/tests/block_log.rs</code></td><td>17-F1, 18-F1</td></tr>
      <tr><td>The installer and the units</td><td>one script, <code>deploy/install.sh</code>, writes the units <code>deploy/cairnd.service</code> and <code>deploy/cairn-explorer.service</code></td><td></td><td>27-F1, 27-F2</td></tr>
      <tr><td>Dependencies</td><td>the crates a shipped program pulls in, few on purpose, checked against the advisory database every week, <code>.github/workflows/audit.yml</code>, <code>cargo audit</code></td><td></td><td></td></tr>
      <tr><td>Contracts, a virtual machine, a bridge</td><td>none exists</td><td></td><td></td></tr>
    </tbody>
  </table>
</div>

## What makes this model unusual

There is no finality. A node will not undo more than `MAX_REORG_DEPTH`
blocks, and that is its own policy, not a rule of the chain: two
nodes with different limits part company only over a reorganisation deeper
than one of them accepts.

The bound on what a node holds is itself a claim this model has to carry. If
the state a validator holds is not bounded after all, the thesis falls
without anyone losing money: it is a failure of the promise rather than of
consensus. The papers state every term of it and a test computes each one.

And two mechanisms carry the security that have no deployed precedent in
this form, the sampled start and the handover. That is where review is most
worth spending, and where every row above that ends in an open finding
points.
