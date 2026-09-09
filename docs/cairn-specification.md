---
title: Cairn Protocol Specification
language: en
stylesheet: cairn-whitepaper.css
strap:
  What a node must do to be a node on this network, written so that a second
  implementation could be built from it without reading the first.
byline: Draft, against block version 1
byline: [github.com/cairnchain/cairn](https://github.com/cairnchain/cairn)
byline: Sections 1 to 7 drafted; consensus, state and joining to follow
abstract: Why this exists apart from the implementation
---

# Cairn protocol specification

Until this document, the implementation was the specification. That is a
problem with two halves. A second implementation cannot exist, because there is
nothing to build it from except a reading of the first, and two readings of the
same Rust are not two independent implementations. And a reviewer cannot check
a rule without being a Rust programmer, which excludes most of the people whose
review would be worth having.

This document is normative. Where it and the implementation disagree that is a
defect in one of them, and neither is presumed right. Every statement here that
names a number, a byte layout or an ordering is held against the code by a
test, and section 8 says where those tests are. A specification nobody checks
goes wrong the way a comment goes wrong: quietly, and without anyone deciding
to.

## Conformance

**MUST** and **MUST NOT** mark what a node has to do to reach the same
conclusions as every other node. Getting one of them wrong is a chain split,
not a matter of taste. **SHOULD** marks what a node is expected to do, where
doing otherwise costs that node or its operator and nobody else. **MAY** marks
a choice.

This document specifies what a node must agree with other nodes about. It does
not specify how a node stores anything, how it schedules work, what it keeps on
disk, or how it talks to a person. Those are the implementation's own, and the
reference implementation makes choices in all of them that another
implementation is free to make differently.

Anything not stated here is not a rule. If the reference implementation refuses
something this document does not say it must refuse, that is a defect in the
implementation or an omission here, and the way to tell them apart is to ask
whether two honest nodes could disagree about it.

## Primitives

### Integers

Integers are unsigned, of fixed width, and encoded little-endian with no
padding, no length prefix and no tag: `u8` in one byte, `u16` in two, `u32` in
four, `u64` in eight, `u128` in sixteen. There is no variable-length integer
anywhere in this protocol. A decoder MUST read exactly the width the field's
type says and no more.

There are no signed integers in any encoded structure. Arithmetic on a decoded
value MUST NOT wrap: an operation whose result does not fit is a refusal, not a
wrapped value, and the refusal is named where the operation is specified.

### Byte arrays and hashes

A fixed-size byte array is encoded as its bytes in order, with no length
prefix, because its width is known from its type. A hash is a 32-byte array and
is encoded the same way.

Every hash is BLAKE3 in keyed mode. The key is a 32-byte domain constant, and a
value hashed under one domain MUST NOT be accepted where another domain is
required. Each domain is a distinct constant, so a preimage under one says
nothing under any other.

### Sequences

A sequence is encoded as a `u32` count, little-endian, followed by that many
items back to back in order. There is no terminator and no per-item framing.

A decoder MUST refuse a declared count above 1 048 576 before reading any item,
and MUST NOT reserve memory in proportion to a count it has not yet read. Every
sequence in a block or a message has its own tighter limit, stated where that
structure is specified. This one is the floor under all of them, and it exists
so that a declared length can never drive an allocation.

An encoder MUST NOT produce a sequence longer than that limit. A structure
holding one would encode to bytes no conforming decoder can read back, and a
node could then commit to an identifier over a structure it cannot re-parse.

### Structures and choices

A structure is encoded as its fields in the order this document lists them,
back to back, with nothing between them and nothing around them. There is no
field tag, no optional field and no reordering. The order is part of the
format, and changing it changes every identifier ever computed.

A choice between shapes is encoded as a `u8` tag followed by the bytes of the
shape that tag selects. A decoder MUST refuse a tag it does not know rather
than skipping it, since it cannot know how many bytes to skip.

### Money

An amount is a count of pebbles, encoded as a `u64`. One CAIRN is 100 000 000
pebbles. No amount may exceed the monetary ceiling, and a decoder MUST refuse
an amount above it rather than accepting and clamping, so a value past the
ceiling cannot exist in a decoded structure anywhere in the system.

## Identifiers

An identifier is the hash of an encoding under a stated domain. Because the
encoding is positional and unpadded, an identifier commits to every field of
what it names, in order, and to nothing else.

Two consequences follow and both are load-bearing.

Adding a field to a structure changes every identifier that structure ever had,
so it cannot be done to a chain that already exists. Extending a structure at a
version boundary is a different operation, and whether this protocol permits it
is settled in part 4 rather than here.

A field left out of an identifier's encoding is a field the identifier does not
commit to, which is a place two nodes can hold the same identifier over
different bytes. Where that is done deliberately it is stated, with the reason,
where the structure is specified.

## Notes

A note is an amount and the public key that may spend it.

<table>
  <thead><tr><th>Field</th><th>Type</th><th class="n">Bytes</th></tr></thead>
  <tbody>
    <tr><td>value</td><td>amount</td><td class="n">8</td></tr>
    <tr><td>owner</td><td>public key</td><td class="n">32</td></tr>
  </tbody>
</table>

A note has no identity of its own. It is named by where it was created: the
identifier of the transaction that made it, and its index among that
transaction's outputs.

<table>
  <thead><tr><th>Field</th><th>Type</th><th class="n">Bytes</th></tr></thead>
  <tbody>
    <tr><td>source</td><td>hash</td><td class="n">32</td></tr>
    <tr><td>index</td><td>u32</td><td class="n">4</td></tr>
  </tbody>
</table>

A public key is 32 bytes and is an Ed25519 verifying key. A decoder MUST refuse
bytes that are not a canonical encoding of a point on the curve, and MUST
refuse a key of small order. Both refusals happen at decode, so a structure
that decoded holds no unusable key.

## Transactions

There are two kinds and they are not interchangeable. A transfer moves notes
that exist. A coinbase creates them, and exactly one appears in each block.

### Transfer

<table>
  <thead><tr><th>Field</th><th>Type</th><th class="n">Bytes</th></tr></thead>
  <tbody>
    <tr><td>version</td><td>u16</td><td class="n">2</td></tr>
    <tr><td>inputs</td><td>sequence of input</td><td class="n">4 + n</td></tr>
    <tr><td>outputs</td><td>sequence of note</td><td class="n">4 + 40m</td></tr>
  </tbody>
</table>

An input names a note, says how its existence is being shown, and carries the
signature that authorises spending it.

<table>
  <thead><tr><th>Field</th><th>Type</th><th class="n">Bytes</th></tr></thead>
  <tbody>
    <tr><td>note_id</td><td>note identifier</td><td class="n">36</td></tr>
    <tr><td>witness</td><td>witness</td><td class="n">1 or more</td></tr>
    <tr><td>signature</td><td>signature</td><td class="n">64</td></tr>
  </tbody>
</table>

A witness is a choice. Tag `0` means the note is in the hot set and the node
already holds it, and carries nothing further. Tag `1` means the note has
fallen to the cold set, and carries the note itself, its position, and a proof
that it sits at that position. A decoder MUST refuse any other tag.

**A transfer's identifier is not the hash of its wire encoding.** It is the
hash, under the transfer domain, of the version, the count of inputs, each
input's note identifier alone, and the outputs. Signatures and witnesses are
left out.

That is deliberate and a second implementation must reproduce it exactly. A
cold witness carries a proof that goes stale as the accumulator moves, and it
has to be refreshable without changing the identifier, for the same reason a
signature must not change it: everything already built on top of that
transaction would otherwise become invalid. It also means the identifier is
known before the transaction is signed.

It is an instance of the case section 3 names: a field left out of an
identifier's encoding is a field the identifier does not commit to. Two nodes
can hold the same transfer identifier over different bytes, differing in
signatures and witnesses, and that is intended rather than tolerated.

### What a signature commits to

Each input is signed separately, over the hash under the signature domain of:
the network identifier, the transfer's version, the transfer's identifier, the
input's index, and the value and owner of the note being spent.

The last two matter and are not obvious. Without them a wallet shown a false
value for the note it is spending would sign a transaction whose real fee is
the difference, and the signature would be perfectly valid.

### Rules a transfer must satisfy

Applied in this order, each producing the refusal named.

<table>
  <thead><tr><th class="n">#</th><th>Refusal</th><th>When</th></tr></thead>
  <tbody>
    <tr><td class="n">1</td><td>UnsupportedVersion</td><td>the version is not one these rules know</td></tr>
    <tr><td class="n">2</td><td>NoInputs</td><td>it spends nothing</td></tr>
    <tr><td class="n">3</td><td>NoOutputs</td><td>it pays nobody</td></tr>
    <tr><td class="n">4</td><td>TooManyInputs</td><td>past the network's limit</td></tr>
    <tr><td class="n">5</td><td>TooManyOutputs</td><td>past the network's limit</td></tr>
    <tr><td class="n">6</td><td>DuplicateInput</td><td>one note named twice</td></tr>
    <tr><td class="n">7</td><td>ZeroValueOutput</td><td>a note worth nothing</td></tr>
    <tr><td class="n">8</td><td>ValueOverflow</td><td>the outputs do not sum</td></tr>
  </tbody>
</table>

The shape is checked before any signature is verified, because the shape is
cheap and a signature is not.

Outputs MUST NOT exceed inputs. The difference is the fee, and it is claimed by
the block's coinbase or destroyed; there is no third destination.

### Coinbase

<table>
  <thead><tr><th>Field</th><th>Type</th><th class="n">Bytes</th></tr></thead>
  <tbody>
    <tr><td>version</td><td>u16</td><td class="n">2</td></tr>
    <tr><td>height</td><td>u64</td><td class="n">8</td></tr>
    <tr><td>outputs</td><td>sequence of note</td><td class="n">4 + 40m</td></tr>
    <tr><td>extra</td><td>sequence of u8</td><td class="n">4 + k</td></tr>
  </tbody>
</table>

The height is inside the coinbase and MUST equal the height of the block
carrying it, so the same coinbase cannot be replayed at another height. `extra`
is free bytes for a miner, bounded, and committed to like everything else.

A coinbase MUST NOT pay more than the schedule allows at its height plus the
fees the block's own transfers gave up. Paying less is permitted, and the
difference is destroyed rather than held anywhere.

## Blocks

<table>
  <thead><tr><th>Field</th><th>Type</th><th class="n">Bytes</th></tr></thead>
  <tbody>
    <tr><td>version</td><td>u16</td><td class="n">2</td></tr>
    <tr><td>network</td><td>u32</td><td class="n">4</td></tr>
    <tr><td>height</td><td>u64</td><td class="n">8</td></tr>
    <tr><td>previous</td><td>hash</td><td class="n">32</td></tr>
    <tr><td>transactions_root</td><td>hash</td><td class="n">32</td></tr>
    <tr><td>state_root</td><td>hash</td><td class="n">32</td></tr>
    <tr><td>history</td><td>hash</td><td class="n">32</td></tr>
    <tr><td>timestamp</td><td>u64</td><td class="n">8</td></tr>
    <tr><td>difficulty</td><td>u64</td><td class="n">8</td></tr>
    <tr><td>total_work</td><td>u128</td><td class="n">16</td></tr>
    <tr><td>nonce</td><td>u64</td><td class="n">8</td></tr>
  </tbody>
</table>

The header is a fixed 182 bytes. Nothing in it is optional and nothing is
variable-length, which is what lets a header log store them at a fixed stride
and what makes extending the header a different problem from extending anything
else in this protocol.

A block is its header, its coinbase, and its sequence of transfers. The
identifier of a block is the identifier of its header, and the header commits
to the body through `transactions_root`.

### The order a node applies the rules

This order is normative. Several of these rules are cheap and decisive and the
ones after them are not, so applying them out of order lets a sender spend a
node's time for nothing.

<table>
  <thead><tr><th class="n">#</th><th>Refusal</th><th>What it means</th></tr></thead>
  <tbody>
    <tr><td class="n">1</td><td>WrongNetwork</td><td>a header for another network</td></tr>
    <tr><td class="n">2</td><td>BeforeTheNetworkOpened</td><td>dated before this network existed</td></tr>
    <tr><td class="n">3</td><td>HeightOverflow</td><td>a height with no successor</td></tr>
    <tr><td class="n">4</td><td>SoftwareTooOld</td><td>the rules here need a build this is not</td></tr>
    <tr><td class="n">5</td><td>UnsupportedVersion</td><td>a version these rules do not know</td></tr>
    <tr><td class="n">6</td><td>WrongVersion</td><td>not the version the rules demand here</td></tr>
    <tr><td class="n">7</td><td>WrongGenesis</td><td>a first block that is not this network's</td></tr>
    <tr><td class="n">8</td><td>WrongHeight</td><td>not one above its parent</td></tr>
    <tr><td class="n">9</td><td>WrongParent</td><td>naming a block that is not the tip it follows</td></tr>
    <tr><td class="n">10</td><td>WrongDifficulty</td><td>not what the retarget demands</td></tr>
    <tr><td class="n">11</td><td>WorkOverflow</td><td>cumulative work with no room left</td></tr>
    <tr><td class="n">12</td><td>WrongTotalWork</td><td>not the parent's work plus its own</td></tr>
    <tr><td class="n">13</td><td>HistoryMismatch</td><td>not committing to the headers before it</td></tr>
    <tr><td class="n">14</td><td>InsufficientWork</td><td>the identifier does not meet the target</td></tr>
    <tr><td class="n">15</td><td>BlockTooLarge</td><td>past the byte limit</td></tr>
    <tr><td class="n">16</td><td>TimestampTooFarAhead</td><td>further ahead than the reader allows</td></tr>
    <tr><td class="n">17</td><td>TimestampNotAfterMedian</td><td>not later than the median before it</td></tr>
    <tr><td class="n">18</td><td>CoinbaseHeightMismatch</td><td>a coinbase for another height</td></tr>
    <tr><td class="n">19</td><td>TransactionsRootMismatch</td><td>a body the header does not name</td></tr>
    <tr><td class="n">20</td><td>StateRootMismatch</td><td>a state the header does not name</td></tr>
  </tbody>
</table>

**Fourteen is where the work is checked, and its position is deliberate.** It
comes after the header's own arithmetic, which costs nothing, and before the
body is looked at, which costs a great deal. A forged block therefore costs its
sender the work or costs the reader one hash.

**Sixteen is the one refusal in this list that two honest nodes can disagree
about.** It is measured against the reading node's own clock, so the same block
is refused by one node and taken by another, and the same node reverses its
verdict by waiting. A node MUST NOT remember this verdict as a property of the
block, and MUST NOT hold it against the peer that offered it. Every other
refusal here is a fact about the block that any node reaches from the same
bytes.

The body is evaluated between seventeen and eighteen: every transfer in order,
each producing `InvalidTransfer` or `InvalidSignature`, then the coinbase
against `CoinbaseOverpay`, then the eviction the block causes against
`TooManyEvictions`. A block MUST NOT both spend a note and evict it.

## Where this document is held to the code

Every statement above that names a layout or a number is checked against the
reference implementation by tests in
`crates/cairn-primitives/tests/audit_vectors.rs`. They pin the encoded bytes of
each structure and the identifier computed over them, so a change to either
side that the other did not make fails the build.

This is not a courtesy. Sixteen figures published by this project have turned
out to contradict the code, and in every case the defect was in the instrument
rather than in the thing measured. A specification is a published figure with
more surface than most.

Until round 19 the vectors pinned the twenty hash domains and the Merkle tree
and no encoding at all. A domain says how bytes are hashed; an encoding says
which bytes. Swapping two fields of the block header in both directions left
every round trip passing, left the record width the header log asserts, left
every domain vector green, and changed every block identifier ever computed.

## What the remaining parts will cover

Part 2, transactions and blocks: the shape of a transfer and a coinbase, what a
signature commits to, the block header, and every rule a block must satisfy in
the order a node applies them, each with the refusal it produces.

Part 3, the state: the two tiers, what the state root commits to, how eviction
chooses, the grace window, and the accumulator.

Part 4, consensus: difficulty and timestamps, emission, fork choice, burial,
and the rules that activate at a height.

Part 5, joining and the wire: the handover, sampled verification, the message
set, versions, and the allowance. This part states the threat model and the
failures a conforming node is permitted to have, which the whitepaper discusses
and no document currently specifies.
