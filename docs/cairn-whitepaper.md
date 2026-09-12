---
title: The Cairn Protocol
language: en
stylesheet: cairn-whitepaper.css
strap:
  A proof-of-work currency in which the state every node must hold is capped
  by consensus rule at a fixed size, and everything beyond that cap is
  carried in sixty four hashes.
byline: Draft, 31 August 2026
byline: [github.com/cairnchain/cairn](https://github.com/cairnchain/cairn)
byline: testnet-6, no mainnet exists
abstract: Abstract
footer: Cairn · draft whitepaper · 29 August 2026
footer: Nothing here is investment advice
footer: No mainnet exists
---

# Cairn: a chain whose validation state does not grow

Every deployed chain grows the state a validator must hold as it is used.
Bitcoin's unspent output set is past 170 million entries and roughly 11 GB;
Ethereum has pursued statelessness for years and its own documentation
places it several years from mainnet. The consequence is uncomfortable and
rarely stated plainly: the more a chain succeeds, the fewer people can
afford to verify it, and verification drifts toward the parties that can.

Cairn caps that cost by rule. A bounded hot set of 131 072 notes is held in
full by every node, measured at 516 bytes each, about 68 MB, and that
figure is a ceiling rather than an average. Everything older lives in an
append-only Merkle forest which a node carries as sixty four hashes,
whatever its size. Spending from it takes an inclusion proof supplied by the
spender and checked against roots the node already holds. Nothing is ever
destroyed, expired, or charged rent.

The design accepts a proven cost rather than claiming to escape it. Christ
and Bonneau show that a succinct global state forces a near-linear rate of
local proof updates <sup>[[1]](#r1)</sup>; Cairn falls on that
side deliberately, and confines the burden to notes that have not moved
recently, which on a busy chain means hours, not years: the hot set holds
a fixed number of notes, not a fixed span of time. Headers commit to accumulated work and to a forest of every
earlier header, so that joining the chain need not mean downloading it.

## The problem is the cost of verifying, not the cost of transacting

A permissionless currency works because many independent parties check
it. Nobody is in charge, so the checking is what prevents cheating. The
security of the system is therefore a function of how many people can
afford to be one of those parties.

That number falls as the chain succeeds. A full node holds the set of
unspent outputs and validates every rule against it, and that set grows
with adoption. Bitcoin's is past 170 million entries and roughly 11 GB
<sup>[[2]](#r2)</sup>. Ethereum's state has driven a research
programme spanning state expiry, weak statelessness and Verkle trees,
which its own roadmap places several years out and dependent on two other
unfinished efforts <sup>[[3]](#r3)</sup>.

The usual answer is that hardware gets cheaper. Perhaps, but the
direction is still wrong: the ratio between what a chain demands and what
an ordinary person owns moves against the person. Light clients do not
resolve this. They change who is trusted rather than removing the need to
trust.

<p class="claim">
  Cairn treats the growth of validation state as the design problem, not as
  an operational detail to be managed later.
</p>

## Notes, and why they are not balances

Cairn keeps notes rather than accounts. A note is a value locked to a
public key, identified by the transaction that created it and its index
among that transaction's outputs. It is written once and consumed once.
This is the unspent output model, as in Bitcoin.

The choice is not stylistic. An account balance must be read and written,
so the account has to be held. A note is created once and destroyed once,
which means a node can hold a commitment to it instead of the note
itself, and can forget it entirely while remaining certain about what
remains. Everything that follows depends on this property.

Ordering over note identifiers is defined, so the note set has exactly
one canonical enumeration, which the state commitment depends on.
Transfer identifiers exclude signatures and witnesses. That gives
malleability resistance, and more importantly it means a stale inclusion
proof can be replaced with a fresh one without changing any identifier
that anything else has committed to.

Hashing is BLAKE3 with a distinct derived key per domain, so a value
hashed as a note leaf can never be read as a header leaf or a Merkle
node. Signatures are Ed25519 with two restrictions beyond the standard:
small-order keys are rejected at construction, and non-canonical
encodings are refused, so two byte strings can never name one key. Every
signature commits to the network, the version, the transaction
identifier, the input index, and the value and owner of the note being
spent. Committing to the spent note is the lesson of transaction formats
that could be deceived about their own inputs.

## Two tiers, and only one of them is held

Validation state is split in two by a consensus rule.

<figure>
  <figcaption>Figure 1. What a node holds, at any age of the chain</figcaption>
  <div class="tiers">
    <div class="tier-row hot">
      <div class="tier-label">Hot set</div>
      <div class="tier-body">
        <b>Held in full by every node</b>
        Notes that have moved recently, in a sparse Merkle tree, capped at
        131 072 entries. When the cap is reached, the oldest are evicted at
        block boundaries by a rule every node applies identically.
        <span class="tier-figure">131 072 notes · 516 bytes each measured · 68 MB at capacity</span>
      </div>
    </div>
    <div class="tier-row cold">
      <div class="tier-label">Cold set</div>
      <div class="tier-body">
        <b>Held by nobody</b>
        An append-only Merkle forest of everything evicted. A node keeps
        its roots and nothing else. Spending from it requires an inclusion
        proof, supplied by the spender, verified against those roots.
        <span class="tier-figure">unbounded contents · 64 hashes · 2 kB, constant</span>
      </div>
    </div>
  </div>
  <p class="fig-note">
    The cap is consensus, not configuration. Two nodes disagreeing on it
    would evict different notes at the same height, produce different state
    commitments, and follow different chains while each believed it was on
    the same one.
  </p>
</figure>

### The hot set

A sparse Merkle tree, persistent through structural sharing so that a
reorganisation restores the previous root without a rebuild. Eviction is
by age, oldest first, in batches at block boundaries. The measured cost is
516 bytes per note, which is the note, its identifier, and its share of
the tree. Rather more than half of that is the tree, which makes a leaner
tree the clearest remaining optimisation; it changes no rule.

### The cold set

An append-only forest of perfect binary trees, held as one root per
possible height. This is the structure introduced by Utreexo
<sup>[[4]](#r4)</sup>, and Cairn does not claim it.

The property the whole design turns on is that adding a leaf requires
only the roots. A node holding none of the set can still extend the
accumulator correctly, which is not true of a plain Merkle tree. On
insertion the new leaf rides on the right of every merge, so the trees it
swallows are its own siblings in order, and the inclusion proof falls out
of the addition itself at no extra cost.

Removal is batched. Every proof in a block is verified against the
pre-block root before anything is applied, then applied in order with the
remaining proofs refreshed, so two cold spends in the same block cannot
invalidate each other.

### Where Cairn differs from prior accumulator work

Utreexo is a node-level optimisation. Any operator may adopt it
independently, the protocol is unchanged, and the underlying set remains
unbounded. Accumulator schemes over RSA groups, such as MiniChain
<sup>[[5]](#r5)</sup> and CompactChain
<sup>[[6]](#r6)</sup>, achieve constant-size commitments but
require a group of unknown order, meaning either a trusted setup or class
groups, and likewise leave the set unbounded.

Mina takes the opposite route to the same goal, compressing the entire
chain to about 22 kB with recursive zero-knowledge proofs
<sup>[[12]](#r12)</sup>. It works, and it is the most complete
answer to this problem in production. The price is proof of stake, with
the initial distribution that implies, and a cryptographic stack almost
nobody can audit. Cairn pays a different price for a weaker guarantee:
the state is bounded rather than eliminated, and everything used to do it
is old and widely understood.

Cairn's contribution is not the accumulator. It is the pairing of a
consensus-enforced cap on the held tier with an accumulator for the
remainder, so that what a validator must hold is bounded by rule rather
than by the operator's choice of implementation.

## Spending what nobody holds

A spender of a fallen note supplies an inclusion proof. The node verifies
it against roots it already has and never needs the set. Two windows make
this workable rather than merely correct.

### A proof is worth what it is worth now

A proof is checked against the cold set as it stands, and against nothing
else. Earlier versions accepted one matching any of the last thirty two
states, so that a transfer written while a block was being found was not
invalid through no fault of its author. That was half a rule. Removing a
note folds the empty leaf along the path the proof carries, and an old
path does not reach the root that is there now, so the removal did
nothing, reported it through a value no caller read, and the note stayed
to be spent again. Every node computed the same wrong state, so the
network agreed and nothing forked.

Completing the rule instead of removing it would mean carrying, as
committed state, whatever changed between an old root and the current
one. That is bounded, at roughly four megabytes, but it is bought for a
convenience that costs nothing to have another way. A transfer's
identifier excludes its witness by design, so refreshing a proof does not
make a different transfer. One that waited too long is the same transfer
offered again; the pool already drops what the state no longer accepts,
and a wallet already keeps its own proofs current as the forest grows.

### The grace window

A note that has just fallen remains spendable with no proof at all for
`GRACE_BLOCKS = 64` blocks, bounded also at
`GRACE_NOTES = 8 192` entries. Every node still holds both the
note and its proof during that window, so nothing is asked of the
spender. Without it the boundary between tiers would be a cliff that a
payer falls off for no reason of their own.

Utreexo has a comparable observation, that outputs created and spent
within one block need not enter the accumulator at all
<sup>[[4]](#r4)</sup>, and roughly 40% of outputs live fewer
than twenty blocks. There it is an optimisation each node may choose.
Here it is a rule the whole network applies, which turns a likelihood
into a guarantee for whoever is paying.

### Archivists

A wallet keeps its own proofs current from what every block already
carries, and asks nobody. A wallet that has been offline long enough, or
that has lost its records, needs someone who kept the cold set.
Archivists are optional nodes that do. Nobody pays them, and the network
does not depend on them: joining a chain takes the headers, which every
node keeps at 182 bytes each, and a wallet that kept its own proofs asks
no one. What an archivist offers is recovery for a wallet that lost
theirs.

They were in the design from the first day, for an intuition. Section 8
explains why they turn out to be structural rather than convenient.

What an archivist costs is a number that had never been written down,
and it is worth writing down beside the claim it is the exception to.
Measured over 3.2 million notes falling to the cold set, a plain node's
ledger stays flat between 15 and 20 MB, from 319 000 notes to ten times
that. An archiving node costs **exactly 64 bytes for every note that
has ever fallen**: the note's leaf, and the one inner node that leaf
completes, at thirty two bytes each. That is the size of the exception,
and it is the price of being able to rebuild a proof for somebody who
lost theirs.

That second figure is structural rather than measured, and saying which
is the point. What an archive holds is 64 bytes a note and does not
vary. What a process holding one occupies is more and moves about: the
hashes live in vectors that grow by doubling, so between two doublings a
vector carries up to its own length again in capacity nobody is using,
and occupancy swings between 64 and about 90 bytes a note as the set
grows. A slope read off a handful of points lands wherever those points
happened to fall on that swing, which is how the explorer came to serve
72 for the same quantity. The design costs 64. What a process costs is a
fact about an allocator.

The measurements here were first published wrong, and how is worth more
than the correction. They were read with `ps`, which reports
the pages a process has resident. A cold set is written once and never
read again, which is exactly what an operating system's memory
compressor takes away, so the instrument was measuring the one thing it
could not see: it reported 9 MB where the process was actually holding
204. A twenty-one-fold under-report, in the direction that flatters. The
figures above are read with the footprint the kernel actually charges.
The lesson is not that the first number was wrong, it is that a measured
number is worth exactly what the instrument is worth, and nobody had
asked what this one measured.

An audit found that the role had no protocol at all: nothing in the
message set let a wallet ask an archivist for anything, and the error a
stuck wallet showed named an archivist as though asking one were
possible. That is closed. A wallet now asks for the paths it is missing,
by position and not by name, so what it hands over is a list of places in
a set the archivist already holds in full; and it folds every answer
against the root its own node worked out from blocks it checked itself,
so the answer can come from a stranger.

What is left of it is narrower and is still a real hole. A path is asked
for by where the note sits, and where a note sits is learned as it falls.
A wallet that was not running when its note fell, and kept no record of
it, has nothing to ask about: the set is a list of hashes with no name
attached to any of them. That wallet's money is on the chain and is its
own, and nothing here can reach it. Compensating archivists remains open
as well, and is the lesser of the two.

## Consensus

### Proof of work, and why not stake

The reason is the beginning rather than the steady state. Proof of stake
requires an initial distribution before it can function, which means
somebody decides who holds influence on day one. Proof of work requires
nobody to decide anything: the network opens and the first block goes to
whoever mines it. For a currency whose claim is that no party is
privileged, the opening is exactly where that claim is tested.

### Difficulty and timestamps

Difficulty retargets every block over a linearly weighted moving average
of the previous 90, with solve times clamped at six times the target in
either direction and a maximum factor of four per retarget. A large miner
arriving or leaving changes the rate without stranding the chain.

In either direction is the load-bearing part, and it was not there at
first. A solve time was read as the gap from the parent, floored at one
second, which made lying about time asymmetric: a miner dating its own
blocks six minutes ahead took six minutes out of the measurement, and the
honest block that followed put one second back. The retarget then read a
chain running far slower than it was and answered by lowering the
difficulty, and since the arithmetic does not depend on the difficulty
there was no level at which it settled. Past roughly a sixth of the hash
rate the difficulty fell to its floor within the hour, at which point
cumulative work stops measuring electricity and the fork choice stops
meaning anything. The measurement now runs along a timeline of its own
that moves only by what it counted, so a spike is repaid in full by the
blocks after it and a window telescopes to the distance between its own
ends however its middle was stamped. Simulated against every share up to
a half, the fastest a liar can now make the chain run is the target.

Timestamps are validated against the median of the previous 11 blocks
rather than against the parent. A miner writes its own timestamp but holds
one vote in a median, which removes the single-block manipulation that a
later-than-parent rule permits. A block may not be dated more than two
hours ahead of the receiving node's clock, nor before the moment the
network opened.

### Fork choice

By cumulative work, not length. Ties keep the branch already followed, so
churning the tip costs work rather than nothing. A switch is applied
atomically: each applied block records its own inverse, and a bad block
discovered partway through a switch returns the node exactly where it
was.

Undo records are kept for the most recent
`MAX_REORG_DEPTH = 1 024` blocks. The switch is refused at the
network’s own burial, which is the same 1 024 here and which is
what a handover is anchored at and what a reward matures at. Those three
are one number on purpose: a node that undid past its burial would hand a
newcomer a ledger anchored at a block it went on to orphan, and would
take back a reward its own rules had called spendable. Keeping records
further back than the refusal would be harmless, and a shorter test
network makes use of that.

The depth itself is a local safety policy rather than a consensus rule:
two nodes with different limits build the same chain and differ only
after a reorganisation deeper than either would accept, which on a live
network means an attack or a partition lasting most of a day.

## Emission

Nothing is allocated. There is no sale, no founder allocation and no
reserve; on the day a network opens the supply is zero and every unit
since has been paid for the work of finding a block. The first blocks of
both existing networks pay nobody at all.

The reward begins at 50 CAIRN and halves every 1 051 200 blocks, about two
years at a one minute block time, until halving would take it below a
floor of 0.01 CAIRN, which is then paid indefinitely. Roughly 105 million
CAIRN exist by the time the floor takes over. The smallest unit is the
pebble, at 10<sup>8</sup> to one CAIRN.

The perpetual tail is deliberate. Whether transaction fees alone can fund
security in the long run is an open question, and a chain whose central
promise is verifiability in thirty years cannot rest its security budget
on an open question. The price is a known, small and permanently
decreasing rate of dilution.

A block reward cannot be spent until its block is past the deepest
reorganisation the rules accept. It is the one kind of note whose
existence depends on its own block surviving: a payment undone by a
reorganisation can be mined again on the branch that won, a reward
cannot. Without the wait, a two-block reorganisation took back money
somebody had already been paid, with no rule broken and nothing to
complain, which is why it is a rule here rather than a convention. The
question is asked of the coinbase every note names, not of the tier the
note is sitting in, because the hot set, the grace window and the cold
set are three ways of holding the same note and a rule covering one of
them would be a way to launder the other two.

The state root carries the money as well as the notes. A node can say
how much exists and a header commits to the answer, so a defect that
minted a pebble is a fork rather than something every node agrees about.
That is not hypothetical: this chain was renumbered once for a defect
whose own description reads *money out of nothing, agreed by every
node, so nothing forked and nothing complained*. Eight bytes and one
checked addition per block buys the ability to notice.

## Joining a chain without downloading it

A bounded steady-state cost is not the whole promise if arrival is
unbounded, and this is where the design was weakest.

### The measured cost of arrival

On this implementation, at one block per minute with blocks carrying 64
ordinary payments, thirty years of chain is 197 GB to download and about
19 hours to revalidate on one core, to arrive at a validation state
weighing 68 MB. The wall is bandwidth, not computation.

### What headers commit to

Every header carries two fields beyond its own block, for 48 bytes:

**Accumulated work.** The work behind this block and every
block before it, checked against the parent's, so a block cannot claim
work it did not do.

**A commitment to every earlier header.** The root of an
append-only forest holding one leaf per header, carried by a node as
sixty four hashes exactly like the cold set, at a cost of one append per
block.

These were added before any network carried value, because they could not
be added afterwards: changing the shape of a header invalidates every
block already mined. The test network took the next number when they
landed, which cost nothing at the time and would have cost everything
later.

### What sampling does not settle

Weighing settles which chain carries the most work. It settles nothing
about what that chain's ledger says, and the two are easily confused. A
header commits to a state root, and proof of work says that somebody
spent electricity on those bytes, not that the state in them is what
honest transactions would have produced. A node that read the chain knows
the difference because it watched every transaction go past. A newcomer
has watched none.

So a newcomer that took the ledger of the heaviest tip would be buying an
arbitrary ledger for the price of one block: mine one on top of the real
chain, commit to any state you like, be heaviest for the moment somebody
arrives. The honest network is unharmed (every node that read the chain
rejects that block on sight), but the newcomer, which is the party this
whole construction exists to serve, is not.

Cairn does not take a ledger at the tip. It takes one from
`BURIAL = 1 024` blocks below it and validates every block in
between itself, checking every rule as any node does. A lie must
therefore be buried that deep, and to be that deep while still being the
heaviest chain on offer, its author had to out-mine everybody else for as
long as it took to build them. That is the assumption the chain already
rests on. The arrival stops being the weak part, and it stops being a
light client: what a newcomer ends on is a ledger it built, from a
starting point nobody could have written without doing the work.

The depth is the same as the deepest reorganisation a node accepts, so a
newcomer lands exactly where a node that was away and came back lands,
with the same ability to be moved off it by a heavier chain. What it
costs is the blocks in between, once, and that cost does not grow with
the chain: in thirty years it is still a thousand blocks.

### Sampled verification

One assumption is load-bearing here and was not stated before: that at
least one of the peers a newcomer is talking to is honest and can answer.
Joining is trust-minimised, not trust-free. Every chain offered proves
its own work, and the checks below are what make that true rather than
merely intended, but a newcomer surrounded entirely by one party's nodes
is shown only what that party chooses to show. That is the same assumption every proof-of-work client makes at
the moment it first connects, and it is worth writing down rather than
implying it away.

With those commitments, a newcomer holding only the tip can be handed a
logarithmic sample of old headers, verify that each sits where it claims
in the tip's commitment, and conclude what work stands behind the tip
without reading the headers in between. This is FlyClient
<sup>[[7]](#r7)</sup>, whose security rests on the same
assumption as the chain itself, that no adversary controls a majority of
the work.

The earlier superblock approach, NIPoPoW <sup>[[11]](#r11)</sup>,
achieves a similar compression by showing only unusually heavy blocks,
but is vulnerable to bribing the miners who find them into withholding
them. FlyClient's sampling has no equivalent target and is the
construction to follow.

Cairn takes the published construction with its proven distribution
rather than devising its own. It is implemented: a newcomer draws 4 096
headers against accumulated work rather than height, with a Fiat-Shamir
seed taken from the tip, and each opened header is checked against the
tip's own commitment. Weighing a thirty year chain costs about 3 MB, of
which the run described below is 200 kB.

Four checks sit around the draw, and they are not decoration. An audit
of the implementation found that without them a stranger could hand a
newcomer a chain nobody had mined, for a single hash. It took the honest
chain's headers, which any node serves to anyone who asks, put them in a
commitment of its own, appended a thousand leaves that were not headers
at all, and mined a tip at the difficulty floor declaring one unit more
work than the honest chain. Every draw landed in the honest work below
and every one was answered by a genuine header with a genuine proof. The
lesson is worth stating plainly: a commitment places a header at a
position, and a position is not a chain.

So the tip must open the header it was built on, at the height below it,
carrying the work its own total leaves over, which a tip mined on nothing
cannot produce. A number of blocks implies a least amount of work,
because the difficulty falls by at most a fixed factor per block and
never below the floor, so the stretches between opened headers cost
something whether or not a draw looked at them: a thousand blocks cannot
be worth one hash. And the run of headers between a handed-over ledger
and the tip travels with it, so a newcomer rebuilds the commitment from
the anchor upward and sees whether it arrives where the tip says it
should, which catches a substituted header wherever it sat.

That last one is also what makes the burial cost work rather than block
count. The run is checked block by block against the difficulty its own
window demands, so the sender does not choose the price of its burial:
before that check existed, a thousand blocks of burial could be laid at
the difficulty floor for a thousand hashes, and the phrase bought
nothing.

Those three were written first and were not enough, which is worth
recording rather than tidying away. The draw deliberately stops
resolving about a thousand blocks from the tip, and nothing else looked
up there either. So a forger left the honest chain untouched, appended
its own headers at the difficulty floor, one hash each, and put the work
it was inventing inside the band the draw never reaches. Every check
above passes: the tip has a parent, because the forger mined one; the
blocks between opened headers are worth what they say, because a cheap
run honestly states that it is cheap; and the ledger's own run reaches
the tip, because the whole run is the forger's. The anchor a newcomer is
handed is then one of its headers, with whatever ledger it likes.

What was missing is that the top of a chain was tied to no difficulty
anybody could check. So the run from the deepest header the draw
actually landed on, up to the tip, travels with the weighing and is
walked under the retarget: each header carries the difficulty its window
demands, dates after that window's median, and adds its own work. The
window below the pinned header comes along too and is honest by
construction, because those headers have to chain into it, and swapping
them would mean having mined the pinned header on top of one's own.

The tip's timestamp is then measured against the reader's own clock,
which is what turns the whole thing into a cost. Blocks at the
difficulty floor have to be spaced at the target or the retarget demands
more of them, so the thousand cheap blocks a forger needs span most of a
day of stated time, and they cannot be backdated because they have to
date after the honest window they descend from. More than two hours
ahead of the reader is refused. What the attack costs is therefore real
waiting, and the honest chain out-mines it while it waits.

That run is capped, at 8 282 headers, about 1.5 MB, and the cap is a
real limit rather than a formality: past it a chain cannot be weighed at
all, and a newcomer reads it block by block instead. The run is a band of
work rather than a distance from the tip, so its length in blocks is that
band divided by the difficulty at the tip, and it grows as the tip's
difficulty falls below what the chain averaged over its life. Measured
over this implementation's own draw, on chains from three months to
thirty years old: a chain that loses twenty four to forty eight times its
hash rate, depending on its length, and does not recover cannot be
weighed from about five days after the loss until months or years after
it. While that lasts, every honest node answering is refused in the same
words a forger would be. The cap is kept rather than raised, because
raising it moves the cliff instead of removing it: the same measurement
puts the run a thirty year chain needs a year after a four thousand fold
loss at 526 033 headers and 96 MB, sixty three times the cap, and nothing
in the shape of the problem stops the next chain needing more: the run is
work divided by a difficulty whose only floor is one. Every metre of
whatever number were chosen instead would be memory a stranger decides a
newcomer will allocate before one check about the chain has been made.
What the cap costs is the shorter way in, not the chain.

The count follows from the assumption the chain already makes. A forger
cannot mine what it did not mine, so a chain heavier than the honest one,
presented by a party holding a share *s* of the world's work, has
at least *1 − s/(1−s)* of itself invented: work no
block of it spans. At a third of the world's work that is half the chain.
What does not follow (and an earlier version of this paper said it did)
is that a draw lands in that invented part with the same probability. It
would if the draw were uniform, and it is deliberately not: the density is
one over the distance from the tip. That is what makes the bound
indifferent to how deep a forger forks, and its price is a factor of the
number of halvings on every draw. A draw lands in the gap with probability
*ln(1/(1−lie)) / levels*, not *lie*, and that factor is
the whole of the correction.

**That factor is an input, and for six networks it was one a prover wrote
down.** *levels* is the number of halvings the draw spreads over, and it
was computed from the height the tip states. A height is not work: the only
rule holding the two together prices a stretch nobody opened at the
difficulty floor, one unit a block, and a forest of any size costs what is
opened in it and nothing for the rest. So a chain whose blocks averaged
difficulty *d* could state a height *d* times its own, buy *log2(d)*
halvings with it in work it was already inventing, and take that many
slices off what every draw was worth. At a real chain's numbers that is
fifty odd halvings against the fifteen the count is set for, and it took a
forger at 40% from missing every draw with 2^-207 to missing them with
2^-58, against the 2^-128 this paper publishes. The count now comes from
how old the tip says its chain is, over the block time the network aims at,
and never past its height. A node refuses a tip more than two hours ahead
of its own clock and the opening moment is written into the software, so no
chain can say it is older than the network: a prover reaches the honest
count rather than passing it. Understating it is left open and buys
nothing, because fewer halvings make every draw worth more and widen the
band nearest the tip, which is the run of headers the prover then has to
hand over in full.

Setting the count from the real expression gives 4 096 draws, holding
against every forger up to at least 42.96% of the world's work over a
thirty year chain, measured against the function this implementation
ships, and against forgeries built and put through the check. At least,
and the word is exact: the figure is a maximum over hundreds of
placements, each a hit rate taken over a finite number of seeds, and a
maximum over noisy estimates runs high, so the threshold reads low and
reads lower the fewer seeds are spent. It is published as a floor. This paper claims 40%,
keeping the rest for the difference between a staircase of halvings
and the smooth density it stands for. Past 50% nothing helps: a forger at
half the work has nothing left to invent and can mine the chain.

**The guarantee is a depth, and it is worth stating as one.**
The draw stops resolving 512 blocks from the tip, deliberately, because
resolving finer would cost the count again to separate chains nothing else
here separates either. So a forger cannot put a newcomer on a branch
differing from the real one by more than about 633 blocks (ten hours).
Inside that it can, and so can a slow peer: it is where any node sits for
its first blocks after connecting.

**That depth is the same whatever share of the work the forger holds, and
this paragraph used to imply otherwise.** Measured over the shipped draw, a
forger at 5% of the world's work reaches exactly the depth a forger at 40%
reaches: 633 blocks in both cases, and at every share between. The reason
is that the crossing sits below the deepest band the draw resolves, where
the overlap does not depend on the share at all. So the 40% is not a bound
on how far a newcomer can be moved. It is the point past which there is no
bound: past the share the count holds to, the same measurement gives
millions of blocks. The failure is a cliff and not a slope, and a reader
who took "a forger at 40%" to mean a weaker forger does less damage was
reading something this paper did not check.

**That depth sits inside the node's own reorganisation limit, and getting
the two to line up is what the 512 is for.** `MAX_REORG_DEPTH` is 1 024
and the effective undo limit is the lesser of that and the network's
burial, so a newcomer put on a branch at the far end of the guarantee is
somewhere the ordinary reorganisation rule can carry it back from. It was
not always so. The draw stopped at 1 024, the same number, which looked
like the two rules agreeing and was not: the guarantee is not the band, it
is the band plus what the staircase costs at its edges, and that measured
1 240 against a limit of 1 024. This paper stated that gap and named three
ways of closing it. The first of them is what was done, and what it cost is
one more level of halving: a draw is now worth a fifteenth of a uniform one
rather than a fourteenth, which takes the share the count holds to from
43.37% to 42.96%. The published 40% did not move, and an earlier version of
this paragraph said the opposite of all of it, that the depth was shallower
than the deepest reorganisation, which its own two figures at the time
refute.

The first version of this paper claimed 512 draws and 45.7%, on the
assumption that a draw lands in invented work with probability
*lie*. Measured against the shipped function, the placement that
suits a forger best left that at 2<sup>-5.8</sup> rather than
2<sup>-128</sup>. The count and the density above are the correction; the
claim went from 45.7% to 40%, and the cost went up eightfold with the
draws.
None of this is a proof in the other direction: it is a measurement over
one family of placements, made in-house, and it is the part of this design
that most wants an outside eye.

Measurement checks the derivation the other way, by forging chains and
watching them fail, and it also shows why the distribution must be taken
and not improvised: under a uniform draw, a forger who keeps the real
chain and fakes only the last twenty blocks goes unnoticed 88% of the
time, which is precisely why FlyClient samples the recent end of the
chain more densely.

Serving that sample takes the headers and the forest they make, which a
node keeps on disk at 182 bytes a header and 64 for its place in the
forest: 129 MB a year, against 50 GB a year for Bitcoin and 200 for
Ethereum. Every node keeps them, so joining a chain does not depend on
anyone volunteering to carry its history.
Blocks a node has already applied are dropped once it has written down
the ledger they add up to, which is what stops a node's disk from growing
with the chain.

One practical note in Cairn's favour. A production study of FlyClient
reports that proof size is dominated by header size, and that
restructuring headers would reduce proofs by 71% at the cost of a
consensus change the chain it studied can no longer make
<sup>[[8]](#r8)</sup>. That chain's header is 1 487 bytes, of
which 1 344 is one Equihash solution. A Cairn header is 182 bytes, which
is the same lesson taken before rather than after.

## The limit that applies, and where Cairn falls

Christ and Bonneau prove an information-theoretic result about any system
of this shape <sup>[[1]](#r1)</sup>: there is no useful
trade-off point. A system must either hold a global state linear in the
number of accounts, or require a near-linear rate of local proof updates
as coins are spent. They add, and this bears directly on the design here,
that so long as the succinct state is too small to capture the full
state, enlarging it helps little.

<p class="claim">
  Cairn falls on the proof-update side of that dilemma, deliberately, and
  had accepted the cost before knowing it was proven inevitable.
</p>

A wallet refreshes its own proofs from what every block already carries.
The hot set does not repeal the result; what it changes is who is
affected. Notes that have moved recently, which are the ones ordinarily
spent, are held in full by every node and require no proof at all. The
obligation falls only on value that has not moved recently. How recently
is worth stating plainly rather than leaving to the word: the hot set is
capped at a *number* of notes, so how long a note stays in it
depends on how busy the chain is. Measured at full blocks (686 payments
a block, which is what success looks like), a note falls to the cold set
in **3.2 hours**, and the grace window that follows lasts
about twelve minutes. At a tenth of that traffic it is 32 hours, and at a
hundredth, thirteen days.

So the honest statement is that the validator's cost is capped and the
saver's inconvenience is not: the busier the chain, the more of anyone's
money needs an inclusion proof to spend. That is the Christ–Bonneau cost
this design accepts rather than escapes, and it lands hardest exactly
when the chain succeeds. A wallet that stays online refreshes its own
proofs and never notices. One that does not must keep them, or find
somebody who did.

The authors name proof-serving nodes, third parties holding the full
state and producing current witnesses for others, as the natural
relaxation, and call for work on how such parties would be compensated.
Those are Cairn's archivists. They were included for an intuition and
turn out to be structural.

Cairn does not answer the compensation question; it narrows what rests on
it. Two services were bundled under the name: showing a newcomer which
chain carries the most work, which the network cannot do without, and
rebuilding the proof of a note whose owner lost theirs, which it can. The
first was separated out and made small enough that every node performs
it (182 bytes a header and 64 for its place in the forest, 129 MB a
year), so nothing in the protocol now depends on a party being paid. What
is left is recovery for a wallet that kept no records, and a wallet that
keeps its own needs no one.

## What this borrows, stated plainly

Overclaiming is the fastest way to lose the only readers whose opinion
matters.

The append-only forest carried by its roots is Utreexo's
<sup>[[4]](#r4)</sup>. Spender-supplied inclusion proofs are
the common model of Utreexo, MiniChain and CompactChain. The header
commitment and work-weighted sampling are FlyClient's
<sup>[[7]](#r7)</sup>. The archivists are the proof-serving
nodes of Christ and Bonneau <sup>[[1]](#r1)</sup>, arrived at
independently. None of the cryptography is novel, and it is not meant to
be: BLAKE3 and Ed25519, both with domain separation and canonical
encoding enforced, and no trusted setup anywhere.

What a survey of the field did not find an equivalent of: a hot set
capped by consensus rule; the two tiers paired, holding a bounded set in
full while carrying the remainder in constant space; a grace window as a
network rule rather than a per-node cache; and bounding state without
destroying anything. Ergo charges storage rent and lets a miner take a
box left idle for four years <sup>[[9]](#r9)</sup>; a December
2025 proposal to the bitcoin-dev list would render outputs below a moving
floor permanently unspendable <sup>[[10]](#r10)</sup>. Both
bound the state by removing value from its owner, which the first
guarantee here forbids.

A search is not proof of absence, and this section should be read as a
claim about what was found rather than about what exists.

## Parameters and measurements

Every figure below is measured on the implementation rather than
estimated, on one core of an ordinary machine.

<div class="params">
  <div><span class="k">Hot set capacity</span><span class="v">131 072 notes</span></div>
  <div><span class="k">Bytes per hot note, measured</span><span class="v">516</span></div>
  <div><span class="k">Hot set at capacity</span><span class="v">68 MB</span></div>
  <div><span class="k">Cold set carried by a node</span><span class="v">64 hashes, 2 kB</span></div>
  <div><span class="k">Grace window</span><span class="v">64 blocks, 8 192 notes</span></div>
  <div><span class="k">Difficulty window</span><span class="v">90 blocks, LWMA</span></div>
  <div><span class="k">Median time past</span><span class="v">11 blocks</span></div>
  <div><span class="k">Maximum retarget</span><span class="v">factor 4</span></div>
  <div><span class="k">Maximum reorganisation depth</span><span class="v">1 024 blocks</span></div>
  <div><span class="k">Burial before a ledger is taken</span><span class="v">1 024 blocks</span></div>
  <div><span class="k">Coinbase maturity</span><span class="v">1 024 blocks</span></div>
  <div><span class="k">Initial reward</span><span class="v">50 CAIRN</span></div>
  <div><span class="k">Halving interval</span><span class="v">1 051 200 blocks</span></div>
  <div><span class="k">Tail reward</span><span class="v">0.01 CAIRN, perpetual</span></div>
  <div><span class="k">Header size</span><span class="v">182 bytes</span></div>
  <div><span class="k">Ordinary payment</span><span class="v">191 bytes</span></div>
  <div><span class="k">Empty block</span><span class="v">244 bytes</span></div>
  <div><span class="k">Block with 64 ordinary payments</span><span class="v">12 468 bytes</span></div>
  <div><span class="k">Validation, empty block</span><span class="v">0.016 ms</span></div>
  <div><span class="k">Validation, 64 payments</span><span class="v">4.4 ms</span></div>
</div>

<div class="scroll">
  <table>
    <caption>Thirty years of chain at one block per minute, blocks carrying 64 ordinary payments</caption>
    <thead>
      <tr>
        <th>Quantity</th>
        <th class="n">Size</th>
        <th>Bounded?</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>All blocks, to download</td>
        <td class="n">197 GB</td>
        <td>No, grows with history</td>
      </tr>
      <tr>
        <td>All headers, to read</td>
        <td class="n">2.9 GB</td>
        <td>No, grows with history</td>
      </tr>
      <tr>
        <td>Revalidating from genesis</td>
        <td class="n">19 h</td>
        <td>No, grows with history</td>
      </tr>
      <tr class="us">
        <td>Validation state a node holds</td>
        <td class="n">68 MB</td>
        <td>Yes, by consensus rule</td>
      </tr>
      <tr class="us">
        <td>Blocks a node may hold to undo</td>
        <td class="n">233 MB</td>
        <td>Yes, by the block size and window</td>
      </tr>
      <tr class="us">
        <td>Headers a node keeps on disk</td>
        <td class="n">3.9 GB</td>
        <td>No, 129 MB a year</td>
      </tr>
      <tr class="us">
        <td>Cold set a node carries</td>
        <td class="n">2 kB</td>
        <td>Yes, whatever its contents</td>
      </tr>
      <tr class="us">
        <td>Header history a node carries</td>
        <td class="n">2 kB</td>
        <td>Yes, whatever the height</td>
      </tr>
    </tbody>
  </table>
</div>

<p class="fig-note">
  The first three rows are what arriving used to cost, and section 7 is how
  it stopped costing that. Arriving now has three parts, and it is worth
  adding them up rather than quoting the smallest: about 3 MB to weigh the
  chain, about 12 MB for the ledger, and the thousand blocks between that
  ledger and the tip, which a newcomer validates itself. Those blocks are
  at most 134 MB, the block size limit a thousand and twenty four times
  over, and in practice far less, since a block is only as large as the
  traffic that filled it: call it 20 MB on a quiet chain. Against a hundred
  and ninety-seven gigabytes of reading, and none of the three grows with
  the chain's age.
</p>

<p class="fig-note">
  Seven of the figures above were wrong until this draft, and how is worth
  more than the correction. A block carrying 64 payments was published at
  3 211 bytes. The program that measured it asked for 64 transfers a block
  and could fund only 16, because a coinbase carries at most 16 outputs and
  the purse it spent from was refilled by the coinbase alone; so a figure
  labelled 64 was the cost of 16, and the thirty-year download built on it
  was short by four times over. Underneath that, the block sizes and the
  timings were taken before headers carried the two commitments described
  in 7.2. The header row was corrected for those 48 bytes and the block
  rows were not, so the table disagreed with itself by exactly the number
  it stated a page earlier. Both are the same failure as the memory
  readings in 4.3: not arithmetic, but nobody asking what the instrument
  was pointed at. The figures here are now checked against the running
  build every time the tests are run.
</p>

## Limitations

**Nothing here has been audited.** No external review has
taken place. The only network in existence is a test network whose
currency is worthless by design and which will be reset.

**A node that started from a handed ledger is not the same node as
one that read the chain.** A validator that applied every block
from the first refuses an invalid history however much work stands behind
it, and no amount of mining takes that from it. A node that started at an
anchor has that property for every block above the anchor and not for the
blocks below it: for those it has the work, and the commitments the
headers carry, and nothing else. The difference is invisible until
somebody out-mines the network for the length of the burial, which is the
assumption the chain already rests on, so the fast start adds no new one.
What it does is turn a check that held against any amount of work into
one that holds against less than a majority of it, and that is worth
saying rather than leaving to be inferred.

**The block by block way in needs blocks somebody kept.**
It is named above as what a newcomer falls back to when a chain cannot be
weighed, and it checks more rather than less, which is true. What is also
true is that an ordinary node keeps a bounded number of bytes of blocks
and drops the rest once its ledger is written, and no rule obliges anyone
to keep more. Headers are kept for ever and a header does not rebuild a
body. So the fallback rests on somebody having chosen to archive, and on
a newcomer being able to find them. A node says what its own retention
costs a newcomer when asked, which is the half an operator can act on;
the other half, finding an archivist on a network that has none, is not
solved here.

**The sampling bound is measured, not proved.** 4 096 draws
hold to 40% of the world's work and a depth of about 633 blocks, and
both figures come from measuring the placement a forger would choose
rather than from a theorem. The first version of this claimed 512 draws
and 45.7% from a derivation that assumed a uniform draw; measurement put
it at 2<sup>-5.8</sup> instead of 2<sup>-128</sup>, which is how the
correction was found. That the same thing is not still hiding one level
down is exactly what nobody outside this project has checked, and it is
where an outside review should start.

There is a second reason to start there. The next thing found was not in
the bound at all but beside it: the sampling was sound about how much
work a chain carried and said nothing about whether the tip stood at the
end of that chain, which let a forger borrow a weight somebody else had
mined. Three checks close it and they are described in 7.4. What is worth
taking from the episode is that the failure was not in the arithmetic
everybody looks at. It was in an assumption the arithmetic never made and
the surrounding code quietly relied on.

**A chain that loses most of its miners cannot be weighed while it
recovers.** The run of headers a weighing carries is capped at
8 282, and a chain whose difficulty at the tip has fallen far below its
lifetime average needs a longer one. Measured over this implementation's
own draw: a loss of twenty four to forty eight times the hash rate,
depending on the chain's length, puts a chain out of reach of the short
way in from about five days after the loss until months or years after
it. Nothing is lost and nobody is attacked. Newcomers read the chain
block by block, which checks more rather than less; what it costs is the
bandwidth and the hours the sampling exists to save, at the moment a
chain is least able to spare either. The cap is deliberate, because the
run needed has no bound of its own. What was wrong, and is mended, is
that a node meeting it told nobody: the two refusals were discarded where
they were made, so an operator saw a node asking peers, dropping them and
taking hours, with no reason anywhere. It now says, when several peers
fail in the same words, that the chain in front of it is what those
failures have in common.

**A rule changes at a height, and a node that has not updated by
then is on another chain.** Renumbering the network, which is what
the test networks did three times, throws every balance away with the
chain; on a network carrying value that is not a mechanism but a loss. So
a rule that changes names the height it takes effect at, and blocks below
it go on being judged by the rule that judged them: nothing already mined
becomes invalid. Nobody votes on it. The height is in the software,
published long before it arrives, and miner signalling is refused for the
reason proof of stake is: it would hand whoever mines a veto over the
rules. What none of that fixes is the node that did not update: it is
following a chain the network has left. It is told which version it
lacks, and stops, because a wallet reading a balance off an abandoned
chain answers confidently and wrongly.

**A node that joined cannot take in a newcomer.** Showing
which chain carries the most work takes the headers from the first block,
and a node handed a ledger has them only from where it was handed on. It
can become one by reading the chain; nothing else is lost.

**The theorem's cost is real.** A wallet offline long enough,
or one that lost its records, must ask an archivist. Nobody is paid for
that service and the network runs without it, which bounds the problem
rather than solving it: a wallet in that position depends on someone
having chosen to keep the cold set.

**Smaller.** An archivist rebuilds a proof in time
proportional to the depth of the set rather than its size. Over half of
what a hot note costs is the tree that commits to it, which is where the
room left is.

The implementation is roughly 44 700 lines of Rust with 1 235 tests, no
unsafe code, no asynchronous runtime, and five dependencies. Arithmetic
side effects, slice indexing, and panicking helpers are denied at the
workspace level. It is small enough to be read, which is the point: a
chain asking people to verify for themselves should be verifiable in
more than one sense.

## References

<ol class="refs">
  <li id="r1">
    M. Christ and J. Bonneau. <em>Limits on revocable proof systems, with
    applications to stateless blockchains.</em> Financial Cryptography and
    Data Security, 2023.
    <a href="https://eprint.iacr.org/2022/1478">eprint.iacr.org/2022/1478</a>
  </li>
  <li id="r2">
    Bitcoin Optech. <em>Utreexo topic page</em>, UTXO set size figures.
    <a href="https://bitcoinops.org/en/topics/utreexo/">bitcoinops.org/en/topics/utreexo</a>
  </li>
  <li id="r3">
    Ethereum Foundation. <em>Statelessness, state expiry and history
    expiry.</em>
    <a href="https://ethereum.org/roadmap/statelessness/">ethereum.org/roadmap/statelessness</a>
  </li>
  <li id="r4">
    T. Dryja. <em>Utreexo: a dynamic hash-based accumulator optimized for
    the Bitcoin UTXO set.</em> MIT Digital Currency Initiative, 2019.
    <a href="https://eprint.iacr.org/2019/611">eprint.iacr.org/2019/611</a>
  </li>
  <li id="r5">
    <em>MiniChain: a lightweight protocol to combat the UTXO growth in
    public blockchain.</em> Journal of Parallel and Distributed Computing,
    2020.
  </li>
  <li id="r6">
    <em>CompactChain: an efficient stateless chain for UTXO-model
    blockchain.</em> Frontiers of Computer Science, 2023.
    <a href="https://arxiv.org/pdf/2211.06735">arxiv.org/abs/2211.06735</a>
  </li>
  <li id="r7">
    B. Bünz, L. Kiffer, L. Luu and M. Zamani. <em>FlyClient: super-light
    clients for cryptocurrencies.</em> IEEE Symposium on Security and
    Privacy, 2020.
    <a href="https://eprint.iacr.org/2019/226.pdf">eprint.iacr.org/2019/226</a>
  </li>
  <li id="r8">
    <em>Catching the Fly: practical challenges in making blockchain
    FlyClient real.</em> 2026.
    <a href="https://arxiv.org/html/2604.26736v1">arxiv.org/abs/2604.26736</a>
  </li>
  <li id="r9">
    Ergo Platform. <em>Storage rent.</em>
    <a href="https://docs.ergoplatform.com/dev/protocol/storage-rent/">docs.ergoplatform.com/dev/protocol/storage-rent</a>
  </li>
  <li id="r10">
    <em>Reducing RAM requirements with dynamic dust.</em> bitcoin-dev
    mailing list, December 2025.
    <a href="https://groups.google.com/g/bitcoindev/c/PMtM_I3qwqg/m/CsbaSXRaCwAJ">groups.google.com/g/bitcoindev</a>
  </li>
  <li id="r11">
    A. Kiayias, A. Miller and D. Zindros. <em>Non-interactive proofs of
    proof-of-work.</em> 2017.
    <a href="https://eprint.iacr.org/2017/963.pdf">eprint.iacr.org/2017/963</a>
  </li>
  <li id="r12">
    O(1) Labs. <em>Mina: a 22 kB blockchain, technical reference.</em>
    <a href="https://minaprotocol.com/blog/22kb-sized-blockchain-a-technical-reference">minaprotocol.com</a>
  </li>
</ol>
