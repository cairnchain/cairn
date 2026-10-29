---
title: Cairn, the open questions
language: en
stylesheet: cairn-design.css
strap:
  Three questions an *outside review* asked, and the position taken on
  each.
byline: Open questions · v1.3
byline: 31 August 2026, revised 7 October 2026, translated from the French 29 October 2026
byline: [The French original](https://github.com/cairnchain/cairn/blob/main/docs/cairn-open-questions.fr.md), served at /open-questions/fr
byline: Completes the design document
numerals: roman
subsections: unnumbered
footer: Cairn · open questions v1.3
footer: Status: positions taken, open to argument
footer: Nothing in this document is investment advice
---

# CAIRN

## The frame | Three omissions, not three bugs

<p class="lede">An outside design review named three things a currency has to deal with and that our documents had never dealt with. Nothing breaks, nothing leaks: they are silences. Checked against the code, the review is right on all three.</p>

The three: what the chain shows about its users; what a quantum computer
could one day take from it; and whom the saver who comes back after years
away depends on. The review puts the first two in the first rank, and judges
the third more serious than our papers say.

The rule of this document is the rule of all the others: what follows is
established from the code, not from our own papers, every figure is measured
or counted, and what is not known is written down as such. A reader should
learn of a weakness from us, not against us.

For each question: what is true today, what the field has already tried and
at what price, what it would cost here, the position taken, and what it
changes in the format of a note. That last point is not a detail. A rule can
change at an announced height, but a note already created keeps for ever the
shape it was born with: what is decided about the format today holds for all
the value that will come to rest on it.

## Privacy | What the chain shows, and to whom

<p class="lede">Today Cairn protects privacy less well than Bitcoin. Not by a choice it owns: by silence. That is the sentence our documents ought to have contained and did not.</p>

### What an observer learns

The address is written on the chain when the note is created, in the clear,
beside the amount. Up to 0.11.0 it was the public key itself; since then it is
the key's hash, which changes nothing about what an observer reads. An
ordinary payment weighs 223 bytes and every one of them can be read: which
notes die, which notes are born, for whom, for how much, and the difference
between the two, which is the fee. Nothing is encrypted anywhere.

The wallet makes worse what the protocol exposes. It holds one key per
file, so one address per person, reused for every payment: the salary, the
rent and the donations arrive at the same place, and anyone who knows the
address reads the balance and the whole history. Bitcoin's original paper
already recommended a fresh key per transaction, and that network's wallets
have done so by default for years. Ours does not.

The explorer, finally, industrialises the reading. For every owner it holds
everything received and spent, at what height, the balance that follows, and
it publishes the fifty richest holders. It is a separate program nobody has
to run, and that separation is real on the side of what nodes cost; on the
side of privacy it protects from nothing, because anyone can build the same
index from what the network broadcasts anyway. A node forgets; the world
does not. What has been broadcast once is public for ever.

The network, for its part, learns something other than the chain: where one
speaks from. A wallet is a node, and each of its peers sees the machine's IP
address. A payment goes to every peer connected at the moment it is sent,
with no delay and no detour: the first to receive it can read where it came
from, and link that IP address to the notes spent, and so to their owner.
Bitcoin has the same exposure and has added ways to blur it; Cairn has not,
and that is a choice that was written nowhere. A wallet that must ask for the
path of a fallen note sends places in the cold set, and a place names, to
anyone who holds the chain, the note, its owner and its amount: so it asks
only peers that say they keep the whole cold set. It does not ask its peers
to write its address in their books, and a node that does not keep the whole
cold set answers nobody from the paths it holds for its owner, which would
tell a stranger whose machine it is. It dials the address written into the
program, the seed, only if fewer than two of the peers it met last time
answer. When it dials it, the seed sees the session, and where a payment sent
while it is connected comes from; what it keeps of that, the code does not
say.

### What others do, and at what price

<div class="tablewrap">
  <table>
    <caption>The field, honestly</caption>
    <thead><tr><th>Network</th><th>What is hidden</th><th>The price paid</th></tr></thead>
    <tbody>
      <tr><td>Bitcoin</td><td>Nothing, but the address is the key's hash and a fresh key per payment is the norm</td><td>Graph analysis stays effective; whole companies live on it</td></tr>
      <tr><td>Monero</td><td>The sender, the recipient, the amount</td><td>About 2 kB per transaction, ten times ours; every output ever created and a receipt per spend kept for ever, so a state that grows without bound</td></tr>
      <tr><td>Zcash</td><td>Everything, in the shielded part</td><td>Transactions of several kilobytes; a receipt per spend kept for ever; finding one's own money means trying to decrypt every output on the chain</td></tr>
      <tr><td>Mimblewimble</td><td>The amounts, and the graph compacts</td><td>Interactive payments, the two wallets have to talk; about a hundred bytes per transaction kept for ever</td></tr>
      <tr class="us"><td>Cairn today</td><td>Nothing, and the address is the key itself, reused</td><td>Reading is free, for everyone, for ever</td></tr>
    </tbody>
  </table>
</div>

<p class="push-md">A pattern runs through this table, and it is no accident. Hiding who spends what forces the network to remember something per spend, for ever: Monero keeps a key image, Zcash a nullifier, Mimblewimble a kernel. Or it forces the user to carry the history: Monero's decoys are drawn from every past output, and a Zcash wallet coming back from absence tries to decrypt everything it missed. An eternal memory in the nodes, or the history in the users: both are exactly the growing cost this project exists to refuse.</p>

One nuance, because it is true: our accumulator can prove absence, so a set
of spend receipts would fit in every node as sixty four hashes, like the cold
set. What does not fit is the upkeep. The proof of absence of a receipt still
secret can be refreshed only by its owner, who cannot hand it to anyone
without pointing at themselves. The update burden this project accepted for
notes would extend to paths nobody can watch over for you. Nobody has solved
this, we have not either, and this document does not pretend otherwise.

Finally, everything the field deploys to hide, committed amounts, ring
signatures, zero-knowledge proofs, rests on the discrete logarithm, which the
adversary of the next section breaks.

### The position

<div class="decisions">
  <div class="dec">
    <span class="q">Address reuse</span>
    <span class="a">The wallet draws a fresh key per payment, before mainnet</span>
    <span class="why">One seed, derived keys, a fresh address for every payment received. The wallet is already a node that reads every block: recognising a hundred addresses instead of one is one more comparison per output, not one more server, and nobody learns which ones it recognises, where a phone wallet elsewhere hands its list of addresses to the server it queries. That brings Cairn to Bitcoin's norm, not beyond it: a spend that gathers several notes links them publicly, and a published donation address stays a fixed point. It is a software change, not a protocol change, and today's key file stays readable.</span>
    <span class="state">Status: not started. No rule reads how a key was made: it is a wallet file and the scan the wallet already does, which can come in any version.</span>
  </div>
  <div class="dec">
    <span class="q">Amounts</span>
    <span class="a">In the clear, and this is not a postponement</span>
    <span class="why">Hidden amounts exist and have a price: about 700 bytes of proof per amount to establish that it is not negative, a check in milliseconds, a payment that grows from 223 bytes to nearly a kilobyte, the throughput divided by five. The refusal does not come from there. It comes from this: a hidden supply can then be checked only through a mathematical assumption, the discrete logarithm, which a quantum computer breaks; the day it breaks it, somebody can make hidden money and nobody, ever, can show it. A chain whose promise is to be checkable in thirty years does not rest its issuance on that. Cairn promises a supply anyone can count again, and writes it down.</span>
  </div>
  <div class="dec">
    <span class="q">Hiding who pays whom</span>
    <span class="a">Not at the protocol level while the dilemma above holds</span>
    <span class="why">Stealth addresses would cost every wallet a scan and rest on a key exchange that is not post-quantum; spend receipts run into the upkeep described above. Rather than a vague promise, a door left open: the hashed address of the next section is compatible with one-time keys, so nothing locked in today forbids coming back to it when somebody, here or elsewhere, has solved the upkeep without an eternal memory. Until then, what Cairn offers is transparency that is stated, not anonymity that failed.</span>
  </div>
  <div class="dec">
    <span class="q">The explorer</span>
    <span class="a">It goes on showing what everyone can see, and says so</span>
    <span class="why">Removing the index from our explorer would take the information from nobody except the honest reader: the network broadcasts everything, and anyone can rebuild the same index. So the site will show, beside an address's balance, that this page is possible precisely because the chain is public. One consequence deserves writing down: on a transparent chain, third parties can judge a note by its history. The rules judge none, no note is worth more or less than another under them, and that is all a protocol can promise on the matter. Bitcoin lives with the same limit; it seldom says so.</span>
  </div>
</div>

<p class="push-md">What this position changes in the format of a note: nothing for the amounts, which stay eight bytes in the clear. For the address, the change comes from the next section, decided for another reason, and it serves here too.</p>

## The quantum computer | An adversary announced thirty years ahead

<p class="lede">The project's promise is counted in decades, and that is exactly the horizon at which public estimates place a quantum computer able to break these keys. The review is right: a line in an aside was not enough.</p>

### What is exposed, precisely

There are two families of cryptography in Cairn, and they do not fall
together. The structure, the seal, the two forests, the proof of work, the
identifiers, is made of hash functions, which a quantum computer does not
dent in any useful way. That point was already in the design document, and it
holds: the state, the seal that commits to it and the history of the headers
have nothing to fear.

The funds do. A note is locked by an Ed25519 signature, whose secret key can
be recovered from the public key on a large enough quantum computer. And as
long as the address was the public key itself, up to 0.11.0, the key of every
unspent note sat in the clear on the chain from its creation. Such an
adversary
does not need to catch a transaction in flight: it reads the chain, at its
leisure, and every dormant note is a target that does not move. The saver,
precisely the person this project puts forward, is the most exposed.

Bitcoin does better, and it is worth saying why. An ordinary output there
carries the key's hash, and the key appears only at the moment of spending:
a note never spent, from an address never reused, offers nothing to break,
and the window of attack shrinks to the minutes between a payment's
broadcast and its burial. The shield is imperfect, public counts put around a
quarter of Bitcoin's supply already in the open, reused keys and outputs from
the first years, and the most recent format, Taproot, gives it up by putting
the key back into the output. But the norm protects. Cairn did not have the
norm: here, a hundred per cent of the supply was in the open, by
construction, until the decision that follows.

### What a post-quantum signature would cost

The standardised schemes exist, published in 2024; a fourth, Falcon, is
still waiting for its final version at the time of writing. None gives back
Ed25519's 64 bytes: a post-quantum signature is counted in kilobytes, and
that is a particular problem for a design whose whole point is to be small.
Measured against our format, an ordinary payment, one note spent, two
created, in a block of 128 kB:

<div class="tablewrap">
  <table>
    <caption>An ordinary payment under each scheme, address as the key's hash</caption>
    <thead><tr><th>Scheme</th><th>Public key</th><th>Signature</th><th>One payment</th><th>Per block</th><th>Per second</th></tr></thead>
    <tbody>
      <tr><td>Ed25519, address = key (up to 0.11.0)</td><td class="num">32 B</td><td class="num">64 B</td><td class="num">191 B</td><td class="num">686</td><td class="num">11.4</td></tr>
      <tr class="us"><td>Ed25519, address as hash</td><td class="num">32 B</td><td class="num">64 B</td><td class="num">223 B</td><td class="num">587</td><td class="num">9.8</td></tr>
      <tr><td>Falcon-512</td><td class="num">897 B</td><td class="num">666 B</td><td class="num">1 690 B</td><td class="num">77</td><td class="num">1.3</td></tr>
      <tr><td>ML-DSA-44</td><td class="num">1 312 B</td><td class="num">2 420 B</td><td class="num">3 859 B</td><td class="num">33</td><td class="num">0.55</td></tr>
      <tr><td>SLH-DSA-128s</td><td class="num">32 B</td><td class="num">7 856 B</td><td class="num">8 015 B</td><td class="num">16</td><td class="num">0.27</td></tr>
    </tbody>
  </table>
</div>

<p class="push-md">The block is not the only casualty, and this is the figure that decides everything. As long as the address is the key, the key lives in the note, and the note lives in the drawer every node carries: under ML-DSA-44, every hot note grows by 1 280 bytes, the drawer goes from about 68 MB to about 236 MB, and the phone, which is the reason for the figure, can no longer keep up. With the address as a hash, the note keeps its forty bytes whatever the scheme: the key appears only on the wire, when spent, and the drawer does not move. That is the difference between a costly migration and an impossible one.</p>

On the choice of scheme itself: SLH-DSA is the only one that rests on the
same assumptions as our structure, hashing and nothing else, and it is the
heaviest in the table. Falcon is the smallest and the hardest to implement
correctly. The lattice schemes are young on the scale this project counts
in. There is no hurry to decide, on one condition: that the format no longer
has to change on the day the decision is made.

### The position

<div class="decisions">
  <div class="dec">
    <span class="q">The address</span>
    <span class="a">The key's hash, never again the key, before mainnet</span>
    <span class="why">A note now carries thirty-two bytes that name a key without showing it. The spender reveals the key by spending, the node checks the hash and then the signature: one more hash and one more comparison. The price: thirty-two bytes per input, a payment goes from 191 to 223 bytes, a block from 686 to 587 payments, 9.8 a second. What it buys: Bitcoin's shield, an unspent note from an address never reused exposes nothing, and above all the decoupling, because the note no longer knows which signature scheme guards it, so the scheme can change without the format changing. It is the only decision in this document that had to enter the format before a chain of value exists, and it costs thirty-two bytes.</span>
    <span class="state">Status: done in 0.11.0, on testnet-7. The note carries the hash, the input that spends it carries the key, and an address is written in Bech32m with its network's prefix, tcairn1 on the test networks, so that a typo is refused instead of paid.</span>
  </div>
  <div class="dec">
    <span class="q">The signature scheme</span>
    <span class="a">Ed25519 today, no post-quantum scheme chosen</span>
    <span class="why">Choosing today means freezing brutal sizes onto standards two years old, for an adversary whose arrival nobody can date. The way in already exists: a rule that changes names its activation height, and transfers carry a version number, so a second kind of witness is added on the day without renumbering anything. Every year of waiting makes the choice better informed, and the hashed address means nothing in the format makes the wait more expensive. What is decided now is not the scheme: it is that the format no longer depends on it.</span>
  </div>
  <div class="dec">
    <span class="q">The migration, when the day comes</span>
    <span class="a">A move of the funds, announced, and an edge accepted</span>
    <span class="why">No protocol replaces a key in its owner's place: on the day a post-quantum scheme activates, everyone will have to move their funds to an address of the new kind, and funds whose key is lost will stay open to the adversary. Bitcoin has exactly the same edge and no better answer. What the two previous decisions change is everything before that day: with the hash and without reuse, the exposure shrinks to payments in flight, a few minutes that our one-minute blocks make shorter than Bitcoin's. It stops being a property of the format and becomes a choice of behaviour, which is the best a chain knows how to do.</span>
  </div>
</div>

## The archivist | Whom the saver who comes back depends on

<p class="lede">The cold set is not a loss, our documents say, since an archivist can always rebuild a proof. The review answers: and if there is none? It is right to ask at that level, because the person most concerned is the one this project puts forward, the saver who has been offline for years.</p>

### The exact situation, in figures

The drawer holds 131 072 notes, and the oldest falls when it is full. At full
blocks, a note that does not move goes down to the cold set in 3.2 hours; at
a tenth of the traffic, in 32 hours; at a hundredth, in thirteen days. The
window after the fall, during which it can still be spent without a proof,
lasts twelve minutes at full load. The cold set is therefore the normal state
of all savings, not a rare case, and the design document said so already.

Three situations, and they do not call for the same service. A wallet that
is on notices nothing: every block carries what it needs to refresh its
proofs, it asks nobody for anything, and a proof weighs 586 bytes on average
at a million fallen notes, on the order of a kilobyte at thirty years of full
chain. A wallet switched off for a few days catches up by reading the blocks
it missed, which nodes keep for that purpose: a gigabyte by default, about
five days of full chain.

Beyond that, everything depends on what survived. Whoever kept their record,
which notes, at which position in the forest, needs only a fresh proof.
Producing it takes the archive of the cold set, 104 bytes per fallen note not
yet spent, which the program today holds in memory and rebuilds by reading
the whole chain again at every start; it costs a few microseconds and an
answer of a kilobyte, and the wallet checks the result on its own against the
roots every node holds. The trust asked for is none: an archivist cannot lie,
it can only stay silent. Whoever has lost everything but their key must first
find out what they own, and that, the archive does not know, because it holds
hashes, not names. Finding takes the history of the blocks, or an index by
owner like the explorer's.

And nobody is paid to hold either one. That is the omission, stated from
the code: the second guarantee of the design document, rebuildable for ever,
rests on a role the protocol does not pay, which the network does not depend
on, and on which the saver depends entirely.

<div class="tablewrap">
  <table>
    <caption>What the two services weigh, measured at thirty years, one block a minute</caption>
    <thead><tr><th>The chain is</th><th>Payments / s</th><th>The archive, to prove</th><th>The history, to find</th></tr></thead>
    <tbody>
      <tr><td>1 % full</td><td class="num">0.1</td><td class="num">8.2 GB</td><td class="num">20.7 GB</td></tr>
      <tr><td>10 % full</td><td class="num">1.0</td><td class="num">95.1 GB</td><td class="num">206.7 GB</td></tr>
      <tr class="us"><td>full</td><td class="num">9.8</td><td class="num">962.6 GB</td><td class="num">2.1 TB</td></tr>
    </tbody>
  </table>
</div>

<p class="push-md">Even at worst, the archive would fit on one ordinary disk; that the program keeps it in memory today rather than on disk is a defect of the program, not of the role. It is a volunteer's role in the sense that Bitcoin's full archive is one, with two differences: there, every newcomer depends on it, here only the saver without a record does; and there it weighs terabytes already today. The risk is therefore not the price of the service. The risk is that a quiet year of a small chain has nobody to provide it, and a protocol does not manufacture volunteers. What it can do: multiply them, make them checkable, and make them payable.</p>

### What already exists, and what is being built

Two pieces are already in the code. The explorer keeps the whole cold set by
default, on top of its index: every public explorer is therefore already,
materially, a complete point of recovery, the index to find and the archive
to prove. And an ordinary node accepts a flag that makes it keep the cold
set. The path has existed too since 2 September: two messages of the network
protocol let a wallet ask an archivist where a fallen note is and receive its
proof, which a wallet checks on its own against the roots every node holds.
What is missing is paying whoever provides it.

<div class="decisions">
  <div class="dec">
    <span class="q">The wallet's record</span>
    <span class="a">Fifty-two bytes per note, exported and encrypted</span>
    <span class="why">The identifier, the position, the amount: 52 bytes that change only at a payment, never at a block, and that the wallet exports encrypted to be put anywhere. That file turns "I have lost everything" into "I need a fresh proof", which is the service that costs nothing and asks for no trust. What the seed alone never can: a proof depends on the shape of the whole forest, which no seed knows. What a seed brings back is the keys, and with the derived keys of section II, every address. Seed plus any complete archivist is therefore enough for the worst case; seed alone, never, and writing that down is better than letting it be believed.</span>
    <span class="state">Status: not started. A file a wallet writes and the same wallet reads back: no node, no message, no commitment reads it, and it can come in any version.</span>
  </div>
  <div class="dec">
    <span class="q">Paying for recovery</span>
    <span class="a">A market, small, not atomic, without touching consensus</span>
    <span class="why">The format already allows it, and that was intended: a transfer's signature commits to the notes and the amounts, never to the witness that comes with them. So a wallet signs a transfer that spends the recovered note and pays the archivist in an ordinary output; the archivist attaches the proof and broadcasts it. It cannot divert a cent, everything is signed; the wallet can hardly cheat, since spending the same note elsewhere would take another fresh proof, which it does not have. The only theft possible is the recovery fee itself, by lifting the proof off a transaction already in flight: at this level of stakes, aiming for atomicity would cost the protocol more than the market weighs. The two messages it needs, asking and delivering, are already in the network protocol; it adds nothing to consensus, nothing to the format. The price is found between the parties; serving costs microseconds, it is carrying the set that is paid for.</span>
  </div>
  <div class="dec">
    <span class="q">Who carries what</span>
    <span class="a">The archive is cut into pieces, and each piece can be checked</span>
    <span class="why">The forest is a set of trees, and positions are never reused: a volunteer can carry one tree, or one range of positions, and serve proofs on that piece only. A false proof passes no check, so a partial archivist has nothing to prove about itself to be useful. The role asks for neither the whole, nor an identity, nor a permission: all it needs is that between them, the pieces cover the set, and the market of the previous point gives a reason to cover the pieces left aside.</span>
    <span class="state">Status: not started. Saying which positions an archivist carries is a field of the message that announces what a node keeps, and a routing choice for the request for proofs: a version of the protocol, which installs without restarting the chain.</span>
  </div>
  <div class="dec">
    <span class="q">The window after the fall</span>
    <span class="a">Does not move</span>
    <span class="why">It exists for the payer a block overtakes, not for the saver, and it cannot serve both. Covering a year of sleep at full load would take keeping about 360 million notes hot, that is 186 GB in every node: a window large enough for the saver is the cold set under another name, and the node's ceiling is the project's reason to exist. All the margin on that side is already taken.</span>
  </div>
</div>

<p class="push-md">What stays true after all this, and has to be written down rather than worked around: recovery rests on at least one volunteer carrying a set that grows. The protocol makes that volunteer cheap, divisible, checkable and payable; it cannot make one exist. The test network is the experiment that will say whether that is enough, and this document will be corrected by what it shows.</p>

## What comes out of it | One decision buys all three

Across three questions, only one thing had to enter the format of a note
before a chain of value exists: the owner of a note becomes the hash of a
key, never again a key. Thirty-two bytes unchanged in the note, thirty-two
more per spend, and that buys Bitcoin's quantum shield, a signature scheme
that can be replaced without touching the format, and a door open to one-time
keys if privacy at the protocol level ever becomes tenable. Everything else,
keys derived from a seed, the exported record, the recovery market, is
software around the format, replaceable at will.

What stays open, in decreasing order of certainty about what we know of it:

<ul class="open">
  <li><b>The upkeep of secret proofs.</b> Hiding who spends without an eternal memory in the nodes would take refreshing proofs of absence that nobody can watch over for their owner. Our accumulator holds the bounded half of the problem; nobody, anywhere, holds the other half.</li>
  <li><b>The choice of post-quantum scheme, and its height.</b> In a few years, better informed, with no penalty for waiting now that the format no longer depends on it. The honest trigger is the state of the art, not a date.</li>
  <li><b>Whether the recovery market finds sellers.</b> A small chain in a quiet year is the unfavourable case, and no reasoning replaces observation: it is a question for the test network, not for this document.</li>
</ul>

<p class="pull">The review asked for three silences to become three positions. Here they are: dated, in figures, and taken in order to be contradicted in writing.</p>

## The difficulty | What the testnet-8 wave leaves open

<p class="lede">These questions do not come from the review. They come from the test network: on 2 October 2026, a stranger mined eighty blocks in two minutes and the moving average that set the difficulty nearly stopped the network for 33 hours. The rule has changed; two variants were set aside from that change, the new rule gives the first block a weight it did not have, and what the same hired hash rate can do otherwise is still untouched. All of it is written here rather than forgotten.</p>

The rule is now ASERT: what a block owes in difficulty depends on the gap
between the chain and a schedule fixed at its first block, with a half-life
of sixty blocks, an hour on the public networks, and never more than a factor
of four from one block to the next. A burst that takes the difficulty to `X`
times that of the honest miners has cost about `X` times the honest rate for
`tau / ln 2`; it leaves about `X` target times to the next honest block, and
the honest chain gives back in all the lead the burst took on the schedule,
`log2(X)` half-lives. The delay therefore grows as the logarithm of what the
burst paid, and not as what it paid. Measured on one basis for both rules, the
next hundred honest blocks arrive 5.6 hours late after five minutes at 1 260
times the honest rate and 11.3 after an hour, where the moving average left 71
and 298: for the same effort, thirteen to twenty-six times less. The 2 October
burst itself, eighty blocks, would still cost the honest chain about half of
what it paid: an hour, at that size. The whitepaper gives the table.

<ul class="open">
  <li><b>Reading the block's own timestamp.</b> The rule reads the parent's timestamp. A variant would read the timestamp of the block being made: the first honest block after a miner leaves would see its difficulty fall as time passes, and would wait at most about <code>tau * log2(1 + X T ln 2 / tau)</code> instead of <code>X</code> target times. But a header's difficulty would stop being fixed by its parent alone: the weighing of an unknown chain, which works out the least work of a run of blocks from the bound per block, would reason over a rule of which the header chooses a part itself. Set aside from this wave for that reason, and to be reopened together with the weighing.</li>
  <li><b>Cutting the window to the median's eleven headers: no, for testnet-9.</b> A node keeps ninety-one headers, the old moving average's window; the rule now reads only one of them, the median eleven. The number is on the wire: a ledger handover carries that many, and the run a weighing examines starts ninety headers below the deepest draw. Since the testnet-9 wave, those two runs have the difficulty and the work of each header judged from the second one on, the anchor of a handover and the pinned header of a weighing included, since the rule now reads only the parent; the window is now the reach of those checks, and the first header of each run stays the only one they do not see. Cutting it would save about 29 KB per newcomer, would narrow that reach as much, and would change both exchanges: an old node and a new one could no longer hand each other either a ledger or a weighing, a change that belongs only in a network that restarts anyway. The floor would then be twelve and not eleven: the assertion that keeps the median's window below the pinned header asks for one more than the walk reads.</li>
  <li><b>The date of the first block now counts for ever.</b> The schedule starts from the first block's timestamp. A network opened long after the date of its first block starts behind its schedule, at the difficulty floor, until it has caught up that delay: blocks that are nearly free. The specification writes it down and draws the rule from it: the first block of a public network is minted on the day it opens. One command now mints the test network's first block at the moment it runs, and the devnet's with it, and rewrites everything that quotes them; it is run one last time on the day the network opens. The devnet stays the hard case. Its first block was dated twenty-nine days before it was mined, for a test that mines a long chain ahead of it; measured, a devnet opened on the day that block was mined reached the floor at the thirteenth block and stayed there until block 517 036. It is now dated two and a half hours back, which is what that test really needs (its longest chain covers two hours six minutes of the schedule), and minted again with every restart: a devnet opened on the day of minting spends about one thousand eight hundred blocks at the floor. That only pushes the problem back, since a devnet ages by about seventeen thousand nearly free blocks for every day that passes after that. The real answer would be a schedule of its own for every devnet started, which needs the date of the first block to travel with a weighing and a ledger handover: a protocol change, left to a later wave.</li>
  <li><b>A large departure also ends at the floor.</b> After a miner who took the difficulty to <code>X</code> times that of the honest ones leaves, the first honest block waits about <code>X</code> target times. Beyond about 120 times, that wait exceeds two half-lives, and the bound of four per block holds back the fall that follows: each block comes down only to a quarter of the one before, where the schedule alone would have asked for less at once, and from a few hundred times on this adds to the stall about a third of the first wait, <code>X / 3</code> target times. An hour at 1 260 times the honest rate leaves the next hundred honest blocks 11.3 hours late with the bound and 9.6 without it; the plan had measured the rule without its bound and written that it changed nothing. Beyond a few thousand times, the stall leaves the chain further behind its schedule than the edge of the floor, <code>log2(D) - 1</code> half-lives, and the honest chain then mines hundreds or thousands of blocks at difficulty 1, in a few minutes, until it is back at that edge: it is the debt to the schedule being paid back. Measured on testnet-8's rules, when each block takes the mean time its difficulty asks for: 579 blocks at the floor after a departure from 2 048 times, 3 455 after 4 096 times, less than five hours at the 2 October intruder's rate, and 9 191 after 8 192 times; with block times drawn at random, the median over sixty four seeds is about twenty, 2 244 and 7 793. This document used to say none after 2 048 times and 874 after 4 096 times: medians over sixteen seeds, which fell low, and which the study of the testnet-9 wave did again. The bound brings this run forward and makes it longer. A payment written in those blocks has almost no work behind it until the chain has climbed back, since a branch of blocks at the floor costs nothing. The variant that reads the block's own timestamp, above, would bound the first wait; it will have to be measured, bound included, before concluding that it removes these two effects.</li>
  <li><b>The half-life and a cap on the debt, settled for testnet-9: sixty blocks, the bound of four, no cap.</b> The run at the floor after a large departure is the repayment of the debt to the schedule, and the study of the testnet-9 wave measured each lever in simulation, at equal cost to the attacker. The figures in this paragraph are those of its simulations, which are not in this repository, and no test here measures them: the departures and the caps as medians over thirty-two seeds (the study's <code>sims/q2_departures.py</code>), the losses of hash rate over sixteen (<code>sims/q2_loss.py</code>), the start of the run at the floor on the mean path, with no draw (<code>sims/q2_onset.py</code>). A cap that reads only the parent and the origin can erase nothing: relative to the parent's difficulty, it is the bound of four under another name, and the debt stays whole (measured with a bound of two and one of eight, the run gets longer at two and a little shorter at eight, without ever disappearing); relative to the origin, it is a least difficulty fixed at the opening, which changes only the level of the catching up and stops a chain whose hash rate falls lower. The cap that works carries a state from one block to the next, so a new header field: it removes the run at the floor and the windfall of a late opening, but lengthens large stalls by about five hours at <code>K = 2</code> (from nothing to two hours at <code>K = 4</code>), and the chain never again catches up its written schedule: it stays behind by about the length of the stall, 67 hours at <code>K = 2</code> after a departure from 4 096 times. No difficulty rule either makes a rewrite from an old fork point expensive in time, since the time elapsed since that point is real and free to declare; that question stays for the outside review. The half-life, finally, moves the damage from one kind of event to another without removing any: at equal cost, a hundred and twenty blocks halve the large stalls and leave a run at the floor only after an attack of about 9 100 hours of the honest rate instead of 2 300, but a real loss of hash rate is absorbed twice as slowly (after a loss of nine tenths, the next thousand blocks are 6.6 hours late against 3.3, and 13.2 against 6.6 after a loss of ninety-nine hundredths). Sixty stays, because a young network with few miners will see real losses far more often than departures of thousands of times; a hundred and twenty is the defensible alternative if one judges the opposite, and would need a restart. What the run at the floor damages is dealt with outside consensus. The test network's watcher rings on a run of ten blocks at the floor (the <code>floor-run</code> alarm of <code>.github/scripts/watch_testnet.py</code>). The wallet and the explorer will have to count a payment's confirmations by the work above it rather than in blocks: that is owed, and it is not done yet. The cap carried by the header is described and ready if the main network's launch review decides otherwise, <code>K = 4</code> being the best constant; deciding it then will mean deciding it without a test network that ran it.</li>
  <li><b>A young chain can be rewritten beyond what a node undoes.</b> A node never undoes more than 1 024 blocks, 32 on the devnet: that is its policy, not a rule of the chain. While the network is small, hired hash rate is enough to mine in private a heavier branch that forks lower than that limit: 1 024 blocks at testnet-7's honest difficulty were about seventeen hours of honest work, and less than a minute at the rate of the 2 October intruder. The nodes that were following refuse that branch and say it is out of reach; newcomers, and nodes that were away, weigh it and take it, since it is the heaviest. The network then splits in two for good, with nobody at fault, and nothing sews it back. The difficulty's schedule changes nothing here: it sets what a block costs, not who mines the most of them. Nothing in the protocol answers it, and nothing could, since it is the majority assumption bought cheaply; the only answer is more honest hash rate. The threat model writes it down as such.</li>
</ul>

## Fees | What lab D leaves open

Lab D showed that a payment spending only notes fallen from the hot set
waited without end behind blocks kept full of transfers at the floor. The
wallet offered it its exact floor, and that floor leaves its miner less per
unit of weight than the filler that takes no place. The wallet now always
offers enough to get ahead of that filler. That is the narrow answer, and it
leaves a question.

<ul class="open">
  <li><b>Outbidding the next block, not only the floor.</b> The wallet looks at the lowest rate in its pool only when the pool is full. A pool that holds more than a block without being full leaves out everything that pays less than the lowest rate the next block would take, so that filler paid a little above the floor still holds back a payment offered just ahead of the floor. The wide version would offer, as soon as the pool holds more than a block, enough to beat that rate. It asks the wallet to read its own node's selection, which another miner may sort differently, and it makes every payment cost more during an attack that costs the attacker what it costs the payers. Left for later, and to be measured before it is chosen.</li>
</ul>
