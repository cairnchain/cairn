---
title: Integrating Cairn
language: en
stylesheet: cairn-whitepaper.css
strap:
  What an exchange, a custodian or a price aggregator needs to know to take
  Cairn deposits, pay withdrawals and publish its supply.
byline: Draft, for testnet-8; no mainnet exists
byline: [github.com/cairnchain/cairn](https://github.com/cairnchain/cairn)
byline: Every number and command held to the code by a test
abstract: Before you start
---

# Integrating Cairn

There is no mainnet. Everything below describes testnet-8, whose coins are
worth nothing and whose chain may be thrown away, and the release that runs
it. It is written now so that the questions an integrator asks are answered
before the day they matter, and so that what cannot be done yet is said
rather than discovered.

Every figure, default and command here is checked against the code by
`crates/cairn-explorer/tests/the_integration_guide.rs`, which fails when the
two part company. Where this guide and the specification disagree, the
specification is the one that is normative.

The guide says plainly where Cairn does not yet do what an exchange needs. The
largest gap is the first one an exchange meets: there is no way today to
watch many deposit addresses at once, or to spend from many of them with one
wallet. *Deposits* says what there is instead.

## The programs

Three programs, all built from the same source and released together.

<table>
  <thead><tr><th>Program</th><th>What it is</th><th>Data directory by default</th></tr></thead>
  <tbody>
    <tr><td><code>cairnd</code></td><td>a node: it checks every block and relays them</td><td><code>cairn-data</code></td></tr>
    <tr><td><code>cairn-explorer</code></td><td>a node that also indexes the whole chain and answers the HTTP API below</td><td><code>cairn-explorer-data</code></td></tr>
    <tr><td><code>cairn-wallet</code></td><td>a wallet that is itself a node: it holds one key, checks the chain itself and spends</td><td><code>cairn-wallet-data</code></td></tr>
  </tbody>
</table>

An exchange that only reads the chain needs `cairn-explorer`. One that pays
withdrawals needs `cairn-wallet` as well. Each wants a data directory of its
own: two programs never share one.

## Running a node for an exchange

### Ports

<table>
  <thead><tr><th>Program</th><th>Listens on, by default</th><th>For</th></tr></thead>
  <tbody>
    <tr><td><code>cairnd</code></td><td><code>0.0.0.0:9944</code></td><td>peers, set with <code>--listen</code></td></tr>
    <tr><td><code>cairn-explorer</code></td><td><code>0.0.0.0:9945</code></td><td>peers, set with <code>--listen</code></td></tr>
    <tr><td><code>cairn-explorer</code></td><td><code>127.0.0.1:8080</code></td><td>the website and the HTTP API, set with <code>--http</code></td></tr>
  </tbody>
</table>

The peer port is what other nodes connect to. The HTTP API is on the
loopback by default and is best left there, with the exchange's own systems
on the same machine or behind its own proxy. It answers `GET` and `HEAD` and
reads no request body.

`cairnd` and `cairn-explorer` both take `--check`, which prints what the
program would do with the settings it was given and stops without starting
anything. `cairnd` also reads `cairn.conf` inside its data directory, the
same names as `key = value`, and the command line wins over the file.

```text
cairn-explorer --data /var/lib/cairn-explorer --http 127.0.0.1:8080 --check
```

### Disk, memory and `--keep`

A plain node does not need old blocks. It keeps the ledger they add up to,
and keeps blocks only for other peers to read: `--keep` sets how many bytes of
them, `1GB` by default, or `all`. However small a size is asked for, the
blocks a reorganisation may still have to read back are never dropped.

What a node holds in memory is bounded by rule. The largest part is the hot
set, the notes every node holds, which is about 68 MB at capacity. A node that
keeps it is a whole node; nothing about running one grows with the age of the
chain.

The explorer is the exception, and on purpose. It keeps every block whatever
`--keep` says, because its index is built by reading the chain from the first
block at every start, and the index grows with everything that has ever
happened: 627 bytes for every note that has ever existed, against 104 for
every note that has fallen out of the hot set and not been spent. Both are
reported live in `/api/status`. Give the explorer a disk that can grow.

### An archivist or not

`--archive` makes a plain node an archivist: it keeps the cold set, every note
that has fallen out of the hot set, so it can tell a wallet where one of its
put-away notes sits. It costs about a hundred bytes of memory for every such
note, a cost that grows with the chain, and it keeps every block.

An exchange does not need to run one to read or to pay. It needs one to be
sure of spending a deposit that has sat untouched long enough to fall, which
is the case *Deposits* comes back to: a wallet that has its own record of
where the note sits needs nobody, and one that lost that record asks
archivists. The explorer always keeps the cold set, so an exchange running
the explorer already holds one.

## Addresses

An address is the hash of a public key, written in Bech32m as BIP 350 defines
it: a prefix naming the kind of network, the separator `1`, fifty two
characters of data and six of checksum. There is no version character.

<table>
  <thead><tr><th>Network</th><th>Prefix</th><th class="n">Characters</th></tr></thead>
  <tbody>
    <tr><td>mainnet</td><td><code>cairn</code></td><td class="n">64</td></tr>
    <tr><td>every test network</td><td><code>tcairn</code></td><td class="n">65</td></tr>
    <tr><td>devnet</td><td><code>dcairn</code></td><td class="n">65</td></tr>
  </tbody>
</table>

An address can be validated without a node, with any Bech32m decoder. Accept
it if, and only if, it decodes with a Bech32m checksum (not the older Bech32
one), its prefix is the one for the network you run, it is not a mix of
capital and small letters, the spare bits of its last data character are
zero, and the data is exactly 32 bytes. The same string written all in
capitals is the same address, which is how a QR code carries it; store and
compare the small-letter form. Bech32m detects every error of up to four
characters in a string this long, so a typo is refused, not paid.

`cairn-wallet address <key file> --network testnet-8` prints the address of a
key. What an address cannot tell you is whether anybody holds its key: a note
can be paid to an address nobody can spend from, as on any chain that pays to
the hash of a key.

## Deposits

### One address per user

On a chain without a field for a memo, a deposit is told apart by the address
it was paid to, so each user is given an address of their own. On Cairn today
that means a key of their own. A wallet holds exactly one key, made from
twenty four words along one fixed path, `m/44'/1'/0'/0'/0'` on every test
network, so the words give one address and no more. There is no way yet to
make many addresses from one set of words. And until Cairn's coin type is
registered at SLIP-0044, on mainnet a wallet makes no key from words at all.

### Watching many addresses: not possible yet

This is what the programs offer, and what they do not.

The explorer answers one address per request: `/api/address/<address>` gives
its balance, the notes it holds unspent with the height each was created at,
and its movements in and out with their heights and transactions. It answers
from an index of the whole chain, so it covers any address, including ones it
was never told about. Watching a thousand deposit addresses is a thousand
requests each time you look, and nothing tells you when one of them is paid:
there is no request that takes a list of addresses, no notification, and no
feed of what a block paid to addresses you care about.

The wallet watches its own key and no other. The node has no list of
addresses to follow that an integrator can give it.

And spending from many addresses is the same: a wallet spends from its one
key, so collecting deposits from a thousand addresses into one is a thousand
wallets, each with its own data directory and its own copy of the chain.

So an exchange cannot run deposits on Cairn as it runs them elsewhere until
this is built. It is on the project's launch list. Until then, what does work
is polling the explorer for each deposit address, at the cost of one request
each.

### Deposits that sit

A note that nobody spends falls, in time, out of the hot set every node holds
into the cold set, where spending it needs a proof of where it sits. The
wallet that was paid writes that down for itself in `history.dat`, in its data
directory, and the explorer reports which of the two sets each unspent note
is in, as `tier`. A wallet that loses `history.dat` gets the proof from an
archivist instead, or reads the whole chain again to find it. Back up
`history.dat` and `pending.dat` with the key: `cairn-wallet backup` copies all
three.

## Confirmations

**Policy: credit a deposit at 1 024 confirmations. Below that, it is only as
safe as the work it would cost somebody to outweigh it.**

`/api/tx/<id>` gives a transaction's `confirmations`: the block carrying it
counted as one, and every block on top of it one more. Nought means it is not
in a block on the chain this node follows.

The reasoning, from the two rules that decide whether a block stays.

The fork choice follows the branch with the most work. It is not a total
order: two blocks at the same height are ordinary, two honest nodes can follow
different ones for a block or two, and the next block settles it. So one
confirmation means nothing on its own, and a few mean only that no rival has
appeared yet. Any branch with more work replaces the one followed, however
many blocks it undoes, up to the depth below. On a young chain the work behind
a block is cheap to outweigh, and the threat model says plainly that nothing
in this design stops a majority of the work from rewriting recent history.

The undo depth is 1 024 blocks. A node keeps the records needed to undo that
many and no more, and refuses a switch that would reach deeper. The same
number is the burial, the depth at which the network calls a block settled,
and the coinbase maturity: a miner's own reward cannot be spent until the
block that paid it is 1 024 deep. At one block a minute that is about
17 h 04 m. A deposit at that depth is one this node will never take back,
and the depth at which the protocol trusts a miner with its own money.

That is a ceiling on risk for this node, not a guarantee about the network. A
node that refuses a deeper branch stays where it is, on a branch it can see is
not the heaviest, while a node starting fresh weighs that branch and takes
it, so the network splits. The threat model's row for a miner who rents a
majority while the chain is young is that case, and nothing in the protocol
answers it but more honest work. A node in it says so: `/api/status` counts
the blocks that arrived from a chain it cannot switch to as
`node.outOfReach`. If that keeps rising while the rest of the network is not
heard from, stop crediting and find out why.

An exchange that wants to credit small deposits sooner can, at its own risk,
by weighing what a deposit is worth against what renting more work than the
network for that many blocks would cost. There is no figure for that cost
yet, which is why the policy above does not offer one.

## Fees

A transfer's fee is what its inputs hold less what its outputs pay. Two parts
make the least a node will carry:

- **ten pebbles for each byte** of the encoded transfer, which is the pool's
  floor and a node's own policy, not a rule of the chain;
- **6 000 pebbles for each place** the transfer takes in the hot set, which
  is a rule of the chain and is destroyed, never paid to anybody. A
  transfer's places are its outputs less the hot notes it spends, or none if
  it spends more than it makes: a payment with change, spending one hot note,
  takes one.

One CAIRN is 100 000 000 pebbles.

The simplest choice is to name no fee: `cairn-wallet send` without `--fee`
works out the least the network will carry for that transfer and adds a
margin, so a note it spends falling out of the hot set before a block
carries it does not leave it paying too little. `--fee <cairn>` names one
instead, and the wallet stops and asks before paying a fee out of all
proportion to the amount, unless told `--fee-anyway`.

```text
cairn-wallet send hot.key --to <address> --amount 12.5 --data /var/lib/cairn-wallet --yes
```

A payment the wallet has sent is written down beside its chain at once and
offered to peers again on every later run until a block carries it. "Sent"
means handed to peers; only a block confirms it.

## Reorganisations

What happens when the chain this node follows changes under a payment.

Nothing is announced. Neither the node nor the explorer sends a message when
it switches branches; a switch is seen in what the API then answers.

- A block that was undone is no longer at its height: `/api/block/<height>`
  answers the block the new branch has there, with a different `id`. Keep the
  identifier of every block you credited from, and compare.
- A transfer whose block was undone goes back to the pool if it is still
  valid, and `/api/tx/<id>` then answers `"pooled":true` with
  `confirmations` 0, until a block on the new branch carries it again. If the
  new branch spent the same notes elsewhere, the transfer is answered as not
  found.
- The explorer's index unwinds to the branch and reads it again, which on a
  long chain can take a while. Until it has caught up, every answer carries
  `coverage`, and `coverage.behind` above nought, or `coverage.whole` false,
  means a count or a balance may be a floor rather than the figure.

A payee's wallet says when a payment it received was taken back:
`crates/cairn-wallet/tests/a_payment_reversed_ten_blocks_deep.rs` is that
case, run end to end, and what the wallet reports at each step.

## The supply, for aggregators

Three endpoints, all on the explorer.

<table>
  <thead><tr><th>Endpoint</th><th>Answers</th></tr></thead>
  <tbody>
    <tr><td><code>/api/supply/total</code></td><td>one number, as <code>text/plain</code>, in whole CAIRN with eight decimals</td></tr>
    <tr><td><code>/api/supply/circulating</code></td><td>the same, for what can move</td></tr>
    <tr><td><code>/api/supply</code></td><td>both, as JSON, with the height, the units and the schedule</td></tr>
  </tbody>
</table>

**The total** is every pebble the chain has issued and not destroyed, read
off the ledger at the tip this node follows. It is the figure `/api/status`
serves as `supply.issued`, in pebbles there and in CAIRN here. A coinbase is
the only thing that creates money, and two things destroy it: the part of a
fee that pays for places in the hot set, `supply.destroyed`, and whatever of
the reward and fees a miner chose not to claim, `supply.unclaimed`, which
never existed. Fees otherwise move money from a sender to a miner and change
nothing. So the schedule's running total at the tip is exactly the total plus
`destroyed` plus `unclaimed`.

**The circulating figure** is the total less the rewards nobody can spend
yet: a coinbase's notes wait 1 024 blocks, and those still waiting at the tip
are left out. There is no premine, no allocation held back and nothing else
locked, so nothing else is left out. `/api/supply` gives the difference as
`maturing`. A node that was handed its ledger rather than building it does
not hold the blocks that paid those rewards until it has applied that many of
its own, and until then the circulating figure answers 503, and `/api/supply`
answers it as null, rather than counting them as free.

**There is no maximum supply.** The reward halves every 1 051 200 blocks,
from 50 CAIRN, until halving would take it below 0.01 CAIRN, and from then on
every block pays 0.01 CAIRN for as long as blocks are mined. `/api/supply`
answers `maximum` as null and gives what the schedule has instead:

<table>
  <thead><tr><th>Field</th><th>Value</th><th>Meaning</th></tr></thead>
  <tbody>
    <tr><td><code>floorFrom</code></td><td class="n">13665600</td><td>the first height that pays the floor</td></tr>
    <tr><td><code>beforeTheFloor</code></td><td class="n">105107167.95955200</td><td>what the halvings pay out, in CAIRN, below that height</td></tr>
    <tr><td><code>floorPerBlock</code></td><td class="n">0.01000000</td><td>what every block pays from then on, in CAIRN</td></tr>
  </tbody>
</table>

At a block a minute the floor adds 5 256 CAIRN a year. The monetary ceiling,
one billion CAIRN, is the most any amount can hold and not a supply the
schedule reaches: the floor would take about 170 000 years to get there. Do
not publish it as a maximum.

## The API

The explorer answers these, as JSON unless said otherwise. Amounts are
strings of pebbles, so that no figure is rounded by a reader's floating point,
except the supply endpoints, which answer in CAIRN because that is what
aggregators read. Lists come a page at a time and say where the next page
starts; on `/api/blocks` and `/api/pool`, `limit` sets a page's length, 25 by
default and at most 128. Every answer is sent `Cache-Control: no-store`, and
an error is a JSON object with an `error` field.

<table>
  <thead><tr><th>Endpoint</th><th>Answers</th></tr></thead>
  <tbody>
    <tr><td><code>/api/status</code></td><td>the tip, the supply in pebbles, the index's coverage, and the node's health</td></tr>
    <tr><td><code>/api/params</code></td><td>the rules of the network</td></tr>
    <tr><td><code>/api/blocks</code></td><td>blocks, newest first, from <code>from</code></td></tr>
    <tr><td><code>/api/block/&lt;height or id&gt;</code></td><td>one block, its coinbase and its transfers</td></tr>
    <tr><td><code>/api/tx/&lt;id&gt;</code></td><td>one transaction, its height, its <code>confirmations</code>, or that it is <code>pooled</code></td></tr>
    <tr><td><code>/api/address/&lt;address&gt;</code></td><td>one address: balance, unspent notes, movements</td></tr>
    <tr><td><code>/api/note/&lt;id&gt;</code></td><td>one note, where it was made, whether it was spent</td></tr>
    <tr><td><code>/api/pool</code></td><td>the transfers waiting for a block</td></tr>
    <tr><td><code>/api/holders</code></td><td>the largest holders, out of what the index has read</td></tr>
    <tr><td><code>/api/search?q=</code></td><td>what a string is: a block, a note, a transaction or an address</td></tr>
    <tr><td><code>/api/supply</code></td><td>the supply, as above</td></tr>
    <tr><td><code>/api/supply/total</code></td><td>the total, as one number</td></tr>
    <tr><td><code>/api/supply/circulating</code></td><td>the circulating figure, as one number</td></tr>
  </tbody>
</table>

An address answer lists at most 100 movements a page, and looks at no more
than the newest 10 000 notes of one address; when it stops short it says so,
with `counted` false. A note is named by the transaction that made it and its
position among that transaction's outputs, as `<transaction>:<index>`.

Nothing here sends a payment. Withdrawals go through `cairn-wallet`.

## Test vectors

### An address from a known key

The public key of the specification's signature vectors, and its address
under each prefix:

```text
public key  47da95e3585bde332648ce1bf660eb1d68bb4fd9a6b206f80996056edd78995c

cairn   cairn1yzdmhpelkqzgvxufa7jn6aeds27hkym0klz387872lgs4s348ysqkvxac6
tcairn  tcairn1yzdmhpelkqzgvxufa7jn6aeds27hkym0klz387872lgs4s348ysqtk5uk3
dcairn  dcairn1yzdmhpelkqzgvxufa7jn6aeds27hkym0klz387872lgs4s348ysq5lsh2e
```

The 32 bytes under the text are the address itself, which is BLAKE3 keyed
with the address domain over the scheme byte `00` followed by the key:

```text
address     209bbb873fb004861b89efa53d772d82bd7b136fb7c513f8fe57d10ac2353920
```

### A transfer's identifier

A transfer of version 1 spending one note, the first output of a transaction
whose identifier is 32 zero bytes, and paying 1 CAIRN to the address above.
Its identifier is not the hash of its wire encoding: it is BLAKE3 keyed with
the transfer domain over the version, the count of inputs, each input's note
identifier alone, and the outputs, with keys, signatures and witnesses left
out. Integers are little-endian. So the bytes hashed are these, and the
identifier is the hash below them:

```text
version     0100
inputs      01000000
note        0000000000000000000000000000000000000000000000000000000000000000 00000000
outputs     01000000
value       00e1f50500000000
owner       209bbb873fb004861b89efa53d772d82bd7b136fb7c513f8fe57d10ac2353920

identifier  435df8bc8bc8e0aaf50333a9c3b87817190711b027dcc38c94667b94a750a30a
```

Because signatures are left out, the identifier is known before a transfer is
signed, and is the same whatever witness its inputs carry.
