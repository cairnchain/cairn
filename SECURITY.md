# Reporting a vulnerability

Nothing in this repository has been audited, and the only network in existence
is a test network whose currency is worthless by design. That does not make a
flaw uninteresting: the point of finding one now is that it costs nothing to
fix now.

## Where to send it

Open a private advisory:

  https://github.com/cairnchain/cairn/security/advisories/new

It is private between you and us until we publish it, and it is the only
channel we watch for this. **Please do not open a public issue for a security
flaw**, and please do not disclose it publicly before we have answered.

If the advisory form is not available to you for any reason, open an ordinary
issue saying only that you have something to report, with no detail in it,
and we will come back with a private channel.

## What to expect

We will acknowledge within **72 hours** and tell you, within **7 days**, whether
we think the report is a flaw, and what we intend to do about it. If we
disagree with you, we will say why rather than go quiet. There is no bounty:
this is an unfunded project, and we would rather say so than imply a reward
that does not exist.

We will credit you in the fix unless you ask us not to.

## What is worth reporting

Anything that lets money be created, spent twice, or frozen; anything that
makes two honest nodes disagree about which chain is heaviest; anything that
stops a node dead on a message anyone can send it; anything that makes a newcomer
accept a chain that is not the heaviest one.

The sampling bound that lets a newcomer weigh a chain by drawing 4 096 samples
is a **conjecture, not a theorem**: our own derivation, unreviewed. Work that
proves it, or breaks it, is the single most useful thing anyone outside this
project could do.

Two things this paragraph used to say are no longer true, and the correction
matters because it moves where the weak point is. It said 512 samples, which
was the count before a measurement put the adversary's best placement at a far
better ratio than the derivation had assumed; the count went to 4 096 and the
claim from 45.7% to 40%. And it said the derivation accounted for neither
adversarial placement under moving difficulty nor grinding of the Fiat-Shamir
seed. Both are measured now, in `crates/cairn-ledger/examples/adversarial_placement.rs`.

What is worth knowing about that measurement is that it was itself wrong until
recently, and in a way no test caught: it built a forgery by re-mining headers
without rebuilding the links between them, so every attempt was refused for a
broken parent chain and counted as a forgery the sampling had caught. It now
separates what the draw refuses from what every other check refuses, and
reports only the first. Anyone starting here should read that example before
the bound, and doubt it in the same way.

**The bound has been broken once, by this project, and the break is worth
reading before looking for the next one.** The count is set from an inequality
in which every quantity but one is fixed by the forger's share. The one was
`levels`, the number of halvings the draw spreads over, and through testnet-6
it was read off the height the tip states. A height is not work, and the only
rule holding the two together prices a stretch nobody opened at one unit a
block. So a chain could state a height far past the blocks carrying its work,
buy halvings with it in work it was already inventing, and dilute every draw. A
forger at 40% of the world's work went from missing all 4 096 draws with 2^-207
to missing them with 2^-58, against a published 2^-128, and the share the count
held to was 31% rather than 40%. The count now comes from the tip's own age
against a clock the reading node holds itself, which is a ceiling no prover can
raise. The break, the closure, and the measurements of both are in
`crates/cairn-ledger/tests/audit_the_bound.rs` and
`crates/cairn-ledger/examples/searching_for_a_break.rs`.

## The shape every flaw here has had so far

This project has found a fair number of defects in itself, and every one of
them has had the same shape: **a sentence that is true and answers a different
question from the one the argument needed answered.** Not one of them was a
false statement. Each was a correct observation standing where a different
observation was required, which is exactly why they survived reading: checking
the sentence confirms it.

Four that shipped, and what each one actually answered:

*"The draw spreads over `bit_length(height / 1024)` levels."* True. The bound
needed to know how much work the chain carries, and a height is a field the
prover writes down. That is the break described above.

*"A run of headers from anybody but the peer this node is filling from is
refused before a byte of it is written."* True, and it answers who can reach
the code where the question was what reaching it costs. The peer holding the
turn is a stranger too, chosen by nothing better than having the lowest
connection number this node happened to have, and a million and a half records
went onto a disk for a third of one allowance window.

*"The worst a join request held the chain shut for was 53.6 milliseconds."*
True of that run on that machine. The question was whether the code holds the
lock, and the answer given was the machine's load: the same commit read 7.5
against 53.6, then 8.6 against 48.8, then 12.0 against 35.0. Any claim resting
on two wall clock readings taken at different moments is measuring the machine
at both of them.

*"The share the sampling bound holds to is 42.96 per cent."* True, and it is a
floor rather than a measurement. The figure is a maximum over noisy per seed
estimates, so it reads low, and lower the fewer seeds are spent: 42.80 at
thirty two, 42.96 at sixty four, 43.03 at five hundred and twelve.

So the useful question to put to any justification in this repository is not
whether it is true. It is **what question it answers, and whether that is the
question the claim above it needed.** Concretely, the ones that have caught
something here:

- A quantity a derivation treats as the chain's that the protocol lets a
  prover write down.
- A cost argument that prices what the code is expected to be sent rather than
  what the rules permit anyone to send it.
- An argument about who can reach something, standing in for one about what
  reaching it costs.
- A price that does not move with the length of what it is charging for, or
  that differs between the two directions of the same exchange.
- A test whose claim rests on a comparison between two wall clock readings.
- A figure quoted as a point estimate that an estimator produces as a bound.

## Scope

In scope: `crates/cairn-ledger`, `crates/cairn-chain`, `crates/cairn-accumulator`,
`crates/cairn-crypto`, `crates/cairn-primitives`, `crates/cairn-store`,
`crates/cairn-net`, and `crates/cairn-wallet` where it touches keys or spending.

Out of scope: the explorer and the site under `web/`, the deployment scripts
under `deploy/`, and the servers themselves. Reports against a running testnet
node are welcome but the network is expected to be reset.

## Supported versions

Only the tip of `main`. There is no released version to support yet.
