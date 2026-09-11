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
issue saying only that you have something to report — no detail — and we will
come back with a private channel.

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

The lesson generalises, and it is the thing to look for next: an input the
derivation treats as the chain's that the protocol lets a prover write down.

## Scope

In scope: `crates/cairn-ledger`, `crates/cairn-chain`, `crates/cairn-accumulator`,
`crates/cairn-crypto`, `crates/cairn-primitives`, `crates/cairn-store`,
`crates/cairn-net`, and `crates/cairn-wallet` where it touches keys or spending.

Out of scope: the explorer and the site under `web/`, the deployment scripts
under `deploy/`, and the servers themselves. Reports against a running testnet
node are welcome but the network is expected to be reset.

## Supported versions

Only the tip of `main`. There is no released version to support yet.
