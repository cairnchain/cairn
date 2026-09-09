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

## Scope

In scope: `crates/cairn-ledger`, `crates/cairn-chain`, `crates/cairn-accumulator`,
`crates/cairn-crypto`, `crates/cairn-primitives`, `crates/cairn-store`,
`crates/cairn-net`, and `crates/cairn-wallet` where it touches keys or spending.

Out of scope: the explorer and the site under `web/`, the deployment scripts
under `deploy/`, and the servers themselves. Reports against a running testnet
node are welcome but the network is expected to be reset.

## Supported versions

Only the tip of `main`. There is no released version to support yet.
