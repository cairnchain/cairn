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

The sampling bound that lets a newcomer join by opening 512 headers is a
**conjecture, not a theorem** — our own derivation, unreviewed, and known not to
account for adversarial placement under moving difficulty or for grinding the
Fiat-Shamir seed. Work that proves it, or breaks it, is the single most useful
thing anyone outside this project could do.

## Scope

In scope: `crates/cairn-ledger`, `crates/cairn-chain`, `crates/cairn-accumulator`,
`crates/cairn-crypto`, `crates/cairn-primitives`, `crates/cairn-store`,
`crates/cairn-net`, and `crates/cairn-wallet` where it touches keys or spending.

Out of scope: the explorer and the site under `web/`, the deployment scripts
under `deploy/`, and the servers themselves. Reports against a running testnet
node are welcome but the network is expected to be reset.

## Supported versions

Only the tip of `main`. There is no released version to support yet.
