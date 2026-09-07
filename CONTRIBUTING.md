# Contributing

Cairn is a proof-of-work chain built on one claim: **a full validating node
costs the same to run in thirty years as it does today**. Every design decision
here answers to that, and it is the first thing a change is judged against. A
patch that makes something faster or smaller but puts a cost in proportion to
the chain's age is not an improvement here, however good it looks in isolation.

Read [README.md](README.md) for what the design actually is, and
[SECURITY.md](SECURITY.md) before reporting anything that lets money be created,
spent twice, or frozen. Security flaws do not go in public issues.

## Getting it built

The toolchain is pinned in `rust-toolchain.toml`, so `rustup` picks it up on
its own. Nothing else is needed: there is no build script, no code generator,
and the whole dependency list is six crates.

```
cargo test --workspace
```

The dependencies are compiled with optimisation in every profile, deliberately,
because the tests mine and mining is blake3. The reason is written at the
bottom of `Cargo.toml`, along with why `debug-assertions` stays on regardless.

## What has to hold

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked
cargo test --workspace --locked
cargo test --workspace --release --locked
```

Clippy must print **zero warnings**. CI compiles with `-D warnings`, so one
warning is one failed build. Both test profiles are run because the release
profile compiles every `debug_assert!` out of existence, and several of this
codebase's invariants are held by those and by nothing else.

The workspace forbids `unsafe`, and denies `unwrap`, `expect`, `panic`,
indexing that can go out of range, and bare arithmetic that can overflow. Those
are denied in shipped code and allowed inside `#[cfg(test)]` modules, which is
the only escape any of them has. If you find yourself wanting one outside a
test, the answer is almost always a different shape rather than an `#[allow]`.

**Green on your machine is not green.** CI runs the suite on Linux, macOS and
Windows, in both profiles, and the differences that catch people are the ones
nobody thought to look for: file locks, path separators, socket behaviour,
timer granularity. This project spent twelve consecutive pushes red while being
green on one laptop.

## Writing a test

Two rules, both learned the hard way, and both worth more than they look.

**A test must fail when the thing it guards is broken.** Before you are done,
break the code your test is about, watch the test fail, put it back, watch it
pass. A test asserting that a field is *present*, or that a value is zero, or
that a call returns `Ok`, will very often pass just as happily against a
function that does nothing at all. Pin a value the system moves.

**Never assert on how long something took.** A comparison between two wall
clock measurements taken at different moments measures the machine's load
between them, and it will pass here and fail on a shared runner, or pass for a
year and then fail because the code got faster. Where the property is about
cost, count the operations: `crates/cairn-explorer/tests/audit_index_cost.rs`
counts blocks read and `crates/cairn-ledger/tests/audit_serving_a_join.rs`
counts header reads, and neither can be fooled by a busy machine. Where it
genuinely can only be time, calibrate against a quantity measured on the same
machine in the same run, and take both measurements under the same load.

Tests that exist to hold a specific past defect are named for it and carry the
finding in their doc comment, with the measurement that produced it. That is
deliberate: the comment is the only record of why the code is shaped the way it
is, and a future reader deserves the reason and not just the rule.

## Writing the code

The house style is plain English. Functions read as statements about the
domain: `settles_the_header`, `worth_speaking_to`, `cannot_be_taken`,
`held_from`. There are no abbreviations and no Hungarian prefixes.

Comments carry information or they are not written. A comment restating the
line under it is noise; a comment saying what went wrong before, what was
measured, and why the shape is what it is, is the most valuable thing in the
file. Several bugs here were found because a comment and the code beneath it
disagreed, so a comment is a claim and is held to the same standard as an
assertion.

No em dashes and no emoji, anywhere, including in commit messages.

Anything a person reads on a screen says what happened and what to do about it.
No apology, no vagueness, and never a cheerful message over a failure.

## Commits and pull requests

A commit message says what was wrong, not what was changed: the diff already
says what was changed. Give the measurement if there is one. The subject line
names the defect in plain words.

Keep a pull request to one subject. If you found three unrelated things, that
is three pull requests, and all three are welcome.

`main` is the only long-lived branch, and it is never red: every change goes on
a branch of its own, the checks run there, and `main` moves once they are
green. Name the branch for what it does, with the same word the commit will
carry:

    feat/wallet-input-cap
    fix/clock-skew-bans-the-messenger
    docs/contributing
    test/join-part-cost
    chore/pin-cargo-audit

The exception is an audit round, which is deliberately many subjects at once
and is named `round-14` and nothing else. A round is not a fix or a feature,
and a prefix claiming it is one would be a label that lies about what is under
it. This project spends most of its time finding labels that lie, so it should
not add one here.

## What is most wanted

From [SECURITY.md](SECURITY.md): the sampling bound that lets a newcomer join
by opening 512 headers is **a conjecture, not a theorem**. It is our own
derivation, unreviewed, and known not to account for adversarial placement
under moving difficulty or for grinding the Fiat-Shamir seed. Work that proves
it, or breaks it, is the single most useful thing anyone outside this project
could do.

After that: anything that makes a node's cost grow with the chain, anywhere. It
is the one claim everything else rests on, and it has been quietly broken and
repaired several times already.

## Licence

Contributions are taken under the same terms as the project: MIT or Apache 2.0,
at the user's option. By opening a pull request you agree your work may be
distributed under both.
