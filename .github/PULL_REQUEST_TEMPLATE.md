## What was wrong

Say what the defect was, not what the diff changes. The diff already says that.
If there is a measurement, give it.

## How this holds

- [ ] There is a test that fails without this change
- [ ] I broke the fix on purpose and watched that test fail, then put it back
      and watched it pass
- [ ] The test asserts on a value the system moves, not on a constant and not
      on how long something took

## The gate

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --locked` prints zero warnings
- [ ] `cargo test --workspace --locked`
- [ ] `cargo test --workspace --release --locked`

CI runs these again on Linux, macOS and Windows. Green on one machine is not
green: see [CONTRIBUTING.md](../CONTRIBUTING.md).

## Cost

- [ ] Nothing here makes a node's work, memory or disk grow with the length of
      the chain

If it does, say so and say why it is worth it. That is the one claim the whole
design rests on, so it is a decision rather than an oversight.
