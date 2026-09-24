#!/usr/bin/env bash
# One job of a one-off second opinion on the weekly run's survivors.
#
# The weekly run puts a mutant only to the tests of its own crate, so one that
# a dependent crate's tests would catch reads there as a survivor. This asks
# those dependents, and plays the mutants the weekly run never reached.
#
# Mutants are chosen by marking every other name as already caught and passing
# `--iterate`, because `--re` and `--exclude-re` do not apply to "delete field"
# mutants in cargo-mutants 27.1.0: those are played whatever the filter says.
set -euo pipefail
job="second-opinion/jobs/$1"
export CARGO_TERM_COLOR=never

cargo mutants --list > all.txt
for list in fresh missed; do
  unknown=$(comm -23 <(sort "$job/$list.txt") <(sort all.txt) | wc -l)
  test "$unknown" -eq 0 || { echo "$unknown names in $list.txt are not listed at this commit" >&2; exit 1; }
done

only() {
  mkdir -p "$1/mutants.out"
  grep -vxF -f "$2" all.txt > "$1/mutants.out/caught.txt" || true
  for f in unviable missed timeout; do : > "$1/mutants.out/$f.txt"; done
}

# cargo-mutants exits 2 for survivors and 3 for timeouts, which are results.
mutants() { cargo mutants "$@" || { rc=$?; [ "$rc" -eq 2 ] || [ "$rc" -eq 3 ] || exit "$rc"; }; }

: > own-missed.txt
if [ -s "$job/fresh.txt" ]; then
  only own "$job/fresh.txt"
  mutants --iterate -o own --test-workspace=false --minimum-test-timeout 120 -j 2
  grep -xF -f "$job/fresh.txt" own/mutants.out/missed.txt > own-missed.txt || true
fi

sort -u "$job/missed.txt" own-missed.txt > dependents-targets.txt
if [ -s dependents-targets.txt ] && [ -s "$job/packages.txt" ]; then
  only dependents dependents-targets.txt
  packages=()
  while read -r p; do packages+=(--test-package "$p"); done < "$job/packages.txt"
  extra=()
  if grep -qx yes "$job/fuzz"; then
    # Only the fuzz targets use this crate, and the rest of those suites would
    # be hours of tests that cannot see it.
    extra=(--cargo-test-arg=--test --cargo-test-arg='fuzz_*')
  fi
  # No baseline: cargo-mutants runs it on the mutated crate whatever
  # `--test-package` says and derives the test timeout from it, so a crate
  # whose own suite takes nine seconds would give its dependents' suites,
  # which take twelve minutes, a two minute budget. The timeouts are stated.
  mutants --iterate -o dependents "${packages[@]}" ${extra[@]+"${extra[@]}"} \
    --baseline skip --timeout 2400 --build-timeout 3600 -j 2
fi
