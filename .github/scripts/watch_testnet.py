#!/usr/bin/env python3
"""Watches the public test network and keeps one GitHub issue open per kind of alarm.

Run by `.github/workflows/watch-testnet.yml` every fifteen minutes. It reads the
explorer's public JSON API and knocks on the seed's port, runs seven checks,
and then makes the open issues say what the checks found: an issue is opened
when an alarm starts, commented when its figures change materially, and closed
with a comment when it clears.

Standard library only. Every network call has a hard time limit, and a network
that cannot be reached is alarm `unreachable`, never a crashed job.

Locally: `python3 .github/scripts/watch_testnet.py --dry-run` prints what it
would do to issues and calls neither `gh` nor GitHub.
"""

from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, NamedTuple, Optional

# ---------------------------------------------------------------------------
# Thresholds. One line each on why it is the number it is.
# ---------------------------------------------------------------------------

# What a target block time is when the explorer does not say; the public testnets run at 60 s.
DEFAULT_TARGET_SECONDS = 60
# Twenty target block times with no block is a stopped network, not a long gap.
STALE_TIP_IN_TARGETS = 20
# Blocks the difficulty is judged over: about an hour at 60 s, inside the retarget's own window.
DIFFICULTY_LOOKBACK = 60
# The retarget is damped (1.2x was testnet-7's widest 60 block swing), so 8x is hash rate moving.
DIFFICULTY_SWING = 8
# Blocks in the run that is judged for speed.
FAST_RUN_BLOCKS = 20
# That many blocks inside this many target times is four times schedule or better (5 min at 60 s).
FAST_RUN_SPAN_IN_TARGETS = 5
# Blocks asked per run: the explorer's largest page, two hours at 60 s, enough to bridge a late run.
LISTED_BLOCKS = 128
# A reorganisation is an event, so its issue is held open this long (the span the listing covers).
REORG_HOLD_SECONDS = 2 * 60 * 60
# Coinbase owners remembered between runs, to bound the state file.
OWNERS_KEPT = 1000

# ---------------------------------------------------------------------------
# Limits on the watcher itself.
# ---------------------------------------------------------------------------

# No HTTP request waits longer than this for a socket operation.
HTTP_TIMEOUT_SECONDS = 8
# The same for the seed: a port that accepts takes well under a second.
TCP_TIMEOUT_SECONDS = 5
# Tries before a party counts as unreachable: a blip on the runner's side is not the network's.
ATTEMPTS = 3
# Pause between tries.
RETRY_PAUSE_SECONDS = 5
# Largest answer read, far above a full listing (40 KB), so a runaway server cannot fill memory.
MAX_BODY_BYTES = 1_000_000
# No `gh` call waits longer than this.
GH_TIMEOUT_SECONDS = 30
# After this much of the run has gone, no new request is started.
RUN_BUDGET_SECONDS = 150
# The index can trail a chain switch by half a second, so supply is read again before it alarms.
CONFIRM_AFTER_SECONDS = 3

# ---------------------------------------------------------------------------
# What the explorer's node reports.
# ---------------------------------------------------------------------------

# `status.node` fields that are null when the node is well (api.rs `node_object`).
NODE_NULL_WHEN_WELL = (
    "outdated",
    "stranded",
    "probation",
    "unwritten",
    "unread",
    "clockBehind",
    "unjudged",
    "unweighable",
    "filling",
    "unanswered",
    "unsavedAddresses",
)
# Counters that are 0 when well: blocks out of reach, and torn disk nodes mended.
NODE_ZERO_WHEN_WELL = ("outOfReach", "mended")
# `joining` is "no" on a node with a chain and "done" once a join finished (the site agrees).
NODE_JOINING_WELL = ("no", "done")
# Lifetime counter of visitors refused: it never returns to 0, so growth is what matters.
NODE_GROWTH = ("turnedAway",)
# Fields that are readings and not faults: never alarms, and never reported as unknown.
NODE_READINGS = ("writtenThrough",)

# ---------------------------------------------------------------------------
# The seven alarms.
# ---------------------------------------------------------------------------

STALE = "stale-tip"
SWING = "difficulty-swing"
FAST = "fast-run"
SUPPLY = "supply-mismatch"
HEALTH = "node-health"
REORG = "reorg"
UNREACHABLE = "unreachable"
KINDS = (STALE, SWING, FAST, SUPPLY, HEALTH, REORG, UNREACHABLE)

LABEL = "testnet-alarm"
LABEL_COLOR = "B60205"
LABEL_TEXT = "Raised by the test network watcher"

CHECK_NAMES = {
    STALE: "tip age",
    SWING: "difficulty",
    FAST: "block pace",
    SUPPLY: "supply figures",
    HEALTH: "node health",
    REORG: "reorganisation",
    UNREACHABLE: "reachability",
}

TITLES = {
    STALE: "testnet alarm: the tip is stale",
    SWING: "testnet alarm: the difficulty has swung",
    FAST: "testnet alarm: a run of blocks came far faster than schedule",
    SUPPLY: "testnet alarm: the explorer's supply figures disagree",
    HEALTH: "testnet alarm: the explorer's node reports a fault",
    REORG: "testnet alarm: blocks seen earlier were replaced",
    UNREACHABLE: "testnet alarm: the explorer or the seed cannot be reached",
}

MEANING = {
    STALE: "No block has been added for much longer than the schedule allows. "
    "Either nothing is mining, or the explorer's node has stopped following the chain.",
    SWING: "The difficulty moved by a factor the retarget is built not to allow in this "
    "many blocks. A large share of the hash rate has arrived or left.",
    FAST: "A run of blocks arrived much faster than the schedule. That is a miner with "
    "far more power than the difficulty expects, and it is the opening move of a freeze: "
    "the difficulty overshoots and the chain stalls after it.",
    SUPPLY: "Two counts of the money in existence that the explorer computes from "
    "different things do not agree, or its own totals do not add up. One of them is wrong.",
    HEALTH: "The explorer's node is reporting a state that is normally empty. Several of "
    "these mean the node has stopped following the chain and will not start again alone.",
    REORG: "A block the watcher saw at some height earlier is no longer the block at "
    "that height. The chain was reorganised, or the explorer went back.",
    UNREACHABLE: "The explorer's API or the seed's port did not answer, three tries "
    "in a row, within the time allowed.",
}

OK = "ok"
ALARM = "ALARM"
UNKNOWN = "not checked"


# ---------------------------------------------------------------------------
# Plain data.
# ---------------------------------------------------------------------------


class Block(NamedTuple):
    height: int
    id: str
    timestamp: int
    difficulty: int
    miner: Optional[str]


@dataclass(frozen=True)
class Verdict:
    """What one check made of what it was given.

    `level` and `members` are what an issue's comments compare: a comment is
    made when the level rises or the set of members changes, and not for
    movement inside a level.
    """

    kind: str
    state: str
    detail: str
    level: int = 0
    members: tuple = ()
    facts: tuple = ()


@dataclass(frozen=True)
class Reorg:
    fork: int
    depth: int
    old_tip: int
    old_id: str
    new_id: Optional[str]


@dataclass(frozen=True)
class Step:
    verb: str  # open, comment, close, close-duplicate, leave-closed
    kind: str
    number: Optional[int]
    title: str
    body: str


class Unreachable(Exception):
    """A party did not answer, or did not answer something readable."""


class BadAnswer(Exception):
    """The explorer answered with a shape this script does not know."""


class GhError(Exception):
    """A `gh` call failed or timed out."""


# ---------------------------------------------------------------------------
# Small helpers.
# ---------------------------------------------------------------------------


def code(value, limit: int = 160) -> str:
    """Wraps text from outside in a code span that cannot break out of its line.

    Everything the explorer says goes through here before it reaches an issue
    or the job summary: no markup, no mentions, no table breaks, no workflow
    commands, and ASCII only.
    """
    text = " ".join(str(value).split())
    text = text.encode("ascii", "replace").decode("ascii")
    text = text.replace("`", "'").replace("|", "/")
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return "`" + text + "`"


def duration(seconds) -> str:
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 7200:
        return f"{seconds // 60} min"
    hours, rest = divmod(seconds, 3600)
    if hours < 48:
        return f"{hours} h {rest // 60} min"
    days, hours = divmod(hours, 24)
    return f"{days} d {hours} h"


def stamp(epoch: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(epoch))


def doublings(value: float, base: float) -> int:
    """How many times `value` has doubled past `base`: 0 up to twice it, 1 up to four times."""
    if base <= 0 or value < base:
        return 0
    return int(math.log2(value / base))


def short(identifier: Optional[str]) -> str:
    return "none" if identifier is None else identifier[:16]


def say(text: str = "") -> None:
    """Prints a log line that the runner cannot read as a workflow command."""
    for line in str(text).split("\n"):
        print(line.replace("::", ": :") if line.lstrip().startswith("::") else line)


def dig(payload, *path):
    for key in path:
        if not isinstance(payload, dict):
            return None
        payload = payload.get(key)
    return payload


def number(value) -> Optional[int]:
    """An integer out of a decimal string or an integer; None for anything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


# ---------------------------------------------------------------------------
# Reading the explorer's answers.
# ---------------------------------------------------------------------------


def parse_blocks(payload) -> list:
    """The blocks of an `/api/blocks` answer, lowest height first."""
    rows = payload.get("blocks") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise BadAnswer("the block listing has no `blocks` list")
    found = {}
    for row in rows:
        height = number(dig(row, "height"))
        identifier = dig(row, "id")
        stamped = number(dig(row, "timestamp"))
        difficulty = number(dig(row, "difficulty"))
        if None in (height, stamped, difficulty) or not isinstance(identifier, str):
            raise BadAnswer("a listed block is missing a height, id, timestamp or difficulty")
        miner = dig(row, "miner")
        found[height] = Block(
            height, identifier, stamped, difficulty, miner if isinstance(miner, str) else None
        )
    return [found[height] for height in sorted(found)]


def target_seconds(params) -> int:
    """The target block time the explorer states, else the default."""
    stated = number(dig(params, "targetBlockTime"))
    return stated if stated else DEFAULT_TARGET_SECONDS


# ---------------------------------------------------------------------------
# The seven checks. Pure: they take what was read and return a verdict.
# ---------------------------------------------------------------------------


def check_stale_tip(tip_timestamp, opens_at, now: int, target: int, peers=None) -> Verdict:
    reference = tip_timestamp if tip_timestamp is not None else opens_at
    if reference is None:
        return Verdict(STALE, UNKNOWN, "the explorer states no tip and no opening time")
    age = max(0, now - reference)
    limit = STALE_TIP_IN_TARGETS * target
    if age <= limit:
        return Verdict(STALE, OK, f"tip is {duration(age)} old (alarm past {duration(limit)})")
    facts = [
        f"tip dated {stamp(reference)}, {duration(age)} before this reading",
        f"alarm threshold: {STALE_TIP_IN_TARGETS} target block times of {target} s, "
        f"{duration(limit)}",
    ]
    if tip_timestamp is None:
        facts.append("the explorer states no tip at all, so age is counted from the opening")
    if peers is not None:
        facts.append(f"the explorer's node has {peers} peers")
    return Verdict(
        STALE,
        ALARM,
        f"tip is {duration(age)} old (alarm past {duration(limit)})",
        level=doublings(age, limit),
        facts=tuple(facts),
    )


def check_difficulty(blocks, lookback: int = DIFFICULTY_LOOKBACK, swing: int = DIFFICULTY_SWING):
    recent = blocks[-lookback:]
    if len(recent) < 2:
        return Verdict(SWING, OK, "fewer than two blocks, nothing to compare")
    low = min(recent, key=lambda block: block.difficulty)
    high = max(recent, key=lambda block: block.difficulty)
    ratio = high.difficulty / max(low.difficulty, 1)
    span = f"the last {len(recent)} blocks, heights {recent[0].height} to {recent[-1].height}"
    if ratio <= swing:
        return Verdict(
            SWING, OK, f"widest swing {ratio:.2f}x over {span} (alarm past {swing}x)"
        )
    direction = "rose" if high.height > low.height else "fell"
    return Verdict(
        SWING,
        ALARM,
        f"difficulty {direction} {ratio:.1f}x over {span} (alarm past {swing}x)",
        level=doublings(ratio, swing),
        facts=(
            f"lowest {low.difficulty} at height {low.height}",
            f"highest {high.difficulty} at height {high.height}",
            f"so it {direction} by a factor of {ratio:.1f} within {span}",
            f"alarm threshold: more than {swing}x",
        ),
    )


def check_fast_run(
    blocks,
    target: int,
    run: int = FAST_RUN_BLOCKS,
    span_targets: int = FAST_RUN_SPAN_IN_TARGETS,
) -> Verdict:
    limit = span_targets * target
    covered = set()
    fastest = None
    for start in range(len(blocks) - run + 1):
        window = blocks[start : start + run]
        if window[-1].height - window[0].height != run - 1:
            continue  # a gap in the listing: not a run of consecutive blocks
        stamps = [block.timestamp for block in window]
        span = max(stamps) - min(stamps)
        if fastest is None or span < fastest[0]:
            fastest = (span, window[0].height, window[-1].height)
        if span < limit:
            covered.update(block.height for block in window)
    if fastest is None:
        return Verdict(FAST, OK, f"fewer than {run} consecutive blocks listed, nothing to judge")
    span, first, last = fastest
    if not covered:
        return Verdict(
            FAST,
            OK,
            f"fastest {run} blocks took {duration(span)} (alarm under {duration(limit)})",
        )
    speedup = (run - 1) * target / max(span, 1)
    return Verdict(
        FAST,
        ALARM,
        f"{len(covered)} listed blocks lie in runs of {run} that took under {duration(limit)}",
        level=doublings(len(covered), run),
        facts=(
            f"{len(covered)} blocks, heights {min(covered)} to {max(covered)}, belong to a run "
            f"of {run} whose timestamps span under {duration(limit)}",
            f"the fastest run is heights {first} to {last}: {run} blocks in {span} s, "
            f"about {speedup:.0f}x faster than the {target} s schedule",
            f"alarm threshold: {run} blocks inside {span_targets} target block times "
            f"({duration(limit)})",
        ),
    )


def check_supply(status) -> Verdict:
    """The two identities the explorer's code guarantees, and nothing it merely hopes for.

    `counted` is computed as `paidToMiners - fees` (index.rs `Totals::issued`),
    so those three always add up whatever the chain holds. `issued` comes from
    the ledger and `counted` from the notes the index read, and the explorer
    states both so that they can be compared (its own page does, once the
    index has read the whole chain); they agree exactly then and only then.
    """
    supply = dig(status, "supply")
    index = dig(status, "index")
    figures = {
        name: number(dig(supply, name)) for name in ("issued", "counted", "fees", "paidToMiners")
    }
    if None in figures.values():
        return Verdict(SUPPLY, UNKNOWN, "the status carries no readable supply figures")
    issued, counted = figures["issued"], figures["counted"]
    fees, paid = figures["fees"], figures["paidToMiners"]
    broken = []
    facts = []
    # The explorer clamps `counted` at nought when fees exceed payments, and a sum that
    # was clamped is not a disagreement.
    if paid >= fees and counted + fees != paid:
        broken.append("paid-is-counted-plus-fees")
        facts.append(
            f"paidToMiners {paid} is not counted {counted} plus fees {fees} "
            f"(difference {paid - counted - fees})"
        )
    whole = dig(index, "fromTheStart") is True and number(dig(index, "behind")) == 0
    if whole and issued != counted:
        broken.append("issued-is-counted")
        facts.append(
            f"the ledger says {issued} pebbles were issued and the index counted {counted} "
            f"(difference {issued - counted})"
        )
    if broken:
        facts.append("these are computed from different things and cannot both be right")
        return Verdict(
            SUPPLY,
            ALARM,
            "supply figures disagree: " + ", ".join(broken),
            members=tuple(broken),
            facts=tuple(facts),
        )
    if not whole:
        behind = dig(index, "behind")
        return Verdict(
            SUPPLY,
            OK,
            f"totals add up; issued against counted not compared, index is behind "
            f"({behind} blocks) or does not start at block zero",
        )
    return Verdict(SUPPLY, OK, f"issued equals counted ({issued}), and paid is counted plus fees")


def check_node_health(node, turned_away_before=None) -> tuple:
    """Which `status.node` fields are set, and which fields this script does not know."""
    if not isinstance(node, dict):
        return Verdict(HEALTH, UNKNOWN, "the status carries no `node` object"), ()
    set_fields = {}
    for name in NODE_NULL_WHEN_WELL:
        if node.get(name) is not None:
            set_fields[name] = node[name]
    for name in NODE_ZERO_WHEN_WELL:
        value = number(node.get(name))
        if value is None or value > 0:
            set_fields[name] = node.get(name)
    joining = node.get("joining")
    if joining is not None and joining not in NODE_JOINING_WELL:
        set_fields["joining"] = joining
    for name in NODE_GROWTH:
        value = number(node.get(name))
        if value is not None and turned_away_before is not None and value > turned_away_before:
            set_fields[name] = f"{value}, up from {turned_away_before} at the last reading"
    known = (
        set(NODE_NULL_WHEN_WELL)
        | set(NODE_ZERO_WHEN_WELL)
        | set(NODE_GROWTH)
        | set(NODE_READINGS)
        | {"joining"}
    )
    unknown = tuple(sorted(name for name in node if name not in known))
    if not set_fields:
        return Verdict(HEALTH, OK, "every node field is at its normal value"), unknown
    facts = tuple(
        f"{code(name)}: {code(json.dumps(value, sort_keys=True), 200)}"
        for name, value in sorted(set_fields.items())
    )
    return (
        Verdict(
            HEALTH,
            ALARM,
            "set: " + ", ".join(sorted(set_fields)),
            members=tuple(sorted(set_fields)),
            facts=facts,
        ),
        unknown,
    )


def find_reorg(previous: dict, current: dict) -> Optional[Reorg]:
    """Whether a block seen at some height earlier is no longer the block there.

    Both are height to id. Only heights both could know are compared: a height
    below the current listing cannot be judged. A height above the current tip
    counts as replaced, since the block seen there is no longer on the chain.
    """
    if not previous or not current:
        return None
    low, tip = min(current), max(current)
    replaced = sorted(
        height
        for height, old in previous.items()
        if height >= low and ((height in current and current[height] != old) or height > tip)
    )
    if not replaced:
        return None
    fork = replaced[0]
    old_tip = max(previous)
    return Reorg(fork, old_tip - fork + 1, old_tip, previous[fork], current.get(fork))


def check_reorgs(events, compared: int, baseline: bool) -> Verdict:
    """The verdict over the reorganisations still held, newest last."""
    if not events:
        if baseline:
            return Verdict(REORG, OK, f"first reading, {compared} blocks recorded to compare with")
        return Verdict(REORG, OK, f"no block seen earlier was replaced ({compared} compared)")
    deepest = max(event["depth"] for event in events)
    facts = []
    for event in events:
        replacement = (
            f"replaced by {short(event['new'])}"
            if event["new"]
            else "gone, the tip is now below it"
        )
        facts.append(
            f"seen {stamp(event['at'])}: from height {event['fork']}, {event['depth']} "
            f"block(s) deep, up to the old tip {event['old_tip']}; {short(event['old'])} was "
            f"{replacement}"
        )
    return Verdict(
        REORG,
        ALARM,
        f"{len(events)} reorganisation(s) in the last {duration(REORG_HOLD_SECONDS)}, "
        f"deepest {deepest}",
        level=deepest,
        members=tuple(f"h{event['fork']}:{event['old'][:8]}" for event in events),
        facts=tuple(facts),
    )


def check_reachability(explorer_error, seed_error, explorer_note, seed_note) -> Verdict:
    members = []
    facts = []
    if explorer_error:
        members.append("explorer")
        facts.append(f"explorer: {code(explorer_error)}")
    if seed_error:
        members.append("seed")
        facts.append(f"seed: {code(seed_error)}")
    if not members:
        return Verdict(UNREACHABLE, OK, f"explorer {explorer_note}; seed {seed_note}")
    return Verdict(
        UNREACHABLE,
        ALARM,
        "cannot reach: " + ", ".join(members),
        members=tuple(members),
        facts=tuple(facts),
    )


def new_owners(known: list, blocks) -> list:
    """Coinbase owners in `blocks` that are not in `known`, as (owner, first height, blocks)."""
    seen = set(known)
    first = {}
    counts = {}
    for block in blocks:
        if block.miner is None:
            continue
        counts[block.miner] = counts.get(block.miner, 0) + 1
        first.setdefault(block.miner, block.height)
    return [(owner, first[owner], counts[owner]) for owner in first if owner not in seen]


# ---------------------------------------------------------------------------
# What the open issues say, and what to do about it.
# ---------------------------------------------------------------------------

MARKER = re.compile(
    r"<!-- testnet-alarm kind=([a-z-]+) level=(\d+) members=([A-Za-z0-9_.:,-]*) -->"
)


def clean_member(member: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", member)


def marker(verdict: Verdict) -> str:
    members = ",".join(sorted(clean_member(member) for member in verdict.members))
    return f"<!-- testnet-alarm kind={verdict.kind} level={verdict.level} members={members} -->"


def read_marker(text) -> Optional[tuple]:
    """The last marker in `text` as (kind, level, members)."""
    found = MARKER.findall(text or "")
    if not found:
        return None
    kind, level, members = found[-1]
    return kind, int(level), frozenset(filter(None, members.split(",")))


def last_marker(issue: dict) -> Optional[tuple]:
    """What the issue last said: its newest comment's marker, else its body's."""
    for comment in reversed(issue.get("comments") or []):
        found = read_marker(comment.get("body"))
        if found:
            return found
    return read_marker(issue.get("body"))


def changed_materially(verdict: Verdict, last: Optional[tuple]) -> bool:
    if last is None:
        return True
    _, level, members = last
    members_now = frozenset(clean_member(member) for member in verdict.members)
    return verdict.level > level or members_now != members


def issue_body(verdict: Verdict, headline: dict, when: int, run_url: str) -> str:
    lines = [
        MEANING[verdict.kind],
        "",
        f"What the watcher saw at {stamp(when)} on {code(headline['network'])}:",
        "",
    ]
    lines += [f"- {fact}" for fact in verdict.facts]
    lines += [
        "",
        f"Tip: {headline['tip']}. Peers: {headline['peers']}.",
        "",
        "This issue is opened, commented and closed by "
        "`.github/workflows/watch-testnet.yml`. It is commented when the figures change "
        "materially and closed by the watcher when the alarm clears. Closing it by hand "
        "silences it until the alarm has cleared and come back.",
    ]
    if run_url:
        lines += ["", f"Run: {run_url}"]
    lines += ["", marker(verdict)]
    return "\n".join(lines)


def comment_body(verdict: Verdict, when: int, run_url: str) -> str:
    lines = [f"Figures changed at {stamp(when)}:", ""]
    lines += [f"- {fact}" for fact in verdict.facts]
    if run_url:
        lines += ["", f"Run: {run_url}"]
    lines += ["", marker(verdict)]
    return "\n".join(lines)


def close_body(verdict: Verdict, when: int, run_url: str) -> str:
    lines = [f"The alarm cleared at {stamp(when)}: {verdict.detail}.", "", "Closing."]
    if run_url:
        lines += ["", f"Run: {run_url}"]
    return "\n".join(lines)


def plan_steps(
    verdicts, issues, was_active, headline: dict, when: int, run_url: str
) -> list:
    """What to do to the issues so that they say what the verdicts say.

    One open issue per kind, found by the marker in its body. A kind whose
    check could not run is left alone, neither opened nor closed. A kind that
    was alarming at the last run and has no open issue was closed by hand and
    is not opened again until it has cleared.
    """
    by_kind = {}
    for issue in sorted(issues, key=lambda item: item["number"]):
        found = read_marker(issue.get("body"))
        if found and found[0] in KINDS:
            by_kind.setdefault(found[0], []).append(issue)
    steps = []
    for verdict in verdicts:
        kind = verdict.kind
        open_ones = by_kind.get(kind, [])
        for extra in open_ones[1:]:
            steps.append(
                Step(
                    "close-duplicate",
                    kind,
                    extra["number"],
                    extra["title"],
                    f"Closing as a duplicate of #{open_ones[0]['number']}: there is one issue "
                    "per kind of alarm.",
                )
            )
        if verdict.state == UNKNOWN:
            continue
        if verdict.state == ALARM:
            if not open_ones:
                if kind in was_active:
                    steps.append(Step("leave-closed", kind, None, TITLES[kind], ""))
                else:
                    steps.append(
                        Step(
                            "open",
                            kind,
                            None,
                            TITLES[kind],
                            issue_body(verdict, headline, when, run_url),
                        )
                    )
            else:
                primary = open_ones[0]
                if changed_materially(verdict, last_marker(primary)):
                    steps.append(
                        Step(
                            "comment",
                            kind,
                            primary["number"],
                            primary["title"],
                            comment_body(verdict, when, run_url),
                        )
                    )
        else:
            for issue in open_ones[:1]:
                steps.append(
                    Step(
                        "close",
                        kind,
                        issue["number"],
                        issue["title"],
                        close_body(verdict, when, run_url),
                    )
                )
    return steps


# ---------------------------------------------------------------------------
# Doing it: with `gh`, or by saying what would be done.
# ---------------------------------------------------------------------------


class Gh:
    """Issue changes through the `gh` CLI, with GH_TOKEN from the environment."""

    def __init__(self, repo: str):
        self.repo = repo

    def run(self, args: list, stdin: Optional[str] = None) -> str:
        try:
            done = subprocess.run(
                ["gh", *args],
                input=stdin,
                capture_output=True,
                text=True,
                timeout=GH_TIMEOUT_SECONDS,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as error:
            raise GhError(f"gh {args[0]} {args[1]}: {type(error).__name__}") from None
        if done.returncode != 0:
            raise GhError(f"gh {args[0]} {args[1]} failed: {done.stderr.strip()[:300]}")
        return done.stdout

    def open_issues(self) -> list:
        text = self.run(
            [
                "issue", "list", "--repo", self.repo, "--label", LABEL, "--state", "open",
                "--limit", "100", "--json", "number,title,body,comments",
            ]
        )  # fmt: skip
        return json.loads(text or "[]")

    def ensure_label(self) -> None:
        names = json.loads(
            self.run(["label", "list", "--repo", self.repo, "--limit", "200", "--json", "name"])
        )
        if any(item.get("name") == LABEL for item in names):
            return
        self.run(
            [
                "label", "create", LABEL, "--repo", self.repo, "--color", LABEL_COLOR,
                "--description", LABEL_TEXT,
            ]
        )  # fmt: skip

    def open(self, title: str, body: str) -> int:
        self.ensure_label()
        url = self.run(
            [
                "issue", "create", "--repo", self.repo, "--title", title, "--label", LABEL,
                "--body-file", "-",
            ],
            stdin=body,
        ).strip()  # fmt: skip
        return int(url.rstrip("/").rsplit("/", 1)[-1])

    def comment(self, number_: int, body: str) -> None:
        self.run(
            ["issue", "comment", str(number_), "--repo", self.repo, "--body-file", "-"],
            stdin=body,
        )

    def close(self, number_: int, body: str) -> None:
        self.run(
            [
                "issue", "close", str(number_), "--repo", self.repo, "--reason", "completed",
                "--comment", body,
            ]
        )  # fmt: skip


def execute(steps: list, gh: Optional[Gh]) -> tuple:
    """Applies the steps, or prints them when `gh` is None.

    Returns the lines for the job summary and the kinds whose step failed.
    """
    lines = []
    failed = set()
    for step in steps:
        label = step.kind
        if step.verb == "leave-closed":
            lines.append(
                f"{label}: still alarming, its issue was closed by hand, so not opened again"
            )
            continue
        if gh is None:
            where = f"#{step.number}" if step.number else "a new issue"
            lines.append(f"dry run, would {step.verb} {where} for {label}")
            say(f"--- dry run: {step.verb} {where} ({label}): {step.title}")
            say(step.body)
            continue
        try:
            if step.verb == "open":
                made = gh.open(step.title, step.body)
                lines.append(f"{label}: opened #{made}")
            elif step.verb == "comment":
                gh.comment(step.number, step.body)
                lines.append(f"{label}: commented on #{step.number}")
            else:
                gh.close(step.number, step.body)
                lines.append(f"{label}: closed #{step.number}")
        except (GhError, ValueError) as error:
            failed.add(step.kind)
            lines.append(f"{label}: could not {step.verb}: {code(error, 200)}")
    return lines, failed


# ---------------------------------------------------------------------------
# State kept between runs.
# ---------------------------------------------------------------------------


def load_state(path: Optional[str]) -> tuple:
    """The saved state and a note if it could not be used."""
    empty = {"blocks": {}, "owners": [], "reorgs": [], "active": [], "turned_away": None}
    if not path or not os.path.exists(path):
        return empty, None
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        state = dict(empty)
        state["blocks"] = {
            int(height): identifier
            for height, identifier in raw.get("blocks", {}).items()
            if isinstance(identifier, str)
        }
        state["owners"] = [owner for owner in raw.get("owners", []) if isinstance(owner, str)]
        state["reorgs"] = [
            event
            for event in raw.get("reorgs", [])
            if isinstance(event, dict)
            and all(key in event for key in ("at", "fork", "depth", "old_tip", "old", "new"))
        ]
        state["active"] = [kind for kind in raw.get("active", []) if kind in KINDS]
        state["turned_away"] = number(raw.get("turned_away"))
        state["genesis"] = raw.get("genesis") if isinstance(raw.get("genesis"), str) else None
        return state, None
    except (OSError, ValueError, AttributeError, TypeError) as error:
        return empty, f"the saved state could not be read ({type(error).__name__}), starting over"


def save_state(path: Optional[str], state: dict) -> None:
    if not path:
        return
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    out = dict(state)
    out["blocks"] = {str(height): identifier for height, identifier in state["blocks"].items()}
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(out, handle, sort_keys=True)
    os.replace(temporary, path)


# ---------------------------------------------------------------------------
# Reaching the network. Every call here has a hard limit.
# ---------------------------------------------------------------------------


class Budget:
    def __init__(self, seconds: float):
        self.end = time.monotonic() + seconds

    def spent(self) -> bool:
        return time.monotonic() >= self.end


def within(seconds: float, function: Callable, *args):
    """Runs `function` and gives up after `seconds` whatever it is stuck in.

    The socket timeouts bound each wait, not the whole, and name resolution is
    bounded by neither. A thread that is abandoned is a daemon, so it cannot
    hold the process open.
    """
    box = {}

    def work():
        try:
            box["value"] = function(*args)
        except BaseException as error:  # handed to the caller, which re-raises it
            box["error"] = error

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        raise Unreachable(f"no answer within {seconds:g} s")
    if "error" in box:
        raise box["error"]
    return box["value"]


def fetch_once(url: str):
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise Unreachable("only http and https are fetched")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cairn-watch-testnet", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as error:
        error.close()
        raise Unreachable(f"HTTP {error.code}") from None
    except urllib.error.URLError as error:
        raise Unreachable(f"{type(error.reason).__name__}: {error.reason}") from None
    except (OSError, http.client.HTTPException) as error:
        raise Unreachable(f"{type(error).__name__}: {error}") from None
    if len(raw) > MAX_BODY_BYTES:
        raise Unreachable("the answer is larger than any this watcher expects")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise Unreachable("the answer is not JSON") from None
    if not isinstance(payload, dict):
        raise Unreachable("the answer is not a JSON object")
    return payload


def get_json(base: str, path: str, budget: Budget) -> tuple:
    """(payload, seconds taken). Tries up to ATTEMPTS times, then raises Unreachable."""
    url = base.rstrip("/") + path
    failure = Unreachable("not tried")
    for attempt in range(ATTEMPTS):
        if budget.spent():
            raise Unreachable("the run's time budget is used up")
        if attempt:
            time.sleep(RETRY_PAUSE_SECONDS)
        began = time.monotonic()
        try:
            payload = within(HTTP_TIMEOUT_SECONDS + 2, fetch_once, url)
            return payload, time.monotonic() - began
        except Unreachable as error:
            failure = error
    raise failure


def probe_tcp(host: str, port: int, budget: Budget) -> float:
    """Seconds a connection to the seed took. Raises Unreachable after ATTEMPTS tries."""
    failure = Unreachable("not tried")
    for attempt in range(ATTEMPTS):
        if budget.spent():
            raise Unreachable("the run's time budget is used up")
        if attempt:
            time.sleep(RETRY_PAUSE_SECONDS)
        began = time.monotonic()
        try:
            connection = within(
                TCP_TIMEOUT_SECONDS + 2,
                socket.create_connection,
                (host, port),
                TCP_TIMEOUT_SECONDS,
            )
            connection.close()
            return time.monotonic() - began
        except Unreachable as error:
            failure = error
        except OSError as error:
            failure = Unreachable(f"{type(error).__name__}: {error}")
    raise failure


@dataclass
class Observed:
    status: Optional[dict] = None
    params: Optional[dict] = None
    blocks: Optional[list] = None
    explorer_error: Optional[str] = None
    seed_error: Optional[str] = None
    explorer_note: str = ""
    seed_note: str = ""
    confirmed_status: Optional[dict] = None


def observe(api: str, seed: tuple, budget: Budget) -> Observed:
    seen = Observed()
    try:
        seen.status, took = get_json(api, "/api/status", budget)
        try:
            seen.params, _ = get_json(api, "/api/params", budget)
        except Unreachable:
            seen.params = None  # optional: the default target block time stands in
        payload, _ = get_json(api, f"/api/blocks?limit={LISTED_BLOCKS}", budget)
        seen.blocks = parse_blocks(payload)
        seen.explorer_note = f"answered in {took:.1f} s"
        if check_supply(seen.status).state == ALARM:
            time.sleep(CONFIRM_AFTER_SECONDS)
            seen.confirmed_status, _ = get_json(api, "/api/status", budget)
    except (Unreachable, BadAnswer) as error:
        seen.explorer_error = str(error)
        seen.status = seen.blocks = None
    try:
        took = probe_tcp(seed[0], seed[1], budget)
        seen.seed_note = f"accepted a connection in {took:.2f} s"
    except Unreachable as error:
        seen.seed_error = str(error)
    return seen


# ---------------------------------------------------------------------------
# Putting it together.
# ---------------------------------------------------------------------------


@dataclass
class Analysis:
    verdicts: list
    headline: dict
    new_owners: list
    owners_window: list
    notes: list
    state: dict


def analyse(seen: Observed, state: dict, now: int) -> Analysis:
    notes = []
    verdicts = []
    reach = check_reachability(
        seen.explorer_error, seen.seed_error, seen.explorer_note, seen.seed_note
    )
    new_state = dict(state)
    headline = {"network": "unknown", "tip": "unknown", "peers": "unknown", "difficulty": "unknown"}
    owners_new, owners_window = [], []

    if seen.status is None or seen.blocks is None:
        for kind in (STALE, SWING, FAST, SUPPLY, HEALTH, REORG):
            verdicts.append(Verdict(kind, UNKNOWN, "the explorer could not be read"))
        verdicts.append(reach)
        return Analysis(verdicts, headline, [], [], notes, new_state)

    status, blocks = seen.status, seen.blocks
    genesis = dig(status, "network", "genesis")
    name = dig(status, "network", "name") or "unknown"
    if state.get("genesis") not in (None, genesis):
        notes.append(
            "the network's first block changed, so what was remembered of the old network "
            "was dropped"
        )
        state = {
            "blocks": {}, "owners": [], "reorgs": [], "turned_away": None,
            "active": state.get("active", []),
        }  # fmt: skip
        new_state = dict(state)
    baseline = not state["blocks"]

    target = target_seconds(seen.params)
    tip = dig(status, "tip")
    tip_stamp = number(dig(tip, "timestamp"))
    if tip_stamp is None and blocks:
        tip_stamp = blocks[-1].timestamp
    tip_height = number(dig(tip, "height"))
    peers = number(dig(status, "peers"))
    age = None if tip_stamp is None else max(0, now - tip_stamp)
    headline = {
        "network": f"{name} ({dig(status, 'network', 'id')})",
        "tip": "none"
        if tip_height is None
        else f"height {tip_height}, {duration(age) if age is not None else 'age unknown'} old",
        "peers": "unknown" if peers is None else peers,
        "difficulty": dig(tip, "difficulty") or "unknown",
        "age": age,
        "target": target,
    }

    verdicts.append(
        check_stale_tip(tip_stamp, number(dig(status, "network", "opensAt")), now, target, peers)
    )
    verdicts.append(check_difficulty(blocks))
    verdicts.append(check_fast_run(blocks, target))
    judged = seen.confirmed_status if seen.confirmed_status is not None else status
    verdicts.append(check_supply(judged))
    health, unknown_fields = check_node_health(dig(status, "node"), state.get("turned_away"))
    verdicts.append(health)
    if unknown_fields:
        notes.append(
            "node fields this watcher does not know, left unjudged: "
            + ", ".join(code(field) for field in unknown_fields)
        )

    current = {block.height: block.id for block in blocks}
    found = find_reorg(state["blocks"], current)
    held = [event for event in state["reorgs"] if now - event["at"] < REORG_HOLD_SECONDS]
    if found:
        held.append(
            {
                "at": now, "fork": found.fork, "depth": found.depth, "old_tip": found.old_tip,
                "old": found.old_id, "new": found.new_id,
            }
        )  # fmt: skip
    verdicts.append(check_reorgs(held, len(current), baseline))
    verdicts.append(reach)

    known = state["owners"]
    if baseline and not known:
        owners_new = []
        notes.append("first reading: coinbase owners recorded without being called new")
        fresh = [owner for owner, _, _ in new_owners([], blocks)]
    else:
        owners_new = new_owners(known, blocks)
        fresh = [owner for owner, _, _ in owners_new]
    counts = {}
    for block in blocks:
        if block.miner:
            counts[block.miner] = counts.get(block.miner, 0) + 1
    owners_window = sorted(counts.items(), key=lambda item: -item[1])

    new_state.update(
        {
            "network": name,
            "genesis": genesis,
            "blocks": current,
            "owners": (known + fresh)[-OWNERS_KEPT:],
            "reorgs": held,
            "turned_away": number(dig(status, "node", "turnedAway")),
            "saved_at": now,
        }
    )
    return Analysis(verdicts, headline, owners_new, owners_window, notes, new_state)


def render_summary(analysis: Analysis, step_lines: list, extra: list, when: int) -> str:
    head = analysis.headline
    lines = [
        "## Test network watch",
        "",
        "| | |",
        "|---|---|",
        f"| network | {head['network']} |",
        f"| tip | {head['tip']} |",
        f"| difficulty | {head['difficulty']} |",
        f"| peers | {head['peers']} |",
        f"| read at | {stamp(when)} |",
        "",
        "### Checks",
        "",
        "| check | state | detail |",
        "|---|---|---|",
    ]
    for verdict in analysis.verdicts:
        detail = verdict.detail.replace("|", "/")
        lines.append(f"| {CHECK_NAMES[verdict.kind]} | {verdict.state} | {detail} |")
    lines += ["", "### Coinbase owners", ""]
    if analysis.owners_window:
        window = ", ".join(f"{code(owner, 80)} x{count}" for owner, count in analysis.owners_window)
        lines.append(f"In the listed blocks: {window}.")
    else:
        lines.append("No coinbase owners in the listed blocks.")
    if analysis.new_owners:
        lines.append("")
        for owner, first, count in analysis.new_owners:
            lines.append(
                f"- new coinbase owner {code(owner, 80)}: first listed at height {first}, "
                f"{count} block(s) in the listing. Noted, not an alarm."
            )
    if step_lines:
        lines += ["", "### Issues", ""] + [f"- {line}" for line in step_lines]
    notes = analysis.notes + extra
    if notes:
        lines += ["", "### Notes", ""] + [f"- {note}" for note in notes]
    return "\n".join(lines) + "\n"


def parse_seed(text: str) -> tuple:
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"the seed must be host:port, not {text!r}")
    return host, int(port)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--api", default=os.environ.get("WATCH_API", "https://cairnchain.org"))
    parser.add_argument("--seed", default=os.environ.get("WATCH_SEED", "seed.cairnchain.org:9944"))
    parser.add_argument("--state", default=os.environ.get("WATCH_STATE"))
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument(
        "--dry-run", action="store_true", help="print what would be done to issues, call no gh"
    )
    parser.add_argument(
        "--open-issues", help="dry run only: a JSON file of the issues to pretend are open"
    )
    args = parser.parse_args(argv)
    seed = parse_seed(args.seed)
    now = int(time.time())
    budget = Budget(RUN_BUDGET_SECONDS)
    run_url = ""
    if os.environ.get("GITHUB_RUN_ID") and args.repo:
        server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        run_url = f"{server}/{args.repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}"

    state, state_note = load_state(args.state)
    seen = observe(args.api, seed, budget)
    analysis = analyse(seen, state, now)
    if state_note:
        analysis.notes.append(state_note)

    extra = []
    ok = True
    if args.dry_run:
        gh = None
        issues = []
        if args.open_issues:
            with open(args.open_issues, encoding="utf-8") as handle:
                issues = json.load(handle)
        else:
            extra.append("dry run: no gh call was made, and no issue is assumed to be open")
    else:
        if not args.repo:
            raise SystemExit("no repository: set GITHUB_REPOSITORY or pass --repo")
        gh = Gh(args.repo)
        try:
            issues = gh.open_issues()
        except (GhError, ValueError) as error:
            issues = None
            ok = False
            extra.append(f"could not list the open issues: {code(error, 200)}")

    step_lines = []
    before = set(state.get("active", []))
    active = before
    if issues is not None:
        steps = plan_steps(analysis.verdicts, issues, before, analysis.headline, now, run_url)
        step_lines, failed = execute(steps, gh)
        ok = ok and not failed
        alarming = {v.kind for v in analysis.verdicts if v.state == ALARM}
        unjudged = {v.kind for v in analysis.verdicts if v.state == UNKNOWN}
        # A kind whose issue could not be made is not recorded, so that the next run tries again.
        active = (alarming - failed) | (before & unjudged)
    analysis.state["active"] = sorted(active)

    summary = render_summary(analysis, step_lines, extra, now)
    say(summary)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(summary)
    if ok:
        try:
            save_state(args.state, analysis.state)
        except OSError as error:
            say(f"could not save the state: {type(error).__name__}")
            return 1
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
