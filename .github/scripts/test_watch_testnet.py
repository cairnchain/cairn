"""Tests of the test network watcher.

The checks are pure functions and are tested on small fixtures and on blocks
built here. The few tests that touch a socket talk to 127.0.0.1 only.

Run: python3 -m unittest discover -s .github/scripts
"""

import copy
import http.server
import json
import os
import socket
import threading
import time
import unittest
from unittest import mock

import watch_testnet as watch
from watch_testnet import ALARM, OK, UNKNOWN, Block

HERE = os.path.dirname(os.path.abspath(__file__))


def fixture(name):
    with open(os.path.join(HERE, "fixtures", name), encoding="utf-8") as handle:
        return json.load(handle)


def chain(count, first=1, gap=60, difficulty=1000, start=1_000_000, miner="tcairn1aaa"):
    """`count` blocks, `gap` seconds apart, at one difficulty, lowest height first."""
    return [
        Block(first + i, f"id{first + i:06d}", start + i * gap, difficulty, miner)
        for i in range(count)
    ]


def by_kind(analysis):
    return {verdict.kind: verdict for verdict in analysis.verdicts}


class Helpers(unittest.TestCase):
    def test_text_from_outside_cannot_break_out_of_its_code_span(self):
        text = watch.code("a`b|c\n@someone ::error:: \u2014 \U0001f600")
        self.assertTrue(text.startswith("`") and text.endswith("`"))
        self.assertNotIn("\n", text)
        self.assertNotIn("|", text)
        self.assertEqual(text.count("`"), 2)
        self.assertTrue(text.isascii())

    def test_long_text_is_cut(self):
        self.assertLessEqual(len(watch.code("x" * 1000, 50)), 52)

    def test_durations_read_as_a_person_would_say_them(self):
        self.assertEqual(watch.duration(90), "90 s")
        self.assertEqual(watch.duration(1200), "20 min")
        self.assertEqual(watch.duration(3 * 3600 + 5 * 60), "3 h 5 min")
        self.assertEqual(watch.duration(3 * 86400 + 7200), "3 d 2 h")

    def test_doublings(self):
        self.assertEqual(watch.doublings(9, 8), 0)
        self.assertEqual(watch.doublings(16, 8), 1)
        self.assertEqual(watch.doublings(31, 8), 1)
        self.assertEqual(watch.doublings(32, 8), 2)
        self.assertEqual(watch.doublings(1, 8), 0)

    def test_log_lines_cannot_be_workflow_commands(self):
        with mock.patch("builtins.print") as printed:
            watch.say("::set-output name=x::y\nfine")
        self.assertEqual(printed.call_args_list[0].args[0], ": :set-output name=x: :y")
        self.assertEqual(printed.call_args_list[1].args[0], "fine")

    def test_numbers_come_from_decimal_strings_and_integers_only(self):
        self.assertEqual(watch.number("123"), 123)
        self.assertEqual(watch.number(7), 7)
        for bad in (None, True, "1.5", "-3", "abc", [], 2.5):
            self.assertIsNone(watch.number(bad))


class Reading(unittest.TestCase):
    def test_the_listing_fixture_parses_lowest_first(self):
        blocks = watch.parse_blocks(fixture("blocks.json"))
        self.assertEqual(len(blocks), 24)
        self.assertEqual([b.height for b in blocks], sorted(b.height for b in blocks))
        self.assertEqual(blocks[-1].height, 1832)
        self.assertEqual(blocks[-1].difficulty, 393899660)
        self.assertTrue(blocks[0].miner.startswith("tcairn1"))

    def test_a_listing_of_the_wrong_shape_is_refused(self):
        for bad in ({}, {"blocks": 3}, {"blocks": [{"height": 1}]}, []):
            with self.assertRaises(watch.BadAnswer):
                watch.parse_blocks(bad)

    def test_a_block_that_pays_nobody_has_no_miner(self):
        row = dict(fixture("blocks.json")["blocks"][0], miner=None)
        self.assertIsNone(watch.parse_blocks({"blocks": [row]})[0].miner)

    def test_the_target_comes_from_the_params_or_defaults_to_sixty(self):
        self.assertEqual(watch.target_seconds(fixture("params.json")), 60)
        self.assertEqual(watch.target_seconds({"targetBlockTime": 5}), 5)
        self.assertEqual(watch.target_seconds(None), 60)
        self.assertEqual(watch.target_seconds({}), 60)


class StaleTip(unittest.TestCase):
    def test_a_fresh_tip_is_fine(self):
        verdict = watch.check_stale_tip(1000, None, 1072, 60)
        self.assertEqual(verdict.state, OK)

    def test_exactly_twenty_targets_is_still_fine_and_one_second_more_is_not(self):
        self.assertEqual(watch.check_stale_tip(0, None, 1200, 60).state, OK)
        self.assertEqual(watch.check_stale_tip(0, None, 1201, 60).state, ALARM)

    def test_the_threshold_follows_the_target_block_time(self):
        self.assertEqual(watch.check_stale_tip(0, None, 101, 5).state, ALARM)
        self.assertEqual(watch.check_stale_tip(0, None, 101, 60).state, OK)

    def test_the_level_rises_each_time_the_age_doubles(self):
        levels = [watch.check_stale_tip(0, None, age, 60).level for age in (1300, 2399, 2400, 4800)]
        self.assertEqual(levels, [0, 0, 1, 2])

    def test_a_tip_dated_ahead_of_the_clock_is_not_stale(self):
        self.assertEqual(watch.check_stale_tip(5000, None, 1000, 60).state, OK)

    def test_no_tip_counts_age_from_the_opening(self):
        self.assertEqual(watch.check_stale_tip(None, 0, 5000, 60).state, ALARM)
        self.assertEqual(watch.check_stale_tip(None, 10_000, 5000, 60).state, OK)
        self.assertEqual(watch.check_stale_tip(None, None, 5000, 60).state, UNKNOWN)

    def test_the_alarm_says_how_old_and_how_many_peers(self):
        verdict = watch.check_stale_tip(0, None, 4000, 60, peers=0)
        text = " ".join(verdict.facts)
        self.assertIn("66 min", text)
        self.assertIn("0 peers", text)


class Difficulty(unittest.TestCase):
    def test_the_live_listing_is_calm(self):
        blocks = watch.parse_blocks(fixture("blocks.json"))
        verdict = watch.check_difficulty(blocks)
        self.assertEqual(verdict.state, OK)

    def test_a_rise_past_eight_times_is_an_alarm(self):
        blocks = chain(60)
        blocks[-1] = blocks[-1]._replace(difficulty=9001)
        verdict = watch.check_difficulty(blocks)
        self.assertEqual(verdict.state, ALARM)
        self.assertIn("rose", verdict.detail)

    def test_a_fall_past_eight_times_is_an_alarm_too(self):
        blocks = chain(60)
        blocks[-1] = blocks[-1]._replace(difficulty=100)
        verdict = watch.check_difficulty(blocks)
        self.assertEqual(verdict.state, ALARM)
        self.assertIn("fell", verdict.detail)

    def test_exactly_eight_times_is_not(self):
        blocks = chain(60)
        blocks[-1] = blocks[-1]._replace(difficulty=8000)
        self.assertEqual(watch.check_difficulty(blocks).state, OK)

    def test_only_the_last_sixty_blocks_are_judged(self):
        blocks = chain(100)
        blocks[0] = blocks[0]._replace(difficulty=1)
        self.assertEqual(watch.check_difficulty(blocks).state, OK)
        blocks[50] = blocks[50]._replace(difficulty=1)
        self.assertEqual(watch.check_difficulty(blocks).state, ALARM)

    def test_the_level_rises_when_the_swing_doubles(self):
        small, large = chain(60), chain(60)
        small[-1] = small[-1]._replace(difficulty=9000)
        large[-1] = large[-1]._replace(difficulty=17000)
        self.assertLess(watch.check_difficulty(small).level, watch.check_difficulty(large).level)

    def test_one_block_has_nothing_to_compare(self):
        self.assertEqual(watch.check_difficulty(chain(1)).state, OK)


class FastRun(unittest.TestCase):
    def test_the_live_listing_is_not_a_burst(self):
        blocks = watch.parse_blocks(fixture("blocks.json"))
        self.assertEqual(watch.check_fast_run(blocks, 60).state, OK)

    def test_twenty_blocks_in_under_five_minutes_is_an_alarm(self):
        blocks = chain(60, gap=60) + chain(20, first=61, gap=10, start=1_000_000 + 60 * 60)
        verdict = watch.check_fast_run(blocks, 60)
        self.assertEqual(verdict.state, ALARM)
        self.assertIn("faster", " ".join(verdict.facts))

    def test_twenty_blocks_in_exactly_five_minutes_is_not(self):
        blocks = chain(20, gap=300 / 19)
        blocks = [b._replace(timestamp=1_000_000 + round(i * 300 / 19)) for i, b in enumerate(blocks)]
        self.assertEqual(blocks[-1].timestamp - blocks[0].timestamp, 300)
        self.assertEqual(watch.check_fast_run(blocks, 60).state, OK)

    def test_nineteen_fast_blocks_are_not_a_run(self):
        self.assertEqual(watch.check_fast_run(chain(19, gap=1), 60).state, OK)

    def test_blocks_with_a_gap_in_the_listing_are_not_a_run(self):
        blocks = chain(20, gap=1)
        blocks[10:] = [b._replace(height=b.height + 5) for b in blocks[10:]]
        self.assertEqual(watch.check_fast_run(blocks, 60).state, OK)

    def test_the_limit_follows_the_target_block_time(self):
        blocks = chain(20, gap=2)
        self.assertEqual(watch.check_fast_run(blocks, 60).state, ALARM)
        self.assertEqual(watch.check_fast_run(blocks, 5).state, OK)
        self.assertEqual(watch.check_fast_run(chain(20, gap=1), 5).state, ALARM)

    def test_the_level_rises_as_the_burst_grows(self):
        short = watch.check_fast_run(chain(25, gap=1), 60)
        long = watch.check_fast_run(chain(60, gap=1), 60)
        self.assertLess(short.level, long.level)

    def test_timestamps_that_run_backwards_do_not_break_it(self):
        blocks = chain(20, gap=1)
        blocks[5] = blocks[5]._replace(timestamp=1_000_000 - 10)
        self.assertEqual(watch.check_fast_run(blocks, 60).state, ALARM)


class Supply(unittest.TestCase):
    def setUp(self):
        self.status = fixture("status.json")

    def test_the_live_figures_agree(self):
        verdict = watch.check_supply(self.status)
        self.assertEqual(verdict.state, OK)
        self.assertIn("issued equals counted", verdict.detail)

    def test_issued_and_counted_apart_is_an_alarm_when_the_index_is_whole(self):
        self.status["supply"]["counted"] = str(int(self.status["supply"]["counted"]) - 5)
        self.status["supply"]["paidToMiners"] = str(int(self.status["supply"]["paidToMiners"]) - 5)
        verdict = watch.check_supply(self.status)
        self.assertEqual(verdict.state, ALARM)
        self.assertEqual(verdict.members, ("issued-is-counted",))

    def test_issued_is_not_compared_while_the_index_is_behind(self):
        self.status["supply"]["counted"] = "1"
        self.status["supply"]["paidToMiners"] = str(1 + int(self.status["supply"]["fees"]))
        self.status["index"]["behind"] = 9
        self.assertEqual(watch.check_supply(self.status).state, OK)

    def test_issued_is_not_compared_when_the_index_starts_above_block_zero(self):
        self.status["supply"]["counted"] = "1"
        self.status["supply"]["paidToMiners"] = str(1 + int(self.status["supply"]["fees"]))
        self.status["index"]["fromTheStart"] = False
        self.assertEqual(watch.check_supply(self.status).state, OK)

    def test_totals_that_do_not_add_up_are_an_alarm_even_when_the_index_is_behind(self):
        self.status["supply"]["paidToMiners"] = "1" + self.status["supply"]["paidToMiners"]
        self.status["index"]["behind"] = 9
        verdict = watch.check_supply(self.status)
        self.assertEqual(verdict.state, ALARM)
        self.assertEqual(verdict.members, ("paid-is-counted-plus-fees",))

    def test_both_identities_broken_names_both(self):
        self.status["supply"]["paidToMiners"] = "1" + self.status["supply"]["paidToMiners"]
        self.status["supply"]["counted"] = "5"
        verdict = watch.check_supply(self.status)
        self.assertEqual(
            sorted(verdict.members), ["issued-is-counted", "paid-is-counted-plus-fees"]
        )

    def test_fees_above_payments_is_the_explorers_clamp_and_not_a_disagreement(self):
        self.status["supply"].update(counted="0", fees="10", paidToMiners="4", issued="0")
        self.assertEqual(watch.check_supply(self.status).state, OK)

    def test_missing_figures_are_not_checked_rather_than_passed(self):
        del self.status["supply"]["counted"]
        self.assertEqual(watch.check_supply(self.status).state, UNKNOWN)
        self.assertEqual(watch.check_supply({}).state, UNKNOWN)


class NodeHealth(unittest.TestCase):
    def setUp(self):
        self.node = fixture("status.json")["node"]

    def test_the_live_node_is_well(self):
        verdict, unknown = watch.check_node_health(self.node)
        self.assertEqual(verdict.state, OK)
        self.assertEqual(unknown, ())

    def test_every_field_that_is_null_when_well_alarms_when_set(self):
        for name in watch.NODE_NULL_WHEN_WELL:
            node = dict(self.node)
            node[name] = {"because": "disk full"} if name != "unsavedAddresses" else "no space"
            verdict, _ = watch.check_node_health(node)
            self.assertEqual(verdict.state, ALARM, name)
            self.assertEqual(verdict.members, (name,))

    def test_the_counters_alarm_above_zero(self):
        for name in watch.NODE_ZERO_WHEN_WELL:
            node = dict(self.node, **{name: 3})
            verdict, _ = watch.check_node_health(node)
            self.assertEqual(verdict.members, (name,))

    def test_joining_is_well_as_no_or_done_and_not_otherwise(self):
        for well in ("no", "done"):
            self.assertEqual(watch.check_node_health(dict(self.node, joining=well))[0].state, OK)
        for busy in ("weighing 1/4", "ledger 2/9"):
            verdict, _ = watch.check_node_health(dict(self.node, joining=busy))
            self.assertEqual(verdict.members, ("joining",))

    def test_visitors_turned_away_alarm_only_when_the_count_grew(self):
        node = dict(self.node, turnedAway=12)
        self.assertEqual(watch.check_node_health(node, None)[0].state, OK)
        self.assertEqual(watch.check_node_health(node, 12)[0].state, OK)
        self.assertEqual(watch.check_node_health(node, 30)[0].state, OK)
        verdict, _ = watch.check_node_health(node, 11)
        self.assertEqual(verdict.members, ("turnedAway",))

    def test_the_written_height_is_a_reading_and_not_a_fault(self):
        node = dict(self.node, writtenThrough=99)
        self.assertEqual(watch.check_node_health(node)[0].state, OK)
        self.assertEqual(watch.check_node_health(dict(self.node, writtenThrough=None))[0].state, OK)

    def test_fields_the_watcher_does_not_know_are_listed_and_not_judged(self):
        verdict, unknown = watch.check_node_health(dict(self.node, brandNew={"x": 1}))
        self.assertEqual(verdict.state, OK)
        self.assertEqual(unknown, ("brandNew",))

    def test_several_set_fields_are_all_named(self):
        node = dict(self.node, unread={"height": 4}, mended=2)
        verdict, _ = watch.check_node_health(node)
        self.assertEqual(verdict.members, ("mended", "unread"))
        self.assertEqual(len(verdict.facts), 2)

    def test_no_node_object_is_not_checked(self):
        self.assertEqual(watch.check_node_health(None)[0].state, UNKNOWN)


class Reorgs(unittest.TestCase):
    def heights(self, first, last, tag=""):
        return {h: f"{tag}id{h}" for h in range(first, last + 1)}

    def test_a_chain_that_only_grew_has_no_reorg(self):
        self.assertIsNone(watch.find_reorg(self.heights(1, 10), self.heights(1, 14)))

    def test_nothing_to_compare_on_the_first_reading(self):
        self.assertIsNone(watch.find_reorg({}, self.heights(1, 10)))

    def test_the_old_tip_replaced_is_depth_one(self):
        old, new = self.heights(1, 10), self.heights(1, 11)
        new[10] = "other10"
        found = watch.find_reorg(old, new)
        self.assertEqual((found.fork, found.depth, found.old_tip), (10, 1, 10))
        self.assertEqual((found.old_id, found.new_id), ("id10", "other10"))

    def test_depth_counts_from_the_fork_to_the_old_tip(self):
        old, new = self.heights(1, 10), self.heights(1, 12)
        for height in (7, 8, 9, 10, 11, 12):
            new[height] = f"fork{height}"
        found = watch.find_reorg(old, new)
        self.assertEqual((found.fork, found.depth), (7, 4))

    def test_a_chain_that_got_shorter_counts_as_replaced(self):
        found = watch.find_reorg(self.heights(1, 10), self.heights(1, 8))
        self.assertEqual((found.fork, found.depth), (9, 2))
        self.assertIsNone(found.new_id)

    def test_heights_below_the_new_listing_cannot_be_judged(self):
        old = self.heights(1, 10)
        new = self.heights(5, 14)
        self.assertIsNone(watch.find_reorg(old, new))
        old[3] = "different, but below anything the new listing shows"
        self.assertIsNone(watch.find_reorg(old, new))

    def test_a_height_missing_from_the_middle_of_the_listing_is_not_a_reorg(self):
        new = self.heights(1, 12)
        del new[5]
        self.assertIsNone(watch.find_reorg(self.heights(1, 10), new))

    def test_no_events_is_ok_and_says_whether_it_was_a_baseline(self):
        self.assertEqual(watch.check_reorgs([], 50, True).state, OK)
        self.assertIn("first reading", watch.check_reorgs([], 50, True).detail)
        self.assertIn("50 compared", watch.check_reorgs([], 50, False).detail)

    def test_held_events_make_the_alarm_with_the_deepest_as_the_level(self):
        events = [
            {"at": 1, "fork": 7, "depth": 2, "old_tip": 8, "old": "a" * 64, "new": "b" * 64},
            {"at": 2, "fork": 20, "depth": 5, "old_tip": 24, "old": "c" * 64, "new": None},
        ]
        verdict = watch.check_reorgs(events, 128, False)
        self.assertEqual((verdict.state, verdict.level), (ALARM, 5))
        self.assertEqual(len(verdict.members), 2)
        self.assertIn("5 block(s) deep", " ".join(verdict.facts))
        self.assertIn("gone", " ".join(verdict.facts))


class Owners(unittest.TestCase):
    def test_an_owner_not_known_is_reported_with_where_it_first_appears(self):
        blocks = chain(5) + [Block(6, "x6", 9, 1, "tcairn1new"), Block(7, "x7", 10, 1, "tcairn1new")]
        found = watch.new_owners(["tcairn1aaa"], blocks)
        self.assertEqual(found, [("tcairn1new", 6, 2)])

    def test_known_owners_and_blocks_paying_nobody_are_not_new(self):
        blocks = chain(3) + [Block(4, "x4", 9, 1, None)]
        self.assertEqual(watch.new_owners(["tcairn1aaa"], blocks), [])


class Markers(unittest.TestCase):
    def verdict(self, level=2, members=("b", "a")):
        return watch.Verdict(watch.REORG, ALARM, "d", level=level, members=members)

    def test_a_marker_reads_back(self):
        text = "text\n" + watch.marker(self.verdict())
        self.assertEqual(watch.read_marker(text), (watch.REORG, 2, frozenset({"a", "b"})))

    def test_members_cannot_break_the_comment(self):
        marker = watch.marker(self.verdict(members=("x --> <b>", "y,z")))
        self.assertEqual(marker.count("-->"), 1)
        self.assertIsNotNone(watch.read_marker(marker))

    def test_the_newest_comment_is_what_the_issue_last_said(self):
        issue = {
            "body": watch.marker(self.verdict(level=1)),
            "comments": [
                {"body": "a human remark"},
                {"body": watch.marker(self.verdict(level=4))},
                {"body": "another remark"},
            ],
        }
        self.assertEqual(watch.last_marker(issue)[1], 4)
        del issue["comments"]
        self.assertEqual(watch.last_marker(issue)[1], 1)

    def test_a_rise_in_level_or_a_change_of_members_is_material_and_a_fall_is_not(self):
        last = (watch.REORG, 2, frozenset({"a", "b"}))
        same = self.verdict(2, ("a", "b"))
        self.assertFalse(watch.changed_materially(same, last))
        self.assertTrue(watch.changed_materially(self.verdict(3, ("a", "b")), last))
        self.assertFalse(watch.changed_materially(self.verdict(1, ("a", "b")), last))
        self.assertTrue(watch.changed_materially(self.verdict(2, ("a",)), last))
        self.assertTrue(watch.changed_materially(same, None))


HEAD = {"network": "testnet-7", "tip": "height 5", "peers": 4}


def verdict(kind, state, level=0, members=()):
    return watch.Verdict(kind, state, "detail", level=level, members=members, facts=("a fact",))


def issue(number, kind, level=0, members=(), comments=()):
    body = watch.marker(verdict(kind, ALARM, level, members))
    return {"number": number, "title": watch.TITLES[kind], "body": body, "comments": list(comments)}


def plan(verdicts, issues=(), active=()):
    return watch.plan_steps(verdicts, list(issues), set(active), HEAD, 1_000_000, "https://run")


class Planning(unittest.TestCase):
    def test_an_alarm_with_no_issue_opens_one_carrying_its_marker_and_figures(self):
        steps = plan([verdict(watch.STALE, ALARM, 1)])
        self.assertEqual([s.verb for s in steps], ["open"])
        self.assertIn("a fact", steps[0].body)
        self.assertIn("kind=stale-tip level=1", steps[0].body)
        self.assertIn("https://run", steps[0].body)
        self.assertEqual(steps[0].title, watch.TITLES[watch.STALE])

    def test_the_same_alarm_again_changes_nothing(self):
        existing = issue(4, watch.STALE, level=1)
        self.assertEqual(plan([verdict(watch.STALE, ALARM, 1)], [existing]), [])

    def test_a_figure_that_moved_inside_its_level_is_not_commented(self):
        existing = issue(4, watch.STALE, level=2)
        self.assertEqual(plan([verdict(watch.STALE, ALARM, 1)], [existing]), [])

    def test_a_rise_in_level_comments_on_the_existing_issue(self):
        steps = plan([verdict(watch.STALE, ALARM, 2)], [issue(4, watch.STALE, level=1)])
        self.assertEqual([(s.verb, s.number) for s in steps], [("comment", 4)])

    def test_the_level_a_comment_left_is_the_one_compared_with(self):
        existing = issue(
            4, watch.STALE, level=1,
            comments=[{"body": watch.marker(verdict(watch.STALE, ALARM, 3))}],
        )  # fmt: skip
        self.assertEqual(plan([verdict(watch.STALE, ALARM, 3)], [existing]), [])

    def test_a_cleared_alarm_closes_its_issue_with_a_comment(self):
        steps = plan([verdict(watch.STALE, OK)], [issue(4, watch.STALE)])
        self.assertEqual([(s.verb, s.number) for s in steps], [("close", 4)])
        self.assertIn("cleared", steps[0].body)

    def test_a_check_that_could_not_run_leaves_its_issue_alone(self):
        steps = plan([verdict(watch.STALE, UNKNOWN)], [issue(4, watch.STALE)])
        self.assertEqual(steps, [])

    def test_each_kind_has_its_own_issue(self):
        steps = plan(
            [verdict(watch.STALE, ALARM), verdict(watch.REORG, ALARM, 1)],
            [issue(4, watch.STALE)],
        )
        self.assertEqual([(s.verb, s.kind) for s in steps], [("open", watch.REORG)])

    def test_two_open_issues_of_one_kind_are_collapsed_onto_the_oldest(self):
        steps = plan([verdict(watch.STALE, ALARM)], [issue(9, watch.STALE), issue(4, watch.STALE)])
        self.assertEqual([(s.verb, s.number) for s in steps], [("close-duplicate", 9)])

    def test_an_issue_closed_by_hand_is_not_opened_again_while_the_alarm_lasts(self):
        steps = plan([verdict(watch.STALE, ALARM)], [], active=[watch.STALE])
        self.assertEqual([s.verb for s in steps], ["leave-closed"])

    def test_an_issue_without_our_marker_is_never_touched(self):
        stranger = {"number": 2, "title": "mine", "body": "hello", "comments": []}
        self.assertEqual(plan([verdict(watch.STALE, OK)], [stranger]), [])

    def test_a_changed_set_of_members_comments(self):
        existing = issue(4, watch.HEALTH, members=("mended",))
        steps = plan([verdict(watch.HEALTH, ALARM, 0, ("mended", "unread"))], [existing])
        self.assertEqual([s.verb for s in steps], ["comment"])


class Executing(unittest.TestCase):
    def test_a_dry_run_prints_and_calls_nothing(self):
        steps = plan([verdict(watch.STALE, ALARM)])
        with mock.patch("builtins.print") as printed:
            lines, failed = watch.execute(steps, None)
        self.assertEqual(failed, set())
        self.assertIn("would open", lines[0])
        self.assertTrue(printed.called)

    def test_a_failing_gh_is_reported_and_names_the_kind(self):
        class Broken:
            def open(self, title, body):
                raise watch.GhError("no permission")

        lines, failed = watch.execute(plan([verdict(watch.STALE, ALARM)]), Broken())
        self.assertEqual(failed, {watch.STALE})
        self.assertIn("could not open", lines[0])

    def test_gh_is_given_a_time_limit_and_no_shell(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="[]", stderr="")
            watch.Gh("o/r").open_issues()
        _, kwargs = run.call_args
        self.assertEqual(kwargs["timeout"], watch.GH_TIMEOUT_SECONDS)
        self.assertNotIn("shell", kwargs)
        self.assertEqual(run.call_args.args[0][:3], ["gh", "issue", "list"])

    def test_a_gh_that_hangs_is_an_error_and_not_a_hang(self):
        import subprocess

        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("gh", 30)):
            with self.assertRaises(watch.GhError):
                watch.Gh("o/r").open_issues()

    def test_the_label_is_created_only_when_missing(self):
        calls = []

        def fake(self, args, stdin=None):
            calls.append(args[:2])
            if args[:2] == ["label", "list"]:
                return json.dumps([{"name": "bug"}])
            if args[:2] == ["issue", "create"]:
                return "https://github.com/o/r/issues/17\n"
            return ""

        with mock.patch.object(watch.Gh, "run", fake):
            self.assertEqual(watch.Gh("o/r").open("t", "b"), 17)
        self.assertIn(["label", "create"], calls)
        calls.clear()

        def fake_has(self, args, stdin=None):
            calls.append(args[:2])
            if args[:2] == ["label", "list"]:
                return json.dumps([{"name": watch.LABEL}])
            return "https://github.com/o/r/issues/18\n"

        with mock.patch.object(watch.Gh, "run", fake_has):
            watch.Gh("o/r").open("t", "b")
        self.assertNotIn(["label", "create"], calls)


class Analysing(unittest.TestCase):
    def setUp(self):
        self.status = fixture("status.json")
        self.blocks = watch.parse_blocks(fixture("blocks.json"))
        self.now = self.status["tip"]["timestamp"] + 30
        self.empty, _ = watch.load_state(None)

    def seen(self, **changes):
        seen = watch.Observed(
            status=self.status,
            params=fixture("params.json"),
            blocks=self.blocks,
            explorer_note="answered in 0.1 s",
            seed_note="accepted a connection in 0.05 s",
        )
        for name, value in changes.items():
            setattr(seen, name, value)
        return seen

    def test_a_healthy_network_alarms_nothing_and_every_check_reports(self):
        analysis = watch.analyse(self.seen(), self.empty, self.now)
        self.assertEqual([v.kind for v in analysis.verdicts].sort(), list(watch.KINDS).sort())
        self.assertEqual({v.state for v in analysis.verdicts}, {OK})
        self.assertEqual(analysis.headline["network"], "testnet-7 (0x4341525a)")

    def test_the_first_reading_records_owners_without_calling_them_new(self):
        analysis = watch.analyse(self.seen(), self.empty, self.now)
        self.assertEqual(analysis.new_owners, [])
        self.assertEqual(len(analysis.state["owners"]), 1)
        self.assertEqual(len(analysis.state["blocks"]), 24)

    def test_a_second_reading_sees_a_miner_it_has_not_met(self):
        first = watch.analyse(self.seen(), self.empty, self.now).state
        blocks = self.blocks + [Block(1833, "n1833", self.blocks[-1].timestamp + 60, 393899660, "tcairn1fresh")]
        analysis = watch.analyse(self.seen(blocks=blocks), first, self.now + 60)
        self.assertEqual(analysis.new_owners, [("tcairn1fresh", 1833, 1)])
        self.assertIn("tcairn1fresh", analysis.state["owners"])
        self.assertEqual({v.state for v in analysis.verdicts}, {OK})

    def test_a_replaced_block_between_readings_is_a_reorg_alarm_and_is_held(self):
        first = watch.analyse(self.seen(), self.empty, self.now).state
        blocks = list(self.blocks)
        blocks[-1] = blocks[-1]._replace(id="replaced")
        analysis = watch.analyse(self.seen(blocks=blocks), first, self.now + 900)
        reorg = by_kind(analysis)[watch.REORG]
        self.assertEqual((reorg.state, reorg.level), (ALARM, 1))
        # and it is still held at the next reading, while the blocks themselves now agree
        later = watch.analyse(self.seen(blocks=blocks), analysis.state, self.now + 1800)
        self.assertEqual(by_kind(later)[watch.REORG].state, ALARM)
        # and gone once the hold has passed
        over = watch.analyse(
            self.seen(blocks=blocks), later.state, self.now + 900 + watch.REORG_HOLD_SECONDS + 1
        )
        self.assertEqual(by_kind(over)[watch.REORG].state, OK)

    def test_a_new_network_drops_what_was_remembered_instead_of_calling_it_a_reorg(self):
        first = watch.analyse(self.seen(), self.empty, self.now).state
        other = copy.deepcopy(self.status)
        other["network"]["genesis"] = "ff" * 32
        other["network"]["name"] = "testnet-8"
        blocks = [b._replace(id="new" + b.id) for b in self.blocks]
        analysis = watch.analyse(self.seen(status=other, blocks=blocks), first, self.now)
        self.assertEqual(by_kind(analysis)[watch.REORG].state, OK)
        self.assertTrue(any("first block changed" in note for note in analysis.notes))
        self.assertEqual(analysis.state["genesis"], "ff" * 32)

    def test_an_unreachable_explorer_judges_nothing_else_and_keeps_its_state(self):
        first = watch.analyse(self.seen(), self.empty, self.now).state
        down = watch.Observed(explorer_error="timed out", seed_note="accepted a connection")
        analysis = watch.analyse(down, first, self.now + 900)
        states = {v.kind: v.state for v in analysis.verdicts}
        self.assertEqual(states.pop(watch.UNREACHABLE), ALARM)
        self.assertEqual(set(states.values()), {UNKNOWN})
        self.assertEqual(analysis.state["blocks"], first["blocks"])
        self.assertEqual(by_kind(analysis)[watch.UNREACHABLE].members, ("explorer",))

    def test_an_unreachable_seed_alone_is_alarm_seven_and_the_rest_still_runs(self):
        analysis = watch.analyse(self.seen(seed_error="refused"), self.empty, self.now)
        states = {v.kind: v.state for v in analysis.verdicts}
        self.assertEqual(states[watch.UNREACHABLE], ALARM)
        self.assertEqual(states[watch.STALE], OK)
        self.assertEqual(by_kind(analysis)[watch.UNREACHABLE].members, ("seed",))

    def test_both_unreachable_names_both(self):
        verdict = watch.check_reachability("a", "b", "", "")
        self.assertEqual(verdict.members, ("explorer", "seed"))

    def test_a_stopped_chain_trips_the_stale_check_through_the_whole_path(self):
        analysis = watch.analyse(self.seen(), self.empty, self.now + 3 * 3600)
        self.assertEqual(by_kind(analysis)[watch.STALE].state, ALARM)

    def test_the_summary_shows_the_headline_every_check_and_the_new_owners(self):
        analysis = watch.analyse(self.seen(), self.empty, self.now)
        analysis.new_owners = [("tcairn1fresh", 1833, 1)]
        text = watch.render_summary(analysis, ["stale-tip: opened #3"], ["a note"], self.now)
        for needle in ("testnet-7", "height 1832", "393899660", "| peers | 4 |", "new coinbase owner",
                       "opened #3", "a note"):
            self.assertIn(needle, text)
        for name in watch.CHECK_NAMES.values():
            self.assertIn(f"| {name} |", text)
        self.assertTrue(text.isascii())


class State(unittest.TestCase):
    def test_state_survives_a_round_trip_with_integer_heights(self):
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "deeper", "state.json")
            state, _ = watch.load_state(path)
            state.update(blocks={5: "five"}, owners=["o"], active=["reorg"], genesis="g")
            watch.save_state(path, state)
            back, note = watch.load_state(path)
        self.assertIsNone(note)
        self.assertEqual(back["blocks"], {5: "five"})
        self.assertEqual((back["owners"], back["active"], back["genesis"]), (["o"], ["reorg"], "g"))

    def test_a_damaged_state_file_starts_over_and_says_so(self):
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "state.json")
            for damage in ("{not json", "[]", '{"blocks": {"x": "y"}}', '{"blocks": 4}'):
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(damage)
                state, note = watch.load_state(path)
                self.assertEqual(state["blocks"], {})
                self.assertIsNotNone(note, damage)

    def test_no_path_means_no_state(self):
        self.assertEqual(watch.load_state(None)[0]["blocks"], {})
        watch.save_state(None, {"blocks": {}})


class Serving(http.server.BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        body = self.routes.get(self.path.split("?")[0])
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else json.dumps(body).encode())

    def log_message(self, *args):
        pass


class Quiet(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # a client that gave up on an answer is the point of some tests

    def stop(self):
        self.shutdown()
        self.server_close()


def serve(routes):
    handler = type("Handler", (Serving,), {"routes": routes})
    server = Quiet(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def closed_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class Network(unittest.TestCase):
    def setUp(self):
        patches = [
            mock.patch.object(watch, "RETRY_PAUSE_SECONDS", 0),
            mock.patch.object(watch, "HTTP_TIMEOUT_SECONDS", 0.5),
            mock.patch.object(watch, "TCP_TIMEOUT_SECONDS", 0.5),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_a_json_answer_is_read(self):
        server = serve({"/api/status": {"a": 1}})
        self.addCleanup(server.stop)
        base = f"http://127.0.0.1:{server.server_port}"
        payload, took = watch.get_json(base, "/api/status", watch.Budget(10))
        self.assertEqual(payload, {"a": 1})
        self.assertLess(took, 5)

    def test_every_way_of_not_answering_is_unreachable_and_never_another_error(self):
        server = serve({"/text": b"<html>", "/list": b"[1]", "/big": b"{" + b" " * 2_000_000})
        self.addCleanup(server.stop)
        base = f"http://127.0.0.1:{server.server_port}"
        for path in ("/missing", "/text", "/list", "/big"):
            with self.assertRaises(watch.Unreachable, msg=path):
                watch.get_json(base, path, watch.Budget(10))
        with self.assertRaises(watch.Unreachable):
            watch.get_json(f"http://127.0.0.1:{closed_port()}", "/api/status", watch.Budget(10))
        with self.assertRaises(watch.Unreachable):
            watch.get_json("file:///etc/hosts", "", watch.Budget(10))

    def test_a_server_that_accepts_and_never_answers_is_given_up_on_in_time(self):
        silent = socket.socket()
        silent.bind(("127.0.0.1", 0))
        silent.listen(5)
        self.addCleanup(silent.close)
        began = time.monotonic()
        with self.assertRaises(watch.Unreachable):
            watch.get_json(f"http://127.0.0.1:{silent.getsockname()[1]}", "/x", watch.Budget(30))
        self.assertLess(time.monotonic() - began, 15)

    def test_a_spent_budget_stops_new_requests(self):
        with self.assertRaises(watch.Unreachable) as caught:
            watch.get_json("http://127.0.0.1:1", "/x", watch.Budget(-1))
        self.assertIn("budget", str(caught.exception))

    def test_the_seed_is_reached_when_something_listens(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        self.addCleanup(listener.close)
        self.assertLess(watch.probe_tcp("127.0.0.1", listener.getsockname()[1], watch.Budget(10)), 5)

    def test_the_seed_is_unreachable_when_nothing_listens(self):
        with self.assertRaises(watch.Unreachable):
            watch.probe_tcp("127.0.0.1", closed_port(), watch.Budget(10))

    def test_a_name_that_does_not_resolve_is_unreachable(self):
        with self.assertRaises(watch.Unreachable):
            watch.probe_tcp("no-such-host.invalid", 9944, watch.Budget(10))

    def routes(self, **changes):
        status = fixture("status.json")
        status.update(changes)
        return {
            "/api/status": status,
            "/api/params": fixture("params.json"),
            "/api/blocks": fixture("blocks.json"),
        }

    def run_main(self, base, seed_port, state, extra=()):
        argv = ["--dry-run", "--api", base, "--seed", f"127.0.0.1:{seed_port}", "--state", state]
        stamp = fixture("status.json")["tip"]["timestamp"] + 20
        with mock.patch("time.time", return_value=stamp), mock.patch("builtins.print") as out:
            code = watch.main(argv + list(extra))
        return code, "\n".join(str(c.args[0]) for c in out.call_args_list if c.args)

    def test_a_whole_dry_run_against_a_healthy_local_network(self):
        import tempfile

        server = serve(self.routes())
        self.addCleanup(server.stop)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        self.addCleanup(listener.close)
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "state.json")
            code, text = self.run_main(
                f"http://127.0.0.1:{server.server_port}", listener.getsockname()[1], path
            )
            self.assertTrue(os.path.exists(path))
        self.assertEqual(code, 0)
        self.assertIn("Test network watch", text)
        self.assertNotIn("ALARM", text)
        self.assertIn("no gh call was made", text)

    def test_a_dead_network_is_alarm_seven_and_the_job_still_succeeds(self):
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            code, text = self.run_main(
                f"http://127.0.0.1:{closed_port()}", closed_port(), os.path.join(folder, "s.json")
            )
        self.assertEqual(code, 0)
        self.assertIn("| reachability | ALARM |", text)
        self.assertIn("dry run, would open a new issue for unreachable", text)
        self.assertIn("| tip age | not checked |", text)


class Hygiene(unittest.TestCase):
    """What the brief forbids anywhere in the files this adds."""

    def files(self):
        root = os.path.abspath(os.path.join(HERE, "..", ".."))
        paths = [os.path.join(HERE, name) for name in os.listdir(HERE) if name.endswith(".py")]
        paths += [os.path.join(HERE, "fixtures", name) for name in os.listdir(os.path.join(HERE, "fixtures"))]
        workflow = os.path.join(root, ".github", "workflows", "watch-testnet.yml")
        if os.path.exists(workflow):
            paths.append(workflow)
        return paths

    def test_ascii_only_so_no_em_dash_and_no_emoji(self):
        for path in self.files():
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            self.assertTrue(text.isascii(), path)

    def test_no_third_party_import_in_the_script(self):
        allowed = {
            "argparse", "http", "json", "math", "os", "re", "socket", "subprocess", "sys",
            "threading", "time", "urllib", "dataclasses", "typing", "__future__",
        }  # fmt: skip
        with open(os.path.join(HERE, "watch_testnet.py"), encoding="utf-8") as handle:
            for line in handle:
                if line.startswith(("import ", "from ")):
                    self.assertIn(line.split()[1].split(".")[0], allowed, line)


if __name__ == "__main__":
    unittest.main()
