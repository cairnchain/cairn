//! What this program says to whoever runs it, about its node.
//!
//! The explorer is a node, and its node stops itself in the three states
//! `cairnd` stops in: a disk past saving, a ledger nobody will deliver the
//! blocks under, and rules this build does not have. `cairnd` prints a
//! paragraph and exits one; the explorer said nothing and went on serving a
//! frozen chain for ever, with a unit file whose `Restart=always` never fired
//! because the process never ended. It also printed two of the ten things a
//! start can say about the disk, and none of what `cairnd` says before it is a
//! minute old.
//!
//! The sentences are `cairnd`'s, word for word, and not a paraphrase: the two
//! programs read the same node, and two descriptions of one state are how
//! one of them comes to be wrong. They are copied rather than shared because
//! `cairnd` is a binary and keeps them in its own `main.rs`;
//! `the_words_are_cairnds_word_for_word` holds each function here to its twin
//! there, so a change to one without the other fails rather than drifts.

use cairn_chain::Outdated;
use cairn_ledger::block::BLOCK_VERSION;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::node::{Stranded, Unread, Unwritten, MAX_BEHIND};
use cairn_net::Restored;

/// Why this node stopped itself, in the words an operator reads, or nothing
/// if it has not.
///
/// A function of what the node says about itself rather than of the node, so
/// that the mapping can be read and held to without a disk that has filled or
/// a chain whose rules moved on. Every state that answers here is a state the
/// node cannot get out of on its own, which is what makes it a fault and not
/// a stop.
///
/// The disk is the one with a condition on it. A node behind on its writes and
/// still able to catch up is not stopping: it says so on its status lines and
/// carries on, and the difference between the two is `within_reach`.
pub(crate) fn stopped_itself(
    outdated: Option<Outdated>,
    stranded: Option<Stranded>,
    unwritten: Option<Unwritten>,
    directory: &str,
) -> Option<String> {
    // A rule took effect at a height this build has no rules for. Going on
    // would mean refusing every peer that had updated and following whoever
    // had not, so the node says which version it needs and stops.
    if let Some(outdated) = outdated {
        return Some(format!(
            "the rules at height {} are block version {}, and this build knows only \
             version {}. Update and start again; the chain on disk is kept and nothing \
             is lost.",
            outdated.height, outdated.required, outdated.known,
        ));
    }
    // A ledger this node was handed, and blocks above it that nobody will
    // deliver. It cannot get back below where it was handed on, so there is
    // nothing to wait for and nothing it can do about it; the cure is the
    // operator's.
    if let Some(stranded) = stranded {
        return Some(format!(
            "this node was handed a ledger at height {}, and had to check its way to \
             height {} before it could stand behind it. It waited {} seconds with peers \
             to ask and not one of the blocks in between arrived{}. It holds nothing \
             below the ledger, so no chain forking under it can be followed from here. \
             Delete the data directory and start again, from a seed you trust.",
            stranded.anchor,
            stranded.settles_at,
            stranded.waited,
            if stranded.out_of_reach > 0 {
                format!(
                    ", while {} blocks arrived from a chain it cannot reach",
                    stranded.out_of_reach
                )
            } else {
                String::new()
            },
        ));
    }
    // The disk stopped taking what this node writes, and it has now accepted
    // more blocks than it could ever write down. Nothing an operator does from
    // here puts those blocks on the disk, so what is left to protect is the
    // directory itself: every block accepted past this point is one more the
    // disk does not have, and one more the next start has to fetch again.
    unwritten
        .filter(|held| !held.within_reach)
        .map(|unwritten| lost_the_disk(&unwritten, directory))
}

/// The disk this node keeps and the block it has reached, said in one place.
///
/// Both messages below need it and it is the awkward half of either: the log
/// may hold nothing at all, and "up to block none" is not a sentence.
pub(crate) fn as_far_as(unwritten: &Unwritten) -> String {
    match unwritten.written_through {
        Some(height) => format!(
            "The chain is at block {} and the disk holds up to block {height}, so {} blocks \
             have been accepted and not kept",
            unwritten.reached, unwritten.blocks
        ),
        None => format!(
            "The chain is at block {} and the disk holds no blocks at all, so all {} of them \
             have been accepted and not kept",
            unwritten.reached, unwritten.blocks
        ),
    }
}

/// And what they are told once it cannot.
///
/// The deadline in the line above, reached. There is nothing left to ask of
/// the operator except the same thing, and the reason for stopping has to be
/// clear enough that nobody reads it as the node giving up early.
pub(crate) fn lost_the_disk(unwritten: &Unwritten, directory: &str) -> String {
    format!(
        "the disk under {directory} stopped taking what this node writes, and it has now \
         accepted more than the {MAX_BEHIND} blocks it will carry without writing them down. \
         It was writing {}, and the disk said: {}. {}, and a restart asks the network for \
         the blocks in between. It stops here so that what is on the disk is still worth \
         starting from: every block it took from now on would be one more the disk does not \
         have. Free some room under that directory and start it again.",
        unwritten.what,
        unwritten.because,
        as_far_as(unwritten),
    )
}

/// What the disk held when this node opened it.
///
/// The moment an operator finds out what they are starting, which is why the
/// two ways a stored log can be short are told apart here rather than added
/// together into a byte count.
///
/// Built rather than printed, so what it says can be asked of it. It printed,
/// and `cargo mutants` answered that the whole function could be replaced by
/// nothing without a test noticing: every sentence an operator reads at the
/// one moment they find out what they are starting was held by nobody.
pub(crate) fn what_was_restored(restored: &Restored, directory: &str) -> Vec<String> {
    let mut said = vec![format!(
        "restored     {} blocks, {} addresses",
        restored.blocks, restored.addresses
    )];
    if restored.rejoining {
        said.push(
            "             the stored blocks start partway up the chain, so this \
             node joins again rather than reading its way back"
                .to_owned(),
        );
    }
    if restored.refused > 0 {
        said.push(format!(
            "             {} stored blocks were cut from the log; they will be asked for again",
            restored.refused
        ));
    }
    if restored.discarded_bytes > 0 {
        said.push(format!(
            "             {} bytes of an unfinished write were dropped",
            restored.discarded_bytes
        ));
    }
    if restored.left_in_place > 0 {
        said.push(format!(
            "             {} bytes past it are still on the disk, unread",
            restored.left_in_place
        ));
    }
    // Told apart from the line above, because they mean opposite things. Bytes
    // at the end of the file are a machine that stopped mid write, and they
    // cost one block. A whole record that will not read is damage, and it is
    // left exactly where it is: nothing here is confident enough about what
    // those bytes are to delete them.
    // Before the block log's version of the same news, because this one costs
    // more: a block set aside is asked for again in seconds, and headers the
    // blocks cannot replace are only ever given back by a peer that kept them.
    if restored.blocks_set_aside > 0 {
        for line in wrapped(&format!(
            "{} stored blocks were set aside because the first of them could not be \
             checked against the one after it, so this node does not know what height \
             its own log begins at. Nothing was cut, but the first record is written \
             over by the first block this node writes, which on a network that pins its \
             first block is this start; the records after it stay on the disk until the \
             log grows over them. This node fetches the chain again from the network. If \
             this happens again after a clean restart, the disk under {directory} is the \
             thing to check.",
            restored.blocks_set_aside
        )) {
            said.push(format!("             {line}"));
        }
    }
    if restored.headers_set_aside > 0 {
        for line in wrapped(&format!(
            "{} stored headers were set aside because the first of them could not be \
             checked against the one after it. The header log is written again from the \
             blocks this node kept, and the first of those writes cuts the file, so it \
             begins at the oldest block this node holds and the headers below that are \
             gone until a peer hands them back. Until it has them it cannot show the \
             chain to anybody arriving new. If this happens again after a clean restart, \
             the disk under {directory} is the thing to check.",
            restored.headers_set_aside
        )) {
            said.push(format!("             {line}"));
        }
    }
    // Said whether or not the line above was, because they are two different
    // pieces of news about the same file: one is bytes left where they are,
    // this one is bytes that have gone.
    if restored.headers_dropped > 0 {
        for line in wrapped(&format!(
            "{} stored headers were deleted because they stopped below the oldest block \
             this node kept, so nothing joined them to it. The header log has been \
             written again from the blocks. Until a peer hands the older run back, this \
             node cannot show the chain to anybody arriving new. Nothing this build does \
             leaves a header log in that state, so what is left is a file an older one \
             left or a disk that changed underneath it: {directory} is the thing to \
             check.",
            restored.headers_dropped
        )) {
            said.push(format!("             {line}"));
        }
    }
    if let Some(record) = restored.unreadable {
        for line in wrapped(&format!(
            "stored block {record} will not read back. That is damage to the file rather \
             than an unfinished write, so nothing was cut for it: the bytes stay on the disk \
             until the first block this node writes past them. This node starts from the \
             blocks before it and asks the network for the rest. If it happens again after \
             a clean restart, the disk under {directory} is the thing to check."
        )) {
            said.push(format!("             {line}"));
        }
    }
    said
}

/// What an operator is told when this node's own disk will not give back
/// something it holds.
///
/// Written for somebody who has never read the protocol, and the hard part is
/// that nothing looks wrong. The height climbs, the peers connect, the disk
/// takes every write. What is happening is that some of what this node
/// already wrote will not come back out, so the peers asking it for that
/// stretch are quietly served answers with holes in them and go elsewhere.
///
/// It says what to check rather than what to do. The index beside the blocks
/// is worked out from the blocks and can be worked out again, so a node that
/// says this and comes back clean was carrying a derived file that had rotted;
/// one that says it again is being told something about the drive.
pub(crate) fn will_not_read_back(unread: &Unread, directory: &str) -> String {
    let again = if unread.refusals > 1 {
        format!(
            " It has happened {} times since this node started.",
            unread.refusals
        )
    } else {
        String::new()
    };
    format!(
        "the disk under {directory} will not give back something this node put there. It \
         was reading {} at block {}, and the store said: {}.{again} Nothing has been \
         deleted and nothing has been cut: the record is still on the disk to look at, and \
         the chain this node follows is not affected by it. What is affected is everybody \
         else. A peer catching up over that block is sent the blocks around it and drops \
         the rest, so it looks to them like a node that will not answer, and this node is \
         quietly doing less for the network than the line above it suggests. A restart \
         reads the disk again and will say this again if the damage is real, which is the \
         cheapest way to find out. After that, the drive under {directory} is the thing to \
         look at, along with anything else on this machine that has been unhappy.",
        unread.what, unread.height, unread.because,
    )
}

/// What an operator is told about the rules running out under this build.
///
/// The other half of `cairnd`'s `too_old`, and the half that arrives in time
/// to be acted on. That one is a reading of what strangers have sent: blocks under
/// a version this build has no rules for, which is evidence a stranger can
/// manufacture, so it hedges and says so. This one is a reading of the rules
/// this node already runs. A rule change is announced by being put in the
/// schedule, so the height is known the day the build ships, and nobody can
/// say anything to bring it forward.
///
/// That is also why the answer is not a check against a list of releases
/// somewhere. A node that asked a server whether it should update would be a
/// node whose rules the server's owner decides, which in a currency is the
/// whole of the thing. The schedule is already in the binary and the chain's
/// own height is what turns it into a date.
///
/// Two shapes, because two situations want different words. A height ahead is
/// something to plan around. A height already passed is a node that is not
/// following this chain, whatever the line above it says.
pub(crate) fn rules_running_out(params: &ConsensusParams, height: Option<u64>) -> Option<String> {
    let leaving = params.leaves_behind(BLOCK_VERSION)?;
    let reached = height.unwrap_or(0);

    if leaving.height <= reached {
        return Some(format!(
            "this build cannot follow this chain any further. At height {} the rules              became version {}, and this build has the rules only for version {}, so              every block from there is refused. Nothing on the disk is lost by              installing a newer one: the chain here is picked up where it was left.",
            leaving.height, leaving.version, BLOCK_VERSION,
        ));
    }

    let blocks = leaving.height.saturating_sub(reached);
    Some(format!(
        "this build has {blocks} blocks left on this chain, about {}. At height {} the          rules become version {} and this build has the rules only for version {}, so          from there it stops following the chain. This is read off the schedule in this          node's own rules rather than asked of anybody, so the date does not move.",
        roughly(blocks.saturating_mul(params.target_block_time)),
        leaving.height,
        leaving.version,
        BLOCK_VERSION,
    ))
}

/// A stretch of seconds, said the way somebody plans around it.
///
/// Rounded hard and openly: "about two months" is what a person acts on, and
/// a figure to the minute over a stretch that long would be a precision the
/// block rate does not have. Not a date either, and deliberately not offered
/// as one: blocks come at the rate the network mines them, and the schedule
/// is written in heights.
pub(crate) fn roughly(seconds: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    const MONTH: u64 = 30 * DAY;
    match seconds {
        s if s >= 2 * MONTH => format!("{} months", s / MONTH),
        s if s >= 2 * DAY => format!("{} days", s / DAY),
        s if s >= 2 * HOUR => format!("{} hours", s / HOUR),
        s if s >= 2 * MINUTE => format!("{} minutes", s / MINUTE),
        s => format!("{s} seconds"),
    }
}

/// Breaks a paragraph into lines that fit a terminal.
///
/// Everything above is written for a person rather than for a log parser, and
/// a person reading a two hundred column line has been given the words and not
/// the sense of them.
pub(crate) fn wrapped(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len().saturating_add(word.len()) >= 76 {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        lost_the_disk, roughly, rules_running_out, stopped_itself, what_was_restored,
        will_not_read_back, wrapped,
    };
    use cairn_chain::Outdated;
    use cairn_ledger::block::{Activation, BLOCK_VERSION};
    use cairn_ledger::validation::ConsensusParams;
    use cairn_net::node::{Reading, Stranded, Unread, Unwritten, Writing, MAX_BEHIND};
    use cairn_net::Restored;

    /// The source of the program whose words these are.
    const CAIRND: &str = include_str!("../../cairn-node/src/main.rs");
    /// This file.
    const HERE: &str = include_str!("said.rs");

    /// The body of `fn name(` in `source`, with its whitespace folded, so that
    /// the two files can differ in indentation and visibility and in nothing
    /// else.
    fn body(source: &str, name: &str) -> String {
        let at = source
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("{name} is written"));
        let text = source[at..].split_once("\n}\n").unwrap().0;
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Every sentence here is `cairnd`'s, word for word.
    ///
    /// The explorer said none of this, and copying it is how it now does. A
    /// copy is how two programs reading one node come to say two different
    /// things about it, which is the shape of defect this project keeps
    /// finding; so the copy is held to what it was copied from, function by
    /// function. Nothing held a paraphrase to its original, so one that had
    /// drifted passed.
    #[test]
    fn the_words_are_cairnds_word_for_word() {
        for name in [
            "stopped_itself",
            "as_far_as",
            "lost_the_disk",
            "what_was_restored",
            "will_not_read_back",
            "rules_running_out",
            "roughly",
            "wrapped",
        ] {
            assert_eq!(
                body(HERE, name),
                body(CAIRND, name),
                "the explorer's `{name}` says something other than cairnd's, about the \
                 same node in the same state"
            );
        }
    }

    fn disk(within_reach: bool) -> Unwritten {
        Unwritten {
            what: Writing::Blocks,
            because: "no space left on device".to_owned(),
            reached: 1_200,
            written_through: Some(1_000),
            blocks: 200,
            within_reach,
        }
    }

    /// Every state that stops the explorer is one its node cannot leave, and
    /// each is said with the facts it was given.
    ///
    /// The explorer read none of them for itself: it wrote them into
    /// `/api/status` and served a frozen chain under them for as long as the
    /// process lived.
    #[test]
    fn every_state_that_stops_the_explorer_is_one_its_node_cannot_leave() {
        let outdated = stopped_itself(
            Some(Outdated {
                height: 900,
                required: 3,
                known: 1,
            }),
            None,
            None,
            "/var/lib/cairn-explorer",
        )
        .expect("a build with no rules for the chain stops");
        assert!(outdated.contains("height 900"), "{outdated}");

        let stranded = stopped_itself(
            None,
            Some(Stranded {
                anchor: 1_000,
                settles_at: 2_024,
                waited: 600,
                out_of_reach: 4,
            }),
            None,
            "/var/lib/cairn-explorer",
        )
        .expect("a ledger nobody will deliver the blocks under stops");
        assert!(stranded.contains("2024"), "{stranded}");

        let gone = stopped_itself(None, None, Some(disk(false)), "/var/lib/cairn-explorer")
            .expect("a disk past saving stops");
        assert!(
            gone.contains("/var/lib/cairn-explorer") && gone.contains("no space left on device"),
            "{gone}"
        );
        assert!(
            stopped_itself(None, None, Some(disk(true)), "/var/lib/cairn-explorer").is_none(),
            "a disk that can still be caught up with is not a reason to stop"
        );
        assert!(
            stopped_itself(None, None, None, "/var/lib/cairn-explorer").is_none(),
            "and a node with nothing wrong with it is not either"
        );
    }

    /// Every way a start can be short is said, and a clean start says only
    /// what it restored.
    ///
    /// The explorer printed the blocks and the addresses and none of the eight
    /// other things the open reports, so an archivist whose first record would
    /// not check against the second fetched the whole chain again without a
    /// word, when `cairnd`'s own paragraph for that case says what happens to
    /// that record.
    #[test]
    fn every_way_a_start_is_short_is_said_and_a_clean_one_is_not() {
        type Case = (&'static str, fn(&mut Restored), &'static str);
        fn clean() -> Restored {
            Restored {
                blocks: 12,
                refused: 0,
                discarded_bytes: 0,
                left_in_place: 0,
                unreadable: None,
                headers_set_aside: 0,
                headers_dropped: 0,
                blocks_set_aside: 0,
                rejoining: false,
                addresses: 3,
            }
        }
        let quiet = what_was_restored(&clean(), "/var/lib/cairn-explorer");
        assert_eq!(quiet.len(), 1, "a clean start says one line: {quiet:?}");
        let first = quiet.first().unwrap();
        assert!(first.contains("12 blocks") && first.contains("3 addresses"));

        let cases: [Case; 8] = [
            ("rejoining", |r| r.rejoining = true, "partway"),
            ("refused", |r| r.refused = 4, "cut from the log"),
            ("discarded_bytes", |r| r.discarded_bytes = 96, "unfinished"),
            ("left_in_place", |r| r.left_in_place = 96, "unread"),
            (
                "blocks_set_aside",
                |r| r.blocks_set_aside = 12,
                "written over",
            ),
            (
                "headers_set_aside",
                |r| r.headers_set_aside = 12,
                "stored headers",
            ),
            (
                "headers_dropped",
                |r| r.headers_dropped = 12,
                "were deleted",
            ),
            ("unreadable", |r| r.unreadable = Some(7), "block 7"),
        ];
        for (field, set, word) in cases {
            let mut restored = clean();
            set(&mut restored);
            let said = what_was_restored(&restored, "/var/lib/cairn-explorer").join("\n");
            assert!(
                said.contains(word),
                "`{field}` is set and nothing said `{word}`: {said}"
            );
            assert!(!quiet.join("\n").contains(word));
        }
    }

    /// The paragraph a node past saving stops on carries the two heights,
    /// the difference, what the disk said and which disk, and does not say
    /// the blocks in the gap have left memory, which they have not.
    ///
    /// The explorer said nothing when its node stopped, so nothing here was
    /// asked; these are the questions `cairnd` asks of the same words.
    #[test]
    fn the_paragraph_about_a_lost_disk_carries_what_an_operator_acts_on() {
        let mut gone = disk(false);
        gone.reached = 1_083;
        gone.written_through = Some(32);
        gone.blocks = MAX_BEHIND + 1;
        let text = lost_the_disk(&gone, "/var/lib/cairn-explorer");
        assert!(text.contains("1083") && text.contains("block 32"), "{text}");
        assert!(text.contains(&(MAX_BEHIND + 1).to_string()), "{text}");
        assert!(text.contains("no space left on device"), "{text}");
        assert!(text.contains("/var/lib/cairn-explorer"), "{text}");
        assert!(
            !text.contains("memory") && text.contains("asks the network"),
            "{text}"
        );

        gone.written_through = None;
        let text = lost_the_disk(&gone, "/var/lib/cairn-explorer");
        assert!(
            text.contains("no blocks at all") && !text.contains("block None"),
            "a disk holding nothing is still a sentence: {text}"
        );
    }

    /// A disk that will not read back says where, what the store said, and
    /// how often, once it is more than once.
    #[test]
    fn a_disk_that_will_not_read_back_says_where_and_how_often() {
        let once = Unread {
            what: Reading::Blocks,
            height: 812,
            because: "input/output error".to_owned(),
            refusals: 1,
        };
        let said = will_not_read_back(&once, "/var/lib/cairn-explorer");
        assert!(said.contains("at block 812") && said.contains("input/output error"));
        assert!(said.contains("/var/lib/cairn-explorer"), "{said}");
        assert!(!said.contains("It has happened"), "{said}");
        let again = Unread {
            refusals: 3,
            ..once
        };
        assert!(will_not_read_back(&again, "/var/lib/cairn-explorer")
            .contains("It has happened 3 times since this node started."));
    }

    /// The rule change ahead is read off the schedule: nothing when level
    /// with it, how far and how long when it is ahead, and a stop when it is
    /// passed.
    #[test]
    fn the_notice_period_is_read_off_the_schedule() {
        let mut level = ConsensusParams::testnet();
        level.activations = &[Activation {
            height: 0,
            version: BLOCK_VERSION,
        }];
        assert_eq!(rules_running_out(&level, Some(900)), None);

        let mut ahead = ConsensusParams::testnet();
        ahead.activations = &[
            Activation {
                height: 0,
                version: BLOCK_VERSION,
            },
            Activation {
                height: 9_000,
                version: BLOCK_VERSION + 1,
            },
        ];
        ahead.target_block_time = 600;
        let said = rules_running_out(&ahead, Some(1_000)).expect("a change ahead is a notice");
        assert!(
            said.contains("8000 blocks left") && said.contains("55 days"),
            "{said}"
        );
        assert!(
            said.contains("height 9000") && said.contains("does not move"),
            "{said}"
        );

        let past = rules_running_out(&ahead, Some(9_000)).expect("past it is a notice too");
        assert!(past.contains("cannot follow this chain"), "{past}");
        assert!(past.contains("picked up where it was left"), "{past}");
        let past = rules_running_out(&ahead, None);
        assert!(
            past.is_some_and(|said| said.contains("9000 blocks left")),
            "a node with no chain yet is at height nought"
        );
    }

    /// Every stretch is said at its own edge.
    #[test]
    fn every_stretch_is_said_at_its_own_edge() {
        const MINUTE: u64 = 60;
        const HOUR: u64 = 60 * MINUTE;
        const DAY: u64 = 24 * HOUR;
        const MONTH: u64 = 30 * DAY;
        for (seconds, said) in [
            (0, "0 seconds"),
            (2 * MINUTE - 1, "119 seconds"),
            (2 * MINUTE, "2 minutes"),
            (2 * HOUR - 1, "119 minutes"),
            (2 * HOUR, "2 hours"),
            (2 * DAY - 1, "47 hours"),
            (2 * DAY, "2 days"),
            (2 * MONTH - 1, "59 days"),
            (2 * MONTH, "2 months"),
            (14 * MONTH, "14 months"),
        ] {
            assert_eq!(roughly(seconds), said);
        }
    }

    /// A paragraph is wrapped under the margin without losing a word.
    #[test]
    fn a_paragraph_is_wrapped_without_losing_a_word() {
        let text = "the disk under the directory will not give back something this node put \
                    there, and a peer catching up over that block is sent the blocks around \
                    it and drops them.";
        let lines = wrapped(text);
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|line| line.len() < 76 && !line.is_empty()));
        assert_eq!(
            lines.join(" "),
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        );
        assert!(wrapped("").is_empty());
    }
}
