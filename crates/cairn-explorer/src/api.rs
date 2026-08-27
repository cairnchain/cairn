//! Answering the questions a page asks about the chain.
//!
//! Amounts, difficulties and accumulated work are sent as decimal strings
//! rather than JSON numbers. A pebble count runs past what a double can hold
//! exactly, and a money figure that is silently rounded in the last digits is
//! the kind of wrong that nobody notices until it matters.

use std::sync::{Mutex, MutexGuard, PoisonError};

use cairn_chain::ChainStore;
use cairn_crypto::PublicKey;
use cairn_ledger::block::Block;
use cairn_ledger::emission::reward_at;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::work_of;
use cairn_ledger::transaction::{Transfer, Witness};
use cairn_ledger::validation::ConsensusParams;
use cairn_net::Node;
use cairn_primitives::codec::Encode;
use cairn_primitives::{hex, Amount, Hash32};

use crate::http::{Request, Response};
use crate::index::{Index, NoteRecord};
use crate::json::Writer;

/// Blocks listed per page.
const PAGE: usize = 25;
/// Largest page a caller may ask for.
const MAX_PAGE: usize = 200;
/// Entries returned for one address before the caller has to ask for more.
///
/// Both the notes an address holds and the movements through it are paged. An
/// address that has mined for a year holds hundreds of thousands of notes, and
/// an answer carrying all of them is one an anonymous caller could ask for
/// repeatedly to make this node do arbitrary work and send arbitrary bytes.
const ADDRESS_PAGE: usize = 100;

/// Bytes one hot note costs a node, measured on the running implementation:
/// the note itself, its identifier, and its share of the sparse tree.
///
/// Reported so a page can state what a node carries without inventing the
/// figure, and so the number moves if the implementation ever changes.
const HOT_BYTES_PER_NOTE: u64 = 813;

/// The node the explorer reads, plus what it keeps on top of it.
pub(crate) struct Explorer {
    node: Node,
    index: Mutex<Index>,
}

impl std::fmt::Debug for Explorer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Explorer").finish_non_exhaustive()
    }
}

impl Explorer {
    pub(crate) fn new(node: Node) -> Self {
        Self {
            node,
            index: Mutex::new(Index::new()),
        }
    }

    pub(crate) fn node(&self) -> &Node {
        &self.node
    }

    fn index(&self) -> MutexGuard<'_, Index> {
        self.index.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reads whatever the chain has added since the last call.
    pub(crate) fn refresh(&self) {
        let mut index = self.index();
        self.node.with_chain(|chain| index.refresh(chain));
    }

    /// Routes one request, or reports that nothing here answers it.
    pub(crate) fn answer(&self, request: &Request) -> Option<Response> {
        let index = self.index();
        self.node.with_chain(|chain| {
            let context = Context {
                chain,
                index: &index,
                node: &self.node,
            };
            route(&context, request)
        })
    }
}

/// Everything a route reads, held still for the length of one answer.
struct Context<'a> {
    chain: &'a ChainStore,
    index: &'a Index,
    node: &'a Node,
}

impl Context<'_> {
    fn params(&self) -> &ConsensusParams {
        self.chain.params()
    }

    fn height(&self) -> Option<u64> {
        self.chain.height()
    }

    /// Blocks mined on top of the one at `height`, the block itself counted.
    fn confirmations(&self, height: u64) -> u64 {
        self.height()
            .and_then(|tip| tip.checked_sub(height))
            .and_then(|behind| behind.checked_add(1))
            .unwrap_or(0)
    }
}

fn route(context: &Context<'_>, request: &Request) -> Option<Response> {
    if let Some(rest) = request.after("/api/") {
        return Some(match rest {
            "status" => status(context),
            "params" => params(context),
            "blocks" => blocks(context, request),
            "pool" => pool(context),
            "holders" => holders(context),
            "search" => search(context, request),
            other => match other.split_once('/') {
                Some(("block", reference)) => block(context, reference),
                Some(("tx", id)) => transaction(context, id),
                Some(("address", owner)) => address(context, owner, request),
                Some(("note", id)) => note(context, id),
                _ => Response::error(404, "no such endpoint"),
            },
        });
    }
    None
}

fn status(context: &Context<'_>) -> Response {
    let params = context.params();
    let state = context.chain.state();
    let totals = context.index.totals();
    let tip_height = context.height();

    let mut json = Writer::new();
    json.begin_object();

    json.key("network");
    network_object(&mut json, params);

    json.key("tip");
    match (tip_height, context.chain.tip()) {
        (Some(height), Some(id)) => {
            json.begin_object();
            json.field_u64("height", height);
            json.field_str("id", &id.to_string());
            if let Some(block) = context.chain.block(&id) {
                json.field_u64("timestamp", block.header.timestamp);
                json.field_str("difficulty", &block.header.difficulty.to_string());
                json.field_usize("transfers", block.transfers.len());
            }
            json.end_object();
        }
        _ => json.null(),
    }

    json.field_str("work", &context.chain.total_work().to_string());
    json.field_usize("blocksKnown", context.chain.len());
    json.field_usize("indexed", context.index.blocks_read());
    json.field_usize("peers", context.node.peer_count());
    json.field_usize("pool", context.chain.pool_len());
    json.field_bool("archiving", context.chain.is_archiving());

    json.key("hot");
    json.begin_object();
    json.field_usize("notes", state.hot_len());
    json.field_usize("capacity", params.hot_capacity);
    json.field_u64("bytesPerNote", HOT_BYTES_PER_NOTE);
    json.field_str(
        "bytesAtCapacity",
        &u64::try_from(params.hot_capacity)
            .unwrap_or(u64::MAX)
            .saturating_mul(HOT_BYTES_PER_NOTE)
            .to_string(),
    );
    json.field_usize("grace", state.grace_len());
    json.end_object();

    json.key("cold");
    json.begin_object();
    json.field_str("notes", &state.cold().len().to_string());
    // What a node actually carries for the cold set, whatever its size.
    json.field_usize("roots", 64);
    json.end_object();

    json.key("supply");
    json.begin_object();
    json.field_str("issued", &totals.issued().as_pebbles().to_string());
    json.field_str("fees", &totals.fees.as_pebbles().to_string());
    json.field_str(
        "paidToMiners",
        &totals.paid_to_miners.as_pebbles().to_string(),
    );
    let next_height = tip_height
        .and_then(|height| height.checked_add(1))
        .unwrap_or(0);
    json.field_str(
        "nextReward",
        &reward_at(
            next_height,
            params.halving_interval,
            params.initial_reward,
            params.tail_reward,
        )
        .as_pebbles()
        .to_string(),
    );
    json.field_u64("halvingInterval", params.halving_interval);
    json.field_u64(
        "nextHalving",
        next_halving(next_height, params.halving_interval),
    );
    json.end_object();

    json.key("chain");
    json.begin_object();
    json.field_u64("transfers", totals.transfers);
    json.field_u64("notesCreated", totals.notes_created);
    json.field_u64("notesSpent", totals.notes_spent);
    json.field_usize("holders", context.index.holders());
    json.end_object();

    json.end_object();
    Response::json(json.finish())
}

/// Blocks left before the reward halves.
fn next_halving(height: u64, interval: u64) -> u64 {
    if interval == 0 {
        return 0;
    }
    let into = height.checked_rem(interval).unwrap_or(0);
    interval.saturating_sub(into)
}

fn network_object(json: &mut Writer, params: &ConsensusParams) {
    json.begin_object();
    json.field_str("name", params.network_name());
    json.field_str("id", &format!("0x{:08x}", params.network.as_u32()));
    match params.genesis {
        Some(genesis) => json.field_str("genesis", &genesis.to_string()),
        None => json.field_null("genesis"),
    }
    json.field_u64("opensAt", params.opens_at);
    json.end_object();
}

/// The rules of the network, as one document a page can render.
///
/// Every field here is consensus. Two nodes that disagree on any of them build
/// different chains while believing they are on the same one, which is why the
/// page shows them rather than describing them from memory.
fn params(context: &Context<'_>) -> Response {
    let params = context.params();
    let mut json = Writer::new();
    json.begin_object();
    json.key("network");
    network_object(&mut json, params);
    json.field_u64("targetBlockTime", params.target_block_time);
    json.field_str("genesisDifficulty", &params.genesis_difficulty.to_string());
    json.field_usize("hotCapacity", params.hot_capacity);
    json.field_u64("bytesPerNote", HOT_BYTES_PER_NOTE);
    json.field_str(
        "initialReward",
        &params.initial_reward.as_pebbles().to_string(),
    );
    json.field_str("tailReward", &params.tail_reward.as_pebbles().to_string());
    json.field_u64("halvingInterval", params.halving_interval);
    json.field_str(
        "pebblesPerCairn",
        &cairn_primitives::amount::PEBBLES_PER_CAIRN.to_string(),
    );
    json.field_usize("maxTransfersPerBlock", params.max_transfers_per_block);
    json.field_usize("maxInputsPerTransfer", params.max_inputs_per_transfer);
    json.field_usize("maxOutputsPerTransfer", params.max_outputs_per_transfer);
    json.field_u64("maxTimestampDrift", params.max_timestamp_drift);
    json.end_object();
    Response::json(json.finish())
}

fn blocks(context: &Context<'_>, request: &Request) -> Response {
    let Some(tip) = context.height() else {
        let mut json = Writer::new();
        json.begin_object();
        json.key("blocks");
        json.begin_array();
        json.end_array();
        json.field_null("next");
        json.end_object();
        return Response::json(json.finish());
    };

    let from = request
        .parameter("from")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(tip)
        .min(tip);
    let limit = request
        .parameter("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(PAGE)
        .clamp(1, MAX_PAGE);

    let mut json = Writer::new();
    json.begin_object();
    json.key("blocks");
    json.begin_array();
    let mut height = from;
    let mut listed = 0usize;
    loop {
        if listed >= limit {
            break;
        }
        if let Some(block) = context.chain.block_at(height) {
            block_summary(&mut json, context, block);
            listed = listed.saturating_add(1);
        }
        let Some(next) = height.checked_sub(1) else {
            break;
        };
        height = next;
    }
    json.end_array();
    match from
        .checked_sub(u64::try_from(listed).unwrap_or(0))
        .filter(|_| listed >= limit)
    {
        Some(next) => json.field_u64("next", next),
        None => json.field_null("next"),
    }
    json.end_object();
    Response::json(json.finish())
}

fn block_summary(json: &mut Writer, context: &Context<'_>, block: &Block) {
    json.begin_object();
    json.field_u64("height", block.header.height);
    json.field_str("id", &block.id().to_string());
    json.field_u64("timestamp", block.header.timestamp);
    json.field_str("difficulty", &block.header.difficulty.to_string());
    json.field_usize("transfers", block.transfers.len());
    json.field_usize("size", block.encode().len());
    json.field_str(
        "paidToMiner",
        &block
            .coinbase
            .total_output()
            .unwrap_or(Amount::ZERO)
            .as_pebbles()
            .to_string(),
    );
    match block.coinbase.outputs.first() {
        Some(output) => json.field_str("miner", &output.owner.to_string()),
        None => json.field_null("miner"),
    }
    json.field_str("fees", &block_fees(context, block).as_pebbles().to_string());
    json.end_object();
}

/// What senders paid in this block, which is what the coinbase carries beyond
/// the emission schedule.
fn block_fees(context: &Context<'_>, block: &Block) -> Amount {
    let params = context.params();
    let paid = block.coinbase.total_output().unwrap_or(Amount::ZERO);
    let reward = reward_at(
        block.header.height,
        params.halving_interval,
        params.initial_reward,
        params.tail_reward,
    );
    paid.checked_sub(reward).unwrap_or(Amount::ZERO)
}

fn block(context: &Context<'_>, reference: &str) -> Response {
    let Some(block) = resolve_block(context, reference) else {
        return Response::error(404, "no such block");
    };
    let height = block.header.height;
    let params = context.params();

    let mut json = Writer::new();
    json.begin_object();
    json.field_u64("height", height);
    json.field_str("id", &block.id().to_string());
    json.field_str("previous", &block.header.previous.to_string());
    json.field_u64("version", u64::from(block.header.version));
    json.field_str("network", context.params().network_name());
    json.field_u64("timestamp", block.header.timestamp);
    json.field_str("difficulty", &block.header.difficulty.to_string());
    json.field_str("nonce", &block.header.nonce.to_string());
    json.field_str("work", &work_of(block.header.difficulty).to_string());
    json.field_str(
        "transactionsRoot",
        &block.header.transactions_root.to_string(),
    );
    json.field_str("stateRoot", &block.header.state_root.to_string());
    json.field_usize("size", block.encode().len());
    json.field_u64("confirmations", context.confirmations(height));
    match height
        .checked_add(1)
        .and_then(|next| context.chain.block_at(next))
    {
        Some(next) => json.field_str("next", &next.id().to_string()),
        None => json.field_null("next"),
    }

    let fees = block_fees(context, block);
    json.field_str("fees", &fees.as_pebbles().to_string());
    json.field_str(
        "reward",
        &reward_at(
            height,
            params.halving_interval,
            params.initial_reward,
            params.tail_reward,
        )
        .as_pebbles()
        .to_string(),
    );

    json.key("coinbase");
    json.begin_object();
    let coinbase = block.coinbase.id();
    json.field_str("id", &coinbase.to_string());
    json.field_str(
        "total",
        &block
            .coinbase
            .total_output()
            .unwrap_or(Amount::ZERO)
            .as_pebbles()
            .to_string(),
    );
    json.field_str("extra", &hex::encode(&block.coinbase.extra));
    match readable(&block.coinbase.extra) {
        Some(text) => json.field_str("extraText", &text),
        None => json.field_null("extraText"),
    }
    json.key("outputs");
    json.begin_array();
    for (index, output) in block.coinbase.outputs.iter().enumerate() {
        let id = NoteId::new(coinbase, u32::try_from(index).unwrap_or(u32::MAX));
        output_object(&mut json, context, &id, output);
    }
    json.end_array();
    json.end_object();

    json.key("transfers");
    json.begin_array();
    for transfer in &block.transfers {
        transfer_object(&mut json, context, transfer, false);
    }
    json.end_array();

    json.end_object();
    Response::json(json.finish())
}

fn resolve_block<'a>(context: &Context<'a>, reference: &str) -> Option<&'a Block> {
    if let Ok(height) = reference.parse::<u64>() {
        return context.chain.block_at(height);
    }
    let id = parse_hash(reference)?;
    context.chain.block(&id)
}

fn output_object(json: &mut Writer, context: &Context<'_>, id: &NoteId, note: &Note) {
    json.begin_object();
    json.field_u64("index", u64::from(id.index));
    json.field_str("note", &note_reference(id));
    json.field_str("value", &note.value.as_pebbles().to_string());
    json.field_str("owner", &note.owner.to_string());
    if let Some(record) = context.index.note(id) {
        json.field_bool("spent", !record.is_unspent());
        match record.spent_by {
            Some(spender) => json.field_str("spentBy", &spender.to_string()),
            None => json.field_null("spentBy"),
        }
        match record.spent_at {
            Some(height) => json.field_u64("spentAt", height),
            None => json.field_null("spentAt"),
        }
        json.field_str("tier", tier_of(context, id, &record));
    } else {
        json.field_bool("spent", false);
        json.field_null("spentBy");
        json.field_null("spentAt");
        json.field_str("tier", "unknown");
    }
    json.end_object();
}

/// Where a note stands: still in the drawer every node holds, still inside the
/// window where a fallen note needs no proof, or down in the cave.
fn tier_of(context: &Context<'_>, id: &NoteId, record: &NoteRecord) -> &'static str {
    if !record.is_unspent() {
        return "spent";
    }
    let state = context.chain.state();
    if state.hot_note(id).is_some() {
        return "hot";
    }
    if state.within_grace(id).is_some() {
        return "grace";
    }
    "cold"
}

fn transfer_object(json: &mut Writer, context: &Context<'_>, transfer: &Transfer, full: bool) {
    let id = transfer.id();
    json.begin_object();
    json.field_str("id", &id.to_string());
    json.field_str("kind", "transfer");
    json.field_usize("size", transfer.encode().len());
    json.field_u64("version", u64::from(transfer.version));

    let mut consumed = Amount::ZERO;
    json.key("inputs");
    json.begin_array();
    for input in &transfer.inputs {
        json.begin_object();
        json.field_str("note", &note_reference(&input.note_id));
        json.field_str("source", &input.note_id.source.to_string());
        json.field_u64("index", u64::from(input.note_id.index));
        json.field_str(
            "witness",
            match input.witness {
                Witness::Hot => "hot",
                Witness::Cold(_) => "cold",
            },
        );
        match &input.witness {
            Witness::Cold(witness) => json.field_str("position", &witness.position.to_string()),
            Witness::Hot => json.field_null("position"),
        }
        if let Some(record) = context.index.note(&input.note_id) {
            consumed = consumed.checked_add(record.value).unwrap_or(consumed);
            json.field_str("value", &record.value.as_pebbles().to_string());
            json.field_str("owner", &record.owner.to_string());
        } else {
            json.field_null("value");
            json.field_null("owner");
        }
        json.end_object();
    }
    json.end_array();

    json.key("outputs");
    json.begin_array();
    for (index, output) in transfer.outputs.iter().enumerate() {
        let note_id = NoteId::new(id, u32::try_from(index).unwrap_or(u32::MAX));
        output_object(json, context, &note_id, output);
    }
    json.end_array();

    let produced = transfer.total_output().unwrap_or(Amount::ZERO);
    json.field_str("totalIn", &consumed.as_pebbles().to_string());
    json.field_str("totalOut", &produced.as_pebbles().to_string());
    match consumed.checked_sub(produced) {
        Some(fee) => json.field_str("fee", &fee.as_pebbles().to_string()),
        None => json.field_null("fee"),
    }

    if full {
        if let Some(location) = context.index.locate(&id) {
            json.field_u64("height", location.height);
            json.field_u64("position", u64::from(location.position));
            json.field_u64("confirmations", context.confirmations(location.height));
            if let Some(block) = context.chain.block_at(location.height) {
                json.field_str("block", &block.id().to_string());
                json.field_u64("timestamp", block.header.timestamp);
            } else {
                json.field_null("block");
                json.field_null("timestamp");
            }
        } else {
            json.field_null("height");
            json.field_null("position");
            json.field_u64("confirmations", 0);
            json.field_null("block");
            json.field_null("timestamp");
        }
    }
    json.end_object();
}

fn transaction(context: &Context<'_>, reference: &str) -> Response {
    let Some(id) = parse_hash(reference) else {
        return Response::error(400, "not a transaction identifier");
    };

    if let Some(transfer) = context.chain.pooled(&id) {
        let mut json = Writer::new();
        json.begin_object();
        json.field_bool("pooled", true);
        json.key("transaction");
        transfer_object(&mut json, context, transfer, true);
        json.end_object();
        return Response::json(json.finish());
    }

    let Some(location) = context.index.locate(&id) else {
        return Response::error(404, "no such transaction");
    };
    let Some(block) = context.chain.block_at(location.height) else {
        return Response::error(404, "no such transaction");
    };

    let mut json = Writer::new();
    json.begin_object();
    json.field_bool("pooled", false);
    json.key("transaction");
    if location.position == 0 {
        coinbase_object(&mut json, context, block);
    } else {
        let index = usize::try_from(location.position)
            .ok()
            .and_then(|position| position.checked_sub(1));
        match index.and_then(|index| block.transfers.get(index)) {
            Some(transfer) => transfer_object(&mut json, context, transfer, true),
            None => return Response::error(404, "no such transaction"),
        }
    }
    json.end_object();
    Response::json(json.finish())
}

fn coinbase_object(json: &mut Writer, context: &Context<'_>, block: &Block) {
    let id = block.coinbase.id();
    json.begin_object();
    json.field_str("id", &id.to_string());
    json.field_str("kind", "coinbase");
    json.field_usize("size", block.coinbase.encode().len());
    json.field_u64("version", u64::from(block.coinbase.version));
    json.key("inputs");
    json.begin_array();
    json.end_array();
    json.key("outputs");
    json.begin_array();
    for (index, output) in block.coinbase.outputs.iter().enumerate() {
        let note_id = NoteId::new(id, u32::try_from(index).unwrap_or(u32::MAX));
        output_object(json, context, &note_id, output);
    }
    json.end_array();
    let total = block.coinbase.total_output().unwrap_or(Amount::ZERO);
    json.field_str("totalIn", "0");
    json.field_str("totalOut", &total.as_pebbles().to_string());
    json.field_null("fee");
    json.field_str("extra", &hex::encode(&block.coinbase.extra));
    match readable(&block.coinbase.extra) {
        Some(text) => json.field_str("extraText", &text),
        None => json.field_null("extraText"),
    }
    json.field_u64("height", block.header.height);
    json.field_u64("position", 0);
    json.field_u64("confirmations", context.confirmations(block.header.height));
    json.field_str("block", &block.id().to_string());
    json.field_u64("timestamp", block.header.timestamp);
    json.end_object();
}

fn address(context: &Context<'_>, reference: &str, request: &Request) -> Response {
    let Some(owner) = parse_owner(reference) else {
        return Response::error(400, "not an address");
    };
    let offset = request
        .parameter("from")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    let mut json = Writer::new();
    json.begin_object();
    json.field_str("address", &owner.to_string());

    let Some(record) = context.index.owner(&owner) else {
        json.field_str("balance", "0");
        json.field_str("received", "0");
        json.field_str("spent", "0");
        json.field_usize("notes", 0);
        json.field_usize("unspentNotes", 0);
        json.field_bool("moreNotes", false);
        json.key("unspent");
        json.begin_array();
        json.end_array();
        json.key("history");
        json.begin_array();
        json.end_array();
        json.field_usize("movements", 0);
        json.field_null("next");
        json.end_object();
        return Response::json(json.finish());
    };

    json.field_str("balance", &record.balance().as_pebbles().to_string());
    json.field_str("received", &record.received.as_pebbles().to_string());
    json.field_str("spent", &record.spent.as_pebbles().to_string());
    json.field_usize("notes", record.notes.len());

    // Newest first, and only one page of them. Walking every note an address
    // ever held is exactly the work this endpoint must not do on demand.
    let mut unspent = 0usize;
    let mut listed = 0usize;
    let mut more_notes = false;
    json.key("unspent");
    json.begin_array();
    for id in record.notes.iter().rev() {
        let Some(note) = context.index.note(id) else {
            continue;
        };
        if !note.is_unspent() {
            continue;
        }
        unspent = unspent.saturating_add(1);
        if listed >= ADDRESS_PAGE {
            more_notes = true;
            continue;
        }
        listed = listed.saturating_add(1);
        json.begin_object();
        json.field_str("note", &note_reference(id));
        json.field_str("value", &note.value.as_pebbles().to_string());
        json.field_u64("createdAt", note.created_at);
        json.field_str("tier", tier_of(context, id, &note));
        json.end_object();
    }
    json.end_array();
    json.field_usize("unspentNotes", unspent);
    json.field_bool("moreNotes", more_notes);

    // One line per movement: a note arriving, and later the transfer that
    // spent it. The index records these as the chain produces them, so they
    // are already in order and a page is a slice rather than a sort.
    let movements = &record.movements;
    let total = movements.len();
    let end = total.saturating_sub(offset);
    let start = end.saturating_sub(ADDRESS_PAGE);

    json.key("history");
    json.begin_array();
    for movement in movements.get(start..end).unwrap_or_default().iter().rev() {
        json.begin_object();
        json.field_u64("height", movement.height);
        json.field_str("direction", if movement.incoming { "in" } else { "out" });
        json.field_str("transaction", &movement.transaction.to_string());
        json.field_str("value", &movement.value.as_pebbles().to_string());
        match context.chain.block_at(movement.height) {
            Some(block) => json.field_u64("timestamp", block.header.timestamp),
            None => json.field_null("timestamp"),
        }
        json.end_object();
    }
    json.end_array();
    json.field_usize("movements", total);
    if start > 0 {
        json.field_usize("next", offset.saturating_add(end.saturating_sub(start)));
    } else {
        json.field_null("next");
    }

    json.end_object();
    Response::json(json.finish())
}

fn note(context: &Context<'_>, reference: &str) -> Response {
    let Some(id) = parse_note(reference) else {
        return Response::error(400, "not a note identifier");
    };
    let Some(record) = context.index.note(&id) else {
        return Response::error(404, "no such note");
    };
    let mut json = Writer::new();
    json.begin_object();
    json.field_str("note", &note_reference(&id));
    json.field_str("source", &id.source.to_string());
    json.field_u64("index", u64::from(id.index));
    json.field_str("value", &record.value.as_pebbles().to_string());
    json.field_str("owner", &record.owner.to_string());
    json.field_u64("createdAt", record.created_at);
    json.field_str("tier", tier_of(context, &id, &record));
    match record.spent_at {
        Some(height) => json.field_u64("spentAt", height),
        None => json.field_null("spentAt"),
    }
    match record.spent_by {
        Some(by) => json.field_str("spentBy", &by.to_string()),
        None => json.field_null("spentBy"),
    }
    // Where a fallen note sits in the forest, which is what a proof is about.
    match context
        .chain
        .state()
        .cold()
        .locate(&id, &Note::new(record.value, record.owner))
    {
        Some(position) => json.field_str("position", &position.to_string()),
        None => json.field_null("position"),
    }
    json.end_object();
    Response::json(json.finish())
}

fn pool(context: &Context<'_>) -> Response {
    let mut json = Writer::new();
    json.begin_object();
    json.field_usize("count", context.chain.pool_len());
    json.key("transfers");
    json.begin_array();
    for (_, transfer) in context.chain.pooled_transfers() {
        transfer_object(&mut json, context, transfer, false);
    }
    json.end_array();
    json.end_object();
    Response::json(json.finish())
}

fn holders(context: &Context<'_>) -> Response {
    let mut json = Writer::new();
    json.begin_object();
    json.field_usize("holders", context.index.holders());
    json.key("richest");
    json.begin_array();
    for (owner, balance) in context.index.richest() {
        json.begin_object();
        json.field_str("address", &owner.to_string());
        json.field_str("balance", &balance.as_pebbles().to_string());
        json.end_object();
    }
    json.end_array();
    json.end_object();
    Response::json(json.finish())
}

/// Works out what someone pasted into the search box.
///
/// A block identifier, a transaction identifier and an address are all thirty
/// two bytes, so the text alone cannot say which it is. Each is looked up in
/// turn and the first that exists wins.
fn search(context: &Context<'_>, request: &Request) -> Response {
    let query = request.parameter("q").unwrap_or_default();
    let query = query.trim();

    let mut json = Writer::new();
    json.begin_object();
    json.field_str("query", query);

    if let Ok(height) = query.parse::<u64>() {
        if context.chain.block_at(height).is_some() {
            json.field_str("kind", "block");
            json.field_str("target", &format!("/block/{height}"));
            json.end_object();
            return Response::json(json.finish());
        }
    }

    if let Some(id) = parse_note(query) {
        if context.index.note(&id).is_some() {
            json.field_str("kind", "note");
            json.field_str("target", &format!("/note/{}", note_reference(&id)));
            json.end_object();
            return Response::json(json.finish());
        }
    }

    if let Some(hash) = parse_hash(query) {
        if let Some(block) = context.chain.block(&hash) {
            json.field_str("kind", "block");
            json.field_str("target", &format!("/block/{}", block.header.height));
            json.end_object();
            return Response::json(json.finish());
        }
        if context.index.locate(&hash).is_some() || context.chain.pooled(&hash).is_some() {
            json.field_str("kind", "transaction");
            json.field_str("target", &format!("/tx/{hash}"));
            json.end_object();
            return Response::json(json.finish());
        }
    }

    if let Some(owner) = parse_owner(query) {
        json.field_str("kind", "address");
        json.field_str("target", &format!("/address/{owner}"));
        json.end_object();
        return Response::json(json.finish());
    }

    json.field_str("kind", "unknown");
    json.field_null("target");
    json.end_object();
    Response::json(json.finish())
}

/// How a note is written down: the transaction that made it, then which output.
fn note_reference(id: &NoteId) -> String {
    format!("{}:{}", id.source, id.index)
}

fn parse_hash(text: &str) -> Option<Hash32> {
    hex::decode_array::<32>(text).map(Hash32::from_bytes)
}

fn parse_owner(text: &str) -> Option<PublicKey> {
    let bytes = hex::decode_array::<32>(text)?;
    PublicKey::from_bytes(&bytes).ok()
}

fn parse_note(text: &str) -> Option<NoteId> {
    let (source, index) = text.split_once(':')?;
    Some(NoteId::new(parse_hash(source)?, index.parse().ok()?))
}

/// The coinbase message, when it is one.
///
/// Miners put arbitrary bytes here as search space, so anything that is not
/// printable text is left as hexadecimal rather than shown as mojibake.
fn readable(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    text.chars()
        .all(|character| !character.is_control())
        .then(|| text.to_owned())
}
