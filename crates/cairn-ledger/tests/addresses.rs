//! A note is owned by the hash of a key, and the key appears when it is spent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{BTreeMap, BTreeSet};

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Address, Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, check_transfer, connect_block, ConsensusParams};
use cairn_ledger::{Block, BlockError, LedgerState, TransferError};
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain};

const NOW: u64 = 1_000_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn mine(
    state: &mut LedgerState,
    params: &ConsensusParams,
    pays: Note,
    transfers: Vec<Transfer>,
) -> Block {
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(height, vec![pays]);
    let block =
        assemble_block(state, coinbase, transfers, params, 1_000 + height * 600, 0).unwrap();
    connect_block(state, &block, params, NOW).unwrap();
    block
}

fn holds_window(bytes: &[u8], window: &[u8; 32]) -> bool {
    bytes.windows(32).any(|here| here == window)
}

/// **A note shows no key until it is spent.**
///
/// A note used to be locked to its owner's public key, so every unspent note
/// showed the key it waits for, the whole supply laid open to whoever can one
/// day work a secret back from a key. Nothing asked what a block paying
/// somebody carried, so a note that held the key passed.
#[test]
fn a_note_shows_no_key_until_it_is_spent() {
    let params = params();
    let (alice, bob, miner) = (wallet(1), wallet(2), wallet(3));
    let key = alice.public_key().to_bytes();
    let mut state = LedgerState::new();

    let paid = Note::new(params.initial_reward, alice.public_key());
    let paying = mine(&mut state, &params, paid, Vec::new());
    assert!(
        !holds_window(&paying.encode(), &key),
        "the block that pays Alice carries her key, so every note she holds shows it \
         for as long as it is unspent"
    );

    let id = NoteId::new(paying.coinbase.id(), 0);
    let mut spend = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(paid.value, bob.public_key())],
    );
    spend.sign_input(params.network, 0, &paid, &alice);
    let spending = mine(
        &mut state,
        &params,
        Note::new(params.initial_reward, miner.public_key()),
        vec![spend],
    );
    assert!(
        holds_window(&spending.encode(), &key),
        "the block that spends Alice's note does not carry her key, so nothing can check \
         her signature against it"
    );
}

/// Alice's note, paid by the first block, and the state after it.
fn alice_is_paid() -> (LedgerState, ConsensusParams, NoteId, Note) {
    let params = params();
    let mut state = LedgerState::new();
    let paid = Note::new(params.initial_reward, wallet(1).public_key());
    let paying = mine(&mut state, &params, paid, Vec::new());
    (state, params, NoteId::new(paying.coinbase.id(), 0), paid)
}

/// **A key that is not the owner's does not spend the note, and it is refused
/// for that before any signature is looked at.**
///
/// Mallory signs a spend of Alice's note, so the input carries Mallory's key
/// and a signature that verifies under it, over a message that names Alice's
/// address as the owner. The owner is a hash, and nothing but comparing the
/// key's hash with it ties the key to the note: without that comparison the
/// signature is checked against whatever key the input carries, holds, and
/// the note is Mallory's to spend.
#[test]
fn a_key_that_is_not_the_owners_does_not_spend_the_note() {
    let (state, params, id, paid) = alice_is_paid();
    let mallory = wallet(9);
    let mut theft = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(paid.value, mallory.public_key())],
    );
    theft.sign_input(params.network, 0, &paid, &mallory);
    assert_eq!(
        theft.inputs[0].key,
        mallory.public_key().to_bytes(),
        "signing puts the signer's key in the input"
    );

    let none = (BTreeSet::new(), BTreeMap::new());
    assert_eq!(
        check_transfer(&theft, &state, &none.0, &none.1, &params),
        Err(TransferError::KeyNotOwner { input_index: 0 }),
        "a spend signed by a key whose address is not the note's owner was not refused \
         as one"
    );

    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, mallory.public_key())],
    );
    assert!(
        matches!(
            assemble_block(
                &state,
                coinbase,
                vec![theft],
                &params,
                1_000 + height * 600,
                0
            ),
            Err(BlockError::InvalidTransfer {
                index: 0,
                source: TransferError::KeyNotOwner { input_index: 0 },
            })
        ),
        "a block carrying a spend by a key that is not the owner's was not refused as one"
    );

    // And Alice's own spend of it goes through, so the refusal above is about
    // the key and not about the note.
    let mut honest = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(paid.value, mallory.public_key())],
    );
    honest.sign_input(params.network, 0, &paid, &wallet(1));
    assert!(check_transfer(&honest, &state, &none.0, &none.1, &params).is_ok());
}

/// **A key that hashes to its owner is still refused when it is not a key a
/// signer can hold, as a signature that does not verify.**
///
/// Nothing on the wire decodes a key any more, so the three refusals a key
/// must pass are asked where it is used, at verification. The bytes here are
/// not a point at all, and whoever chose to be paid at their hash is the only
/// one who can present them: the spend is refused, and the node does not
/// stop over them.
#[test]
fn bytes_that_hash_to_the_owner_and_are_not_a_key_do_not_spend_the_note() {
    let params = params();
    let mut state = LedgerState::new();
    let not_a_key = [0xFF_u8; 32];
    let paid = Note::new(params.initial_reward, Address::of_ed25519(&not_a_key));
    let paying = mine(&mut state, &params, paid, Vec::new());
    let id = NoteId::new(paying.coinbase.id(), 0);

    let mut spend = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(paid.value, wallet(2).public_key())],
    );
    spend.inputs[0].key = not_a_key;
    let none = (BTreeSet::new(), BTreeMap::new());
    assert_eq!(
        check_transfer(&spend, &state, &none.0, &none.1, &params),
        Err(TransferError::InvalidSignature { input_index: 0 }),
        "bytes that are not a key were taken as one because their hash is the owner"
    );
}

/// **An address is the hash of the scheme byte and the key, under the address
/// domain, and nothing else.**
///
/// The scheme byte is what keeps a key of another scheme with the same thirty
/// two bytes from naming the same owner, and the domain is what keeps an
/// address from being read as any other hash. Both are one edit away from
/// gone, and every other test would go on passing with either removed, since
/// every address would still be the same function of every key.
#[test]
fn an_address_is_the_hash_of_the_scheme_and_the_key_under_its_own_domain() {
    let key = wallet(1).public_key();
    let mut preimage = vec![0x00_u8];
    preimage.extend_from_slice(key.as_bytes());
    assert_eq!(
        Address::from(key).to_bytes(),
        hash(Domain::Address, &preimage).to_bytes(),
        "an address is not H(address, 0x00 || key)"
    );
}

/// **An address is read only under its own network's prefix, only whole, and
/// only when every character is the one written.**
///
/// The reader is the one every face uses: the wallet's recipient, the node's
/// `--mine` and the explorer's pages all come through it. A reader that took
/// another network's prefix would pay a test network's address on devnet, or
/// the other way round; one that took thirty one or thirty three bytes would
/// name an owner no key hashes to; one that took a typo would pay nobody.
#[test]
fn an_address_is_read_only_under_its_own_networks_prefix_and_whole() {
    use cairn_ledger::note::{AddressError, NetworkId};

    let address = Address::from(wallet(1).public_key());
    for network in [NetworkId::MAINNET, NetworkId::TESTNET, NetworkId::DEVNET] {
        let text = address.to_text(network);
        assert_eq!(
            Address::from_text(&text, network),
            Ok(address),
            "an address was not read back under its own network"
        );
        for other in [NetworkId::MAINNET, NetworkId::TESTNET, NetworkId::DEVNET] {
            if other.address_prefix() != network.address_prefix() {
                assert!(
                    matches!(
                        Address::from_text(&text, other),
                        Err(AddressError::OtherNetwork { .. })
                    ),
                    "an address for one network was read on another"
                );
            }
        }
    }
    assert_eq!(
        NetworkId::TESTNET_1.address_prefix(),
        NetworkId::TESTNET.address_prefix(),
        "test networks do not share a prefix, so an address changes at every restart"
    );

    let testnet = NetworkId::TESTNET;
    for bytes in [31usize, 33] {
        let text = cairn_primitives::bech32m::encode("tcairn", &vec![7u8; bytes]);
        assert_eq!(
            Address::from_text(&text, testnet),
            Err(AddressError::WrongLength(bytes)),
            "a string carrying other than thirty two bytes was read as an address"
        );
    }

    let mut typo = address.to_text(testnet);
    let last = typo.pop().unwrap();
    typo.push(if last == 'q' { 'p' } else { 'q' });
    assert!(
        matches!(
            Address::from_text(&typo, testnet),
            Err(AddressError::Text(_))
        ),
        "an address with a typo in it was read"
    );
}
