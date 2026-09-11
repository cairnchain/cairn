//! Known answer vectors for everything a node has to agree with every other
//! node about.
//!
//! Nothing in the workspace pinned a single digest before this file. The
//! comment on `Domain` says that changing a context string is a hard fork, and
//! it is right, but nothing enforced it: renaming `"cairn v1 signature
//! message"` in a tidy-up, or reordering the fields of `DomainKeys` so that a
//! `key_for` arm points at the wrong one, would leave every existing test
//! passing and every node built from that commit unable to agree with any node
//! built before it. These vectors are the tripwire. If one fails, the change
//! that caused it is a hard fork and has to be treated as one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain, Hash32, Hasher};
use cairn_primitives::hex;
use cairn_primitives::merkle::{merkle_leaf, merkle_root};

const PROBE: &[u8] = b"cairn audit vector";

/// Every domain, and the digest it gives over [`PROBE`].
///
/// The pairing matters as much as the values: a swap between two arms of
/// `key_for` would keep every digest distinct and still be a fork.
const DOMAIN_VECTORS: [(Domain, &str); 21] = [
    (
        Domain::TransferId,
        "8903a92f6a8473eb072c6c73ba4f3e71322010ddf3a6d961d1256bfa4e19e908",
    ),
    (
        Domain::CoinbaseId,
        "618d51de0d0252e4e600ddfaf3640080fcc6fd8eb47668605075824a5676f8a9",
    ),
    (
        Domain::BlockHeaderId,
        "43ea1615e0f33f96a18af755c2ace36ac8ebd19621778cd22d2c74f7cead9a85",
    ),
    (
        Domain::SignatureMessage,
        "b61f559e48d6b1b0b0d820e164a85ce54e50e06145015588cb9dbf2183374606",
    ),
    (
        Domain::MerkleLeaf,
        "7adc6d1de897631bc365d4f43847983a55e1324b0cd2c09416b203ee4bef7d55",
    ),
    (
        Domain::MerkleNode,
        "0ad0d708c56aa1da78e26f8746ece6e73e8407b74b6c4ab1ddc94ac7f1123193",
    ),
    (
        Domain::MerkleEmpty,
        "dc35a06f9420b9364c6201b1258fa85a5ddc933ae4556c99c18176690cccc1af",
    ),
    (
        Domain::StateEntry,
        "e324edff1d25806c575c30ec7681d9832380ffb305963b712c73b5e20bd92fb3",
    ),
    (
        Domain::AccumulatorEmpty,
        "91f7018918afd6e049574e0870bed4ec26549fe1190d2d64871ebbe4337f9f71",
    ),
    (
        Domain::AccumulatorLeaf,
        "89c2c037f0e176db65a4ccd17102e2f2932f075b49019ff5d2e6ff343bfef0a3",
    ),
    (
        Domain::AccumulatorNode,
        "60f3b42e8af3829cc5daf2ed0107d0cdc60b225dabe311336bb356d895652410",
    ),
    (
        Domain::NoteKey,
        "4b45ffea0b9e5ca5dec83bd7bbe2a7f47ff8b92c4c60b88115ca4ce0fddf3dcd",
    ),
    (
        Domain::HotNoteValue,
        "f380003db3159754be3f6bb20ccfefb3f9df8a7ed1fd9871c800a7bbb789da4c",
    ),
    (
        Domain::StateCommitment,
        "743b9d30cd13aff6cb8bd8633f0e801ea16f2d7527ad23ff66d0acd1dc42b6b1",
    ),
    (
        Domain::ForestLeaf,
        "574e819120f4ff9e742eaba13c749681b6cc0b6e1e31a464fe50d050cf817be1",
    ),
    (
        Domain::ForestNode,
        "9555251b3f20ae7dc20863622f30d6c36f6b2baad614fd758be9f25a48193d6d",
    ),
    (
        Domain::ForestRoots,
        "44f697e0d68a2c21e27712f37aaeeffe28a4162e34ea77824fd6311e48a4d8a2",
    ),
    (
        Domain::HeaderHistoryLeaf,
        "ffe63d7b18bd03b557aac48165eb64c3a7879bb991a906790243dd6f4ad5bb12",
    ),
    (
        Domain::SamplingSeed,
        "562d3acfa2a9beb6c18b8d4fb1c1bb2163c2971a98a87b5ce9d8ab539613f457",
    ),
    (
        Domain::GraceWindow,
        "deb7354cfac902db43130ba979205b8dcaaf4627869cff3afa4b20ab05356336",
    ),
    (
        Domain::WalletHistory,
        "5577b3011c2de48346f32894271cb3eed164794f7eeb30d82c7c5f3a81917b7f",
    ),
];

/// The table above says "every domain", and nothing made that true.
///
/// It was twenty rows against twenty-one domains: `Domain::WalletHistory` was
/// added and no vector came with it, so the one string nothing pinned was the
/// one that stamps the wallet's own history file. Renaming it in a tidy-up
/// would have left this suite green and left every wallet built afterwards
/// refusing the file every wallet before it wrote.
///
/// [`Domain::ALL`] is the list this is checked against. It still has to be
/// written by hand, since an enum cannot be walked, but a domain missing from
/// the vectors now fails here instead of going unnoticed.
#[test]
fn every_domain_the_crate_declares_is_pinned_here() {
    for domain in Domain::ALL {
        assert!(
            DOMAIN_VECTORS.iter().any(|(pinned, _)| *pinned == domain),
            "{domain:?} has no vector, so its context string can change and nothing will say so"
        );
    }
    assert_eq!(
        DOMAIN_VECTORS.len(),
        Domain::ALL.len(),
        "the table pins something that is not a domain, or pins one twice"
    );
}

#[test]
fn every_domain_still_hashes_the_way_it_did() {
    for (domain, expected) in DOMAIN_VECTORS {
        let digest = hash(domain, PROBE);
        assert_eq!(
            digest.to_string(),
            expected,
            "{domain:?} changed: this is a hard fork, not a refactor"
        );
    }
}

#[test]
fn the_tree_still_builds_the_way_it_did() {
    // Every leaf count from zero to six. The empty root, the lone-leaf
    // identity and the promotion of an odd node are all pinned here, so the
    // CVE-2012-2459 defence cannot be traded away by a rewrite that still
    // passes the inequality tests.
    let leaves: Vec<Hash32> = (0..6u32)
        .map(|index| merkle_leaf(&index.encode()))
        .collect();
    let expected = [
        "7c2d92bafb2b5f84b7b74cfe91239b49a94936c40526b4b2e6a3fd4c1ebeec04",
        "554a4efeec2abea9b0ff2b694753c35b8a3495616aa1d1341437936ecdd762c6",
        "0e6564196fe0400a673d11f16c81d9b45e7697c822934f90bc8d00f139d9c111",
        "c25abe646459bbfa3dd956ffaf4813d1dca6b0960423cce9acda7d2e187de18c",
        "617072c403a469c0676be3f7d0b25f1655ce4d28f7a7ddf4756805141b230d07",
        "92d8b8ceafe380ba16a16074006f81c6631d450643dd23d784def7dbd1d7fbe4",
        "f7952e0ec3350ca108c6371a86991370a4864f0e941cb61f4ae6b29019652c8b",
    ];
    for (count, want) in expected.into_iter().enumerate() {
        assert_eq!(
            merkle_root(&leaves[..count]).to_string(),
            want,
            "the root over {count} leaves changed: this is a hard fork"
        );
    }
    // Said out loud because it is a property, not an accident: the empty root
    // is the empty domain, and a lone leaf is its own root.
    assert_eq!(merkle_root(&[]), hash(Domain::MerkleEmpty, &[]));
    assert_eq!(merkle_root(&leaves[..1]), leaves[0]);
}

#[test]
fn the_incremental_hasher_still_matches_the_one_shot() {
    for (domain, expected) in DOMAIN_VECTORS {
        let mut incremental = Hasher::new(domain);
        for chunk in PROBE.chunks(3) {
            incremental.update(chunk);
        }
        assert_eq!(incremental.finalize().to_string(), expected);
    }
}

#[test]
fn hexadecimal_still_renders_the_way_it_did() {
    assert_eq!(hex::encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    assert_eq!(hex::encode(&[]), "");
}

// ---------------------------------------------------------------------------
// Part 1 of `docs/cairn-specification.md`, written from the document.
//
// The vectors above pin digests. These pin the sentences in *Primitives* that
// say which bytes are hashed in the first place, which is the half a domain
// vector cannot see: swapping two fields of a structure leaves every digest
// here unchanged and changes every identifier in the chain.
//
// One link in that chain is still unpinned anywhere, and it is named rather
// than left to be discovered. The document says each domain constant is
// BLAKE3's `derive_key` over a published context string with empty key
// material, and it publishes twenty of the twenty-one strings: the one it
// leaves out is `wallet history`, which stamps a file on one person's disk
// rather than anything two nodes have to agree about. Nothing checks a
// constant against the string that is said to produce it, here or elsewhere:
// `DOMAIN_VECTORS` pins what the constants hash to, not what they are made
// from. Checking it needs BLAKE3 in this crate's dev-dependencies.
// ---------------------------------------------------------------------------

use cairn_primitives::amount::PEBBLES_PER_CAIRN;
use cairn_primitives::codec::{CodecError, Decode, MAX_SEQUENCE_LEN};
use cairn_primitives::Amount;

#[test]
fn an_integer_encodes_little_endian_at_the_width_its_type_says() {
    assert_eq!(0x12u8.encode(), vec![0x12]);
    assert_eq!(0x1234u16.encode(), vec![0x34, 0x12]);
    assert_eq!(0x1234_5678u32.encode(), vec![0x78, 0x56, 0x34, 0x12]);
    assert_eq!(
        0x1122_3344_5566_7788u64.encode(),
        vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
    );
    assert_eq!(u128::from(u64::MAX).encode().len(), 16);
    assert_eq!(
        u128::from(u64::MAX).encode(),
        [vec![0xff; 8], vec![0x00; 8]].concat()
    );

    // "A decoder MUST read exactly the width the field's type says and no
    // more", so a frame one byte short is refused and one byte long is too.
    assert_eq!(u32::decode(&[1, 2, 3]), Err(CodecError::UnexpectedEnd));
    assert_eq!(
        u32::decode(&[1, 2, 3, 4, 5]),
        Err(CodecError::TrailingBytes(1))
    );
}

#[test]
fn a_byte_array_and_a_hash_encode_as_their_bytes_with_no_prefix() {
    let bytes = [0xab_u8; 7];
    assert_eq!(bytes.encode(), bytes.to_vec());
    let digest = hash(Domain::MerkleLeaf, PROBE);
    assert_eq!(digest.encode(), digest.as_bytes().to_vec());
    assert_eq!(digest.encode().len(), 32);
}

#[test]
fn a_sequence_is_a_u32_count_then_the_items_back_to_back() {
    let items: Vec<u16> = vec![0x0102, 0x0304, 0x0506];
    assert_eq!(
        items.encode(),
        vec![3, 0, 0, 0, 0x02, 0x01, 0x04, 0x03, 0x06, 0x05]
    );
    assert_eq!(Vec::<u16>::new().encode(), vec![0, 0, 0, 0]);
    assert_eq!(Vec::<u16>::decode(&items.encode()).unwrap(), items);
}

#[test]
fn a_declared_count_past_the_floor_is_refused_before_any_item_is_read() {
    assert_eq!(MAX_SEQUENCE_LEN, 1_048_576);

    // The count and nothing after it. A decoder that reserved in proportion to
    // the count before checking it would ask for four megabytes here.
    let past = u32::try_from(MAX_SEQUENCE_LEN + 1).unwrap();
    let mut frame = past.to_le_bytes().to_vec();
    assert_eq!(
        Vec::<u32>::decode(&frame),
        Err(CodecError::SequenceTooLong {
            declared: MAX_SEQUENCE_LEN + 1
        }),
        "the count is refused before any item is read"
    );

    // And the limit itself is allowed through the count check, failing only
    // for want of the items, which is what puts the boundary at the right end.
    frame = u32::try_from(MAX_SEQUENCE_LEN)
        .unwrap()
        .to_le_bytes()
        .to_vec();
    assert_eq!(Vec::<u32>::decode(&frame), Err(CodecError::UnexpectedEnd));
}

#[test]
fn an_amount_is_a_count_of_pebbles_and_the_ceiling_is_refused_at_decode() {
    assert_eq!(PEBBLES_PER_CAIRN, 100_000_000);
    assert_eq!(Amount::MAX_MONEY.as_pebbles(), 100_000_000_000_000_000);
    assert_eq!(
        Amount::MAX_MONEY.as_pebbles() / PEBBLES_PER_CAIRN,
        1_000_000_000
    );

    let amount = Amount::from_pebbles(1_234_567_890).unwrap();
    assert_eq!(amount.encode(), 1_234_567_890u64.to_le_bytes().to_vec());
    assert_eq!(amount.encode().len(), 8);

    assert_eq!(
        Amount::decode(&Amount::MAX_MONEY.as_pebbles().to_le_bytes()).unwrap(),
        Amount::MAX_MONEY,
        "the ceiling itself decodes"
    );
    assert_eq!(
        Amount::decode(&(Amount::MAX_MONEY.as_pebbles() + 1).to_le_bytes()),
        Err(CodecError::InvalidValue {
            type_name: "Amount"
        }),
        "one pebble past the ceiling is refused rather than clamped"
    );
    assert!(Amount::from_pebbles(Amount::MAX_MONEY.as_pebbles() + 1).is_none());
}
