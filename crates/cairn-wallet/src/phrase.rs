//! Twenty four words that make a key.
//!
//! A key file is a copy of a key, and a copy lives on a disk. A person who
//! loses the computer loses the disk, and every other copy is one they had to
//! think of taking. So a key is made from words instead: twenty four of them,
//! written once on paper, from which the same key comes back on any machine.
//!
//! Nothing here is this project's own. The words are BIP-39, the English list,
//! with 256 bits of entropy behind them and no passphrase. The seed is BIP-39's
//! too: PBKDF2 over HMAC-SHA512, two thousand and forty eight rounds, the salt
//! `mnemonic`. The key is SLIP-0010 for Ed25519, every level hardened because
//! that is the only kind Ed25519 has, along [`path`]. Each is the standard
//! every other wallet and every hardware device speaks, so words written for
//! this wallet can be checked, and restored, by something that is not it.
//!
//! The key file does not change. What `new` writes is still the derived key,
//! in hexadecimal, on one line, so every wallet made before this, every backup
//! and every script keeps working, and the words themselves are never written
//! to any disk by this program. A key file from before has no words behind it
//! and cannot be given any: a key is not the hash of anything that could be
//! turned back into a phrase.
//!
//! What passes through memory on the way is wiped, as `keyfile` wipes the key:
//! the entropy, the sentence the seed is stretched from, the seed, and each
//! step of the derivation. The gaps are of the same kind `keyfile` names, in
//! crates this module cannot reach into: `bip39` builds the bits it checks a
//! checksum over in arrays of its own, and `pbkdf2` and `hmac` hold their
//! working state in buffers they free themselves. None of them outlives the
//! process the way a file does.
//!
//! Two more sit in the standard library, on either side of the person, and
//! neither is wiped. The words `restore` reads arrive through standard
//! input's buffer, and the words `new` shows leave through standard output's:
//! each is one buffer for the whole process, which nothing here can reach,
//! and each holds the last words that passed through it until the process
//! ends. Closing them means reading and writing the descriptors directly,
//! past the standard library, which is more code on the path of the key than
//! the gap is worth while neither outlives the process either.

use std::fmt;

use bip39::{Language, Mnemonic};
use cairn_crypto::SecretKey;
use cairn_ledger::note::NetworkId;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

/// How many words a phrase is.
pub const WORDS: usize = 24;

/// The entropy behind twenty four words: 256 bits, and an eight bit checksum
/// that is the last part of the last word.
const ENTROPY_BYTES: usize = 32;

/// The SLIP-0044 coin type of every test and development network.
///
/// One is the number SLIP-0044 gives every coin's test networks, so a phrase
/// written on testnet-8 makes the same key on devnet and on the next test
/// network, which is what the key file has always done too.
pub const TEST_COIN_TYPE: u32 = 1;

/// The SLIP-0044 coin type of the main network, which has none yet.
///
/// It has to be registered at SLIP-0044 (github.com/satoshilabs/slips) before
/// a main network opens, and set here when it is. Until then a wallet on the
/// main network refuses to make a key from words at all: a number chosen here
/// and registered differently later would make every phrase written in the
/// meantime restore a key nobody was paid at.
pub const MAINNET_COIN_TYPE: Option<u32> = None;

/// BIP-44's purpose, the first level of every path.
const PURPOSE: u32 = 44;

/// The bit that makes an index hardened.
const HARDENED: u32 = 0x8000_0000;

/// Room for twenty four words of at most eight letters, and the spaces between
/// them, so the sentence the seed is stretched from never has to grow: a
/// `String` that grows leaves its old buffer behind, freed and unwiped.
const SENTENCE_BYTES: usize = WORDS * 9;

/// The path a key is derived along, on `network`: `m/44'/C'/0'/0'/0'`.
///
/// The one place it is written. Every level is hardened when it is derived,
/// so the numbers here are the indices before that bit is set.
pub fn path(network: NetworkId) -> Result<[u32; 5], String> {
    let coin = coin_type(network).ok_or_else(|| {
        "the main network has no coin type registered at SLIP-0044 yet, so this wallet \
         makes no key from words there: a number chosen now and registered differently \
         later would make every phrase written in the meantime restore a key nobody was \
         paid at."
            .to_owned()
    })?;
    Ok([PURPOSE, coin, 0, 0, 0])
}

/// The SLIP-0044 coin type of `network`, when it has one.
fn coin_type(network: NetworkId) -> Option<u32> {
    if network == NetworkId::MAINNET {
        MAINNET_COIN_TYPE
    } else {
        Some(TEST_COIN_TYPE)
    }
}

/// Twenty four words, checked.
pub struct Phrase(Mnemonic);

impl fmt::Debug for Phrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Phrase(<words withheld>)")
    }
}

impl Phrase {
    /// Draws a new phrase from the operating system's entropy source.
    pub fn draw() -> Result<Self, String> {
        let mut entropy = Zeroizing::new([0u8; ENTROPY_BYTES]);
        getrandom::fill(entropy.as_mut())
            .map_err(|error| format!("no entropy available: {error}"))?;
        Self::from_entropy(&entropy)
    }

    fn from_entropy(entropy: &[u8; ENTROPY_BYTES]) -> Result<Self, String> {
        Mnemonic::from_entropy_in(Language::English, entropy)
            .map(Self)
            .map_err(|error| format!("could not make words from the entropy drawn: {error}"))
    }

    /// Reads a phrase somebody typed.
    ///
    /// Any spacing and any case, since what a person copies off paper has
    /// both. What it refuses it says plainly, by position, because the person
    /// reading it has the paper in front of them and a position is what they
    /// can check: a word that is not in the list, a count that is not twenty
    /// four, or words that are each in the list and do not fit together, which
    /// is the checksum, and is almost always one word wrong or two swapped.
    pub fn read(text: &str) -> Result<Self, String> {
        let lowered = Zeroizing::new(text.to_ascii_lowercase());
        let count = lowered.split_whitespace().count();
        if count != WORDS {
            return Err(format!(
                "that is {count} words, and a recovery phrase for this wallet is {WORDS}. Check \
                 that every word on the paper was typed, once, in order."
            ));
        }
        Mnemonic::parse_in_normalized(Language::English, &lowered)
            .map(Self)
            .map_err(|error| match error {
                bip39::Error::UnknownWord(index) => format!(
                    "word {} is not one of the 2048 words a recovery phrase is made of. Check \
                     its spelling against the paper.",
                    index.saturating_add(1)
                ),
                bip39::Error::InvalidChecksum => "every word is in the list, but they do not \
                     fit together: the last word carries a check on all the others, and it \
                     does not match. Usually one word is wrong or two are swapped. Check \
                     them against the paper, in order."
                    .to_owned(),
                other => format!("those words are not a recovery phrase: {other}"),
            })
    }

    /// The words, in order.
    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.words()
    }

    /// The word at `position`, counted from one as the paper numbers them.
    pub fn word(&self, position: usize) -> Option<&'static str> {
        self.words().nth(position.checked_sub(1)?)
    }

    /// The key these words make on `network`.
    pub fn key(&self, network: NetworkId) -> Result<SecretKey, String> {
        let path = path(network)?;
        let seed = self.seed_with("");
        let key = derive(seed.as_slice(), &path)
            .ok_or_else(|| "could not derive a key from these words".to_owned())?;
        Ok(SecretKey::from_bytes(&key))
    }

    /// The BIP-39 seed, stretched from the words and `passphrase`.
    ///
    /// The wallet offers no passphrase and always passes an empty one. It is a
    /// parameter so that the published vectors, which all use one, can be
    /// held against the same code that runs.
    fn seed_with(&self, passphrase: &str) -> Zeroizing<[u8; 64]> {
        let mut sentence = Zeroizing::new(String::with_capacity(SENTENCE_BYTES));
        for (at, word) in self.words().enumerate() {
            if at > 0 {
                sentence.push(' ');
            }
            sentence.push_str(word);
        }
        let mut salt = Zeroizing::new(String::with_capacity(
            8usize.saturating_add(passphrase.len()),
        ));
        salt.push_str("mnemonic");
        salt.push_str(passphrase);
        let mut seed = Zeroizing::new([0u8; 64]);
        pbkdf2::pbkdf2_hmac::<Sha512>(sentence.as_bytes(), salt.as_bytes(), 2048, seed.as_mut());
        seed
    }
}

/// Positions to ask a person to type back, three of them, distinct, drawn at
/// random and in order.
pub fn positions_to_check() -> Result<[usize; 3], String> {
    positions_from(|| {
        cairn_crypto::random_bytes::<16>().map_err(|error| format!("no entropy available: {error}"))
    })
}

/// The same, from bytes `draw` hands out sixteen at a time, so a test can say
/// which bytes are taken and which are passed over.
fn positions_from(
    mut draw: impl FnMut() -> Result<[u8; 16], String>,
) -> Result<[usize; 3], String> {
    let mut chosen = [0usize; 3];
    let mut found = 0usize;
    while found < chosen.len() {
        let drawn = draw()?;
        // Below the largest multiple of twenty four a byte reaches, so that
        // every position is as likely as every other.
        for byte in drawn.into_iter().filter(|byte| *byte < 240) {
            let position = usize::from(byte % 24).saturating_add(1);
            if chosen.contains(&position) {
                continue;
            }
            let Some(slot) = chosen.get_mut(found) else {
                break;
            };
            *slot = position;
            found = found.saturating_add(1);
        }
    }
    chosen.sort_unstable();
    Ok(chosen)
}

/// The string SLIP-0010 keys its first HMAC with, for Ed25519.
///
/// Published in the standard and the same in every implementation: it names
/// the curve and is no secret. The secret is the seed it is applied to.
const CURVE: &[u8] = b"ed25519 seed";

/// SLIP-0010 for Ed25519: the private key at `path`, every level hardened.
///
/// An index may come with the hardened bit set, as the standard writes paths,
/// or without it, as [`path`] does: the bit is set either way, and never
/// cleared.
///
/// Written here rather than taken from a crate, because it is a dozen lines
/// over the HMAC this module already uses, and the crates that do it bring
/// older versions of the same HMAC with them.
fn derive(seed: &[u8], path: &[u32]) -> Option<Zeroizing<[u8; 32]>> {
    let mut node = hmac_sha512(CURVE, &[seed])?;
    for index in path {
        let (key, chain) = node.split_first_chunk::<32>()?;
        let hardened = (index | HARDENED).to_be_bytes();
        node = hmac_sha512(chain, &[&[0], key, &hardened])?;
    }
    let (key, _) = node.split_first_chunk::<32>()?;
    Some(Zeroizing::new(*key))
}

/// HMAC-SHA512 of the parts, one after the other, under `key`.
fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Option<Zeroizing<[u8; 64]>> {
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(key).ok()?;
    for part in parts {
        mac.update(part);
    }
    let mut out = mac.finalize().into_bytes();
    let mut held = Zeroizing::new([0u8; 64]);
    held.copy_from_slice(out.as_slice());
    out.as_mut_slice().zeroize();
    Some(held)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(text: &str) -> [u8; N] {
        cairn_primitives::hex::decode_array::<N>(text).unwrap()
    }

    /// The BIP-39 English vectors of twenty four words, verbatim from Trezor's
    /// reference implementation, `vectors.json` in
    /// <https://github.com/trezor/python-mnemonic>: entropy, words, seed.
    ///
    /// Every vector there is computed with the passphrase `TREZOR`; that is
    /// the passphrase given here. There are no official vectors with an empty
    /// one, which is what this wallet uses, so the empty passphrase is held
    /// below against `bip39`'s own seed, a second implementation written
    /// separately from the PBKDF2 used here.
    const BIP39_ENGLISH_24: [(&str, &str, &str); 8] = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
        ),
        (
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        ),
        (
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
        ),
        (
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
        ),
        (
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
        ),
        (
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
        ),
    ];

    /// One SLIP-0010 test vector for Ed25519: a seed, and for each chain the
    /// path, the chain code, the private key and the public key with its
    /// leading zero byte.
    struct Slip10 {
        seed: &'static str,
        chains: &'static [(&'static [u32], &'static str, &'static str, &'static str)],
    }

    /// Test vectors 1 and 2 for Ed25519, every chain in them, verbatim from
    /// SLIP-0010, <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>.
    /// The paths are written as the standard writes them, every level with
    /// the hardened bit set, so a derivation that cleared it would be seen.
    /// An index as the standard writes it, with the hardened bit set.
    const fn h(index: u32) -> u32 {
        index | HARDENED
    }

    const SLIP10_ED25519: [Slip10; 2] = [
        Slip10 {
            seed: "000102030405060708090a0b0c0d0e0f",
            chains: &[
                (
                    &[],
                    "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
                    "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                    "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
                ),
                (
                    &[h(0)],
                    "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                    "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                    "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
                ),
                (
                    &[h(0), h(1)],
                    "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                    "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                    "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
                ),
                (
                    &[h(0), h(1), h(2)],
                    "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                    "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                    "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
                ),
                (
                    &[h(0), h(1), h(2), h(2)],
                    "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                    "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                    "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
                ),
                (
                    &[h(0), h(1), h(2), h(2), h(1_000_000_000)],
                    "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                    "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                    "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
                ),
            ],
        },
        Slip10 {
            seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            chains: &[
                (
                    &[],
                    "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
                    "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
                    "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a",
                ),
                (
                    &[h(0)],
                    "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
                    "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                    "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
                ),
                (
                    &[h(0), h(2_147_483_647)],
                    "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
                    "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                    "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
                ),
                (
                    &[h(0), h(2_147_483_647), h(1)],
                    "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
                    "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                    "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
                ),
                (
                    &[h(0), h(2_147_483_647), h(1), h(2_147_483_646)],
                    "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
                    "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                    "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
                ),
                (
                    &[h(0), h(2_147_483_647), h(1), h(2_147_483_646), h(2)],
                    "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
                    "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
                    "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
                ),
            ],
        },
    ];

    /// The node at `path`, key and chain code, by the same steps [`derive`]
    /// takes, so the chain codes the vectors give are held as well.
    fn node_at(seed: &[u8], path: &[u32]) -> [u8; 64] {
        let mut node = hmac_sha512(CURVE, &[seed]).unwrap();
        for index in path {
            let (key, chain) = node.split_first_chunk::<32>().unwrap();
            let hardened = (index | HARDENED).to_be_bytes();
            node = hmac_sha512(chain, &[&[0], key, &hardened]).unwrap();
        }
        *node
    }

    #[test]
    fn the_bip39_vectors_give_their_words_and_their_seeds() {
        for (entropy, words, seed) in BIP39_ENGLISH_24 {
            let phrase = Phrase::from_entropy(&bytes::<32>(entropy)).unwrap();
            let made: Vec<&str> = phrase.words().collect();
            assert_eq!(made.join(" "), words, "the words for {entropy}");

            let read = Phrase::read(words).unwrap();
            assert_eq!(
                read.seed_with("TREZOR").as_slice(),
                bytes::<64>(seed).as_slice(),
                "the seed for {words}"
            );
        }
    }

    /// The empty passphrase, which is the one this wallet uses, against a
    /// second implementation: `bip39` stretches the seed with a PBKDF2 of its
    /// own, built on another hash library.
    #[test]
    fn the_seed_with_no_passphrase_is_the_one_another_implementation_gives() {
        for (_, words, _) in BIP39_ENGLISH_24 {
            let phrase = Phrase::read(words).unwrap();
            assert_eq!(
                phrase.seed_with("").as_slice(),
                phrase.0.to_seed_normalized("").as_slice(),
                "{words}"
            );
        }
    }

    #[test]
    fn the_slip10_vectors_give_every_chain_code_private_key_and_public_key() {
        for vector in &SLIP10_ED25519 {
            let seed = cairn_primitives::hex::decode(vector.seed).unwrap();
            for (path, chain_code, private, public) in vector.chains {
                let node = node_at(&seed, path);
                assert_eq!(&node[32..], bytes::<32>(chain_code).as_slice(), "{path:?}");
                let key = derive(&seed, path).unwrap();
                assert_eq!(*key, bytes::<32>(private), "{path:?}");
                assert_eq!(&node[..32], key.as_slice(), "{path:?}");
                let public = bytes::<33>(public);
                assert_eq!(public[0], 0, "{path:?}");
                assert_eq!(
                    SecretKey::from_bytes(&key).public_key().as_bytes(),
                    &public[1..],
                    "the key this wallet signs with is the one SLIP-0010 names: {path:?}"
                );
            }
        }
    }

    /// The path, written out, for a test network: every level is the number
    /// the decision named, and the key is the one SLIP-0010 gives there.
    #[test]
    fn a_test_network_derives_along_m_44_1_0_0_0() {
        let testnet = NetworkId::TESTNET_1;
        assert_eq!(path(testnet).unwrap(), [44, 1, 0, 0, 0]);
        let phrase = Phrase::read(BIP39_ENGLISH_24[0].1).unwrap();
        let seed = phrase.seed_with("");
        let along = derive(seed.as_slice(), &[44, 1, 0, 0, 0]).unwrap();
        assert_eq!(phrase.key(testnet).unwrap().to_bytes(), *along);
        assert_ne!(
            *along,
            *derive(seed.as_slice(), &[44, 0, 0, 0, 0]).unwrap(),
            "the coin type is part of the key"
        );
    }

    #[test]
    fn the_main_network_refuses_to_derive_until_its_coin_type_is_registered() {
        assert_eq!(
            MAINNET_COIN_TYPE, None,
            "set when it is registered, and this test with it"
        );
        let phrase = Phrase::read(BIP39_ENGLISH_24[0].1).unwrap();
        let refused = phrase.key(NetworkId::MAINNET).unwrap_err();
        assert!(refused.contains("SLIP-0044"), "{refused}");
    }

    #[test]
    fn a_word_that_is_not_in_the_list_is_named_by_its_position() {
        let mut words: Vec<&str> = BIP39_ENGLISH_24[4].1.split(' ').collect();
        words[6] = "cairn";
        let refused = Phrase::read(&words.join(" ")).unwrap_err();
        assert!(refused.contains("word 7 is not one of"), "{refused}");
    }

    #[test]
    fn two_words_swapped_fail_the_checksum_and_are_called_that() {
        let mut words: Vec<&str> = BIP39_ENGLISH_24[4].1.split(' ').collect();
        words.swap(0, 1);
        let refused = Phrase::read(&words.join(" ")).unwrap_err();
        assert!(refused.contains("do not fit together"), "{refused}");
    }

    #[test]
    fn a_phrase_of_another_length_is_refused_with_its_count() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon about";
        let refused = Phrase::read(twelve).unwrap_err();
        assert!(refused.contains("that is 12 words"), "{refused}");
    }

    #[test]
    fn a_phrase_is_read_in_any_case_and_any_spacing() {
        let words = BIP39_ENGLISH_24[5].1;
        let typed = format!("  {}\n", words.to_uppercase().replace(' ', " \n\t "));
        let read = Phrase::read(&typed).unwrap();
        assert_eq!(read.words().collect::<Vec<_>>().join(" "), words);
    }

    /// The sentence is sized once so it never grows and leaves a copy behind.
    #[test]
    fn the_longest_sentence_fits_the_room_made_for_it() {
        let longest = Language::English
            .word_list()
            .iter()
            .map(|word| word.len())
            .max()
            .unwrap();
        assert!(WORDS * longest + WORDS - 1 <= SENTENCE_BYTES);
    }

    /// Bytes handed out one run at a time, and then no more: a draw that keeps
    /// asking past what a test meant to give fails rather than spins.
    fn these(runs: Vec<[u8; 16]>) -> impl FnMut() -> Result<[u8; 16], String> {
        let mut runs = runs.into_iter();
        move || {
            runs.next()
                .ok_or_else(|| "asked for more than was given".to_owned())
        }
    }

    /// Which bytes are taken: those below 240, by their remainder after
    /// twenty four, counted from one, each position once.
    #[test]
    fn a_position_is_a_byte_below_240_by_its_remainder_and_each_comes_once() {
        let mut run = [255u8; 16];
        // 240 and 255 are passed over, where taken they would be positions 1
        // and 16; 1 is position 2, and the second 1 the same position again;
        // 239 is position 24; 26 is position 3.
        run[..6].copy_from_slice(&[240, 255, 1, 1, 239, 26]);
        assert_eq!(positions_from(these(vec![run])).unwrap(), [2, 3, 24]);

        // 47 is position 24, 48 is position 1, 71 is position 24 again: two
        // found, so a second run is asked for, and the third comes from it.
        let mut first = [255u8; 16];
        first[..3].copy_from_slice(&[47, 48, 71]);
        let mut second = [255u8; 16];
        second[0] = 100;
        assert_eq!(
            positions_from(these(vec![first, second])).unwrap(),
            [1, 5, 24]
        );
        assert!(
            positions_from(these(vec![first])).is_err(),
            "with two found and nothing more to draw, it asks again"
        );
    }

    /// Random bytes, as `positions_to_check` draws them, but a bounded number
    /// of runs: three positions take one run almost always, and a rule that
    /// could never find three fails here instead of spinning.
    fn random_runs() -> impl FnMut() -> Result<[u8; 16], String> {
        let mut left = 64u32;
        move || {
            left = left
                .checked_sub(1)
                .ok_or("sixty four runs and no three positions")?;
            cairn_crypto::random_bytes::<16>().map_err(|error| error.to_string())
        }
    }

    /// Every word can be asked for, the first and the last among them.
    #[test]
    fn every_position_comes_up_over_many_draws() {
        let mut seen = [false; WORDS];
        for _ in 0..2_000 {
            for at in positions_from(random_runs()).unwrap() {
                seen[at - 1] = true;
            }
        }
        assert!(seen.iter().all(|seen| *seen), "{seen:?}");
    }

    #[test]
    fn the_positions_to_check_are_three_distinct_words_of_the_phrase() {
        for _ in 0..200 {
            let positions = positions_from(random_runs()).unwrap();
            assert!(
                positions.iter().all(|at| (1..=WORDS).contains(at)),
                "{positions:?}"
            );
            assert!(
                positions[0] < positions[1] && positions[1] < positions[2],
                "{positions:?}"
            );
        }
    }

    #[test]
    fn a_word_is_found_by_the_number_the_paper_gives_it() {
        let phrase = Phrase::read(BIP39_ENGLISH_24[4].1).unwrap();
        assert_eq!(phrase.word(1), Some("hamster"));
        assert_eq!(phrase.word(24), Some("length"));
        assert_eq!(phrase.word(0), None);
        assert_eq!(phrase.word(25), None);
    }

    #[test]
    fn a_phrase_does_not_print_its_words() {
        let phrase = Phrase::read(BIP39_ENGLISH_24[4].1).unwrap();
        assert!(!format!("{phrase:?}").contains("hamster"));
    }
}
