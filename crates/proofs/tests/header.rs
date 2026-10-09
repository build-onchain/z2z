//! Connected testnet headers are deterministic ancestry observations, not full
//! transaction/state validity, a best-chain decision, or a settlement fact.

use primitive_types::U256;
use ziquid_proofs::{genesis::bootstrap_testnet_genesis, header::HeaderChain};

const GENESIS: &[u8; 1692] = include_bytes!("fixtures/testnet-genesis.bin");

// Every fixture is the first 1487 decoded bytes of its complete primary block:
// https://github.com/ZcashFoundation/zebra/tree/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-test/src/vectors
// The immutable source files block-test-0-000-001.txt through -010.txt were
// checked against these Git blob identities before extracting the headers:
// 1 eba9b29d12cb6cb13bd3439cdf6dc38700af738d
// 2 8b3dc0c430763a5a188764c512902cbad75d53f4
// 3 4dfb2a5e998e53bc2c3164174300ed397ed4baf1
// 4 11fbb61df4de7e28a3a8fda85d62156caba55646
// 5 775e8fc49d8f30413c4b7f95ab0f385c0473cb86
// 6 cae5abab04993d56a7ac9c05f1476b4d21f9164e
// 7 c9fa50efd35cec49ef6e754ae0533484fdfc7a77
// 8 5d562addc06bf1740558c62047c76a815772622b
// 9 5f5b4d9cd99993a3097c455d978c2cf2e6151213
// 10 75df3c1ec51f26628c99910d2c90e1e495cecadb
const HEADERS: [&[u8; 1487]; 10] = [
    include_bytes!("fixtures/testnet-header-1.bin"),
    include_bytes!("fixtures/testnet-header-2.bin"),
    include_bytes!("fixtures/testnet-header-3.bin"),
    include_bytes!("fixtures/testnet-header-4.bin"),
    include_bytes!("fixtures/testnet-header-5.bin"),
    include_bytes!("fixtures/testnet-header-6.bin"),
    include_bytes!("fixtures/testnet-header-7.bin"),
    include_bytes!("fixtures/testnet-header-8.bin"),
    include_bytes!("fixtures/testnet-header-9.bin"),
    include_bytes!("fixtures/testnet-header-10.bin"),
];

fn internal_hash(display_hex: &str) -> [u8; 32] {
    assert_eq!(display_hex.len(), 64);
    let mut result = [0; 32];
    for (byte, pair) in result
        .iter_mut()
        .rev()
        .zip(display_hex.as_bytes().as_chunks::<2>().0)
    {
        let value = |v: u8| match v {
            b'0'..=b'9' => v - b'0',
            b'a'..=b'f' => v - b'a' + 10,
            _ => panic!("invalid pinned hash"),
        };
        *byte = value(pair[0]) * 16 + value(pair[1]);
    }
    result
}

#[test]
fn authentic_genesis_to_ten_derives_connected_hashes_height_and_cumulative_work() {
    let genesis = bootstrap_testnet_genesis(GENESIS).unwrap();
    let mut chain = HeaderChain::from_testnet_genesis(&genesis);
    assert_eq!(chain.tip().height(), 0);
    assert_eq!(chain.tip().hash(), genesis.tip());
    assert_eq!(chain.tip().cumulative_work(), U256::from(32));

    // Independent SHA256d observations of the exact pinned primary bytes.
    let expected = [
        (
            "025579869bcf52a989337342f5f57a84f3a28b968f7d6a8307902b065a668d23",
            1_477_674_473,
            64,
        ),
        (
            "00f1a49e54553ac3ef735f2eb1d8247c9a87c22a47dbd7823ae70adcd6c21a18",
            1_477_676_169,
            96,
        ),
        (
            "00e141e8da20035b03a406ad93802cdcac010cba87341796af51029094383d45",
            1_477_677_108,
            128,
        ),
        (
            "036b74ae369047798aa3772be049a9c06a8900b8af39f02362fb6e16ee21ef75",
            1_477_677_184,
            160,
        ),
        (
            "00666e008318e8e44108bb318b23b549417aba1f0f835c4a2569ea4a05ae2f1e",
            1_477_677_455,
            192,
        ),
        (
            "067e63eb5040a8dd716f0c719a2a1c327d00bf52d54a9c05191536b1b03f86b8",
            1_477_677_865,
            224,
        ),
        (
            "032f058118920da6359a4af8a7d37fb6f0ced49146bc96c398e5bc3821d20296",
            1_477_678_426,
            256,
        ),
        (
            "05a4d532dd89c97768d884f68f2067762dea8559738cd6c2127beb6f4423ae3d",
            1_477_678_541,
            288,
        ),
        (
            "0235cccd1b981b90bb823b728ffdf41f44a4fc181f554bb19a0dc3f1a38e08b6",
            1_477_678_973,
            320,
        ),
        (
            "079f4c752729be63e6341ee9bce42fbbe37236aba22e3deb82405f3c2805c112",
            1_477_678_977,
            352,
        ),
    ];
    for (index, (raw, (hash, time, work))) in HEADERS.iter().zip(expected).enumerate() {
        let tip = chain.append(*raw).unwrap();
        assert_eq!(tip.height(), u32::try_from(index + 1).unwrap());
        assert_eq!(tip.hash(), internal_hash(hash));
        assert_eq!(tip.time(), time);
        assert_eq!(tip.bits(), 0x2007_ffff);
        assert_eq!(tip.cumulative_work(), U256::from(work));
        assert_eq!(chain.tip(), tip);
    }
    // Header-only observation must not mutate or replace the actual base ledger.
    assert_eq!(genesis.height(), 0);
    assert_eq!(genesis.utxo_count(), 0);
    assert_eq!(genesis.issued_supply(), 0);
}

#[test]
fn missing_parent_and_duplicate_reject_atomically_then_accept_the_real_successor() {
    let genesis = bootstrap_testnet_genesis(GENESIS).unwrap();
    let mut chain = HeaderChain::from_testnet_genesis(&genesis);
    let base = chain.clone();
    assert!(chain.append(HEADERS[1]).is_err());
    assert_eq!(chain, base);
    let first = chain.append(HEADERS[0]).unwrap();
    assert_eq!(first.cumulative_work(), U256::from(64));
    let before_duplicate = chain.clone();
    assert!(chain.append(HEADERS[0]).is_err());
    assert_eq!(chain, before_duplicate);
    let second = chain.append(HEADERS[1]).unwrap();
    assert_eq!(second.height(), 2);
    assert_eq!(second.cumulative_work(), U256::from(96));
}

#[test]
fn hostile_primary_header_mutations_preserve_all_context_and_future_append_behavior() {
    let genesis = bootstrap_testnet_genesis(GENESIS).unwrap();
    let base = HeaderChain::from_testnet_genesis(&genesis);
    let mut cases = Vec::new();
    for version in [3_i32, -1, i32::MIN] {
        let mut bytes = HEADERS[0].to_vec();
        bytes[..4].copy_from_slice(&version.to_le_bytes());
        cases.push(bytes);
    }
    for offset in [4, 36, 68, 100, 104, 108, 143, 1486] {
        let mut bytes = HEADERS[0].to_vec();
        bytes[offset] ^= 1;
        cases.push(bytes);
    }
    for bits in [0_u32, 0x2087_ffff, 0x2300_0001, 0x2008_0000, 0x1f07_ffff] {
        let mut bytes = HEADERS[0].to_vec();
        bytes[104..108].copy_from_slice(&bits.to_le_bytes());
        cases.push(bytes);
    }
    for length in [0, 139, 140, 142, 1486] {
        cases.push(HEADERS[0][..length].to_vec());
    }
    let mut suffix = HEADERS[0].to_vec();
    suffix.push(0);
    cases.push(suffix);
    let mut wrong_solution_length = HEADERS[0].to_vec();
    wrong_solution_length[141] = 0x3f;
    cases.push(wrong_solution_length);
    let mut noncanonical_length = Vec::from(&HEADERS[0][..140]);
    noncanonical_length.extend_from_slice(&[0xfe, 0x40, 0x05, 0, 0]);
    noncanonical_length.extend_from_slice(&HEADERS[0][143..]);
    cases.push(noncanonical_length);
    // A signed version >=4 is not rejected merely for being different from 4;
    // these unmined changes must still fail their cryptographic checks.
    let mut higher_version = HEADERS[0].to_vec();
    higher_version[..4].copy_from_slice(&5_i32.to_le_bytes());
    cases.push(higher_version);

    for (index, bytes) in cases.iter().enumerate() {
        let mut chain = base.clone();
        assert!(
            chain.append(bytes).is_err(),
            "hostile case {index} accepted"
        );
        assert_eq!(chain, base, "hostile case {index} mutated context");
        for raw in &HEADERS {
            chain.append(*raw).unwrap();
        }
        assert_eq!(chain.tip().height(), 10);
        assert_eq!(chain.tip().cumulative_work(), U256::from(352));
    }
}
