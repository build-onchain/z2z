//! Parent-run public codec/ABI fixture generation, not ownership or financial proof.
//! Run only after the independent-fill source freeze. Original v1 fixtures are read-only.
use std::{error::Error, fmt::Write as _, fs, path::PathBuf};
use primitive_types::U256;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ziquid_chains::samechain::build_fill_call;
use ziquid_protocol::samechain::{
    Action, Asset, FeePolicy, FeeRule, OrderPolicy, OwnerJournal, PublicPacket, Role,
    fill::{FillExecution, aggregate_commitment, owner_leaf, validate_commitment},
};

const ORIGINAL_NATIVE: &str = include_str!("../../../contracts/evm/test/fixtures/samechain-native-vectors.json");
const ORIGINAL_CALLS: &str = include_str!("../../../contracts/evm/test/fixtures/samechain-call-vectors.json");

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes { write!(text, "{byte:02x}").unwrap(); }
    text
}

fn unhex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if !text.len().is_multiple_of(2) { return Err("odd public hexadecimal length".into()); }
    text.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?)
    }).collect()
}

fn known_pair(text: &str, collection: &str) -> Result<Value, Box<dyn Error>> {
    let value: Value = serde_json::from_str(text)?;
    Ok(value[collection].as_array().ok_or("missing vector collection")?.iter()
        .find(|packet| packet["name"] == "known_pair").ok_or("missing fill vector")?.clone())
}

fn field(value: &Value, key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    unhex(value[key].as_str().ok_or("missing public bytes")?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/evm/test/fixtures");
    let original = known_pair(ORIGINAL_NATIVE, "packets")?;
    let original_call = known_pair(ORIGINAL_CALLS, "calls")?;
    // Borrow the preserved public descriptors/ciphertexts, never an old private opening.
    let mut packet = PublicPacket::decode(&field(&original, "packethex")?)?;
    packet.terms_commitment = [0; 32];
    let execution = FillExecution {
        asset_a: Asset::Native, asset_b: Asset::Token([7; 20]),
        sell_a: U256::from(40), sell_b: U256::from(50),
    };
    // Deliberately different controlled local policies. These public-codec inputs
    // do not claim to open the authentic input commitments in the borrowed B.
    let policy_a = OrderPolicy {
        sell_asset: execution.asset_a, buy_asset: execution.asset_b,
        min_buy_num: U256::from(1), min_sell_den: U256::from(2),
        fee_policy: FeePolicy { entries: vec![FeeRule {
            payer: Role::A, asset: execution.asset_b, beneficiary: [8; 20], max_atoms: U256::from(5),
        }] },
    };
    let policy_b = OrderPolicy {
        sell_asset: execution.asset_b, buy_asset: execution.asset_a,
        min_buy_num: U256::from(2), min_sell_den: U256::from(3),
        fee_policy: FeePolicy { entries: vec![] },
    };
    // PUBLIC synthetic oracle salts, never production entropy or owner secrets.
    // Real independent-owner process acceptance separately requires OS entropy.
    let salt_a = [0xa1; 32];
    let salt_b = [0xb2; 32];
    let leaves = [
        owner_leaf(&packet, &execution, Role::A, &policy_a, &salt_a)?,
        owner_leaf(&packet, &execution, Role::B, &policy_b, &salt_b)?,
    ];
    packet.terms_commitment = aggregate_commitment(&packet, &execution, &leaves)?;
    validate_commitment(&packet, &execution, &leaves)?;
    packet.validate()?;
    let proof = field(&original_call, "proofhex")?;
    let proof_b = field(&original_call, "proofBhex")?;
    let sender: [u8; 20] = field(&original_call, "from")?.try_into().map_err(|_| "invalid public sender")?;
    let call = build_fill_call(&packet.deployment, &packet, sender, &proof, &proof_b)?;
    let journal_a = OwnerJournal::from_packet(&packet, Role::A, Action::Fill)?.encode()?;
    let journal_b = OwnerJournal::from_packet(&packet, Role::B, Action::Fill)?.encode()?;
    assert_eq!(call.expected_journals(), &[journal_a.clone(), journal_b.clone()]);
    let encoded = packet.encode()?;
    let digest = packet.digest()?;
    let record = json!({
        "kind": "Fill", "name": "known_pair", "relation_version": 2,
        "packethex": hex(&encoded), "digesthex": hex(&digest),
        "deploymenthex": hex(&packet.deployment.encode()?),
        "deploymentdigesthex": hex(&packet.deployment.digest()?),
        "executionhex": hex(&execution.encode()?),
        "leafhexA": hex(&leaves[0]), "leafhexB": hex(&leaves[1]),
        "journalhexA": hex(&journal_a), "journalhexB": hex(&journal_b),
        "datahex": hex(call.data()), "proofhex": hex(&proof), "proofBhex": hex(&proof_b),
        "from": format!("0x{}", hex(&call.from())), "to": format!("0x{}", hex(&call.to())),
        "value_atoms": call.value().to_string(),
    });
    let vectors = serde_json::to_vec_pretty(&json!({
        "scope": "Public fill2 codec/journal/ABI correspondence only; no authentic policy opening, ownership, membership, backing, valid certificate or financial execution.",
        "packets": [record],
    }))?;
    let solidity = format!(
        "// SPDX-License-Identifier: UNLICENSED\npragma solidity 0.8.34;\n\n// Generated by chains/examples/samechain_fill2_vectors.rs; public codec/ABI only.\n// Not an ownership, backing or cryptographic-proof fixture. Original v1 vectors remain unchanged.\nlibrary SamechainFill2Vectors {{\n    function packet() internal pure returns (bytes memory) {{ return hex\"{}\"; }}\n    function journal(bool roleB) internal pure returns (bytes memory) {{\n        if (roleB) return hex\"{}\";\n        return hex\"{}\";\n    }}\n    function data() internal pure returns (bytes memory) {{ return hex\"{}\"; }}\n    function digest() internal pure returns (bytes32) {{ return hex\"{}\"; }}\n}}\n",
        hex(&encoded), hex(&journal_b), hex(&journal_a), hex(call.data()), hex(&digest),
    );
    let provenance = serde_json::to_vec_pretty(&json!({
        "generator": "crates/chains/examples/samechain_fill2_vectors.rs",
        "command": "cargo run -p ziquid-chains --example samechain_fill2_vectors",
        "relation_version": 2, "packet_schema": 1, "outer_journal_version": 1,
        "generation": "Actual native FillExecution, separate owner_leaf calls with distinct controlled policies and public deterministic oracle salts, aggregate_commitment, validate_commitment, OwnerJournal and build_fill_call.",
        "public_oracle_salts_hex": [hex(&salt_a), hex(&salt_b)],
        "limits": "Borrowed original public B does not open the controlled policies; reproducible codec correspondence only, not independent-owner/private-entropy acceptance. Preserved proof bytes have invalid zero pairing points. No real owner policies, seeds or witnesses used or exported. Public deterministic salts must never be used in production; real independent-owner processes require separately qualified private OS entropy.",
        "source_sha256": {
            "generator": hex(&Sha256::digest(include_bytes!("samechain_fill2_vectors.rs"))),
            "protocol": hex(&Sha256::digest(include_bytes!("../../protocol/src/samechain.rs"))),
            "fill": hex(&Sha256::digest(include_bytes!("../../protocol/src/samechain/fill.rs"))),
            "chains": hex(&Sha256::digest(include_bytes!("../src/samechain.rs"))),
            "original_native": hex(&Sha256::digest(ORIGINAL_NATIVE.as_bytes())),
            "original_calls": hex(&Sha256::digest(ORIGINAL_CALLS.as_bytes())),
        },
        "output_sha256": {
            "samechain-fill2-vectors.json": hex(&Sha256::digest(&vectors)),
            "SamechainFill2Vectors.sol": hex(&Sha256::digest(solidity.as_bytes())),
        },
    }))?;
    fs::write(directory.join("samechain-fill2-vectors.json"), vectors)?;
    fs::write(directory.join("SamechainFill2Vectors.sol"), solidity)?;
    fs::write(directory.join("samechain-fill2-vectors.provenance.json"), provenance)?;
    println!("Generated public fill2 codec/ABI overlay and provenance; no financial qualification.");
    Ok(())
}
