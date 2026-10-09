#![cfg(feature = "native")]
//! Independent Solidity/Rust fixed-width vectors; no source or proof claim.
use ziquid_protocol::native::{
    ArmJournal, DeploymentDescriptor, OriginJournal, Resolution,
    ResolveJournal, SourceAcceptanceJournal, SourceBoundary, Statement, stable_j_tag,
};

fn vector(name: &str) -> Vec<u8> {
    let json = include_str!("../../../contracts/evm/test/fixtures/native-financial-vectors.json");
    let key = format!("\"{name}\": \"");
    let hex = json.split_once(&key).unwrap().1.split('"').next().unwrap();
    hex.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

#[test]
fn canonical_financial_statement_matches_independent_target_vector() {
    let raw = vector("statement");
    let statement = Statement::decode(&raw).unwrap();
    assert_eq!(statement.encode().as_slice(), raw);
    assert_eq!(statement.digest().as_slice(), vector("contextHash"));
    assert_eq!(statement.d, [0xff; 32]);
    assert!(Statement::decode(&raw[..raw.len() - 1]).is_err());
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Statement::decode(&trailing).is_err());
    let mut invalid = statement;
    invalid.joint_value += 1;
    assert!(invalid.validate().is_err());
    invalid = statement;
    invalid.expiries[0] = invalid.expiries[2];
    assert!(invalid.validate().is_err());
    let deployment = DeploymentDescriptor {
        schema_version: statement.schema_version, source_network: statement.source_network,
        source_pool: statement.source_pool, transaction_version: statement.transaction_version,
        consensus_branch: statement.consensus_branch, financial_program: statement.financial_program,
        origin_program: statement.origin_program, source_acceptance_program: statement.source_acceptance_program,
        source_policy_id: statement.source_policy_id, target_chain_id: statement.target_chain_id,
        obligation: statement.obligation, obligation_runtime_code: [6; 32], verifier: [7; 20],
        verifier_runtime_code: [8; 32],
    };
    assert_eq!(deployment.digest().as_slice(), vector("deploymentDescriptor"));
    assert_eq!(stable_j_tag(statement.target_chain_id, &statement.obligation, &[17; 32], &[16; 32]).unwrap().as_slice(), vector("stableJtag"));
}

#[test]
fn purpose_journals_bind_exact_context_and_shared_source_boundary() {
    let statement = Statement::decode(&vector("statement")).unwrap();
    let boundary = SourceBoundary::decode(&vector("boundary")).unwrap();
    assert_eq!(ArmJournal::new(&statement, boundary).unwrap().encode().as_slice(), vector("armJournal"));
    let origin = OriginJournal::new(&statement, boundary).unwrap();
    assert_eq!(origin.encode().as_slice(), vector("originJournal"));
    assert_eq!(ResolveJournal::new(&statement, boundary, Resolution::Completion, statement.a).unwrap().encode().as_slice(), vector("resolveCJournal"));
    assert_eq!(ResolveJournal::new(&statement, boundary, Resolution::Recovery, 0).unwrap().encode().as_slice(), vector("resolveRJournal"));
    assert_eq!(SourceAcceptanceJournal::new(&statement, boundary).unwrap().encode().as_slice(), vector("acceptanceJournal"));
    assert!(ResolveJournal::new(&statement, boundary, Resolution::Recovery, 1).is_err());
    assert!(ResolveJournal::new(&statement, boundary, Resolution::Completion, statement.a + 1).is_err());
    assert!(ArmJournal::decode(&vector("resolveRJournal")).is_err());
    let mut changed = statement;
    changed.payer[0] ^= 1;
    assert!(origin.check_statement(&changed).is_err());
    let mut invalid = vector("boundary");
    invalid[36..68].fill(0);
    assert!(SourceBoundary::decode(&invalid).is_err());
}

#[test]
fn native_journals_round_trip_and_reject_invalid_bindings() {
    let statement = Statement::decode(&vector("statement")).unwrap();
    let boundary = SourceBoundary::decode(&vector("boundary")).unwrap();
    let arm = ArmJournal::new(&statement, boundary).unwrap();
    assert_eq!(ArmJournal::decode(&arm.encode()).unwrap(), arm);
    let origin = OriginJournal::new(&statement, boundary).unwrap();
    assert_eq!(OriginJournal::decode(&origin.encode()).unwrap(), origin);
    let completion = ResolveJournal::new(&statement, boundary, Resolution::Completion, statement.a).unwrap();
    assert_eq!(ResolveJournal::decode(&completion.encode()).unwrap(), completion);
    let recovery = ResolveJournal::new(&statement, boundary, Resolution::Recovery, 0).unwrap();
    assert_eq!(ResolveJournal::decode(&recovery.encode()).unwrap(), recovery);
    let acceptance = SourceAcceptanceJournal::new(&statement, boundary).unwrap();
    assert_eq!(SourceAcceptanceJournal::decode(&acceptance.encode()).unwrap(), acceptance);

    let mut changed = statement;
    changed.stable_jtag[0] ^= 1;
    assert!(arm.check_statement(&changed).is_err());
    assert!(ResolveJournal::new(&statement, boundary, Resolution::Recovery, 1).is_err());
    assert!(ResolveJournal::new(&statement, boundary, Resolution::Completion, 0).is_err());
    assert!(stable_j_tag(statement.target_chain_id, &[0; 20], &[17; 32], &[16; 32]).is_err());
}

#[test]
fn deployment_decode_rejects_trailing_versions_and_missing_pins() {
    let statement = Statement::decode(&vector("statement")).unwrap();
    let deployment = DeploymentDescriptor {
        schema_version: statement.schema_version, source_network: statement.source_network,
        source_pool: statement.source_pool, transaction_version: statement.transaction_version,
        consensus_branch: statement.consensus_branch, financial_program: statement.financial_program,
        origin_program: statement.origin_program, source_acceptance_program: statement.source_acceptance_program,
        source_policy_id: statement.source_policy_id, target_chain_id: statement.target_chain_id,
        obligation: statement.obligation, obligation_runtime_code: [6; 32], verifier: [7; 20],
        verifier_runtime_code: [8; 32],
    };
    let bytes = deployment.encode();
    assert_eq!(DeploymentDescriptor::decode(&bytes).unwrap(), deployment);
    for length in 0..bytes.len() { assert!(DeploymentDescriptor::decode(&bytes[..length]).is_err()); }
    let mut trailing = bytes.to_vec(); trailing.push(0);
    assert!(DeploymentDescriptor::decode(&trailing).is_err());
    let mut unsupported = deployment; unsupported.schema_version = 2;
    assert!(DeploymentDescriptor::decode(&unsupported.encode()).is_err());
    let mut missing = deployment; missing.verifier_runtime_code = [0; 32];
    assert!(DeploymentDescriptor::decode(&missing.encode()).is_err());
    let mut wrong_domain = bytes; wrong_domain[0] ^= 1;
    assert!(DeploymentDescriptor::decode(&wrong_domain).is_err());
}
