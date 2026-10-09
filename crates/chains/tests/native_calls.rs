//! ABI/journal review vectors only: no genuine proof, source finality or transfer.
use primitive_types::U256;
use serde_json::Value;
use ziquid_chains::native::{
    build_fund_and_arm_call, build_resolve_call, CallBuildError, UnsignedCall,
};
use ziquid_protocol::native::{DeploymentDescriptor, Resolution, SourceBoundary, Statement};

fn hex(value: &str) -> Vec<u8> {
    value.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

fn vector(name: &str) -> Vec<u8> {
    let json: Value = serde_json::from_str(include_str!(
        "../../../contracts/evm/test/fixtures/native-financial-vectors.json"
    )).unwrap();
    hex(json[name].as_str().unwrap())
}

fn fixture() -> (DeploymentDescriptor, Statement, SourceBoundary) {
    // Independent descriptor, not copied from the statement being checked.
    let deployment = DeploymentDescriptor {
        schema_version: 1, source_network: 1, source_pool: 3,
        transaction_version: 6, consensus_branch: 0x37a5165b,
        financial_program: [1; 32], origin_program: [20; 32],
        source_acceptance_program: [2; 32], source_policy_id: [3; 32],
        target_chain_id: 84532, obligation: [5; 20],
        obligation_runtime_code: [6; 32], verifier: [7; 20],
        verifier_runtime_code: [8; 32],
    };
    (deployment, Statement::decode(&vector("statement")).unwrap(),
        SourceBoundary::decode(&vector("boundary")).unwrap())
}

// Vendored SP1 v6.1.0 public frame with deliberately invalid zero pairing
// points. A builder may describe it; only the actual verifier authenticates it.
fn unverified_frame(nonce: u8) -> Vec<u8> {
    let mut frame = vec![0; 356];
    frame[..4].copy_from_slice(&hex("4388a21c"));
    frame[36..68].copy_from_slice(&hex(
        "002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352"
    ));
    frame[99] = nonce;
    frame
}

// Independent decoder: inspect the emitted head/tail bytes using literal
// compiler selectors and hand-derived offsets, never production ABI helpers.
fn word(data: &[u8], offset: usize) -> u64 {
    assert_eq!(&data[offset..offset + 24], &[0; 24]);
    u64::from_be_bytes(data[offset + 24..offset + 32].try_into().unwrap())
}

fn bytes_arg(data: &[u8], head: usize, offset: usize, length: usize) -> &[u8] {
    assert_eq!(word(data, 4 + head * 32), offset as u64);
    let start = 4 + offset;
    assert_eq!(word(data, start), length as u64);
    let end = start + 32 + length;
    let padded_end = start + 32 + length.div_ceil(32) * 32;
    assert!(data[end..padded_end].iter().all(|byte| *byte == 0));
    &data[start + 32..end]
}

fn rejects(result: Result<UnsignedCall, CallBuildError>, error: CallBuildError) {
    assert_eq!(result.unwrap_err(), error);
}

#[test]
fn fund_and_arm_matches_independent_abi_journals_and_full_width_value() {
    let (deployment, statement, boundary) = fixture();
    let arm = unverified_frame(1);
    let origin = unverified_frame(2);
    let acceptance = unverified_frame(3);
    let call = build_fund_and_arm_call(
        &deployment, &statement, &boundary, &arm, &origin, &acceptance,
    ).unwrap();
    assert_eq!(call.from(), [9; 20]);
    assert_eq!(call.to(), [5; 20]);
    assert_eq!(call.value(), U256::MAX);
    assert_eq!(call.context_digest().as_slice(), vector("contextHash"));
    assert_eq!(call.expected_journals(), &[
        vector("armJournal"), vector("originJournal"), vector("acceptanceJournal"),
    ]);
    assert_eq!(call.allocation(), None);
    let data = call.data();
    assert_eq!(&data[..4], &hex("0660a602"));
    assert_eq!(data.len(), 2244);
    assert_eq!(bytes_arg(data, 0, 160, 638), vector("statement"));
    assert_eq!(bytes_arg(data, 1, 832, 100), vector("boundary"));
    assert_eq!(bytes_arg(data, 2, 992, 356), arm);
    assert_eq!(bytes_arg(data, 3, 1408, 356), origin);
    assert_eq!(bytes_arg(data, 4, 1824, 356), acceptance);
    assert_eq!(call.deployment().obligation, [5; 20]);
    assert_eq!(call.deployment().digest().as_slice(), vector("deploymentDescriptor"));
}

#[test]
fn completion_and_recovery_match_independent_resolve_abi_and_journals() {
    let (deployment, statement, boundary) = fixture();
    let financial = unverified_frame(4);
    let acceptance = unverified_frame(5);
    for (outcome, cnet, expected_journal, user, solver) in [
        (Resolution::Completion, 100000000, "resolveCJournal", U256::MAX, U256::zero()),
        (Resolution::Recovery, 0, "resolveRJournal", U256::zero(), U256::MAX),
    ] {
        let call = build_resolve_call(&deployment, &statement, &boundary,
            [42; 20], outcome, cnet, &financial, &acceptance).unwrap();
        assert_eq!(call.from(), [42; 20]);
        assert_eq!(call.to(), [5; 20]);
        assert_eq!(call.value(), U256::zero());
        assert_eq!(call.context_digest().as_slice(), vector("contextHash"));
        assert_eq!(call.expected_journals(), &[
            vector(expected_journal), vector("acceptanceJournal"),
        ]);
        let allocation = call.allocation().unwrap();
        assert_eq!(allocation.user.get(), user);
        assert_eq!(allocation.solver.get(), solver);
        let data = call.data();
        assert_eq!(&data[..4], &hex("70c1e7b1"));
        assert_eq!(data.len(), 1860);
        assert_eq!(bytes_arg(data, 0, 192, 638), vector("statement"));
        assert_eq!(bytes_arg(data, 1, 864, 100), vector("boundary"));
        assert_eq!(word(data, 68), outcome as u64);
        assert_eq!(word(data, 100), cnet);
        assert_eq!(bytes_arg(data, 4, 1024, 356), financial);
        assert_eq!(bytes_arg(data, 5, 1440, 356), acceptance);
    }
}

#[test]
fn partial_completion_preserves_full_u64_cnet_and_full_u256_allocation() {
    let (deployment, mut statement, boundary) = fixture();
    let proof = unverified_frame(0);
    let partial = build_resolve_call(&deployment, &statement, &boundary,
        [42; 20], Resolution::Completion, 50000000, &proof, &proof).unwrap();
    let allocation = partial.allocation().unwrap();
    assert_eq!(allocation.user.get(), U256::MAX >> 1);
    assert_eq!(allocation.solver.get(), (U256::MAX >> 1) + U256::one());
    statement.a = 0x010203040506;
    statement.joint_value = statement.a + statement.fees[1];
    statement.r_return = statement.joint_value - statement.fees[2];
    let wide = build_resolve_call(&deployment, &statement, &boundary,
        [42; 20], Resolution::Completion, 0x010203040506, &proof, &proof).unwrap();
    assert_eq!(&wide.data()[100..132], &hex(
        "0000000000000000000000000000000000000000000000000000010203040506"
    ));
    assert_eq!(wide.allocation().unwrap().user.get(), U256::MAX);
    assert_eq!(wide.allocation().unwrap().solver.get(), U256::zero());
}

#[test]
fn every_independent_deployment_pin_rejects_for_both_methods() {
    let (deployment, statement, boundary) = fixture();
    let proof = unverified_frame(0);
    let mutations: &[fn(&mut DeploymentDescriptor)] = &[
        |d| d.schema_version += 1, |d| d.source_network += 1,
        |d| d.source_pool += 1, |d| d.transaction_version += 1,
        |d| d.consensus_branch ^= 1, |d| d.financial_program[0] ^= 1,
        |d| d.origin_program[0] ^= 1, |d| d.source_acceptance_program[0] ^= 1,
        |d| d.source_policy_id[0] ^= 1, |d| d.target_chain_id += 1,
        |d| d.obligation[0] ^= 1, |d| d.obligation_runtime_code[0] ^= 1,
        |d| d.verifier[0] ^= 1, |d| d.verifier_runtime_code[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = deployment;
        mutate(&mut changed);
        rejects(build_fund_and_arm_call(&changed, &statement, &boundary,
            &proof, &proof, &proof), CallBuildError::WrongDeployment);
        rejects(build_resolve_call(&changed, &statement, &boundary,
            [42; 20], Resolution::Recovery, 0, &proof, &proof), CallBuildError::WrongDeployment);
    }
}

#[test]
fn statement_cannot_substitute_programs_policy_or_source_pins_under_valid_digest() {
    let (deployment, statement, boundary) = fixture();
    let proof = unverified_frame(0);
    let mutations: &[fn(&mut Statement)] = &[
        |s| s.schema_version += 1, |s| s.source_network += 1,
        |s| s.source_pool += 1, |s| s.transaction_version += 1,
        |s| s.consensus_branch ^= 1, |s| s.financial_program[0] ^= 1,
        |s| s.origin_program[0] ^= 1, |s| s.source_acceptance_program[0] ^= 1,
        |s| s.source_policy_id[0] ^= 1, |s| s.target_chain_id += 1,
        |s| s.obligation[0] ^= 1, |s| s.deployment_descriptor[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = statement;
        mutate(&mut changed);
        rejects(build_fund_and_arm_call(&deployment, &changed, &boundary,
            &proof, &proof, &proof), CallBuildError::WrongDeployment);
        rejects(build_resolve_call(&deployment, &changed, &boundary,
            [42; 20], Resolution::Recovery, 0, &proof, &proof), CallBuildError::WrongDeployment);
    }
}

#[test]
fn invalid_financial_statement_boundary_sender_and_resolution_reject() {
    let (deployment, statement, boundary) = fixture();
    let proof = unverified_frame(0);
    for mutate in [
        (|s: &mut Statement| s.d.fill(0)) as fn(&mut Statement),
        |s| s.payer.fill(0), |s| s.u_payee = s.s_refund,
        |s| s.joint_value += 1, |s| s.fees[1] = s.fee_caps[1] + 1,
        |s| s.expiries[0] = s.expiries[1],
    ] {
        let mut changed = statement;
        mutate(&mut changed);
        rejects(build_fund_and_arm_call(&deployment, &changed, &boundary,
            &proof, &proof, &proof), CallBuildError::InvalidStatement);
        rejects(build_resolve_call(&deployment, &changed, &boundary,
            [42; 20], Resolution::Recovery, 0, &proof, &proof), CallBuildError::InvalidStatement);
    }
    for mutate in [
        (|b: &mut SourceBoundary| b.height = 0) as fn(&mut SourceBoundary),
        |b| b.height = 4465026, |b| b.block_hash.fill(0),
        |b| b.cumulative_work.fill(0), |b| b.ledger_journal_digest.fill(0),
    ] {
        let mut changed = boundary;
        mutate(&mut changed);
        rejects(build_fund_and_arm_call(&deployment, &statement, &changed,
            &proof, &proof, &proof), CallBuildError::InvalidBoundary);
        rejects(build_resolve_call(&deployment, &statement, &changed,
            [42; 20], Resolution::Recovery, 0, &proof, &proof), CallBuildError::InvalidBoundary);
    }
    rejects(build_resolve_call(&deployment, &statement, &boundary,
        [0; 20], Resolution::Recovery, 0, &proof, &proof), CallBuildError::InvalidSender);
    for (outcome, cnet) in [
        (Resolution::Completion, 0), (Resolution::Completion, statement.a + 1),
        (Resolution::Recovery, 1), (Resolution::Recovery, u64::MAX),
    ] {
        rejects(build_resolve_call(&deployment, &statement, &boundary,
            [42; 20], outcome, cnet, &proof, &proof), CallBuildError::InvalidResolution);
    }
}

#[test]
fn malformed_public_proof_headers_and_nonce_reject_in_every_proof_position() {
    let (deployment, statement, boundary) = fixture();
    let proof = unverified_frame(0);
    let mut malformed = vec![vec![], proof[..355].to_vec()];
    let mut trailing = proof.clone();
    trailing.push(0);
    malformed.push(trailing);
    for byte in [0, 4, 35, 36, 67] {
        let mut changed = proof.clone();
        changed[byte] ^= 1;
        malformed.push(changed);
    }
    for nonce in [
        hex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"),
        vec![0xff; 32],
    ] {
        let mut changed = proof.clone();
        changed[68..100].copy_from_slice(&nonce);
        malformed.push(changed);
    }
    for changed in malformed {
        for position in 0..3 {
            let mut proofs = [&proof[..]; 3];
            proofs[position] = &changed;
            rejects(build_fund_and_arm_call(&deployment, &statement, &boundary,
                proofs[0], proofs[1], proofs[2]), CallBuildError::InvalidProofFrame);
        }
        for position in 0..2 {
            let mut proofs = [&proof[..]; 2];
            proofs[position] = &changed;
            rejects(build_resolve_call(&deployment, &statement, &boundary,
                [42; 20], Resolution::Recovery, 0, proofs[0], proofs[1]),
                CallBuildError::InvalidProofFrame);
        }
    }
}

#[test]
fn program_and_nonce_scalar_boundaries_are_not_reduced_and_pairing_is_not_checked() {
    let (deployment, statement, boundary) = fixture();
    let scalar = hex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    for program in 0..3 {
        let mut changed_deployment = deployment;
        let mut changed_statement = statement;
        match program {
            0 => { changed_deployment.financial_program.copy_from_slice(&scalar);
                changed_statement.financial_program.copy_from_slice(&scalar); }
            1 => { changed_deployment.origin_program.copy_from_slice(&scalar);
                changed_statement.origin_program.copy_from_slice(&scalar); }
            _ => { changed_deployment.source_acceptance_program.copy_from_slice(&scalar);
                changed_statement.source_acceptance_program.copy_from_slice(&scalar); }
        }
        changed_statement.deployment_descriptor = changed_deployment.digest();
        let proof = unverified_frame(0);
        rejects(build_fund_and_arm_call(&changed_deployment, &changed_statement, &boundary,
            &proof, &proof, &proof), CallBuildError::InvalidProgram);
        rejects(build_resolve_call(&changed_deployment, &changed_statement, &boundary,
            [42; 20], Resolution::Recovery, 0, &proof, &proof), CallBuildError::InvalidProgram);
    }
    let mut below = scalar;
    below[31] -= 1;
    let mut changed_deployment = deployment;
    changed_deployment.financial_program.copy_from_slice(&below);
    let mut changed_statement = statement;
    changed_statement.financial_program.copy_from_slice(&below);
    changed_statement.deployment_descriptor = changed_deployment.digest();
    let mut proof = unverified_frame(0);
    proof[68..100].copy_from_slice(&below);
    // Arbitrary pairing words remain verbatim, not rejected or called valid.
    proof[100..].fill(0xff);
    let call = build_fund_and_arm_call(&changed_deployment, &changed_statement, &boundary,
        &proof, &proof, &proof).unwrap();
    assert_eq!(bytes_arg(call.data(), 2, 992, 356), proof);
    let call = build_resolve_call(&changed_deployment, &changed_statement, &boundary,
        [42; 20], Resolution::Recovery, 0, &proof, &proof).unwrap();
    assert_eq!(bytes_arg(call.data(), 4, 1024, 356), proof);
}

#[test]
fn matching_digest_does_not_allow_invalid_independent_deployment() {
    let (deployment, statement, boundary) = fixture();
    let proof = unverified_frame(0);
    let mutations: &[fn(&mut DeploymentDescriptor)] = &[
        |d| d.obligation_runtime_code.fill(0), |d| d.verifier.fill(0),
        |d| d.verifier_runtime_code.fill(0),
    ];
    for mutate in mutations {
        let mut changed_deployment = deployment;
        mutate(&mut changed_deployment);
        let mut changed_statement = statement;
        changed_statement.deployment_descriptor = changed_deployment.digest();
        rejects(build_fund_and_arm_call(&changed_deployment, &changed_statement, &boundary,
            &proof, &proof, &proof), CallBuildError::WrongDeployment);
        rejects(build_resolve_call(&changed_deployment, &changed_statement, &boundary,
            [42; 20], Resolution::Recovery, 0, &proof, &proof), CallBuildError::WrongDeployment);
    }
}
