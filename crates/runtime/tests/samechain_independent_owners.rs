//! Controlled native Fill2 construction in two genuinely separate owner processes.
//! Each child generates/retains its own policy, salt, signing seed and openings.
//! Only bounded public descriptors/execution/leaves cross unnamed local sockets.
//! Mathematical membership and native signatures are not admitted backing, proof,
//! durable recovery, funded execution, strict GD2 or a production peer protocol.
#![cfg(target_os = "linux")]

use ed25519_dalek::{Signer, SigningKey};
use primitive_types::{U256, U512};
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::{fd::{AsFd, OwnedFd}, unix::net::UnixStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
use ziquid_proofs::{
    artifacts::owner::OwnerInput,
    samechain::{
        MerkleMembership, NoteOpening, OrderState, OwnerWitness, RelationError,
        decrypt_output, fill_consent_message, review_owner_fill, verify_owner_relation,
    },
};
use ziquid_protocol::samechain::{
    Action, Asset, Deployment, FeePolicy, FeeRule, InputDescriptor, MAX_OUTPUTS,
    MAX_PACKET_BYTES, OrderPolicy, OutputDescriptor, OwnerJournal, PublicPacket, Role,
    SamechainError, fill::{FillExecution, aggregate_commitment, owner_leaf},
    tree::NoteTree, validate_pair,
};
use ziquid_runtime::samechain::preparation::prepare_fill_outputs;

type Result<T, E = &'static str> = std::result::Result<T, E>;
const ROLE_ENV: &str = "Z2Z_CONTROLLED_FILL2_OWNER_ROLE";
const TIME_LIMIT: Duration = Duration::from_secs(30);
const EXECUTION: u8 = 1;
const REFUSED: u8 = 2;
const INPUT: u8 = 3;
const OUTPUT_COUNT: u8 = 4;
const OUTPUT: u8 = 5;
const BODY: u8 = 6;
const LEAF: u8 = 7;
const LEAVES: u8 = 8;
const REVIEW_SELECTION: u8 = 9;
const PACKET: u8 = 10;
const JOURNAL: u8 = 11;
const CHECKS: u8 = 12;
const ADVANCE: u8 = 13;
const EXPIRY: u8 = 14;

fn deployment() -> Deployment {
    Deployment { chain_id: 31337, authority: [1; 20], authority_code: [2; 32],
        verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1 }
}

// Each child independently chooses these public execution atoms before entropy,
// output preparation or leaf publication. This is a controlled local approval.
fn local_approval() -> FillExecution {
    FillExecution { asset_a: Asset::Native, asset_b: Asset::Token([7; 20]),
        sell_a: U256::from(40), sell_b: U256::from(50) }
}

fn approve(selection: &FillExecution) -> Result<FillExecution> {
    selection.validate().map_err(|_| "public execution invalid")?;
    let approved = local_approval();
    if *selection != approved { return Err("public execution not locally approved"); }
    Ok(approved)
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() { return Err("controlled owner deadline exceeded"); }
    Ok(duration)
}

fn read_exact(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?)).map_err(|_| "socket timeout unavailable")?;
        match stream.read(bytes) {
            Ok(0) => return Err("public owner channel closed"),
            Ok(count) => { bytes = &mut bytes[count..]; }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("public owner channel read rejected"),
        }
    }
    Ok(())
}

fn write_all(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?)).map_err(|_| "socket timeout unavailable")?;
        match stream.write(bytes) {
            Ok(0) => return Err("public owner channel closed"),
            Ok(count) => { bytes = &bytes[count..]; }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("public owner channel write rejected"),
        }
    }
    Ok(())
}

fn send(stream: &mut UnixStream, tag: u8, bytes: &[u8], deadline: Instant) -> Result<()> {
    if bytes.len() > MAX_PACKET_BYTES { return Err("public phase exceeds bound"); }
    let mut header = [0; 5];
    header[0] = tag;
    header[1..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
    write_all(stream, &header, deadline)?;
    write_all(stream, bytes, deadline)
}

fn receive(stream: &mut UnixStream, expected: u8, deadline: Instant) -> Result<Vec<u8>> {
    let mut header = [0; 5];
    read_exact(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header[1..].try_into().map_err(|_| "phase header invalid")?) as usize;
    if header[0] != expected || length > MAX_PACKET_BYTES { return Err("public phase rejected"); }
    let mut bytes = vec![0; length];
    read_exact(stream, &mut bytes, deadline)?;
    Ok(bytes)
}

// Every successful spawn is immediately owned. Errors/panics close its channel,
// kill and reap that direct child; neither child spawns descendants or IO threads.
struct OwnerProcess { child: Child, channel: UnixStream }

impl OwnerProcess {
    fn spawn(role: Role) -> Result<Self> {
        let (channel, child_channel) = UnixStream::pair().map_err(|_| "owner socket unavailable")?;
        let child = Command::new(std::env::current_exe().map_err(|_| "test executable unavailable")?)
            .args(["--exact", "owner_process", "--ignored", "--nocapture", "--test-threads=1"])
            .env_clear().env(ROLE_ENV, if role == Role::A { "a" } else { "b" })
            .stdin(Stdio::from(OwnedFd::from(child_channel)))
            .stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().map_err(|_| "controlled owner spawn rejected")?;
        Ok(Self { child, channel })
    }

    fn finish(&mut self, deadline: Instant) -> Result<()> {
        self.channel.shutdown(Shutdown::Both).map_err(|_| "owner channel shutdown rejected")?;
        loop {
            if let Some(status) = self.child.try_wait().map_err(|_| "owner reap rejected")? {
                return if status.success() { Ok(()) } else { Err("controlled owner failed") };
            }
            remaining(deadline)?;
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Drop for OwnerProcess {
    fn drop(&mut self) {
        let _ = self.channel.shutdown(Shutdown::Both);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn entropy(bytes: &mut [u8]) -> Result<()> {
    getrandom::fill(bytes).map_err(|_| "controlled entropy unavailable")?;
    if bytes.iter().all(|byte| *byte == 0) { return Err("controlled entropy invalid"); }
    Ok(())
}

fn descriptor(owner: &OwnerWitness) -> Result<InputDescriptor> {
    let order = owner.input.order.as_ref().ok_or("local order unavailable")?;
    let commitment = owner.input.commitment().map_err(|_| "local input invalid")?;
    Ok(InputDescriptor { commitment,
        root: owner.membership.root(&owner.input.deployment_digest, &commitment),
        tree_id: owner.membership.tree_id, index: owner.membership.index,
        order_id: order.id, generation: order.generation,
        nullifier: owner.input.nullifier().map_err(|_| "local input invalid")?,
        owner_key: owner.input.owner_key })
}

fn insertion(owner: &mut OwnerWitness, tree: &mut NoteTree) -> Result<()> {
    let path = tree.append(owner.input.commitment().map_err(|_| "local input invalid")?)
        .map_err(|_| "mathematical tree insertion rejected")?;
    owner.membership = MerkleMembership { tree_id: path.tree_id, index: path.index, siblings: path.siblings };
    Ok(())
}

fn own_witness(role: Role, execution: FillExecution) -> Result<OwnerWitness> {
    let deployment = deployment();
    let (sell, buy) = match role {
        Role::A => (execution.asset_a, execution.asset_b),
        Role::B => (execution.asset_b, execution.asset_a),
    };
    let mut private_policy_entropy = Zeroizing::new([0; 32]);
    entropy(&mut private_policy_entropy[..])?;
    // Disjoint private ratio/cap ranges ensure different authentic policies,
    // without the supervisor ever receiving either policy or policy entropy.
    let (minimum, cap) = match role {
        Role::A => (80 + private_policy_entropy[0] % 10, 1 + private_policy_entropy[1] % 4),
        Role::B => (65 + private_policy_entropy[0] % 10, 5 + private_policy_entropy[1] % 4),
    };
    let policy = OrderPolicy { sell_asset: sell, buy_asset: buy,
        min_buy_num: U256::from(minimum), min_sell_den: U256::from(100),
        fee_policy: FeePolicy { entries: vec![FeeRule { payer: role, asset: buy,
            beneficiary: [8 + role as u8; 20], max_atoms: U256::from(cap) }] } };
    // Install all erasing owners before filling any salt/seed/input secrets.
    // This incomplete packet is never encoded, hashed or reviewed.
    let mut owner = OwnerWitness {
        packet: PublicPacket { deployment, inputs: [InputDescriptor { commitment: [0; 32],
            root: [0; 32], tree_id: 0, index: 0, order_id: [0; 32], generation: 0,
            nullifier: [0; 32], owner_key: [0; 32] }; 2],
            outputs: Vec::new(), expiry: 500, terms_commitment: [0; 32] },
        execution, leaves: [[0; 32]; 2], own_salt: [0; 32], role, owner_seed: [0; 32],
        input: NoteOpening { deployment_digest: deployment.digest().map_err(|_| "local deployment invalid")?,
            owner_key: [0; 32], nf_key: [0; 32], nonce: [0; 32], salt: [0; 32], asset: sell,
            value: U256::from(if role == Role::A { 105 } else { 100 }),
            order: Some(OrderState { id: [0; 32], generation: 7,
                remaining_sell: U256::from(100), policy }) },
        membership: MerkleMembership { tree_id: 0, index: 0, siblings: [[0; 32]; 32] },
        consent: [0; 64], owned_outputs: Vec::new(),
    };
    entropy(&mut owner.owner_seed)?;
    owner.input.owner_key = SigningKey::from_bytes(&owner.owner_seed).verifying_key().to_bytes();
    entropy(&mut owner.own_salt)?;
    entropy(&mut owner.input.nf_key)?;
    entropy(&mut owner.input.nonce)?;
    entropy(&mut owner.input.salt)?;
    entropy(&mut owner.input.order.as_mut().ok_or("local order unavailable")?.id)?;
    owner.input.validate().map_err(|_| "local input invalid")?;
    Ok(owner)
}

fn public_body(stream: &mut UnixStream, owner: &mut OwnerWitness,
    approved: &FillExecution, round: u8, deadline: Instant) -> Result<()> {
    // Only parameters from the independently approved E reach preparation.
    let (sold, credit, buy) = match owner.role {
        Role::A => (approved.sell_a, approved.sell_b, approved.asset_b),
        Role::B => (approved.sell_b, approved.sell_a, approved.asset_a),
    };
    let order_id = owner.input.order.as_ref().ok_or("local order unavailable")?.id;
    let fees = [OutputDescriptor::Fee { payer: owner.role, asset: buy,
        recipient: [8 + owner.role as u8; 20], amount: U256::from(1 + owner.role as u8) }];
    let mut prepared = prepare_fill_outputs(&owner.input, &deployment(), order_id,
        owner.role, sold, credit, &fees).map_err(|_| "local output preparation rejected")?;
    owner.owned_outputs = std::mem::take(&mut prepared.openings);
    let input = descriptor(owner)?;
    send(stream, INPUT, &input.encode().map_err(|_| "public input encoding rejected")?, deadline)?;
    let count = prepared.descriptors.len() + fees.len();
    send(stream, OUTPUT_COUNT, &(count as u32).to_be_bytes(), deadline)?;
    for output in prepared.descriptors.iter().chain(&fees) {
        send(stream, OUTPUT, &output.encode().map_err(|_| "public output encoding rejected")?, deadline)?;
    }
    let selected_deployment = Deployment::decode(&receive(stream, BODY, deadline)?)
        .map_err(|_| "public body deployment invalid")?;
    let a = InputDescriptor::decode(&receive(stream, INPUT, deadline)?)
        .map_err(|_| "public body input invalid")?;
    let b = InputDescriptor::decode(&receive(stream, INPUT, deadline)?)
        .map_err(|_| "public body input invalid")?;
    let output_count = receive(stream, OUTPUT_COUNT, deadline)?;
    let output_count = u32::from_be_bytes(output_count.as_slice().try_into()
        .map_err(|_| "public body output count invalid")?) as usize;
    if output_count == 0 || output_count > MAX_OUTPUTS { return Err("public body output count invalid"); }
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(OutputDescriptor::decode(&receive(stream, OUTPUT, deadline)?)
            .map_err(|_| "public body output invalid")?);
    }
    let expiry = receive(stream, EXPIRY, deadline)?;
    let expiry = u64::from_be_bytes(expiry.as_slice().try_into().map_err(|_| "public body expiry invalid")?);
    let selected_body = PublicPacket { deployment: selected_deployment, inputs: [a, b],
        outputs, expiry, terms_commitment: [0; 32] };
    // Existing canonical B validation permits only C=0 during construction;
    // the supervisor never supplies a stand-in aggregate or private context.
    approved.context_digest(&selected_body).map_err(|_| "public body invalid")?;
    if selected_body.deployment != deployment() || selected_body.expiry != 500 + u64::from(round)
        || selected_body.inputs[owner.role.index()] != input
    { return Err("selected public body scope rejected"); }
    let mut expected_outputs = prepared.descriptors.iter().chain(&fees);
    let mut own_count = 0;
    for (manifest_index, actual) in selected_body.outputs.iter().enumerate()
        .filter(|(_, output)| output.role() == owner.role) {
        let expected = expected_outputs.next().ok_or("selected own manifest rejected")?;
        if actual != expected { return Err("selected own manifest rejected"); }
        if own_count < prepared.descriptors.len() {
            let opening = owner.owned_outputs.get_mut(own_count)
                .ok_or("selected own opening unavailable")?;
            opening.manifest_index = manifest_index as u32;
        }
        own_count += 1;
    }
    if own_count != count || expected_outputs.next().is_some() { return Err("selected own manifest rejected"); }
    owner.packet = selected_body;
    owner.execution = *approved;
    Ok(())
}

fn complete_owner(stream: &mut UnixStream, owner: &mut OwnerWitness,
    approved: &FillExecution, round: u8, deadline: Instant) -> Result<()> {
    let policy = &owner.input.order.as_ref().ok_or("local order unavailable")?.policy;
    let leaf = owner_leaf(&owner.packet, approved, owner.role, policy, &owner.own_salt)
        .map_err(|_| "local leaf rejected")?;
    send(stream, LEAF, &leaf, deadline)?;
    let leaves = receive(stream, LEAVES, deadline)?;
    if leaves.len() != 64 { return Err("public leaf pair invalid"); }
    owner.leaves = [leaves[..32].try_into().map_err(|_| "public leaf invalid")?,
        leaves[32..].try_into().map_err(|_| "public leaf invalid")?];
    if owner.leaves[owner.role.index()] != leaf { return Err("selected own leaf replaced"); }
    owner.packet.terms_commitment = aggregate_commitment(&owner.packet, approved, &owner.leaves)
        .map_err(|_| "local aggregate rejected")?;
    let wrong_selection = FillExecution::decode(&receive(stream, REVIEW_SELECTION, deadline)?)
        .map_err(|_| "wrong public selection encoding rejected")?;
    let (sold, credit) = match owner.role {
        Role::A => (wrong_selection.sell_a, wrong_selection.sell_b),
        Role::B => (wrong_selection.sell_b, wrong_selection.sell_a),
    };
    let policy = &owner.input.order.as_ref().ok_or("local order unavailable")?.policy;
    let net = U512::from(credit).checked_sub(U512::from(1 + owner.role as u8))
        .ok_or("wrong selection underflow")?;
    if wrong_selection == *approved || net * U512::from(policy.min_sell_den)
        < sold.full_mul(policy.min_buy_num) { return Err("wrong selection is not a limit-valid negative"); }
    let order_id = owner.input.order.as_ref().ok_or("local order unavailable")?.id;
    if review_owner_fill(&owner.packet, owner, &deployment(), order_id, owner.role, &wrong_selection)
        != Err(RelationError::Protocol(SamechainError::OpeningMismatch))
    { return Err("independent wrong execution was not rejected"); }
    owner.consent = [0; 64];
    let message = review_owner_fill(&owner.packet, owner, &deployment(), order_id, owner.role, approved)
        .map_err(|_| "local unsigned review rejected")?;
    if message != fill_consent_message(&owner.packet, owner.role).map_err(|_| "consent framing rejected")?
        || verify_owner_relation(&owner.packet, owner) != Err(RelationError::Signature)
    { return Err("unsigned review and signed check conflated"); }
    owner.consent = SigningKey::from_bytes(&owner.owner_seed).sign(&message).to_bytes();
    let journal = verify_owner_relation(&owner.packet, owner).map_err(|_| "native owner predicate rejected")?;
    let private = OwnerInput::Fill(owner).encode_private().map_err(|_| "private owner ABI rejected")?;
    let encoded = owner.encode().map_err(|_| "private witness encoding rejected")?;
    if private.first() != Some(&0) || private[1..] != encoded[..]
        || OwnerInput::Fill(owner).expected_journal().map_err(|_| "owner journal rejected")?
            != journal.encode().map_err(|_| "public journal encoding rejected")?
    { return Err("new private owner ABI mismatch"); }
    // These are public phase results, not witnesses, consent, policies or salts.
    send(stream, PACKET, &owner.packet.encode().map_err(|_| "public packet encoding rejected")?, deadline)?;
    send(stream, JOURNAL, &journal.encode().map_err(|_| "public journal encoding rejected")?, deadline)?;
    send(stream, CHECKS, &[round, 1, 1], deadline)
}

fn successor(owner: &mut OwnerWitness, tree: &mut NoteTree) -> Result<()> {
    let opening = owner.owned_outputs.iter().find(|opening| opening.note.order.is_some())
        .ok_or("partial fill successor unavailable")?;
    let output = owner.packet.outputs.get(opening.manifest_index as usize)
        .ok_or("successor descriptor unavailable")?;
    let recovered = decrypt_output(output, &opening.recovery_key,
        &owner.input.deployment_digest, &owner.input.owner_key).map_err(|_| "successor decrypt rejected")?;
    let original = owner.input.order.as_ref().ok_or("local order unavailable")?;
    let next = recovered.order.as_ref().ok_or("successor order unavailable")?;
    let sold = if owner.role == Role::A { owner.execution.sell_a } else { owner.execution.sell_b };
    if recovered != opening.note || next.id != original.id || next.generation != 8
        || next.remaining_sell != original.remaining_sell - sold || next.policy != original.policy
    { return Err("partial successor mismatch"); }
    owner.input = recovered;
    owner.owned_outputs.clear();
    owner.consent = [0; 64];
    entropy(&mut owner.own_salt)?;
    insertion(owner, tree)
}

fn run_owner(role: Role) -> Result<()> {
    let fd = std::io::stdin().as_fd().try_clone_to_owned().map_err(|_| "public owner socket unavailable")?;
    let mut stream = UnixStream::from(fd);
    if !stream.peer_addr().map_err(|_| "public owner socket invalid")?.is_unnamed()
        || !stream.local_addr().map_err(|_| "public owner socket invalid")?.is_unnamed()
    { return Err("public owner socket invalid"); }
    let deadline = Instant::now() + TIME_LIMIT;
    // Refuse an independently sent, limit-plausible but unapproved E before
    // generating any private capability, output or opaque leaf.
    let wrong = FillExecution::decode(&receive(&mut stream, EXECUTION, deadline)?)
        .map_err(|_| "public execution invalid")?;
    if approve(&wrong).is_ok() { return Err("unapproved execution accepted before preparation"); }
    send(&mut stream, REFUSED, &[], deadline)?;
    let selected = FillExecution::decode(&receive(&mut stream, EXECUTION, deadline)?)
        .map_err(|_| "public execution invalid")?;
    let approved = approve(&selected)?;
    let mut owner = own_witness(role, approved)?;
    let mut tree = NoteTree::new(owner.input.deployment_digest, 90 + role as u32)
        .map_err(|_| "mathematical tree unavailable")?;
    insertion(&mut owner, &mut tree)?;
    for round in 0..2 {
        if round != 0 {
            if !receive(&mut stream, ADVANCE, deadline)?.is_empty() { return Err("advance phase invalid"); }
            let selected = FillExecution::decode(&receive(&mut stream, EXECUTION, deadline)?)
                .map_err(|_| "public execution invalid")?;
            if approve(&selected)? != approved { return Err("successor execution not independently approved"); }
            successor(&mut owner, &mut tree)?;
        }
        public_body(&mut stream, &mut owner, &approved, round, deadline)?;
        complete_owner(&mut stream, &mut owner, &approved, round, deadline)?;
    }
    Ok(())
}

#[test]
#[ignore = "private child entrypoint; invoked only by the public-process supervisor"]
fn owner_process() {
    let role = match std::env::var(ROLE_ENV).as_deref() {
        Ok("a") => Role::A,
        Ok("b") => Role::B,
        Err(std::env::VarError::NotPresent) => panic!("controlled owner supervisor missing"),
        _ => panic!("controlled public owner role invalid"),
    };
    assert_eq!(run_owner(role), Ok(()), "controlled owner public construction rejected");
}

fn part(process: &mut OwnerProcess, role: Role, deadline: Instant) -> Result<(InputDescriptor, Vec<OutputDescriptor>)> {
    let input = InputDescriptor::decode(&receive(&mut process.channel, INPUT, deadline)?)
        .map_err(|_| "public input invalid")?;
    let count = receive(&mut process.channel, OUTPUT_COUNT, deadline)?;
    let count = u32::from_be_bytes(count.as_slice().try_into().map_err(|_| "public output count invalid")?) as usize;
    if count == 0 || count > MAX_OUTPUTS { return Err("public output count exceeds bound"); }
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        let output = OutputDescriptor::decode(&receive(&mut process.channel, OUTPUT, deadline)?)
            .map_err(|_| "public output invalid")?;
        if output.role() != role { return Err("public output role invalid"); }
        outputs.push(output);
    }
    Ok((input, outputs))
}

fn qualify() -> Result<()> {
    let deadline = Instant::now() + TIME_LIMIT;
    let mut owners = [OwnerProcess::spawn(Role::A)?, OwnerProcess::spawn(Role::B)?];
    if owners[0].child.id() == owners[1].child.id() { return Err("owner processes not independent"); }
    let approved = local_approval();
    let mut wrong = approved;
    wrong.sell_a = U256::from(39);
    let approved_frame = approved.encode().map_err(|_| "public execution invalid")?;
    let wrong_frame = wrong.encode().map_err(|_| "public execution invalid")?;
    for owner in &mut owners {
        send(&mut owner.channel, EXECUTION, &wrong_frame, deadline)?;
    }
    for owner in &mut owners {
        if !receive(&mut owner.channel, REFUSED, deadline)?.is_empty() { return Err("approval refusal invalid"); }
        send(&mut owner.channel, EXECUTION, &approved_frame, deadline)?;
    }
    let mut previous: Option<PublicPacket> = None;
    for round in 0..2 {
        if round != 0 {
            for owner in &mut owners {
                send(&mut owner.channel, ADVANCE, &[], deadline)?;
                send(&mut owner.channel, EXECUTION, &approved_frame, deadline)?;
            }
        }
        let (a, mut a_outputs) = part(&mut owners[0], Role::A, deadline)?;
        let (b, b_outputs) = part(&mut owners[1], Role::B, deadline)?;
        if a.owner_key == b.owner_key || a.order_id == b.order_id || a.nullifier == b.nullifier
            || a.commitment == b.commitment || a.generation != 7 + u64::from(round)
            || b.generation != 7 + u64::from(round) { return Err("independent public input identities invalid"); }
        if let Some(previous) = &previous {
            for (role, input) in [(Role::A, a), (Role::B, b)] {
                if !previous.outputs.iter().any(|output| matches!(output,
                    OutputDescriptor::Note { role: prior_role, commitment, .. }
                        if *prior_role == role && *commitment == input.commitment))
                { return Err("second fill does not consume the prepared successor"); }
            }
        }
        if a_outputs.len() + b_outputs.len() > MAX_OUTPUTS { return Err("public manifest exceeds bound"); }
        a_outputs.extend(b_outputs);
        let mut packet = PublicPacket { deployment: deployment(), inputs: [a, b],
            outputs: a_outputs, expiry: 500 + u64::from(round), terms_commitment: [0; 32] };
        approved.context_digest(&packet).map_err(|_| "public body invalid")?;
        // B crosses as bounded canonical existing descriptor frames; no C or
        // unsalted D is published, and no private policy/opening is serialized.
        for owner in &mut owners {
            send(&mut owner.channel, BODY, &packet.deployment.encode()
                .map_err(|_| "public deployment invalid")?, deadline)?;
            for input in &packet.inputs {
                send(&mut owner.channel, INPUT, &input.encode()
                    .map_err(|_| "public input invalid")?, deadline)?;
            }
            send(&mut owner.channel, OUTPUT_COUNT, &(packet.outputs.len() as u32).to_be_bytes(), deadline)?;
            for output in &packet.outputs {
                send(&mut owner.channel, OUTPUT, &output.encode()
                    .map_err(|_| "public output invalid")?, deadline)?;
            }
            send(&mut owner.channel, EXPIRY, &packet.expiry.to_be_bytes(), deadline)?;
        }
        let mut leaves = [[0; 32]; 2];
        for (index, owner) in owners.iter_mut().enumerate() {
            leaves[index] = receive(&mut owner.channel, LEAF, deadline)?.as_slice().try_into()
                .map_err(|_| "public leaf invalid")?;
        }
        if leaves[0] == leaves[1] || leaves.contains(&[0; 32]) { return Err("independent leaves invalid"); }
        let mut public_leaves = [0; 64];
        public_leaves[..32].copy_from_slice(&leaves[0]);
        public_leaves[32..].copy_from_slice(&leaves[1]);
        packet.terms_commitment = aggregate_commitment(&packet, &approved, &leaves)
            .map_err(|_| "public aggregate invalid")?;
        for owner in &mut owners {
            send(&mut owner.channel, LEAVES, &public_leaves, deadline)?;
            send(&mut owner.channel, REVIEW_SELECTION, &wrong_frame, deadline)?;
        }
        let expected_packet = packet.encode().map_err(|_| "public packet invalid")?;
        let expected_digest = packet.digest().map_err(|_| "public digest invalid")?;
        let mut journals = Vec::with_capacity(2);
        for (index, owner) in owners.iter_mut().enumerate() {
            if receive(&mut owner.channel, PACKET, deadline)? != expected_packet { return Err("independent packets differ"); }
            let journal = OwnerJournal::decode(&receive(&mut owner.channel, JOURNAL, deadline)?)
                .map_err(|_| "public owner journal invalid")?;
            if journal.role.index() != index || journal.action != Action::Fill || journal.relation_version != 2
                || journal.packet_digest != expected_digest
            { return Err("independent owner journal scope invalid"); }
            if receive(&mut owner.channel, CHECKS, deadline)? != [round, 1, 1] {
                return Err("independent selection or ABI qualification missing");
            }
            journals.push(journal);
        }
        if journals[0] == journals[1] { return Err("distinct owner journals missing"); }
        validate_pair(&packet, &journals[0], &journals[1]).map_err(|_| "native paired binding invalid")?;
        previous = Some(packet);
    }
    for owner in &mut owners { owner.finish(deadline)?; }
    Ok(())
}

#[test]
fn two_independent_owners_construct_partial_and_successor_using_public_frames_only() {
    assert_eq!(qualify(), Ok(()), "independent owner-process native qualification rejected");
}
