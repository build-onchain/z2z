//! Fixture-only enrolled ordinary-business producers. No source/native consensus claims.
use super::{Error, Result, target::Section};
use ed25519_dalek::{Signer, SigningKey};
use ziquid_zcash::custody::ReservedNativeInput;
use crate::market::ledger::*;
use ziquid_protocol::market::*;

pub fn key() -> Result<SigningKey> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::KeyBootstrap)?;
    let key = SigningKey::from_bytes(&bytes);
    bytes.fill(0);
    Ok(key)
}

pub fn target(
    section: &Section,
    decision: Decision,
    observer: &SigningKey,
) -> Result<SignedTargetFacts> {
    if section.text("environment")? != "LocalFixture"
        || section.id("pair_head")? != decision.next_head
        || section.number("generation")? != decision.operation.generation
        || section.number("packet_bytes")? > 1232
    {
        return Err(Error::TargetReceipt);
    }
    let transaction: [u8; 64] = section.array("transaction")?;
    let transaction_id = sha256(&transaction);
    if transaction_id != section.id("transaction_id")? {
        return Err(Error::TargetReceipt);
    }
    let facts = TargetFacts {
        decision,
        observation: ChainObservation {
            environment: ObservationEnvironment::LocalFixture,
            operation: decision.operation.id().map_err(|_| Error::TargetReceipt)?,
            transaction: transaction_id,
            slot: section.number("slot")?,
            commitment: ChainCommitment::Finalized,
            effects: decision.operation.effects,
        },
    };
    Ok(SignedTargetFacts {
        signature: observer.sign(&facts.signing_bytes()?).to_bytes(),
        facts,
    })
}

pub fn funding(
    policy: &PairPolicy,
    (source_key, inventory_key): (&SigningKey, &SigningKey),
    claimant: &SigningKey,
    input: &ReservedNativeInput,
    credit: Id,
) -> Result<LedgerCommand> {
    if policy.environment != ObservationEnvironment::LocalFixture {
        return Err(Error::Configuration);
    }
    let occurrence = input.source_occurrence;
    let source = SourceFacts {
        domain: policy.domain,
        provenance: ObservationEnvironment::LocalFixture,
        occurrence,
        receiver: policy.receiver,
        value: input.value,
        block: [40; 32],
        height: 100,
        confirmations: policy.minimum_confirmations,
        history_anchor: policy.history_anchor,
        policy: policy.source_policy,
        effect: SourceEffect::Deposit {
            claimant: claimant.verifying_key().to_bytes(),
            credit_intent: credit,
        },
    };
    let mut claim = FundingClaim {
        domain: policy.domain,
        occurrence,
        claimant: claimant.verifying_key().to_bytes(),
        receiver: policy.receiver,
        value: input.value,
        block_policy: policy.source_policy,
        inventory_note: input.inventory_note,
        evidence_digest: source.digest()?,
        credit_intent: credit,
        authorization: [0; 64],
    };
    claim.authorization = claimant
        .sign(&claim.signing_bytes().map_err(|_| Error::Input)?)
        .to_bytes();
    let inventory = inventory(
        policy,
        inventory_key,
        input,
        InventoryOrigin::Deposit,
        policy.inventory_scope,
    )?;
    Ok(LedgerCommand::IssueCredit {
        claim,
        source: SignedSourceFacts {
            signature: source_key.sign(&source.signing_bytes()?).to_bytes(),
            facts: source,
        },
        inventory,
    })
}

pub fn inventory(
    policy: &PairPolicy,
    producer: &SigningKey,
    input: &ReservedNativeInput,
    origin: InventoryOrigin,
    scope: Id,
) -> Result<SignedInventoryFacts> {
    let facts = InventoryFacts {
        domain: policy.domain,
        provenance: ObservationEnvironment::LocalFixture,
        note: input.inventory_note,
        occurrence: input.source_occurrence,
        note_commitment: input.note_commitment,
        nullifier: input.nullifier,
        receiver: policy.receiver,
        value: input.value,
        scope,
        control: policy.inventory_producer,
        origin,
        condition: InventoryCondition::Spendable,
        history_anchor: policy.history_anchor,
    };
    Ok(SignedInventoryFacts {
        signature: producer.sign(&facts.signing_bytes()?).to_bytes(),
        facts,
    })
}

pub fn observe_native(
    policy: &PairPolicy,
    producer: &SigningKey,
    intent: Id,
    plan: &NativePlan,
) -> Result<SignedNativeFacts> {
    let facts = NativeFacts {
        domain: policy.domain,
        provenance: ObservationEnvironment::LocalFixture,
        intent,
        transaction: plan.transaction,
        inputs: plan
            .inputs
            .iter()
            .chain(&plan.fee_inputs)
            .copied()
            .collect(),
        recipient: plan.recipient,
        amount: plan.amount,
        change: plan.change.clone(),
        block: [41; 32],
        height: 101,
        confirmations: policy.minimum_confirmations,
        history_anchor: policy.history_anchor,
    };
    Ok(SignedNativeFacts {
        signature: producer.sign(&facts.signing_bytes()?).to_bytes(),
        facts,
    })
}
