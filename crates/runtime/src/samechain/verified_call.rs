use std::fmt;

use ziquid_chains::samechain::{
    build_creation_call, build_fill_call, build_single_call, build_withdrawal_call,
    CallBuildError, UnsignedCall,
};
use ziquid_proofs::artifacts::local::{verify_owner_certificate, OwnerCertificate};
use ziquid_protocol::samechain::{
    creation::{NoteCreationJournal, NoteCreationPacket},
    withdrawal::{NoteWithdrawalJournal, NoteWithdrawalPacket},
    Action, Deployment, OwnerJournal, PublicPacket, Role, SingleOwnerPacket,
};

/// Public inputs for one verifier-gated unsigned samechain call.
///
/// Packets, proof frames, and route selectors are borrowed. The request carries
/// no private witness, program bytes, or caller-supplied journal.
pub enum VerifiedCallRequest<'a> {
    Creation {
        packet: &'a NoteCreationPacket,
        proof: &'a [u8],
        token: &'a [u8; 20],
    },
    Fill {
        packet: &'a PublicPacket,
        proof: &'a [u8],
        proof_b: &'a [u8],
        sender: &'a [u8; 20],
    },
    CancelExit {
        packet: &'a SingleOwnerPacket,
        proof: &'a [u8],
        sender: &'a [u8; 20],
        role: &'a Role,
        action: &'a Action,
    },
    Withdrawal {
        packet: &'a NoteWithdrawalPacket,
        proof: &'a [u8],
        sender: &'a [u8; 20],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedCallError {
    InvalidDeployment,
    DeploymentMismatch,
    InvalidPacket,
    InvalidSender,
    WrongToken,
    InvalidRoleAction,
    CertificateRejected,
    CallRejected,
}

impl fmt::Display for VerifiedCallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDeployment => "invalid samechain expected deployment",
            Self::DeploymentMismatch => "samechain packet deployment mismatch",
            Self::InvalidPacket => "invalid samechain public packet",
            Self::InvalidSender => "invalid samechain public sender",
            Self::WrongToken => "samechain token mismatch",
            Self::InvalidRoleAction => "invalid samechain role or action",
            Self::CertificateRejected => "samechain owner certificate verification rejected",
            Self::CallRejected => "samechain verified unsigned call rejected",
        })
    }
}

impl std::error::Error for VerifiedCallError {}

/// Verify exact route journal(s) with the pinned SHA-only Groth16 verifier,
/// then delegate calldata construction to the existing framing-only builders.
pub fn build_verified_call(
    expected: &Deployment,
    request: VerifiedCallRequest<'_>,
) -> Result<UnsignedCall, VerifiedCallError> {
    expected.validate().map_err(|_| VerifiedCallError::InvalidDeployment)?;
    match request {
        VerifiedCallRequest::Creation { packet, proof, token } => {
            check_deployment(expected, &packet.deployment)?;
            if *token == [0; 20] || packet.token != *token {
                return Err(VerifiedCallError::WrongToken);
            }
            if packet.payer == [0; 20] {
                return Err(VerifiedCallError::InvalidSender);
            }
            packet.validate().map_err(|_| VerifiedCallError::InvalidPacket)?;
            let journal = NoteCreationJournal::from_packet(packet)
                .map_err(|_| VerifiedCallError::InvalidPacket)?
                .encode()
                .map_err(|_| VerifiedCallError::InvalidPacket)?;
            verify_certificate(&expected.owner_program, proof, &journal)?;
            build_creation_call(expected, *token, packet, proof).map_err(map_call_error)
        }
        VerifiedCallRequest::Fill { packet, proof, proof_b, sender } => {
            check_deployment(expected, &packet.deployment)?;
            check_sender(*sender)?;
            packet.validate().map_err(|_| VerifiedCallError::InvalidPacket)?;
            let journal_a = OwnerJournal::from_packet(packet, Role::A, Action::Fill)
                .map_err(|_| VerifiedCallError::InvalidPacket)?
                .encode()
                .map_err(|_| VerifiedCallError::InvalidPacket)?;
            let journal_b = OwnerJournal::from_packet(packet, Role::B, Action::Fill)
                .map_err(|_| VerifiedCallError::InvalidPacket)?
                .encode()
                .map_err(|_| VerifiedCallError::InvalidPacket)?;
            verify_certificate(&expected.owner_program, proof, &journal_a)?;
            verify_certificate(&expected.owner_program, proof_b, &journal_b)?;
            build_fill_call(expected, packet, *sender, proof, proof_b).map_err(map_call_error)
        }
        VerifiedCallRequest::CancelExit { packet, proof, sender, role, action } => {
            check_deployment(expected, &packet.deployment)?;
            check_sender(*sender)?;
            if *action == Action::Fill {
                return Err(VerifiedCallError::InvalidRoleAction);
            }
            packet.validate_for(*role)
                .map_err(|_| VerifiedCallError::InvalidRoleAction)?;
            let journal = OwnerJournal::from_single_packet(packet, *role, *action)
                .map_err(|_| VerifiedCallError::InvalidPacket)?
                .encode()
                .map_err(|_| VerifiedCallError::InvalidPacket)?;
            verify_certificate(&expected.owner_program, proof, &journal)?;
            build_single_call(expected, packet, *sender, *role, *action, proof)
                .map_err(map_call_error)
        }
        VerifiedCallRequest::Withdrawal { packet, proof, sender } => {
            check_deployment(expected, &packet.deployment)?;
            check_sender(*sender)?;
            packet.validate().map_err(|_| VerifiedCallError::InvalidPacket)?;
            let journal = NoteWithdrawalJournal::from_packet(packet)
                .map_err(|_| VerifiedCallError::InvalidPacket)?
                .encode()
                .map_err(|_| VerifiedCallError::InvalidPacket)?;
            verify_certificate(&expected.owner_program, proof, &journal)?;
            build_withdrawal_call(expected, packet, *sender, proof).map_err(map_call_error)
        }
    }
}

fn check_deployment(expected: &Deployment, packet: &Deployment) -> Result<(), VerifiedCallError> {
    if expected != packet {
        return Err(VerifiedCallError::DeploymentMismatch);
    }
    Ok(())
}

fn check_sender(sender: [u8; 20]) -> Result<(), VerifiedCallError> {
    if sender == [0; 20] {
        return Err(VerifiedCallError::InvalidSender);
    }
    Ok(())
}

fn verify_certificate(
    program: &[u8; 32], proof: &[u8], journal: &[u8],
) -> Result<(), VerifiedCallError> {
    let certificate = OwnerCertificate {
        program_vkey: *program,
        journal: journal.to_vec(),
        proof_bytes: proof.to_vec(),
    };
    verify_owner_certificate(&certificate, program, journal)
        .map_err(|_| VerifiedCallError::CertificateRejected)
}

fn map_call_error(error: CallBuildError) -> VerifiedCallError {
    match error {
        CallBuildError::WrongDeployment => VerifiedCallError::DeploymentMismatch,
        CallBuildError::InvalidSender => VerifiedCallError::InvalidSender,
        CallBuildError::WrongToken => VerifiedCallError::WrongToken,
        CallBuildError::InvalidRoleAction => VerifiedCallError::InvalidRoleAction,
        _ => VerifiedCallError::CallRejected,
    }
}
