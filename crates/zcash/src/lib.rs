//! Wallet-local Ironwood/v6 authoring with the published upstream cohort.
//!
//! Caller-owned notes, view keys, spend authorization and witnesses stay local.
//! Preparation exports exact unsigned P effects and, after local proof/signing,
//! final Q consensus bytes; sender recovery material is retained before redaction.
//! Owner consent checks semantic input/payment openings and the complete linked
//! P/Q, derives their private binding and independently blinded solver capsule,
//! then borrows the actual Q owner signer for a distinct private signature.
//! The caller reviews all context terms and retains the returned signature privately;
//! neither S's destination quote nor its funding authorization is inferred.
//! Parsing/cryptographic checks do not prove source history, admissible anchors,
//! independent no-FVK ownership, or a DEX financial fact. Task3's application
//! preparation certificate and authorized real-chain runtime evidence remain required.
//!
//! The separate custody module checks caller-enrolled market PCZT effects without
//! signing, generating proofs, or establishing source history or payment.
//!
//! Source-local funding retains unsigned F's exact generated J opening for early
//! R before borrowing the real funding wallet signer to complete unchanged F.
//! It grants no durable-recovery, source-admission, financial-preflight or send
//! authority; the independent route-1a release gates remain caller prerequisites.

mod authoring;
pub mod custody;
pub mod funding;
pub mod joint_spend;
pub mod source;
mod validation;
mod witness;

pub use authoring::{
    AuthoringError, ExecutableSelfSpend, OutputPlan, PreparationIntent, PreparedPair,
    SourceParameters, UnsignedPayment, prepare,
};
pub use validation::{IronwoodTransaction, ValidationError};
pub use witness::{OwnedInput, PayoutWitness, RecoveredOutput, SenderOutputWitness};
