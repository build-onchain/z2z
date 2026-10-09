//! Route-1a §11.3 C-share release gate: the local, ordered bookkeeping that
//! withholds usable C-side contribution material until a caller-asserted
//! irrevocable target arming — the §7 rule that withholding only the aggregate
//! is insufficient, so every usable share is gated.
//!
//! **Scope and trust boundary.** This module enforces the §11.3 order and
//! one-use withholding for the party that holds the material. It does not
//! verify arming (that observation and its finality policy are the
//! target-side R2.2/R4 capability), it cannot constrain the counterparty,
//! and it provides no timer or automatic refund. `ArmingEvidence` is the
//! integration contract: construct it only after the caller's independent,
//! finality-checked target observation succeeded.
//!
//! **R material is out of scope by design:** q(R) contributions are released
//! early (§11.3 step 2) because R returns J to U and grants no C authority;
//! only C-side material travels through this gate.

use zeroize::Zeroize;

/// Ordered §11.3 phases, monotonic. `Aborted` is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Nothing verified yet.
    Created,
    /// Step 1: both DKG key packages verified.
    Keygened,
    /// Step 2: both R contributions signed early.
    RPreauthorized,
    /// Step 3: funding released (only after step 2).
    Funded,
    /// Step 4: J membership verified; finished R completed and backed up.
    RFinalized,
    /// Step 5: independent target arming verified (finality per target policy).
    Armed,
    /// Step 6: local C material released (one-use).
    CReleased,
    /// Step 7: finished C completed (or handed off).
    CCompleted,
    /// Step 8: pre-arming abort; held material zeroized.
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    /// A transition or action was attempted out of its §11.3 position.
    OutOfOrder { expected: Phase, actual: Phase },
    /// The gate was already aborted; nothing proceeds.
    Aborted,
    /// Aborting is not allowed once arming was verified (step 8: post-arming
    /// failures proceed as C or R per the winning source effect).
    PostArmingAbort,
    /// Local C material was already deposited.
    LocalMaterialPresent,
    /// Nothing was deposited to release.
    NoLocalMaterial,
    /// The one-use release already happened.
    AlreadyReleased,
    /// Peer C material was offered before arming was verified; refused —
    /// no party may aggregate the counterparty's C share pre-gate.
    PeerMaterialRefused,
    /// Peer C material was already accepted.
    PeerMaterialPresent,
}

/// Opaque caller attestation that irrevocable target arming was verified.
///
/// This module neither creates nor checks the underlying observation.
/// Constructing this token asserts the integration contract: the caller ran
/// the independent verification (target finality/reorg policy per the
/// selected construction) and only then releases the material.
#[derive(Debug)]
pub struct ArmingEvidence {
    _seal: (),
}

impl ArmingEvidence {
    /// Only call after the independent verification succeeded.
    pub fn from_verified_target_observation() -> Self {
        Self { _seal: () }
    }
}

/// The §11.3 gate for one party's C-side contribution material. `M` is the
/// payload class (e.g. a serialized signature share or prover material);
/// prefer a self-zeroizing payload type — `abort` explicitly zeroizes held
/// material, and `release` moves it to the caller.
pub struct ShareGate<M: Zeroize> {
    phase: Phase,
    local: Option<M>,
    peer: Option<M>,
    released: bool,
}

impl<M: Zeroize> Default for ShareGate<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: Zeroize> ShareGate<M> {
    pub fn new() -> Self {
        Self { phase: Phase::Created, local: None, peer: None, released: false }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Hold this party's C contribution. Holding is not releasing: the
    /// material cannot leave before [`Self::release_local_c_material`].
    pub fn deposit_local_c_material(&mut self, material: M) -> Result<(), GateError> {
        self.check_alive()?;
        if self.released {
            return Err(GateError::AlreadyReleased);
        }
        if self.local.is_some() {
            return Err(GateError::LocalMaterialPresent);
        }
        self.local = Some(material);
        Ok(())
    }

    /// §11.3 step 1.
    pub fn mark_keygen_verified(&mut self) -> Result<(), GateError> {
        self.advance(Phase::Created, Phase::Keygened)
    }

    /// §11.3 step 2: both q(R) contributions signed early.
    pub fn mark_r_preauthorized(&mut self) -> Result<(), GateError> {
        self.advance(Phase::Keygened, Phase::RPreauthorized)
    }

    /// §11.3 step 3: funding released (only after step 2).
    pub fn mark_funding_released(&mut self) -> Result<(), GateError> {
        self.advance(Phase::RPreauthorized, Phase::Funded)
    }

    /// §11.3 step 4: J membership verified; finished R completed and backed up.
    pub fn mark_r_finalized_and_backed_up(&mut self) -> Result<(), GateError> {
        self.advance(Phase::Funded, Phase::RFinalized)
    }

    /// §11.3 step 5 (order-relevant: step 6): the arming observation gate.
    pub fn mark_arming_verified(
        &mut self,
        evidence: ArmingEvidence,
    ) -> Result<(), GateError> {
        let ArmingEvidence { _seal: () } = evidence;
        self.advance(Phase::RFinalized, Phase::Armed)
    }

    /// The one-use release: only in `Armed`, only with deposited material.
    /// The phase moves to `CReleased` and a second call fails.
    pub fn release_local_c_material(&mut self) -> Result<M, GateError> {
        self.check_alive()?;
        if self.released {
            return Err(GateError::AlreadyReleased);
        }
        if self.phase != Phase::Armed {
            return Err(GateError::OutOfOrder { expected: Phase::Armed, actual: self.phase });
        }
        let material = self.local.take().ok_or(GateError::NoLocalMaterial)?;
        self.released = true;
        self.phase = Phase::CReleased;
        Ok(material)
    }

    /// Accept the counterparty's C material. Refused before arming was
    /// verified (§11.3: no aggregation of the other party's C share
    /// pre-gate), and refused twice.
    pub fn accept_peer_c_material(&mut self, material: M) -> Result<(), GateError> {
        self.check_alive()?;
        if self.peer.is_some() {
            return Err(GateError::PeerMaterialPresent);
        }
        if !matches!(self.phase, Phase::Armed | Phase::CReleased | Phase::CCompleted) {
            return Err(GateError::PeerMaterialRefused);
        }
        self.peer = Some(material);
        Ok(())
    }

    /// §11.3 step 7.
    pub fn mark_c_completed(&mut self) -> Result<(), GateError> {
        self.advance(Phase::CReleased, Phase::CCompleted)
    }

    /// §11.3 step 8 pre-arming abort: no shares leave, held material is
    /// zeroized, and nothing can proceed. Post-arming (`Armed` onward) abort
    /// is refused: the winning source effect decides between C and R.
    pub fn abort(&mut self) -> Result<(), GateError> {
        match self.phase {
            Phase::Aborted => Err(GateError::Aborted),
            Phase::Armed | Phase::CReleased | Phase::CCompleted => {
                Err(GateError::PostArmingAbort)
            }
            _ => {
                if let Some(mut material) = self.local.take() {
                    material.zeroize();
                }
                if let Some(mut material) = self.peer.take() {
                    material.zeroize();
                }
                self.phase = Phase::Aborted;
                Ok(())
            }
        }
    }

    fn check_alive(&self) -> Result<(), GateError> {
        if self.phase == Phase::Aborted {
            return Err(GateError::Aborted);
        }
        Ok(())
    }

    fn advance(&mut self, expected: Phase, next: Phase) -> Result<(), GateError> {
        self.check_alive()?;
        if self.phase != expected {
            return Err(GateError::OutOfOrder { expected, actual: self.phase });
        }
        self.phase = next;
        Ok(())
    }
}