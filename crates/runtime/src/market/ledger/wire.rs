use super::codec::{self, Decoder, Encoder};
use super::*;

impl PairPolicy {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        codec::policy_bytes(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        codec::policy_decode(bytes)
    }
}
impl LedgerCommand {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        codec::command_bytes(self, true)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        codec::read_command(bytes)
    }
}
impl JournalAcknowledgement {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let mut e = Encoder::new(b"KERBJA02");
        e.raw(&self.signer);
        e.raw(&self.signature);
        e.blob(&self.decision.canonical_bytes()?)?;
        match self.target {
            Some(target) => {
                e.byte(1);
                e.raw(&target.signer);
                e.raw(&target.signature);
                e.decision(&target.decision)?;
            }
            None => e.byte(0),
        }
        if e.0.len() > MAX_JOURNAL_BYTES {
            Err(LedgerError::InvalidEvidence)
        } else {
            Ok(e.0)
        }
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let mut d = Decoder::new(bytes, b"KERBJA02")?;
        let signer = d.array()?;
        let signature = d.array()?;
        let decision = JournalDecision::decode(d.blob()?)?;
        let target = match d.byte()? {
            0 => None,
            1 => Some(ziquid_protocol::market::Acknowledgement {
                signer: d.array()?,
                signature: d.array()?,
                decision: d.decision()?,
            }),
            _ => return Err(LedgerError::InvalidEvidence),
        };
        d.end()?;
        Ok(Self {
            signer,
            signature,
            decision,
            target,
        })
    }
}
impl RecoveryChallenge {
    pub fn canonical_bytes(&self) -> [u8; 72] {
        let mut bytes = [0; 72];
        bytes[..8].copy_from_slice(b"KERBRC01");
        bytes[8..40].copy_from_slice(&self.pair);
        bytes[40..].copy_from_slice(&self.nonce);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let mut d = Decoder::new(bytes, b"KERBRC01")?;
        let v = Self {
            pair: d.array()?,
            nonce: d.array()?,
        };
        d.end()?;
        Ok(v)
    }
}
impl RetainedHead {
    pub fn canonical_bytes(&self) -> Result<[u8; 573], LedgerError> {
        let mut bytes = [0; 573];
        let unsigned = codec::retained_bytes(self)?;
        bytes[..509].copy_from_slice(&unsigned);
        bytes[509..].copy_from_slice(&self.signature);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let mut d = Decoder::new(bytes, b"KERBRH01")?;
        let v = Self {
            domain: d.domain()?,
            pair: d.array()?,
            signer: d.array()?,
            head: d.array()?,
            target_head: d.array()?,
            sequence: d.u64()?,
            generation: d.u64()?,
            challenge: d.array()?,
            signature: d.array()?,
        };
        d.end()?;
        Ok(v)
    }
}
