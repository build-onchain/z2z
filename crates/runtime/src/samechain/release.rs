//! Immutable encrypted certificates bound to independently selected public expectations.
//! A capsule is not a committed Released row, settlement, finality or transfer evidence.
use std::{fmt, io::{self, Write}};
use sha2::{Digest, Sha256};
use ziquid_protocol::samechain::{Deployment, Role};
use super::backup::SnapshotOperation;
use crate::custody::CustodyError;

const BINDING_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_RELEASE_BINDING\0";
const VERSION: u16 = 1;
const MAX_BINDING_BYTES: usize = 4096;
const MAX_DEPLOYMENT_BYTES: usize = b"Z2Z_SAMECHAIN_DEPLOYMENT\0".len() + 2 + 146;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseBinding {
    pub op_id: [u8; 32],
    pub deployment: Deployment,
    pub operation: SnapshotOperation,
    pub role: Role,
    pub packet_digest: [u8; 32],
    pub program_vkey: [u8; 32],
    pub journal_digest: [u8; 32],
    pub expiry: u64,
    pub required_nfs: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseDigest(pub [u8; 32]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingDigest(pub [u8; 32]);

/// Category-only errors never retain paths, private payloads or upstream errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseError {
    Binding,
    Encoding,
    Certificate,
    ResourceLimit,
    Custody(CustodyError),
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binding => formatter.write_str("samechain release binding rejected"),
            Self::Encoding => formatter.write_str("samechain release encoding rejected"),
            Self::Certificate => formatter.write_str("samechain release certificate rejected"),
            Self::ResourceLimit => formatter.write_str("samechain release exceeds its resource bound"),
            Self::Custody(error) => fmt::Display::fmt(error, formatter),
        }
    }
}
impl std::error::Error for ReleaseError {}

fn nonzero(bytes: &[u8]) -> bool { bytes.iter().any(|byte| *byte != 0) }

impl ReleaseBinding {
    pub fn validate(&self) -> Result<(), ReleaseError> {
        self.validated_deployment().map(|_| ())
    }

    fn validated_deployment(&self) -> Result<Vec<u8>, ReleaseError> {
        if !nonzero(&self.op_id) || !nonzero(&self.packet_digest)
            || !nonzero(&self.program_vkey) || !nonzero(&self.journal_digest) || self.expiry == 0
        { return Err(ReleaseError::Binding); }
        let count = match self.operation {
            SnapshotOperation::Fill => 2,
            SnapshotOperation::Cancel | SnapshotOperation::Exit => 1,
            SnapshotOperation::Withdrawal if self.role == Role::A => 1,
            SnapshotOperation::Withdrawal => return Err(ReleaseError::Binding),
            SnapshotOperation::Creation => 0,
        };
        if self.required_nfs.len() != count || self.required_nfs.iter().any(|nf| !nonzero(nf))
            || (count == 2 && self.required_nfs[0] == self.required_nfs[1])
        { return Err(ReleaseError::Binding); }
        let encoded = self.deployment.encode().map_err(|_| ReleaseError::Binding)?;
        if encoded.len() > MAX_DEPLOYMENT_BYTES { return Err(ReleaseError::ResourceLimit); }
        if Deployment::decode(&encoded).map_err(|_| ReleaseError::Binding)? != self.deployment {
            return Err(ReleaseError::Binding);
        }
        Ok(encoded)
    }

    fn frame_len(&self, deployment_len: usize) -> usize {
        BINDING_DOMAIN.len() + 2 + 32 + 4 + deployment_len + 2 + 96 + 8 + 1
            + 32 * self.required_nfs.len()
    }

    fn write_frame(&self, deployment: &[u8], out: &mut impl Write) -> Result<(), ReleaseError> {
        let write = || -> io::Result<()> {
            out.write_all(BINDING_DOMAIN)?;
            out.write_all(&VERSION.to_be_bytes())?;
            out.write_all(&self.op_id)?;
            out.write_all(&(deployment.len() as u32).to_be_bytes())?;
            out.write_all(deployment)?;
            out.write_all(&[self.operation as u8, self.role as u8])?;
            out.write_all(&self.packet_digest)?;
            out.write_all(&self.program_vkey)?;
            out.write_all(&self.journal_digest)?;
            out.write_all(&self.expiry.to_be_bytes())?;
            out.write_all(&[self.required_nfs.len() as u8])?;
            for nf in &self.required_nfs { out.write_all(nf)?; }
            Ok(())
        };
        let mut write = write;
        write().map_err(|_| ReleaseError::Encoding)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ReleaseError> {
        let deployment = self.validated_deployment()?;
        let length = self.frame_len(deployment.len());
        if length > MAX_BINDING_BYTES { return Err(ReleaseError::ResourceLimit); }
        let mut bytes = Vec::with_capacity(length);
        self.write_frame(&deployment, &mut bytes)?;
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<BindingDigest, ReleaseError> {
        let deployment = self.validated_deployment()?;
        if self.frame_len(deployment.len()) > MAX_BINDING_BYTES { return Err(ReleaseError::ResourceLimit); }
        let mut writer = HashWriter(Sha256::new());
        self.write_frame(&deployment, &mut writer)?;
        Ok(BindingDigest(writer.0.finalize().into()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ReleaseError> {
        if bytes.len() > MAX_BINDING_BYTES { return Err(ReleaseError::ResourceLimit); }
        let mut reader = Reader(bytes);
        if reader.take(BINDING_DOMAIN.len())? != BINDING_DOMAIN || reader.u16()? != VERSION {
            return Err(ReleaseError::Encoding);
        }
        let op_id = reader.array()?;
        let deployment_bytes = reader.blob(MAX_DEPLOYMENT_BYTES)?;
        let deployment = Deployment::decode(deployment_bytes).map_err(|_| ReleaseError::Binding)?;
        let operation = match reader.byte()? {
            0 => SnapshotOperation::Fill, 1 => SnapshotOperation::Cancel, 2 => SnapshotOperation::Exit,
            3 => SnapshotOperation::Withdrawal, 4 => SnapshotOperation::Creation,
            _ => return Err(ReleaseError::Encoding),
        };
        let role = match reader.byte()? {
            0 => Role::A, 1 => Role::B, _ => return Err(ReleaseError::Encoding),
        };
        let packet_digest = reader.array()?;
        let program_vkey = reader.array()?;
        let journal_digest = reader.array()?;
        let expiry = reader.u64()?;
        let count = reader.byte()? as usize;
        if count > 2 { return Err(ReleaseError::Encoding); }
        let nfs = reader.take(count * 32)?;
        reader.finish()?;
        let required_nfs = nfs.as_chunks::<32>().0.to_vec();
        let binding = Self { op_id, deployment, operation, role, packet_digest,
            program_vkey, journal_digest, expiry, required_nfs };
        binding.validate()?;
        Ok(binding)
    }
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.0.update(bytes); Ok(bytes.len()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ReleaseError> {
        if length > self.0.len() { return Err(ReleaseError::Encoding); }
        let (bytes, rest) = self.0.split_at(length); self.0 = rest; Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ReleaseError> {
        self.take(N)?.try_into().map_err(|_| ReleaseError::Encoding)
    }
    fn byte(&mut self) -> Result<u8, ReleaseError> { Ok(self.array::<1>()?[0]) }
    fn u16(&mut self) -> Result<u16, ReleaseError> { Ok(u16::from_be_bytes(self.array()?)) }
    fn u32(&mut self) -> Result<u32, ReleaseError> { Ok(u32::from_be_bytes(self.array()?)) }
    fn u64(&mut self) -> Result<u64, ReleaseError> { Ok(u64::from_be_bytes(self.array()?)) }
    fn blob(&mut self, max: usize) -> Result<&'a [u8], ReleaseError> {
        let length = self.u32()? as usize;
        if length > max { return Err(ReleaseError::ResourceLimit); }
        self.take(length)
    }
    fn finish(self) -> Result<(), ReleaseError> {
        if self.0.is_empty() { Ok(()) } else { Err(ReleaseError::Encoding) }
    }
}

#[cfg(feature = "sp1-local")]
mod capsule {
    use super::*;
    use std::path::Path;
    use subtle::ConstantTimeEq;
    use zeroize::Zeroizing;
    use ziquid_proofs::artifacts::local::{OwnerCertificate, verify_owner_certificate};
    use ziquid_protocol::samechain::{Action, OwnerJournal,
        creation::NoteCreationJournal, withdrawal::NoteWithdrawalJournal};
    use crate::custody::{EnvelopeFormat, load_encrypted_with_digest, save_encrypted};

    const DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_RELEASE_CAPSULE\0";
    const CONTEXT_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_RELEASE_CONTEXT\0";
    const MAX_JOURNAL_BYTES: usize = 1024;
    const PROOF_BYTES: usize = 356;
    const FORMAT: EnvelopeFormat = EnvelopeFormat {
        domain: b"ziquid.samechain.release.v1",
        max_plaintext_bytes: DOMAIN.len() + 2 + 4 + MAX_BINDING_BYTES
            + 4 + MAX_JOURNAL_BYTES + 4 + PROOF_BYTES,
    };

    /// Select this capsule's bounded encrypted bytes without reading a key.
    pub(crate) fn capsule_digest(path: impl AsRef<Path>) -> Result<ReleaseDigest, ReleaseError> {
        crate::custody::encrypted_file_digest(path, FORMAT)
            .map(ReleaseDigest).map_err(ReleaseError::Custody)
    }

    fn bounds(journal: &[u8], proof: &[u8]) -> Result<(), ReleaseError> {
        if journal.len() > MAX_JOURNAL_BYTES { return Err(ReleaseError::ResourceLimit); }
        if proof.len() != PROOF_BYTES { return Err(ReleaseError::Encoding); }
        Ok(())
    }

    fn verify(binding: &ReleaseBinding, certificate: &OwnerCertificate) -> Result<(), ReleaseError> {
        if certificate.program_vkey != binding.program_vkey
            || <[u8; 32]>::from(Sha256::digest(&certificate.journal)) != binding.journal_digest
        { return Err(ReleaseError::Certificate); }
        let deployment = binding.deployment.digest().map_err(|_| ReleaseError::Certificate)?;
        let consistent = match binding.operation {
            SnapshotOperation::Fill | SnapshotOperation::Cancel | SnapshotOperation::Exit => {
                let journal = OwnerJournal::decode(&certificate.journal).map_err(|_| ReleaseError::Certificate)?;
                journal.validate().map_err(|_| ReleaseError::Certificate)?;
                let (action, nf_index) = match binding.operation {
                    SnapshotOperation::Fill => (Action::Fill, binding.role.index()),
                    SnapshotOperation::Cancel => (Action::Cancel, 0),
                    SnapshotOperation::Exit => (Action::Exit, 0),
                    _ => unreachable!(),
                };
                journal.action == action && journal.role == binding.role
                    && journal.packet_digest == binding.packet_digest && journal.deployment_digest == deployment
                    && journal.input_nullifier == binding.required_nfs[nf_index]
            },
            SnapshotOperation::Withdrawal => {
                let journal = NoteWithdrawalJournal::decode(&certificate.journal).map_err(|_| ReleaseError::Certificate)?;
                journal.validate().map_err(|_| ReleaseError::Certificate)?;
                journal.packet_digest == binding.packet_digest && journal.deployment_digest == deployment
                    && journal.input_nullifier == binding.required_nfs[0]
            },
            SnapshotOperation::Creation => {
                let journal = NoteCreationJournal::decode(&certificate.journal).map_err(|_| ReleaseError::Certificate)?;
                journal.validate().map_err(|_| ReleaseError::Certificate)?;
                journal.packet_digest == binding.packet_digest && journal.deployment_digest == deployment
                    && journal.role == binding.role
            },
        };
        if !consistent { return Err(ReleaseError::Certificate); }
        verify_owner_certificate(certificate, &binding.program_vkey, &certificate.journal)
            .map_err(|_| ReleaseError::Certificate)
    }

    fn context(encoded: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new(); hash.update(CONTEXT_DOMAIN);
        hash.update(VERSION.to_be_bytes()); hash.update(Sha256::digest(encoded));
        hash.finalize().into()
    }

    fn length(binding: &[u8], certificate: &OwnerCertificate) -> usize {
        DOMAIN.len() + 2 + 4 + binding.len() + 4 + certificate.journal.len() + 4 + certificate.proof_bytes.len()
    }

    // Compare every canonical plaintext segment without another private allocation.
    fn exact_plaintext(bytes: &[u8], binding: &[u8], certificate: &OwnerCertificate) -> bool {
        if bytes.len() != length(binding, certificate) { return false; }
        let mut remaining = bytes;
        let mut equal = subtle::Choice::from(1);
        for segment in [DOMAIN, &VERSION.to_be_bytes(), &(binding.len() as u32).to_be_bytes(), binding,
            &(certificate.journal.len() as u32).to_be_bytes(), &certificate.journal,
            &(certificate.proof_bytes.len() as u32).to_be_bytes(), &certificate.proof_bytes] {
            let (actual, rest) = remaining.split_at(segment.len());
            equal &= actual.ct_eq(segment); remaining = rest;
        }
        bool::from(equal)
    }

    pub fn save_release(
        path: impl AsRef<Path>, key: &[u8; 32], namespace: [u8; 32],
        binding: &ReleaseBinding, certificate: &OwnerCertificate,
    ) -> Result<ReleaseDigest, ReleaseError> {
        bounds(&certificate.journal, &certificate.proof_bytes)?;
        if !nonzero(&namespace) { return Err(ReleaseError::Binding); }
        let encoded = binding.encode()?;
        verify(binding, certificate)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(length(&encoded, certificate)));
        bytes.extend_from_slice(DOMAIN); bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes()); bytes.extend_from_slice(&encoded);
        bytes.extend_from_slice(&(certificate.journal.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&certificate.journal);
        bytes.extend_from_slice(&(certificate.proof_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&certificate.proof_bytes);
        let context = context(&encoded);
        save_encrypted(path.as_ref(), key, namespace, context, FORMAT, bytes).map_err(ReleaseError::Custody)?;
        let (readback, digest) = load_encrypted_with_digest(path.as_ref(), key, namespace, context, FORMAT)
            .map_err(ReleaseError::Custody)?;
        if !exact_plaintext(&readback, &encoded, certificate) {
            return Err(ReleaseError::Custody(CustodyError::Conflict));
        }
        Ok(ReleaseDigest(digest))
    }

    pub fn load_release(
        path: impl AsRef<Path>, key: &[u8; 32], namespace: [u8; 32],
        expected: &ReleaseBinding, expected_release: ReleaseDigest,
    ) -> Result<OwnerCertificate, ReleaseError> {
        if !nonzero(&namespace) { return Err(ReleaseError::Binding); }
        let encoded = expected.encode()?;
        let (bytes, digest) = load_encrypted_with_digest(path.as_ref(), key, namespace, context(&encoded), FORMAT)
            .map_err(ReleaseError::Custody)?;
        if digest != expected_release.0 { return Err(ReleaseError::Binding); }
        let mut reader = Reader(&bytes);
        if reader.take(DOMAIN.len())? != DOMAIN || reader.u16()? != VERSION { return Err(ReleaseError::Encoding); }
        let binding = reader.blob(MAX_BINDING_BYTES)?;
        let journal = reader.blob(MAX_JOURNAL_BYTES)?;
        let proof_len = reader.u32()? as usize;
        if proof_len != PROOF_BYTES { return Err(ReleaseError::Encoding); }
        let proof = reader.take(proof_len)?;
        reader.finish()?;
        if ReleaseBinding::decode(binding)? != *expected { return Err(ReleaseError::Binding); }
        let certificate = OwnerCertificate { program_vkey: expected.program_vkey,
            journal: journal.to_vec(), proof_bytes: proof.to_vec() };
        verify(expected, &certificate)?;
        Ok(certificate)
    }
}

#[cfg(feature = "sp1-local")]
pub use capsule::{load_release, save_release};

#[cfg(feature = "sp1-local")]
pub(crate) use capsule::capsule_digest;
