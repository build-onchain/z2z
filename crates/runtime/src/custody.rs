//! U-owned encrypted restart custody, not a wallet, source authorization or financial fact.
//!
//! Callers supply their own borrowed encryption capability, opaque filename and independent
//! namespace/context binding. No keys or private PCZTs belong in argv, logs or an S packet.
//! Linux descriptor-relative publication is immutable and committed only after directory
//! fsync. Same-UID/root compromise, backup policy and the filesystem's real durability remain
//! outside this boundary; saving never authorizes releasing P or moving funds.
//! Native P/Q and samechain snapshot callers share only encrypted-byte publication;
//! their wrappers retain semantic review. Guarded allocations do not erase compiler,
//! register or same-UID/root copies, and fsync cannot guarantee hardware durability
//! or secure deletion of removed interrupted staging.

use std::{fmt, path::Path, sync::LazyLock};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use orchard::{
    Address, Anchor, Note,
    circuit::{OrchardCircuitVersion, VerifyingKey},
    keys::FullViewingKey,
    note::{NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zcash_primitives::transaction::components::orchard::{ACTION_SIZE, SPEND_AUTH_SIG_SIZE};
use zcash_protocol::consensus::BranchId;
use zeroize::{Zeroize, Zeroizing};
use ziquid_proofs::preparation::{
    MAX_PRIVATE_INPUT_BYTES, MAX_TRANSACTION_BYTES, PreparationWitness, verify_preparation,
};
use ziquid_protocol::ValidatedContext;
use ziquid_zcash::{IronwoodTransaction, OwnedInput, PayoutWitness};

const DOMAIN: &[u8] = b"ziquid.u.custody.v3";
// Recognition only: never decrypt, rewrite or discard retained old custody.
const RETAINED_DOMAINS: [&[u8]; 2] = [b"ziquid.u.custody.v1", b"ziquid.u.custody.v2"];
const SNAPSHOT_DOMAIN: &[u8] = b"ziquid.samechain.backup.v1";
const RELEASE_DOMAIN: &[u8] = b"ziquid.samechain.release.v1";
const RECOVERY_DOMAIN: &[u8] = crate::native_recovery::ENVELOPE_DOMAIN;
const TRADE_DOMAIN: &[u8] = b"ziquid.native.trade.v1\0";
// Recognition is shared by all callers; these bytes never authorize restoration.
const PROTECTED_DOMAINS: [&[u8]; 7] = [DOMAIN, RETAINED_DOMAINS[0], RETAINED_DOMAINS[1], SNAPSHOT_DOMAIN, RELEASE_DOMAIN, RECOVERY_DOMAIN, TRADE_DOMAIN];
const VERSION_FAMILIES: [&[u8]; 5] = [b"ziquid.u.custody.v", b"ziquid.samechain.backup.v", b"ziquid.samechain.release.v", b"ziquid.nativeR.v", b"ziquid.native.trade.v"];
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = DOMAIN.len() + NONCE_LEN + 4;
const MAX_ACTIONS: usize = MAX_TRANSACTION_BYTES / (ACTION_SIZE + SPEND_AUTH_SIG_SIZE);
const MAX_PLAINTEXT_BYTES: usize = MAX_PRIVATE_INPUT_BYTES + 4 + 4 * MAX_ACTIONS;
const MAX_ENVELOPE_BYTES: usize = HEADER_LEN + MAX_PLAINTEXT_BYTES + TAG_LEN;
const fn max_length(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}
const MAX_HEADER_LEN: usize = max_length(max_length(max_length(max_length(DOMAIN.len(), SNAPSHOT_DOMAIN.len()), RELEASE_DOMAIN.len()), RECOVERY_DOMAIN.len()), TRADE_DOMAIN.len()) + NONCE_LEN + 4;
const _: () = {
    assert!(DOMAIN.len() + NONCE_LEN + 4 <= MAX_HEADER_LEN);
    assert!(SNAPSHOT_DOMAIN.len() + NONCE_LEN + 4 <= MAX_HEADER_LEN);
    assert!(RELEASE_DOMAIN.len() + NONCE_LEN + 4 <= MAX_HEADER_LEN);
    assert!(RECOVERY_DOMAIN.len() + NONCE_LEN + 4 <= MAX_HEADER_LEN);
    assert!(TRADE_DOMAIN.len() + NONCE_LEN + 4 <= MAX_HEADER_LEN);
    assert!(HEADER_LEN + MAX_PLAINTEXT_BYTES + TAG_LEN == MAX_ENVELOPE_BYTES);
};

/// Concrete framing for private-custody callers, not a semantic validator.
/// Future domains must never have a current domain as a byte prefix: use a
/// terminator or distinct family rather than a v30-style name after native v3.
#[derive(Clone, Copy)]
pub(crate) struct EnvelopeFormat {
    pub(crate) domain: &'static [u8],
    pub(crate) max_plaintext_bytes: usize,
}

impl EnvelopeFormat {
    fn header_len(self) -> usize {
        self.domain.len() + NONCE_LEN + 4
    }

    fn max_envelope_bytes(self) -> Result<usize, CustodyError> {
        if self.domain != DOMAIN && self.domain != SNAPSHOT_DOMAIN && self.domain != RELEASE_DOMAIN
            && self.domain != RECOVERY_DOMAIN && self.domain != TRADE_DOMAIN
        {
            return Err(CustodyError::UnsupportedVersion);
        }
        let cipher_len = self.max_plaintext_bytes.checked_add(TAG_LEN)
            .ok_or(CustodyError::ResourceLimit)?;
        u32::try_from(cipher_len).map_err(|_| CustodyError::ResourceLimit)?;
        self.header_len().checked_add(cipher_len).ok_or(CustodyError::ResourceLimit)
    }
}

const NATIVE_FORMAT: EnvelopeFormat = EnvelopeFormat { domain: DOMAIN, max_plaintext_bytes: MAX_PLAINTEXT_BYTES };
static Q_VERIFYING_KEY: LazyLock<VerifyingKey> = LazyLock::new(|| VerifyingKey::build(OrchardCircuitVersion::PostNu6_3));

/// Full private P/Q preparation plus the builder's nth-requested-output mapping.
/// This never contains a solver capability or permission to release source authorization.
#[derive(Clone)]
pub struct PrivatePreparation {
    pub witness: PreparationWitness,
    pub requested_output_actions: Vec<u32>,
}

impl fmt::Debug for PrivatePreparation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivatePreparation([redacted])")
    }
}

/// Categories only: no raw I/O/source error, private path, note, memo or key is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyError {
    UnsupportedPlatform,
    UnsupportedVersion,
    UnsafePath,
    Io,
    NotFound,
    ResourceLimit,
    Encoding,
    Authentication,
    Preparation,
    Conflict,
    /// A barrier failed. An installed final is retained and must be authenticated/synced
    /// on retry; callers must not export protected material based on this outcome.
    Durability,
}

impl fmt::Display for CustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedPlatform => "private preparation custody requires Linux",
            Self::UnsupportedVersion => "private preparation custody version is unsupported; retained bytes require their authenticated restore capability",
            Self::UnsafePath => "custody path is not owner-private",
            Self::Io => "private custody filesystem operation failed",
            Self::NotFound => "private preparation custody is absent",
            Self::ResourceLimit => "private preparation custody exceeds its resource bound",
            Self::Encoding => "private preparation custody encoding rejected",
            Self::Authentication => "private preparation custody authentication rejected",
            Self::Preparation => "private preparation custody relation rejected",
            Self::Conflict => "immutable private preparation custody conflicts",
            Self::Durability => "private preparation custody durability is indeterminate",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CustodyError {}

impl PrivatePreparation {
    /// Recover actual sender authority from caller-private material, never an S packet.
    /// Complete load/save additionally validate the P/Q relation and executable Q proof.
    pub fn restore_payout(&self) -> Result<PayoutWitness, CustodyError> {
        if self.requested_output_actions.is_empty() || self.requested_output_actions.len() > MAX_ACTIONS {
            return Err(CustodyError::ResourceLimit);
        }
        let witness = &self.witness;
        let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&witness.note_recipient))
            .ok_or(CustodyError::Preparation)?;
        let rho = Option::<Rho>::from(Rho::from_bytes(&witness.note_rho))
            .ok_or(CustodyError::Preparation)?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(witness.note_rseed, &rho))
            .ok_or(CustodyError::Preparation)?;
        let note = Option::<Note>::from(Note::from_parts(
            recipient, NoteValue::from_raw(witness.note_value), rho, rseed, NoteVersion::V3,
        )).ok_or(CustodyError::Preparation)?;
        let fvk = FullViewingKey::from_bytes(&witness.full_viewing_key)
            .ok_or(CustodyError::Preparation)?;
        let anchor = Option::<Anchor>::from(Anchor::from_bytes(witness.anchor))
            .ok_or(CustodyError::Preparation)?;
        let mut siblings = [MerkleHashOrchard::from_bytes(&[0; 32]).unwrap(); 32];
        for (sibling, bytes) in siblings.iter_mut().zip(&witness.merkle_siblings) {
            *sibling = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(bytes))
                .ok_or(CustodyError::Preparation)?;
        }
        let input = OwnedInput::new(note, fvk, MerklePath::from_parts(witness.merkle_position, siblings), anchor)
            .map_err(|_| CustodyError::Preparation)?;
        let mapping = self.requested_output_actions.iter()
            .map(|index| usize::try_from(*index).map_err(|_| CustodyError::ResourceLimit))
            .collect::<Result<Vec<_>, _>>()?;
        PayoutWitness::restore(input, witness.private_p_pczt.clone(), mapping)
            .map_err(|_| CustodyError::Preparation)
    }

    fn validate(&self, expected_context: [u8; 32]) -> Result<(), CustodyError> {
        let context = ValidatedContext::decode(&self.witness.context_bytes)
            .map_err(|_| CustodyError::Preparation)?;
        if context.digest() != expected_context {
            return Err(CustodyError::Authentication);
        }
        verify_preparation(&self.witness).map_err(|_| CustodyError::Preparation)?;
        self.restore_payout()?;
        let q = IronwoodTransaction::parse(&self.witness.q_transaction, BranchId::Nu6_3)
            .map_err(|_| CustodyError::Preparation)?;
        q.verify_authorization(
            &Q_VERIFYING_KEY,
            &mut OsRng,
        ).map_err(|_| CustodyError::Preparation)
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
        if self.requested_output_actions.is_empty() || self.requested_output_actions.len() > MAX_ACTIONS {
            return Err(CustodyError::ResourceLimit);
        }
        // The existing codec is already filled with private bytes. Growing it would
        // let Vec free an unwiped old allocation; keep it guarded and copy once into
        // a guarded destination sized for mapping/count; detached AEAD adds no bytes.
        let base = self.witness.encode_private().map_err(|_| CustodyError::Encoding)?;
        let capacity = base.len()
            .checked_add(4 * self.requested_output_actions.len() + 4)
            .ok_or(CustodyError::ResourceLimit)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
        bytes.extend_from_slice(&base);
        drop(base);
        for index in &self.requested_output_actions {
            bytes.extend_from_slice(&index.to_le_bytes());
        }
        bytes.extend_from_slice(&(self.requested_output_actions.len() as u32).to_le_bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        if bytes.len() > MAX_PLAINTEXT_BYTES {
            return Err(CustodyError::ResourceLimit);
        }
        let tail = bytes.len().checked_sub(4).ok_or(CustodyError::Encoding)?;
        let count = u32::from_le_bytes(bytes[tail..].try_into().map_err(|_| CustodyError::Encoding)?) as usize;
        if count == 0 || count > MAX_ACTIONS {
            return Err(CustodyError::ResourceLimit);
        }
        let mapping_len = count.checked_mul(4).ok_or(CustodyError::ResourceLimit)?;
        let mapping_at = tail.checked_sub(mapping_len).ok_or(CustodyError::Encoding)?;
        let witness = PreparationWitness::decode_private(&bytes[..mapping_at])
            .map_err(|_| CustodyError::Encoding)?;
        let requested_output_actions = bytes[mapping_at..tail].as_chunks::<4>().0.iter()
            .map(|bytes| u32::from_le_bytes(*bytes))
            .collect();
        Ok(Self { witness, requested_output_actions })
    }
}

fn aad(header: &[u8], namespace: [u8; 32], context: [u8; 32]) -> [u8; MAX_HEADER_LEN + 64] {
    let mut bytes = [0; MAX_HEADER_LEN + 64];
    let length = header.len();
    bytes[..length].copy_from_slice(header);
    bytes[length..length + 32].copy_from_slice(&namespace);
    bytes[length + 32..length + 64].copy_from_slice(&context);
    bytes
}

fn decrypt(
    envelope: &mut Zeroizing<Vec<u8>>,
    key: &[u8; 32],
    namespace: [u8; 32],
    context: [u8; 32],
    format: EnvelopeFormat,
) -> Result<(), CustodyError> {
    if !matches!(envelope_shape(envelope, format)?, EnvelopeShape::Complete) {
        return Err(CustodyError::Encoding);
    }
    let header_len = format.header_len();
    let mut header = [0; MAX_HEADER_LEN];
    header[..header_len].copy_from_slice(&envelope[..header_len]);
    let header = &header[..header_len];
    let authenticated = aad(header, namespace, context);
    let end = envelope.len() - TAG_LEN;
    let (content, tag) = envelope.split_at_mut(end);
    XChaCha20Poly1305::new(key.into()).decrypt_in_place_detached(
        XNonce::from_slice(&header[format.domain.len()..format.domain.len() + NONCE_LEN]),
        &authenticated[..header_len + 64],
        &mut content[header_len..],
        chacha20poly1305::Tag::from_slice(tag),
    ).map_err(|_| CustodyError::Authentication)
}

enum EnvelopeShape { Complete, Incomplete }

fn envelope_shape(bytes: &[u8], format: EnvelopeFormat) -> Result<EnvelopeShape, CustodyError> {
    if bytes.len() > format.max_envelope_bytes()? {
        return Err(CustodyError::ResourceLimit);
    }
    if bytes.is_empty() {
        return Ok(EnvelopeShape::Incomplete);
    }
    // Protected recognition precedes incompleteness. Only the complete current
    // domain disambiguates this caller's interrupted envelope from other formats.
    if PROTECTED_DOMAINS.iter().filter(|domain| **domain != format.domain)
        .any(|domain| bytes.starts_with(domain) || domain.starts_with(bytes))
    {
        return Err(CustodyError::UnsupportedVersion);
    }
    if !bytes.starts_with(format.domain) {
        if VERSION_FAMILIES.iter().any(|family| family.starts_with(bytes)) {
            return Err(CustodyError::UnsupportedVersion);
        }
        return Err(CustodyError::Encoding);
    }
    let header_len = format.header_len();
    if bytes.len() < header_len {
        return Ok(EnvelopeShape::Incomplete);
    }
    let cipher_len = u32::from_le_bytes(bytes[header_len - 4..header_len].try_into()
        .map_err(|_| CustodyError::Encoding)?) as usize;
    if !(TAG_LEN..=format.max_plaintext_bytes + TAG_LEN).contains(&cipher_len) {
        return Err(CustodyError::ResourceLimit);
    }
    let total = header_len.checked_add(cipher_len).ok_or(CustodyError::ResourceLimit)?;
    match bytes.len().cmp(&total) {
        std::cmp::Ordering::Equal => Ok(EnvelopeShape::Complete),
        std::cmp::Ordering::Less => Ok(EnvelopeShape::Incomplete),
        std::cmp::Ordering::Greater => Err(CustodyError::Encoding),
    }
}

/// Publish already validated canonical bytes; semantic ownership stays with callers.
pub(crate) fn save_encrypted(
    path: &Path, key: &[u8; 32], namespace: [u8; 32], context: [u8; 32],
    format: EnvelopeFormat, plaintext: Zeroizing<Vec<u8>>,
) -> Result<(), CustodyError> {
    #[cfg(target_os = "linux")]
    {
        format.max_envelope_bytes()?;
        if plaintext.len() > format.max_plaintext_bytes { return Err(CustodyError::ResourceLimit); }
        linux::save(path, key, namespace, context, format, plaintext)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, key, namespace, context, format, plaintext);
        Err(CustodyError::UnsupportedPlatform)
    }
}

/// Authenticate independent bindings and return guarded bytes to the caller's decoder.
pub(crate) fn load_encrypted(
    path: &Path, key: &[u8; 32], namespace: [u8; 32], context: [u8; 32], format: EnvelopeFormat,
) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
    load_encrypted_with_digest(path, key, namespace, context, format).map(|(plaintext, _)| plaintext)
}

/// Hash the exact trusted encrypted read, then authenticate and finish its barriers.
pub(crate) fn load_encrypted_with_digest(
    path: &Path, key: &[u8; 32], namespace: [u8; 32], context: [u8; 32], format: EnvelopeFormat,
) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), CustodyError> {
    #[cfg(target_os = "linux")]
    {
        format.max_envelope_bytes()?;
        linux::load(path, key, namespace, context, format)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, key, namespace, context, format);
        Err(CustodyError::UnsupportedPlatform)
    }
}

/// Save validated complete P/Q custody immutably. Identical logical retries authenticate
/// the existing envelope and complete its barriers without generating a new nonce.
/// Any error prevents a caller from treating this attempt as durable custody.
pub fn save_preparation(
    path: impl AsRef<Path>,
    key: &[u8; 32],
    namespace: [u8; 32],
    artifact: &PrivatePreparation,
) -> Result<(), CustodyError> {
    #[cfg(target_os = "linux")]
    {
        let context = ValidatedContext::decode(&artifact.witness.context_bytes)
            .map_err(|_| CustodyError::Preparation)?.digest();
        artifact.validate(context)?;
        let plaintext = artifact.encode()?;
        save_encrypted(path.as_ref(), key, namespace, context, NATIVE_FORMAT, plaintext)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, key, namespace, artifact);
        Err(CustodyError::UnsupportedPlatform)
    }
}

/// Load only against independently supplied caller/order bindings; a file's header is
/// never its own source of trust. Returns actual validated restart material, not a receipt.
pub fn load_preparation(
    path: impl AsRef<Path>,
    key: &[u8; 32],
    namespace: [u8; 32],
    expected_context_digest: [u8; 32],
) -> Result<PrivatePreparation, CustodyError> {
    #[cfg(target_os = "linux")]
    {
        let plaintext = load_encrypted(path.as_ref(), key, namespace, expected_context_digest, NATIVE_FORMAT)?;
        let artifact = PrivatePreparation::decode(&plaintext)?;
        artifact.validate(expected_context_digest)?;
        Ok(artifact)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, key, namespace, expected_context_digest);
        Err(CustodyError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn trusted_existing_private_directory(path: &Path) -> Result<(std::fs::File, std::path::PathBuf), CustodyError> {
    linux::directory(path, false, false)
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_private_directory(file: &std::fs::File) -> Result<(), CustodyError> {
    linux::directory_is_trusted(file, true)
}

#[cfg(target_os = "linux")]
pub(crate) fn trusted_private_file_at(directory: &std::fs::File, name: &std::ffi::OsStr) -> Result<Option<std::fs::File>, CustodyError> {
    linux::opened(directory, name)
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_private_file(file: &std::fs::File) -> Result<(), CustodyError> {
    linux::validate_file(file)
}

// The prover reuses the exact custody ownership/ancestor policy, but never
// creates the caller-selected root or takes the custody publication lock.
#[cfg(all(feature = "sp1-local", target_os = "linux"))]
pub(crate) fn trusted_private_directory(path: &Path) -> Result<(std::fs::File, std::path::PathBuf), CustodyError> {
    linux::directory(path, false, false)
}

/// Open and validate the borrowed key capability without consuming any bytes.
/// The caller owns the fence that permits reading it; this does not publish or sync.
#[cfg(all(feature = "sp1-local", target_os = "linux"))]
pub(crate) fn trusted_backup_key_file(path: &Path) -> Result<std::fs::File, CustodyError> {
    linux::backup_key_file(path)
}

#[cfg(any(feature = "sp1-local", test))]
/// Describe exact bounded encrypted bytes; no decryption or statement authentication.
pub(crate) fn encrypted_file_digest(
    path: impl AsRef<Path>, format: EnvelopeFormat,
) -> Result<[u8; 32], CustodyError> {
    format.max_envelope_bytes()?;
    #[cfg(target_os = "linux")]
    { linux::encrypted_file_digest(path.as_ref(), format) }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(CustodyError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::{OsStr, OsString}, fs::File, io::{Read, Write},
        os::unix::fs::MetadataExt, path::Component,
    };
    use rustix::{
        fs::{AtFlags, FlockOperation, Mode, OFlags, RenameFlags},
        io::Errno,
    };

    fn io_error(error: Errno) -> CustodyError {
        match error {
            Errno::LOOP | Errno::NOTDIR => CustodyError::UnsafePath,
            Errno::NOENT => CustodyError::NotFound,
            _ => CustodyError::Io,
        }
    }

    fn sync(file: &File) -> Result<(), CustodyError> {
        file.sync_all().map_err(|_| CustodyError::Durability)
    }

    pub(super) fn directory_is_trusted(directory: &File, immediate: bool) -> Result<(), CustodyError> {
        let metadata = directory.metadata().map_err(|_| CustodyError::Io)?;
        let owner = rustix::process::geteuid().as_raw();
        let mode = metadata.mode() & 0o7777;
        if !metadata.is_dir()
            || if immediate {
                metadata.uid() != owner || mode != 0o700
            } else {
                (metadata.uid() != 0 && metadata.uid() != owner)
                    || (mode & 0o022 != 0 && !(metadata.uid() == 0 && mode == 0o1777))
            }
        {
            return Err(CustodyError::UnsafePath);
        }
        Ok(())
    }

    fn absolute(path: &Path) -> Result<std::path::PathBuf, CustodyError> {
        if path.components().any(|component| matches!(component, Component::ParentDir)) {
            return Err(CustodyError::UnsafePath);
        }
        let absolute = if path.is_absolute() { path.to_owned() } else {
            std::env::current_dir().map_err(|_| CustodyError::Io)?.join(path)
        };
        if absolute.components().any(|component| matches!(component, Component::ParentDir)) {
            return Err(CustodyError::UnsafePath);
        }
        Ok(absolute)
    }

    pub(super) fn directory(path: &Path, create: bool, durable: bool) -> Result<(File, std::path::PathBuf), CustodyError> {
        let absolute = absolute(path)?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let mut directory: File = rustix::fs::open("/", flags, Mode::empty()).map_err(io_error)?.into();
        directory_is_trusted(&directory, false)?;
        if durable { sync(&directory)?; }
        for component in absolute.components() {
            let child_name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => name,
                _ => return Err(CustodyError::UnsafePath),
            };
            let child = match rustix::fs::openat(&directory, child_name, flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(Errno::NOENT) if create => {
                    match rustix::fs::mkdirat(&directory, child_name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                        Ok(()) | Err(Errno::EXIST) => {},
                        Err(error) => return Err(io_error(error)),
                    }
                    rustix::fs::openat(&directory, child_name, flags, Mode::empty()).map_err(io_error)?
                },
                Err(error) => return Err(io_error(error)),
            };
            let child: File = child.into();
            directory_is_trusted(&child, false)?;
            // Every accepted entry (including existing and mkdir-EEXIST) must cross both
            // barriers before descent; a previous failed initializer is not proof of sync.
            if durable {
                sync(&child)?;
                sync(&directory)?;
            }
            directory = child;
        }
        directory_is_trusted(&directory, true)?;
        Ok((directory, absolute))
    }

    fn parent(path: &Path, create: bool) -> Result<(File, OsString), CustodyError> {
        let absolute = absolute(path)?;
        let name = absolute.file_name().ok_or(CustodyError::UnsafePath)?.to_owned();
        // Dot-prefixed entries are exclusively uncommitted staging, never caller
        // finals. Otherwise a valid final could be renamed away as another's stage.
        if std::os::unix::ffi::OsStrExt::as_bytes(name.as_os_str()).first() == Some(&b'.') {
            return Err(CustodyError::UnsafePath);
        }
        let path = absolute.parent().ok_or(CustodyError::UnsafePath)?;
        let (directory, _) = directory(path, create, true)?;
        // ponytail: one blocking directory-wide publication lock; use per-artifact locks
        // only if real concurrent batch throughput needs them. Drop releases on all errors.
        rustix::fs::flock(&directory, FlockOperation::LockExclusive).map_err(io_error)?;
        directory_is_trusted(&directory, true)?;
        Ok((directory, name))
    }

    pub(super) fn validate_file(file: &File) -> Result<(), CustodyError> {
        validate_file_owner(file, rustix::process::geteuid().as_raw())
    }

    fn validate_file_owner(file: &File, owner: u32) -> Result<(), CustodyError> {
        let metadata = file.metadata().map_err(|_| CustodyError::Io)?;
        if !metadata.is_file() || metadata.uid() != owner
            || metadata.nlink() != 1 || metadata.mode() & 0o7777 != 0o600
        {
            return Err(CustodyError::UnsafePath);
        }
        Ok(())
    }

    #[cfg(test)]
    #[test]
    fn private_file_rejects_different_effective_owner() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let root = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp").unwrap();
        let file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(root.path().join("key")).unwrap();
        let owner = rustix::process::geteuid().as_raw();
        assert!(validate_file_owner(&file, owner).is_ok());
        assert!(matches!(validate_file_owner(&file, owner.wrapping_add(1)), Err(CustodyError::UnsafePath)));
    }

    pub(super) fn opened(directory: &File, name: &OsStr) -> Result<Option<File>, CustodyError> {
        match rustix::fs::openat(directory, name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK, Mode::empty())
        {
            Ok(fd) => {
                let file: File = fd.into();
                validate_file(&file)?;
                Ok(Some(file))
            },
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(io_error(error)),
        }
    }

    #[cfg(feature = "sp1-local")]
    pub(super) fn backup_key_file(path: &Path) -> Result<File, CustodyError> {
        let absolute = absolute(path)?;
        let name = absolute.file_name().ok_or(CustodyError::UnsafePath)?;
        let parent = absolute.parent().ok_or(CustodyError::UnsafePath)?;
        let (directory, _) = directory(parent, false, false)?;
        let file = opened(&directory, name)?.ok_or(CustodyError::NotFound)?;
        if file.metadata().map_err(|_| CustodyError::Io)?.len() != 32 {
            return Err(CustodyError::Encoding);
        }
        Ok(file)
    }

    fn read(file: &File, format: EnvelopeFormat) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
        let length = file.metadata().map_err(|_| CustodyError::Io)?.len();
        if length > format.max_envelope_bytes()? as u64 {
            return Err(CustodyError::ResourceLimit);
        }
        // Fixed guarded storage: a file growing after metadata must not cause a
        // filled buffer to reallocate and free unwiped bytes on this read path.
        let mut bytes = Zeroizing::new(vec![0; length as usize]);
        let mut reader = file;
        reader.read_exact(&mut bytes).map_err(|_| CustodyError::Io)?;
        let mut extra = Zeroizing::new([0; 1]);
        if reader.read(&mut *extra).map_err(|_| CustodyError::Io)? != 0 {
            return Err(CustodyError::Io);
        }
        Ok(bytes)
    }

    #[cfg(any(feature = "sp1-local", test))]
    pub(super) fn encrypted_file_digest(path: &Path, format: EnvelopeFormat) -> Result<[u8; 32], CustodyError> {
        let absolute = absolute(path)?;
        let name = absolute.file_name().ok_or(CustodyError::UnsafePath)?;
        let parent = absolute.parent().ok_or(CustodyError::UnsafePath)?;
        let (directory, _) = directory(parent, false, false)?;
        let file = opened(&directory, name)?.ok_or(CustodyError::NotFound)?;
        let bytes = read(&file, format)?;
        Ok(<sha2::Sha256 as sha2::Digest>::digest(&*bytes).into())
    }

    fn finish_publication(parent: &File, staging_name: &OsStr, name: &OsStr) -> Result<(), CustodyError> {
        rustix::fs::renameat_with(parent, staging_name, parent, name, RenameFlags::NOREPLACE)
            .map_err(|error| if error == Errno::EXIST { CustodyError::Conflict } else { io_error(error) })?;
        // A failed barrier after installation leaves final untouched. An authenticated
        // identical retry syncs file and parent rather than replacing its only copy.
        sync(parent)
    }

    pub(super) fn save(
        path: &Path, key: &[u8; 32], namespace: [u8; 32], context: [u8; 32],
        format: EnvelopeFormat, mut plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<(), CustodyError> {
        let (parent, name) = parent(path, true)?;
        if let Some(final_file) = opened(&parent, &name)? {
            let mut envelope = read(&final_file, format)?;
            decrypt(&mut envelope, key, namespace, context, format)?;
            let end = envelope.len() - TAG_LEN;
            if !bool::from(envelope[format.header_len()..end].ct_eq(&plaintext)) { return Err(CustodyError::Conflict); }
            sync(&final_file)?;
            return sync(&parent);
        }
        let mut staging_name = OsString::from(".");
        staging_name.push(&name);
        staging_name.push(".pending");
        if let Some(stage) = opened(&parent, &staging_name)? {
            let mut envelope = read(&stage, format)?;
            match envelope_shape(&envelope, format) {
                Ok(EnvelopeShape::Complete) => {
                    decrypt(&mut envelope, key, namespace, context, format)?;
                    let end = envelope.len() - TAG_LEN;
                    if !bool::from(envelope[format.header_len()..end].ct_eq(&plaintext)) { return Err(CustodyError::Conflict); }
                    sync(&stage)?;
                    return finish_publication(&parent, &staging_name, &name);
                },
                Ok(EnvelopeShape::Incomplete) => {
                    // Only a reserved, owner-private, known interrupted envelope can be
                    // removed; complete authentication failures/unknown bytes stay intact.
                    rustix::fs::unlinkat(&parent, &staging_name, AtFlags::empty()).map_err(io_error)?;
                    sync(&parent)?;
                },
                Err(CustodyError::UnsupportedVersion) => return Err(CustodyError::UnsupportedVersion),
                Err(_) => return Err(CustodyError::Conflict),
            }
        }
        let header_len = format.header_len();
        let mut header = [0; MAX_HEADER_LEN];
        let header = &mut header[..header_len];
        header[..format.domain.len()].copy_from_slice(format.domain);
        OsRng.try_fill_bytes(&mut header[format.domain.len()..format.domain.len() + NONCE_LEN])
            .map_err(|_| CustodyError::Io)?;
        let cipher_len = plaintext.len().checked_add(TAG_LEN).ok_or(CustodyError::ResourceLimit)?;
        let cipher_len = u32::try_from(cipher_len).map_err(|_| CustodyError::ResourceLimit)?;
        header[header_len - 4..].copy_from_slice(&cipher_len.to_le_bytes());
        let authenticated = aad(header, namespace, context);
        // Detached AEAD never reserves or grows a buffer already holding secrets.
        let tag = XChaCha20Poly1305::new(key.into()).encrypt_in_place_detached(
            XNonce::from_slice(&header[format.domain.len()..format.domain.len() + NONCE_LEN]),
            &authenticated[..header_len + 64],
            &mut plaintext,
        ).map_err(|_| CustodyError::Authentication)?;
        let mut stage: File = rustix::fs::openat(&parent, &staging_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        ).map_err(io_error)?.into();
        validate_file(&stage)?;
        stage.write_all(header).map_err(|_| CustodyError::Io)?;
        stage.write_all(&plaintext).map_err(|_| CustodyError::Io)?;
        stage.write_all(&tag).map_err(|_| CustodyError::Io)?;
        sync(&stage)?;
        finish_publication(&parent, &staging_name, &name)
    }

    pub(super) fn load(
        path: &Path, key: &[u8; 32], namespace: [u8; 32], context: [u8; 32], format: EnvelopeFormat,
    ) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), CustodyError> {
        let (parent, name) = parent(path, false)?;
        let file = opened(&parent, &name)?.ok_or(CustodyError::NotFound)?;
        let mut plaintext = read(&file, format)?;
        let digest = <sha2::Sha256 as sha2::Digest>::digest(&*plaintext).into();
        decrypt(&mut plaintext, key, namespace, context, format)?;
        // Recovery completes a formerly indeterminate publication before success.
        sync(&file)?;
        sync(&parent)?;
        let end = plaintext.len() - TAG_LEN;
        let length = end - format.header_len();
        plaintext.copy_within(format.header_len()..end, 0);
        plaintext[length..].zeroize();
        plaintext.truncate(length);
        Ok((plaintext, digest))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod publisher_tests {
    use super::*;
    use std::{fs, fs::OpenOptions, io::Write, os::unix::fs::{OpenOptionsExt, PermissionsExt}};

    const KEY: [u8; 32] = [0x41; 32];
    const NAMESPACE: [u8; 32] = [0x42; 32];
    const CONTEXT: [u8; 32] = [0x43; 32];
    const FORMATS: [EnvelopeFormat; 5] = [
        NATIVE_FORMAT,
        EnvelopeFormat { domain: b"ziquid.samechain.backup.v1", max_plaintext_bytes: 32 },
        EnvelopeFormat { domain: b"ziquid.samechain.release.v1", max_plaintext_bytes: 32 },
        EnvelopeFormat { domain: RECOVERY_DOMAIN, max_plaintext_bytes: 32 },
        EnvelopeFormat { domain: b"ziquid.native.trade.v1\0", max_plaintext_bytes: 32 },
    ];

    #[test]
    fn native_recovery_domain_is_prefix_disjoint_from_every_retained_format() {
        for domain in PROTECTED_DOMAINS.into_iter().filter(|domain| *domain != RECOVERY_DOMAIN) {
            assert!(!domain.starts_with(RECOVERY_DOMAIN));
            assert!(!RECOVERY_DOMAIN.starts_with(domain));
        }
    }

    fn private_directory() -> tempfile::TempDir {
        tempfile::Builder::new().permissions(fs::Permissions::from_mode(0o700)).tempdir().unwrap()
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn payload(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
        // Exact capacity catches an encryptor that requires spare tag capacity.
        Zeroizing::new(bytes.to_vec().into_boxed_slice().into_vec())
    }

    #[test]
    fn native_aad_preserves_original_header_namespace_and_context_bytes() {
        let header = b"ziquid.u.custody.v3abcdefghijklmnopqrstuvwx\x10\x00\x00\x00";
        let expected = b"ziquid.u.custody.v3abcdefghijklmnopqrstuvwx\x10\x00\x00\x00nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnncccccccccccccccccccccccccccccccc";
        let authenticated = aad(header, [b'n'; 32], [b'c'; 32]);
        assert_eq!(&authenticated[..header.len() + 64], expected);
    }

    #[test]
    fn shared_publisher_full_current_domain_precedes_version_family_protection() {
        for (index, format) in FORMATS.into_iter().enumerate() {
            let mut own_prefix = format.domain.to_vec();
            own_prefix.push(b'0');
            for (requested_index, requested) in FORMATS.into_iter().enumerate() {
                let directory = private_directory();
                let path = directory.path().join("artifact");
                let stage = directory.path().join(".artifact.pending");
                write_private(&stage, &own_prefix);
                if index == requested_index {
                    save_encrypted(&path, &KEY, NAMESPACE, CONTEXT, requested, payload(b"original")).unwrap();
                    assert_eq!(&*load_encrypted(&path, &KEY, NAMESPACE, CONTEXT, requested).unwrap(), b"original");
                } else {
                    assert!(save_encrypted(&path, &KEY, NAMESPACE, CONTEXT, requested, payload(b"original")).is_err());
                    assert_eq!(fs::read(&stage).unwrap(), own_prefix);
                    assert!(!path.exists());
                }
            }
        }
    }

    #[test]
    fn shared_publisher_keeps_exact_bytes_on_retry_and_conflict() {
        for format in FORMATS {
            let directory = private_directory();
            let path = directory.path().join("artifact");
            save_encrypted(&path, &KEY, NAMESPACE, CONTEXT, format, payload(b"opaque payload")).unwrap();
            let original = fs::read(&path).unwrap();
            assert_eq!(&*load_encrypted(&path, &KEY, NAMESPACE, CONTEXT, format).unwrap(), b"opaque payload");
            save_encrypted(&path, &KEY, NAMESPACE, CONTEXT, format, payload(b"opaque payload")).unwrap();
            assert_eq!(fs::read(&path).unwrap(), original);
            assert_eq!(save_encrypted(&path, &KEY, NAMESPACE, CONTEXT, format, payload(b"different")), Err(CustodyError::Conflict));
            assert!(load_encrypted(&path, &[0x44; 32], NAMESPACE, CONTEXT, format).is_err());
            assert!(load_encrypted(&path, &KEY, [0x45; 32], CONTEXT, format).is_err());
            assert!(load_encrypted(&path, &KEY, NAMESPACE, [0x46; 32], format).is_err());
            assert_eq!(fs::read(&path).unwrap(), original);
        }
    }

    #[test]
    fn shared_publisher_preserves_foreign_retained_and_ambiguous_prefixes() {
        for format in FORMATS {
            let directory = private_directory();
            let domains = FORMATS.iter().filter(|other| other.domain != format.domain)
                .map(|other| other.domain).chain([
                    b"ziquid.u.custody.v1".as_slice(), b"ziquid.u.custody.v2".as_slice()]);
            let prefixes = domains.flat_map(|domain| (1..=domain.len()).map(move |length| &domain[..length]));
            let unknown = [b"ziquid.u.custody.v9".as_slice(), b"ziquid.samechain.backup.v9".as_slice(),
                b"ziquid.samechain.release.v9".as_slice(), b"ziquid.nativeR.v9\0".as_slice(), b"unrecognized".as_slice()];
            for (index, bytes) in prefixes.chain(unknown).enumerate() {
                let path = directory.path().join(format!("artifact-{index}"));
                let stage = directory.path().join(format!(".artifact-{index}.pending"));
                write_private(&stage, bytes);
                assert!(save_encrypted(&path, &KEY, NAMESPACE, CONTEXT, format, payload(b"requested")).is_err());
                assert_eq!(fs::read(&stage).unwrap(), bytes);
                assert!(!path.exists());
            }
        }
    }

    #[test]
    fn shared_publisher_preserves_complete_other_format_in_all_directions() {
        for (source_format, requested_format) in FORMATS.into_iter().flat_map(|source|
            FORMATS.into_iter().filter(move |requested| requested.domain != source.domain)
                .map(move |requested| (source, requested))) {
            let directory = private_directory();
            let source = directory.path().join("source");
            save_encrypted(&source, &KEY, NAMESPACE, CONTEXT, source_format, payload(b"original")).unwrap();
            let original = fs::read(&source).unwrap();
            assert!(load_encrypted(&source, &KEY, NAMESPACE, CONTEXT, requested_format).is_err());
            assert!(save_encrypted(&source, &KEY, NAMESPACE, CONTEXT, requested_format, payload(b"requested")).is_err());
            assert_eq!(fs::read(&source).unwrap(), original);
            let path = directory.path().join("resumed");
            let stage = directory.path().join(".resumed.pending");
            write_private(&stage, &original);
            assert!(save_encrypted(&path, &KEY, NAMESPACE, CONTEXT, requested_format, payload(b"requested")).is_err());
            assert_eq!(fs::read(&stage).unwrap(), original);
            assert!(!path.exists());
        }
    }

    #[test]
    fn shared_publisher_reuses_complete_stage_and_discards_only_own_incomplete_stage() {
        for format in FORMATS {
            let directory = private_directory();
            let source = directory.path().join("source");
            save_encrypted(&source, &KEY, NAMESPACE, CONTEXT, format, payload(b"original")).unwrap();
            let original = fs::read(&source).unwrap();
            for (index, bytes) in [b"".as_slice(), format.domain, &original[..original.len() - 1], original.as_slice()].into_iter().enumerate() {
                let path = directory.path().join(format!("artifact-{index}"));
                let stage = directory.path().join(format!(".artifact-{index}.pending"));
                write_private(&stage, bytes);
                save_encrypted(&path, &KEY, NAMESPACE, CONTEXT, format, payload(b"original")).unwrap();
                assert!(!stage.exists());
                assert_eq!(&*load_encrypted(&path, &KEY, NAMESPACE, CONTEXT, format).unwrap(), b"original");
                if bytes.len() == original.len() { assert_eq!(fs::read(&path).unwrap(), original); }
            }
            let path = directory.path().join("tampered");
            let stage = directory.path().join(".tampered.pending");
            let mut tampered = original.clone();
            *tampered.last_mut().unwrap() ^= 1;
            write_private(&stage, &tampered);
            assert_eq!(save_encrypted(&path, &KEY, NAMESPACE, CONTEXT, format, payload(b"original")), Err(CustodyError::Authentication));
            assert_eq!(fs::read(&stage).unwrap(), tampered);
            assert!(!path.exists());
        }
    }

    #[test]
    fn shared_publisher_checks_plaintext_bound_before_filesystem_changes() {
        for format in FORMATS {
            let format = EnvelopeFormat { max_plaintext_bytes: 32, ..format };
            let directory = private_directory();
            let path = directory.path().join("not-created/artifact");
            assert_eq!(save_encrypted(&path, &KEY, NAMESPACE, CONTEXT, format, payload(&[0x47; 33])), Err(CustodyError::ResourceLimit));
            assert!(!path.parent().unwrap().exists());
            let exact = directory.path().join("exact");
            save_encrypted(&exact, &KEY, NAMESPACE, CONTEXT, format, payload(&[0x47; 32])).unwrap();
            assert_eq!(&*load_encrypted(&exact, &KEY, NAMESPACE, CONTEXT, format).unwrap(), &[0x47; 32]);
        }
    }

    #[cfg(feature = "sp1-local")]
    #[test]
    fn trusted_backup_key_file_opens_without_consuming_bytes_or_inheriting_descriptor() {
        use std::io::{Read, Seek};
        let directory = private_directory();
        let path = directory.path().join("generated-key");
        let mut generated = [0; 32]; getrandom::fill(&mut generated).unwrap();
        write_private(&path, &generated);
        let mut file = trusted_backup_key_file(&path).unwrap();
        assert_eq!(file.stream_position().unwrap(), 0);
        assert!(rustix::io::fcntl_getfd(&file).unwrap().contains(rustix::io::FdFlags::CLOEXEC));
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "custody::publisher_tests::trusted_backup_key_file_exec_child", "--nocapture"])
            .env("Z2Z_CUSTODY_KEY_CLOEXEC_CHILD", &path).status().unwrap();
        assert!(status.success());
        let mut actual = Zeroizing::new([0; 32]);
        file.read_exact(&mut *actual).unwrap();
        assert_eq!(&*actual, &generated);
        assert!(!directory.path().join(".generated-key.pending").exists());
    }

    #[cfg(feature = "sp1-local")]
    #[test]
    fn trusted_backup_key_file_exec_child() {
        let Some(path) = std::env::var_os("Z2Z_CUSTODY_KEY_CLOEXEC_CHILD") else { return; };
        for entry in fs::read_dir("/proc/self/fd").unwrap() {
            let entry = entry.unwrap();
            if let Ok(target) = fs::read_link(entry.path()) {
                assert_ne!(target.as_os_str(), path.as_os_str(), "private key descriptor survived exec");
            }
        }
    }

    #[cfg(feature = "sp1-local")]
    #[test]
    fn trusted_backup_key_file_rejects_unsafe_paths_links_modes_and_nonexact_length() {
        use std::os::unix::fs::symlink;
        let directory = private_directory();
        let path = directory.path().join("generated-key");
        write_private(&path, &[0; 32]);
        let link = directory.path().join("symlink"); symlink(&path, &link).unwrap();
        assert_eq!(trusted_backup_key_file(&link).err(), Some(CustodyError::UnsafePath));
        let hard = directory.path().join("hardlink"); fs::hard_link(&path, &hard).unwrap();
        assert_eq!(trusted_backup_key_file(&path).err(), Some(CustodyError::UnsafePath));
        fs::remove_file(&hard).unwrap();
        for mode in [0o640, 0o644] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(trusted_backup_key_file(&path).err(), Some(CustodyError::UnsafePath));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        for length in [0, 31, 33] {
            let wrong = directory.path().join(format!("wrong-{length}"));
            write_private(&wrong, &vec![0; length]);
            assert_eq!(trusted_backup_key_file(&wrong).err(), Some(CustodyError::Encoding));
        }
        let missing = directory.path().join("missing-parent/key");
        assert_eq!(trusted_backup_key_file(&missing).err(), Some(CustodyError::NotFound));
        assert!(!missing.parent().unwrap().exists());
        assert_eq!(trusted_backup_key_file(directory.path()).err(), Some(CustodyError::UnsafePath));
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(trusted_backup_key_file(&path).err(), Some(CustodyError::UnsafePath));
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let hostile = directory.path().join("hostile"); fs::create_dir(&hostile).unwrap();
        fs::set_permissions(&hostile, fs::Permissions::from_mode(0o770)).unwrap();
        let private = hostile.join("private"); fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        let nested = private.join("key"); write_private(&nested, &[0; 32]);
        assert_eq!(trusted_backup_key_file(&nested).err(), Some(CustodyError::UnsafePath));
    }

    #[test]
    fn encrypted_file_digest_matches_exact_authenticated_read_for_all_domains() {
        for format in FORMATS {
            let directory = private_directory();
            let path = directory.path().join("capsule");
            save_encrypted(&path, &KEY, NAMESPACE, CONTEXT, format, payload(b"generated payload")).unwrap();
            let digest = encrypted_file_digest(&path, format).unwrap();
            let original = fs::read(&path).unwrap();
            assert_eq!(digest, <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&original)));
            let (plaintext, authenticated_digest) = load_encrypted_with_digest(&path, &KEY, NAMESPACE, CONTEXT, format).unwrap();
            assert_eq!(digest, authenticated_digest);
            assert_eq!(&*plaintext, b"generated payload");
            assert_eq!(fs::read(&path).unwrap(), original);
        }
    }

    #[test]
    fn encrypted_file_digest_rejects_untrusted_paths_and_oversize_without_decrypting() {
        use std::os::unix::fs::symlink;
        let directory = private_directory();
        let format = FORMATS[2];
        let path = directory.path().join("ciphertext");
        // This intentionally isn't an authenticated envelope: keyless digesting
        // describes exact bounded file bytes and cannot certify their statement.
        write_private(&path, b"opaque ciphertext");
        assert_eq!(encrypted_file_digest(&path, format).unwrap(),
            <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(b"opaque ciphertext")));
        let missing = directory.path().join("missing-parent/capsule");
        assert_eq!(encrypted_file_digest(&missing, format), Err(CustodyError::NotFound));
        assert!(!missing.parent().unwrap().exists());
        let link = directory.path().join("symlink"); symlink(&path, &link).unwrap();
        assert_eq!(encrypted_file_digest(&link, format), Err(CustodyError::UnsafePath));
        let hard = directory.path().join("hardlink"); fs::hard_link(&path, &hard).unwrap();
        assert_eq!(encrypted_file_digest(&path, format), Err(CustodyError::UnsafePath));
        fs::remove_file(hard).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(encrypted_file_digest(&path, format), Err(CustodyError::UnsafePath));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let oversized = directory.path().join("oversized");
        write_private(&oversized, &vec![0; format.max_envelope_bytes().unwrap() + 1]);
        assert_eq!(encrypted_file_digest(&oversized, format), Err(CustodyError::ResourceLimit));
        let unknown = EnvelopeFormat { domain: b"unknown", max_plaintext_bytes: 32 };
        assert_eq!(encrypted_file_digest(&path, unknown), Err(CustodyError::UnsupportedVersion));
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(encrypted_file_digest(&path, format), Err(CustodyError::UnsafePath));
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
}
