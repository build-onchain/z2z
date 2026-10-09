//! Transport-only plaintext custody. Never reads a financial capability.
use super::{Error, Result};
use crate::custody;
use libp2p::identity::{Keypair, ed25519};
use rustix::{fs::{FlockOperation, Mode, OFlags, RenameFlags}, io::Errno};
use std::{
    ffi::OsString, fs::File, io::{Read, Write}, os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf}, thread, time::{Duration, Instant},
};
use zeroize::Zeroizing;

const DOMAIN: &[u8; 18] = b"Z2Z_PEER_IDENTITY\0";
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_RETRY: Duration = Duration::from_millis(10);

fn path_error(error: custody::CustodyError) -> Error {
    match error {
        custody::CustodyError::Io => Error::IdentityIo,
        custody::CustodyError::Durability => Error::IdentityDurability,
        _ => Error::IdentityPath,
    }
}

fn selected_path(path: &Path) -> Result<PathBuf> {
    if path.components().any(|part| matches!(part, Component::ParentDir)) {
        return Err(Error::IdentityPath);
    }
    let path = if path.is_absolute() { path.to_owned() } else {
        std::env::current_dir().map_err(|_| Error::IdentityPath)?.join(path)
    };
    let path: PathBuf = path.components().filter(|part| !matches!(part, Component::CurDir)).collect();
    let name = path.file_name().ok_or(Error::IdentityPath)?;
    if name.as_bytes().first() == Some(&b'.') { return Err(Error::IdentityPath); }
    // Compile-time checkout and actual executable output, not a caller-controlled
    // runtime environment override. Secure directory traversal rejects symlink aliases.
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2)
        .ok_or(Error::IdentityPath)?;
    let executable = std::env::current_exe().map_err(|_| Error::IdentityPath)?;
    let mut output = executable.parent().ok_or(Error::IdentityPath)?;
    if output.file_name().is_some_and(|name| name == "deps") {
        output = output.parent().ok_or(Error::IdentityPath)?;
    }
    if output.file_name().is_some_and(|name| name == "debug" || name == "release") {
        output = output.parent().ok_or(Error::IdentityPath)?;
    }
    if path.starts_with(checkout) || path.starts_with(output) {
        return Err(Error::IdentityPath);
    }
    if let Some(target) = option_env!("CARGO_TARGET_DIR") {
        let target = Path::new(target);
        let target = if target.is_absolute() { target.to_owned() } else { checkout.join(target) };
        if path.starts_with(target) { return Err(Error::IdentityPath); }
    }
    Ok(path)
}

fn lock_until(file: &File, exclusive: bool, deadline: Instant) -> Result<()> {
    let operation = if exclusive { FlockOperation::NonBlockingLockExclusive }
        else { FlockOperation::NonBlockingLockShared };
    loop {
        if Instant::now() >= deadline { return Err(Error::IdentityLock); }
        match rustix::fs::flock(file, operation) {
            Ok(()) => return Ok(()),
            Err(Errno::AGAIN | Errno::INTR) => {
                thread::sleep(LOCK_RETRY.min(deadline.saturating_duration_since(Instant::now())));
            }
            Err(_) => return Err(Error::IdentityLock),
        }
    }
}

fn read_frame(file: &File) -> Result<Zeroizing<[u8; 52]>> {
    custody::validate_private_file(file).map_err(path_error)?;
    let before = file.metadata().map_err(|_| Error::IdentityIo)?;
    if before.len() != 52 { return Err(Error::IdentityEncoding); }
    #[cfg(test)]
    faults::before_read(file)?;
    let mut frame = Zeroizing::new([0; 52]);
    let mut reader = file;
    reader.read_exact(&mut frame[..]).map_err(|_| Error::IdentityIo)?;
    let mut extra = Zeroizing::new([0; 1]);
    if reader.read(&mut extra[..]).map_err(|_| Error::IdentityIo)? != 0
        || &frame[..18] != DOMAIN || frame[18..20] != [0, 1]
    { return Err(Error::IdentityEncoding); }
    #[cfg(test)]
    faults::after_read(file)?;
    custody::validate_private_file(file).map_err(path_error)?;
    let after = file.metadata().map_err(|_| Error::IdentityIo)?;
    if before.len() != after.len() || before.dev() != after.dev() || before.ino() != after.ino()
        || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec()
    { return Err(Error::IdentityPath); }
    Ok(frame)
}

fn sync(file: &File, parent: bool) -> Result<()> {
    #[cfg(test)]
    faults::sync(parent)?;
    #[cfg(not(test))]
    let _ = parent;
    file.sync_all().map_err(|_| Error::IdentityDurability)
}

fn entropy(seed: &mut [u8]) -> Result<()> {
    #[cfg(test)]
    faults::entropy()?;
    getrandom::fill(seed).map_err(|_| Error::IdentityIo)
}

fn publish(directory: &File, stage: &std::ffi::OsStr, name: &std::ffi::OsStr) -> Result<()> {
    #[cfg(test)]
    faults::before_rename(directory, name)?;
    match rustix::fs::renameat_with(directory, stage, directory, name, RenameFlags::NOREPLACE) {
        Ok(()) | Err(Errno::EXIST) => sync(directory, true),
        Err(_) => Err(Error::IdentityIo),
    }
}

pub(super) fn load_or_create(path: &Path) -> Result<Keypair> {
    let deadline = Instant::now() + LOCK_TIMEOUT;
    let path = selected_path(path)?;
    let name = path.file_name().ok_or(Error::IdentityPath)?;
    let (directory, _) = custody::trusted_existing_private_directory(
        path.parent().ok_or(Error::IdentityPath)?,
    ).map_err(path_error)?;
    lock_until(&directory, true, deadline)?;
    custody::validate_private_directory(&directory).map_err(path_error)?;
    if custody::trusted_private_file_at(&directory, name).map_err(path_error)?.is_none() {
        let mut staging_name = OsString::from(".");
        staging_name.push(name);
        staging_name.push(".pending");
        if let Some(stage) = custody::trusted_private_file_at(&directory, &staging_name).map_err(path_error)? {
            lock_until(&stage, true, deadline)?;
            let _frame = read_frame(&stage)?;
            sync(&stage, false)?;
            publish(&directory, &staging_name, name)?;
        } else {
            let mut frame = Zeroizing::new([0; 52]);
            frame[..18].copy_from_slice(DOMAIN);
            frame[18..20].copy_from_slice(&1_u16.to_be_bytes());
            entropy(&mut frame[20..])?;
            let mut stage: File = rustix::fs::openat(&directory, &staging_name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            ).map_err(|_| Error::IdentityIo)?.into();
            custody::validate_private_file(&stage).map_err(path_error)?;
            lock_until(&stage, true, deadline)?;
            #[cfg(test)]
            faults::write()?;
            stage.write_all(&frame[..]).map_err(|_| Error::IdentityIo)?;
            sync(&stage, false)?;
            publish(&directory, &staging_name, name)?;
        }
    }
    // Stage's exclusive lock has dropped before shared-lock readback of the inode.
    let final_file = custody::trusted_private_file_at(&directory, name).map_err(path_error)?
        .ok_or(Error::IdentityIo)?;
    lock_until(&final_file, false, deadline)?;
    let mut frame = read_frame(&final_file)?;
    sync(&final_file, false)?;
    sync(&directory, true)?;
    let secret = ed25519::SecretKey::try_from_bytes(&mut frame[20..])
        .map_err(|_| Error::IdentityEncoding)?;
    Ok(Keypair::from(ed25519::Keypair::from(secret)))
}

// Thread-local, one-shot failure injection at the actual syscall/entropy boundary.
// No production option, feature flag, storage mock or shared test state.
#[cfg(test)]
mod faults {
    use super::*;
    use std::{cell::Cell, os::unix::fs::PermissionsExt};
    #[derive(Clone, Copy, PartialEq)]
    pub(super) enum Fault { None, Entropy, Write, FileSync, ParentSync, Rename, Winner, Metadata, Eof }
    thread_local! { static NEXT: Cell<Fault> = const { Cell::new(Fault::None) }; }
    pub(super) fn set(fault: Fault) { NEXT.with(|next| next.set(fault)); }
    fn take(fault: Fault) -> bool {
        NEXT.with(|next| if next.get() == fault { next.set(Fault::None); true } else { false })
    }
    pub(super) fn entropy() -> Result<()> {
        if take(Fault::Entropy) { Err(Error::IdentityIo) } else { Ok(()) }
    }
    pub(super) fn write() -> Result<()> {
        if take(Fault::Write) { Err(Error::IdentityIo) } else { Ok(()) }
    }
    pub(super) fn sync(parent: bool) -> Result<()> {
        if take(if parent { Fault::ParentSync } else { Fault::FileSync }) {
            Err(Error::IdentityDurability)
        } else { Ok(()) }
    }
    pub(super) fn before_rename(directory: &File, name: &std::ffi::OsStr) -> Result<()> {
        if take(Fault::Rename) { return Err(Error::IdentityIo); }
        if take(Fault::Winner) {
            let mut winner: File = rustix::fs::openat(directory, name,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ).map_err(|_| Error::IdentityIo)?.into();
            let mut frame = Zeroizing::new([0; 52]);
            frame[..18].copy_from_slice(DOMAIN);
            frame[18..20].copy_from_slice(&[0, 1]);
            getrandom::fill(&mut frame[20..]).map_err(|_| Error::IdentityIo)?;
            winner.write_all(&frame[..]).map_err(|_| Error::IdentityIo)?;
            winner.sync_all().map_err(|_| Error::IdentityDurability)?;
        }
        Ok(())
    }
    pub(super) fn before_read(file: &File) -> Result<()> {
        if take(Fault::Eof) {
            // Only used with the actual writable test descriptor.
            let mut file = file;
            std::io::Seek::seek(&mut file, std::io::SeekFrom::End(0)).map_err(|_| Error::IdentityIo)?;
            file.write_all(&[0]).map_err(|_| Error::IdentityIo)?;
            std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(0)).map_err(|_| Error::IdentityIo)?;
        }
        Ok(())
    }
    pub(super) fn after_read(file: &File) -> Result<()> {
        if take(Fault::Metadata) {
            file.set_permissions(std::fs::Permissions::from_mode(0o400)).map_err(|_| Error::IdentityIo)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, fs::OpenOptions, os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink}};
    use faults::Fault;

    fn root() -> tempfile::TempDir {
        tempfile::Builder::new().prefix("z2z-identity-unit-")
            .permissions(fs::Permissions::from_mode(0o700)).tempdir_in("/tmp").unwrap()
    }
    fn frame() -> Zeroizing<[u8; 52]> {
        let mut frame = Zeroizing::new([0; 52]);
        frame[..18].copy_from_slice(DOMAIN);
        frame[18..20].copy_from_slice(&[0, 1]);
        getrandom::fill(&mut frame[20..]).unwrap();
        frame
    }
    fn save(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    fn bytes(path: &Path) -> Zeroizing<Vec<u8>> {
        let mut file = File::open(path).unwrap();
        let length = usize::try_from(file.metadata().unwrap().len()).unwrap();
        let mut bytes = Zeroizing::new(vec![0; length]);
        file.read_exact(&mut bytes[..]).unwrap();
        bytes
    }
    fn peer(path: &Path) -> libp2p::PeerId { load_or_create(path).unwrap().public().to_peer_id() }

    #[test]
    fn rejects_wrong_length_domain_version_final_and_stage_without_mutation() {
        for stage in [false, true] {
            for kind in 0..7 {
                let root = root();
                let final_path = root.path().join("key");
                let path = root.path().join(if stage { ".key.pending" } else { "key" });
                let valid = frame();
                let mut invalid = Zeroizing::new(vec![0; match kind { 0 => 32, 1 => 64, 2 => 51, 3 => 53, _ => 52 }]);
                let count = invalid.len().min(valid.len());
                invalid[..count].copy_from_slice(&valid[..count]);
                match kind { 4 => invalid[0] ^= 1, 5 => invalid[19] = 2, 6 => invalid[18] = 1, _ => {} }
                save(&path, &invalid);
                assert!(matches!(load_or_create(&final_path), Err(Error::IdentityEncoding)));
                assert!(bytes(&path)[..] == invalid[..], "invalid artifact was modified");
                assert_eq!(final_path.exists(), !stage);
            }
        }
    }

    #[test]
    fn complete_stage_resumes_and_valid_final_ignores_invalid_stage() {
        let root = root();
        let path = root.path().join("key");
        let stage = root.path().join(".key.pending");
        let original = frame();
        save(&stage, &original[..]);
        let first = peer(&path);
        assert!(!stage.exists());
        assert!(bytes(&path)[..] == original[..], "resumption changed selected key");
        save(&stage, b"partial");
        assert_eq!(peer(&path), first);
        assert!(bytes(&stage)[..] == *b"partial");
        assert!(bytes(&path)[..] == original[..], "leftover stage rotated final");
    }

    #[test]
    fn invalid_final_does_not_replace_itself_with_complete_stage() {
        let root = root();
        let path = root.path().join("key");
        let stage = root.path().join(".key.pending");
        let chosen = frame();
        save(&path, b"invalid");
        save(&stage, &chosen[..]);
        assert!(load_or_create(&path).is_err());
        assert!(bytes(&path)[..] == *b"invalid");
        assert!(bytes(&stage)[..] == chosen[..], "invalid final consumed stage");
    }

    #[test]
    fn failure_boundaries_retain_artifacts_and_never_rotate() {
        for fault in [Fault::Entropy, Fault::Write, Fault::FileSync, Fault::Rename, Fault::ParentSync] {
            let root = root();
            let path = root.path().join("key");
            let stage = root.path().join(".key.pending");
            faults::set(fault);
            assert!(load_or_create(&path).is_err());
            if fault == Fault::Entropy {
                assert!(!path.exists() && !stage.exists());
            } else if fault == Fault::Write {
                assert!(!path.exists());
                assert_eq!(stage.metadata().unwrap().len(), 0);
                assert!(load_or_create(&path).is_err());
                assert_eq!(stage.metadata().unwrap().len(), 0);
            } else {
                let installed = if path.exists() { &path } else { &stage };
                let chosen = bytes(installed);
                let first = peer(&path);
                assert_eq!(peer(&path), first);
                assert!(bytes(&path)[..] == chosen[..], "failed barrier changed key on retry");
                assert!(!stage.exists());
            }
        }
    }

    #[test]
    fn noreplace_uses_winning_final_and_retains_losing_stage() {
        let root = root();
        let path = root.path().join("key");
        let stage = root.path().join(".key.pending");
        faults::set(Fault::Winner);
        let first = peer(&path);
        let winner = bytes(&path);
        let loser = bytes(&stage);
        assert!(winner[..] != loser[..], "generated contenders unexpectedly coincide");
        assert_eq!(peer(&path), first);
        assert!(bytes(&path)[..] == winner[..], "winner was overwritten");
        assert!(bytes(&stage)[..] == loser[..], "losing stage was removed");
    }

    #[test]
    fn metadata_and_eof_changes_during_read_reject() {
        for fault in [Fault::Metadata, Fault::Eof] {
            let root = root();
            let path = root.path().join("key");
            save(&path, &frame()[..]);
            let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
            faults::set(fault);
            assert!(read_frame(&file).is_err());
        }
    }

    #[test]
    fn unsafe_files_and_stage_aliases_reject_without_repair() {
        for stage in [false, true] {
            for kind in 0..6 {
                let root = root();
                let path = root.path().join("key");
                let artifact = root.path().join(if stage { ".key.pending" } else { "key" });
                let other = root.path().join("other");
                match kind {
                    0 | 1 => {
                        save(&artifact, &frame()[..]);
                        fs::set_permissions(&artifact, fs::Permissions::from_mode(if kind == 0 { 0o644 } else { 0o4600 })).unwrap();
                    }
                    2 => { save(&other, &frame()[..]); symlink(&other, &artifact).unwrap(); }
                    3 => { save(&other, &frame()[..]); fs::hard_link(&other, &artifact).unwrap(); }
                    4 => { rustix::fs::mknodat(rustix::fs::CWD, &artifact, rustix::fs::FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap(); }
                    _ => { fs::create_dir(&artifact).unwrap(); }
                }
                let before = fs::symlink_metadata(&artifact).unwrap();
                assert!(matches!(load_or_create(&path), Err(Error::IdentityPath)));
                let after = fs::symlink_metadata(&artifact).unwrap();
                assert_eq!((before.ino(), before.len(), before.mode(), before.nlink()),
                    (after.ino(), after.len(), after.mode(), after.nlink()));
                if stage { assert!(!path.exists()); }
            }
        }
    }

    #[test]
    fn traversal_namespace_missing_parent_unsafe_ancestor_and_build_paths_reject() {
        let root = root();
        let parent = root.path().join("parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        for path in [root.path().join(".key"), parent.join("../key"), root.path().join("missing/key"),
            Path::new(env!("CARGO_MANIFEST_DIR")).join("key"),
            std::env::current_exe().unwrap().parent().unwrap().join("key")]
        { assert!(matches!(load_or_create(&path), Err(Error::IdentityPath))); }
        let alias = root.path().join("alias");
        symlink(&parent, &alias).unwrap();
        assert!(load_or_create(&alias.join("key")).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(load_or_create(&parent.join("key")).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for mode in [0o755, 0o1700] {
            fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
            assert!(load_or_create(&parent.join("key")).is_err());
        }
        assert!(!parent.join("key").exists());
    }

    #[test]
    fn existing_final_barrier_failure_retries_same_key_without_entropy() {
        for fault in [Fault::FileSync, Fault::ParentSync] {
            let root = root();
            let path = root.path().join("key");
            let first = peer(&path);
            let chosen = bytes(&path);
            faults::set(fault);
            assert!(matches!(load_or_create(&path), Err(Error::IdentityDurability)));
            assert!(bytes(&path)[..] == chosen[..], "readback barrier failure modified final");
            faults::set(Fault::Entropy);
            assert_eq!(peer(&path), first);
            faults::set(Fault::None);
            assert!(!root.path().join(".key.pending").exists());
        }
    }

    #[test]
    fn complete_stage_does_not_generate_new_entropy() {
        let root = root();
        let path = root.path().join("key");
        let chosen = frame();
        save(&root.path().join(".key.pending"), &chosen[..]);
        faults::set(Fault::Entropy);
        assert!(load_or_create(&path).is_ok());
        faults::set(Fault::None);
        assert!(bytes(&path)[..] == chosen[..], "resume generated replacement key");
    }

    #[test]
    fn held_lock_and_expired_deadline_fail_closed() {
        let root = root();
        let held = File::open(root.path()).unwrap();
        rustix::fs::flock(&held, FlockOperation::NonBlockingLockExclusive).unwrap();
        let contender = File::open(root.path()).unwrap();
        let start = Instant::now();
        assert!(matches!(lock_until(&contender, true, start + Duration::from_millis(30)), Err(Error::IdentityLock)));
        assert!(start.elapsed() >= Duration::from_millis(30));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(matches!(lock_until(&contender, false, Instant::now()), Err(Error::IdentityLock)));
    }
}
