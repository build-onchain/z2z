//! Local qualification of the real sender-ciphertext subrelation using a generated
//! V3 cryptographic fixture, NOT actual source-chain evidence or a settlement proof.
//! --features sp1-execute runs only the CPU guest; sp1-local enables real Groth16.

#[cfg(not(feature = "sp1-execute"))]
fn main() {
    eprintln!("prove_sender requires --features sp1-execute or sp1-local");
    std::process::exit(2);
}

#[cfg(feature = "sp1-execute")]
use {
    orchard::{
        Note,
        keys::{FullViewingKey, Scope, SpendingKey},
        note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
    },
    sp1_primitives::Elf,
    std::{fs, io, path::PathBuf},
    zcash_note_encryption::Domain,
    ziquid_proofs::artifacts::{
        QualificationResult, check_private_environment,
        execution::{execute_private, execute_sender},
        sender_relation::{SenderWitness, derive_output_commitment},
    },
};

#[cfg(feature = "sp1-execute")]
fn generated_witness() -> SenderWitness {
    // Public deterministic test material only, never imported into any wallet.
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);
    let rho = Option::<Rho>::from(Rho::from_bytes(&[0; 32])).unwrap();
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes([9; 32], &rho)).unwrap();
    let note = Option::<Note>::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(42_000),
        rho,
        rseed,
        NoteVersion::V3,
    ))
    .unwrap();
    let memo = [11; 512];
    let encryption = IronwoodNoteEncryption::new(None, note, memo);
    let mut witness = SenderWitness {
        context_digest: [12; 32],
        output_commitment: [0; 32],
        // A PUBLIC fixture blind: not an entropy/privacy qualification. Real callers use CSPRNG.
        secret_blind: [13; 32],
        recipient: recipient.to_raw_address_bytes(),
        value: 42_000,
        rho: [0; 32],
        rseed: [9; 32],
        memo,
        cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
        epk: IronwoodDomain::epk_bytes(encryption.epk()).0,
        enc_ciphertext: encryption.encrypt_note_plaintext(),
    };
    witness.output_commitment = derive_output_commitment(&witness);
    witness
}

#[cfg(feature = "sp1-execute")]
fn main() -> QualificationResult<()> {
    check_private_environment()?;
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or_else(|| {
        io::Error::other("usage: prove_sender execute ELF | prove ELF NEW_OUTPUT_DIR")
    })?;
    let elf_path = args
        .next()
        .ok_or_else(|| io::Error::other("missing ELF path"))?;
    let output = args.next().map(PathBuf::from);
    if args.next().is_some()
        || !matches!(mode.to_str(), Some("execute" | "prove"))
        || (mode == "execute" && output.is_some())
        || (mode == "prove" && output.is_none())
    {
        return Err(
            io::Error::other("usage: prove_sender execute ELF | prove ELF NEW_OUTPUT_DIR").into(),
        );
    }
    let elf = Elf::from(fs::read(elf_path)?);
    let witness = generated_witness();
    if mode == "execute" {
        let result = execute_sender(elf.clone(), &witness)?;
        // Bypass host validation: only an actual nonzero guest exit establishes this
        // negative result. Tool/executor failures propagate, never masquerade as rejection.
        let mut tampered = witness.encode_private();
        *tampered.last_mut().expect("fixed private input") ^= 1;
        let altered = execute_private(elf, &tampered)?;
        if altered.exit_code == 0 || !altered.journal.is_empty() {
            return Err(io::Error::other("guest accepted altered AEAD ciphertext").into());
        }
        println!(
            "Generated V3 fixture: guest journal matched reference; altered AEAD rejected with exit={}. instructions={}. No proof or chain-validity claim.",
            altered.exit_code, result.instructions,
        );
    } else {
        #[cfg(feature = "sp1-local")]
        let certificate = {
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(ziquid_proofs::artifacts::local::prove_sender(elf, &witness))?
        };
        #[cfg(not(feature = "sp1-local"))]
        return Err(io::Error::other("Groth16 proving requires --features sp1-local").into());
        #[cfg(feature = "sp1-local")]
        {
            use ziquid_proofs::artifacts::local::verify_certificate;
            let expected = ziquid_proofs::artifacts::sender_relation::verify_sender(&witness)?;
            let mut altered = expected;
            altered[ziquid_proofs::artifacts::sender_relation::JOURNAL_DOMAIN.len()] ^= 1;
            if verify_certificate(&certificate, &certificate.program_vkey, &altered).is_ok() {
                return Err(io::Error::other("certificate accepted altered context").into());
            }
            let output = output.unwrap();
            fs::create_dir(&output)?;
            fs::write(output.join("proof.bin"), &certificate.proof_bytes)?;
            fs::write(output.join("journal.bin"), certificate.journal)?;
            fs::write(output.join("program-vkey.txt"), &certificate.program_vkey)?;
            println!(
                "Generated V3 fixture: local Groth16 wrapped and pairing-verified for caller ELF; changed context rejected. Only proof/journal/vkey published. Independent trusted program pin still required; not settlement or chain evidence.",
            );
        }
    }
    Ok(())
}
