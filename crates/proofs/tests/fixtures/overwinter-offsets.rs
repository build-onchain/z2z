//! Original decoded-byte mutation positions for the recorded V3 transaction.
//! Source bytes/provenance/license are in overwinter-mined.rs. No generated data.
// Source Zebra e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291 block207501:
// https://raw.githubusercontent.com/ZcashFoundation/zebra/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-test/src/vectors/block-test-0-207-501.txt
// Original tx range1854..3771 length1917; SHA256
// 7c7dc59bd131a5d5b25c37f49ac22f87a3e590e75d06b271fc6bacfbf09285f5.
// Positions are relative to that unchanged transaction, not full-block offsets.

// Relative decoded-byte offsets in the original transaction, for field mutations.
pub const MINED_V3_LOCK_TIME_OFFSET: usize = 10;
pub const MINED_V3_EXPIRY_HEIGHT_OFFSET: usize = 14;
pub const MINED_V3_ANCHOR_OFFSET: usize = 35;
pub const MINED_V3_NULLIFIER_OFFSET: usize = 67;
pub const MINED_V3_PROOF_OFFSET: usize = 323;
pub const MINED_V3_CIPHERTEXT_OFFSET: usize = 619;
pub const MINED_V3_PUBKEY_OFFSET: usize = 1821;
pub const MINED_V3_SIGNATURE_OFFSET: usize = 1853;
