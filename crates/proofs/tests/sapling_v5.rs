//! Genuine original NU5 cryptography, not accepted history or settlement.
// Original block-test-1-842-421.txt, Zebra
// e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291; original Git blob
// 1e77de6e1177bd03326d4d2b10bffacf00d06ac4, decoded12367bytes,
// SHA256d0a3527c87773aaaa061320e5eb9ced29966cd1649e0eb0dce0b5365c41c70d1.
/*
Copyright (c) 2019-2025 Zcash Foundation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

use zcash_protocol::consensus::TEST_NETWORK;
use ziquid_proofs::{history::ParsedBlockBody,zip244::{PostNu5SignatureHash,verify_sapling_post_nu5_crypto},sapling_crypto::SaplingCryptoError};
#[test]
fn original_mixed_v5_sapling_crypto_uses_complete_zip244_sighash(){
 let raw=include_bytes!("fixtures/testnet-nu5-block-1842421.bin");let body=ParsedBlockBody::parse(raw,&TEST_NETWORK).unwrap();
 let original=body.block().vtx().iter().find(|tx|tx.sapling_bundle().is_some()&&tx.orchard_bundle().is_some()).expect("original mixed Sapling Orchard transaction");
 assert!(original.transparent_bundle().is_none_or(|bundle|bundle.vin.is_empty()));
 let mut bytes=Vec::new();original.write(&mut bytes).unwrap();assert_eq!(raw.windows(bytes.len()).filter(|part|*part==bytes).count(),1);
 let mut input=bytes.as_slice();let tx=zcash_primitives::transaction::Transaction::read(&mut input,zcash_protocol::consensus::BranchId::Nu5).unwrap();assert!(input.is_empty());
 let hashes=PostNu5SignatureHash::new(tx,vec![]).unwrap();assert_eq!(verify_sapling_post_nu5_crypto(&hashes),Ok(()));
 // Changed expiry affects ZIP244 authorization, while retaining every proof.
 bytes[16]^=1;let changed=zcash_primitives::transaction::Transaction::read(bytes.as_slice(),zcash_protocol::consensus::BranchId::Nu5).unwrap();let hashes=PostNu5SignatureHash::new(changed,vec![]).unwrap();
 assert!(matches!(verify_sapling_post_nu5_crypto(&hashes),Err(SaplingCryptoError::InvalidSpendAuthSignature{..})|Err(SaplingCryptoError::InvalidBindingSignature)));
}
