//! Genuine Canopy ciphertext reused through finite NU6.3 recovery heights, not later mining.
// Original block-test-1-101-629.txt, Zebra
// e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291, Git blob
// 94f120657e2ab74cd99b57159aaf7e4fad94be41.
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
use ziquid_proofs::{
    history::ParsedBlockBody,
    sapling_coinbase::{CoinbaseRecoveryError, recover_sapling_coinbase_output},
};

#[test]
fn original_sapling_zero_ovk_output_remains_recoverable_through_finite_nu63() {
    let body = ParsedBlockBody::parse(
        include_bytes!("fixtures/testnet-canopy-block-1101629.bin"), &TEST_NETWORK,
    ).unwrap();
    let output = &body.block().vtx()[0].sapling_bundle().unwrap().shielded_outputs()[0];
    // Reuse the exact old output as a ciphertext subrelation only: no claim
    // that its original transaction/block was mined at any of these heights.
    for height in [1_842_419, 1_842_420, 2_121_199, 2_121_200, 2_975_999, 2_976_000, 3_395_999, 3_396_000, 3_536_499, 3_536_500, 4_048_499, 4_048_500, 4_051_999, 4_052_000, 4_133_999, 4_134_000, 4_465_025] {
        assert_eq!(recover_sapling_coinbase_output(output, height), Ok(500_000_000));
    }
    assert_eq!(recover_sapling_coinbase_output(output, 4_465_026), Err(CoinbaseRecoveryError::UnsupportedEra));
}
