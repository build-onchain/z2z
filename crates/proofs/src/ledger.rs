//! Complete genesis-derived Sprout through finite NU6.3 testnet transitions.
//!
//! Implements transactions and contextual rules through height4465025, before NU7.
//! This linear ledger is not all-era consensus, competing-fork selection,
//! local-clock admission, finality, or a financial source fact.
//! Primary rules: zcashd 0512e9eb00f97172346e0fac854625d59771e4f7,
//! `main.cpp`, `coins.cpp`, `coins.h`, and `script/{script,interpreter}`.
//! Original Sapling rules: zcashd e8f5e592b864b341391c9becf80bbe3e0e930a33
//! `main.cpp`, `coins.cpp`, `primitives/transaction.cpp` and ZIP243.
//! Blossom subsidy and Founders rotation: ZIP208 and zcashd
//! 86451a18b016af09a4e33c9acc1aa5577e25af17 `consensus/params.cpp`, `chainparams.cpp`.
//! Heartwood coinbase/replay/history: zcashd 65f0a4736acd9adeb91f11899bcee3439068c771
//! `main.cpp`, `zcash/Note.cpp`, ZIP213/221 and bounded upstream V1 accumulation.
//! The replay esk-to-epk check is a later ungated tightening, not every earliest binary.
//! Canopy: zcashd 5e7e9687fc87a2426bafef2837174eac52978b4c `main.cpp`,
//! `consensus/{params,funding}.cpp`, and original ZIP211/212/214/215.
//! NU5: zcashd 16b49eadd56086aae10f2907e5b8e77b773f1813 `main.cpp`,
//! `coins.cpp`, original ZIP203/216/221/225/244 and raw original Orchard.
//! NU6: original testnet zcashd fefd6232f68438008e28eaf727dd2acf4c38d743
//! `main.cpp`, `primitives/transaction.cpp`, ZIP207/214 Revision1 and ZIP2001.
//! NU6.1: original testnet zcashd 2e2633e5001ac52fb21e1c6379a8e6aa0a65e48e,
//! ZIP214 Revision2/ZIP271; ZIP257 disables Orchard at4048500..4051999.
//! NU6.2: zcashd6966f30a8541b0e5998837dce14250ca9e15b16a and ZIP257;
//! fixed Orchard circuit, canonical nonidentity rk/EPK and exact proof framing.
//! NU6.3: Zebra15d578362448fb8c4a5d29a00dcfe8adb5184082 and ZIP229/258;
//! finite endpoint from NU7 release6d1e414d6f55e4180d0e47baaa934bf97d5b4fec.
//! Value-pool accounting also follows pinned Zebra
//! e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291 RFC0012: claimed pruned outputs
//! remain issued, while unclaimed rewards and fees are not newly issued.

use std::{collections::{BTreeMap, BTreeSet}, fmt};

use corez::io::{self, Write};
use incrementalmerkletree::frontier::Frontier;
use orchard::tree::MerkleHashOrchard;
use sapling_crypto::Node as SaplingNode;
use zcash_primitives::transaction::{Authorized, Transaction, TransactionData, TxVersion};
use zcash_protocol::{
    consensus::{BranchId, TEST_NETWORK},
    value::{MAX_MONEY, ZatBalance, Zatoshis},
};
use zcash_script::{
    interpreter::{CallbackTransactionSignatureChecker, Flags},
    script::{Code, Raw},
    signature::HashType,
};
use zcash_transparent::{address::Script, bundle::TxOut};

use super::{GenesisState, ShieldedPool, SproutNode};
use crate::{
    chain_history::{ChainHistoryV1, ChainHistoryV2, ChainHistoryV3, HistoryError, HistoryLeaf, HistoryLeafV2, HistoryLeafV3},
    header::{HeaderChain, HeaderError, HeaderTip},
    history::{BodyError, ParsedBlockBody},
    legacy_joinsplit::{LegacyJoinSplitError, verify_legacy_joinsplit_crypto, verify_overwinter_joinsplit_crypto, verify_sapling_joinsplit_crypto},
    legacy_sighash::{check_legacy_transaction, legacy_signature_hash},
    overwinter::{OverwinterSignatureHash, check_overwinter_transaction},
    post_nu5_body::{PostNu5Block, PostNu5Transaction},
    orchard_original::{FixedOrchardVerifier, OriginalOrchardVerifier, PostNu63OrchardVerifier},
    raw_v5::{RawOrchard, RawV5, RawV5Error},
    sapling_coinbase::{CoinbaseRecoveryError, recover_ironwood_coinbase_output, recover_sapling_coinbase_output},
    sapling_crypto::{SaplingCryptoError, verify_sapling_v4_crypto},
    sapling_sighash::{SaplingSignatureHash, check_sapling_transaction},
    zip244::{PostNu5Authorization, PostNu5SignatureHash, PostNu63CryptoError, verify_post_nu63_crypto, verify_sapling_post_nu5_crypto},
};

const HEADER_BYTES: usize = 1487;
const MAX_TRANSACTION_BYTES: usize = 100_000;
const MAX_SAPLING_TRANSACTION_BYTES: usize = 2_000_000;
const MAX_SIGOPS: u32 = 20_000;
const SCRIPT_FLAGS: Flags = Flags::P2SH.union(Flags::CHECKLOCKTIMEVERIFY);

// All 48 ordered testnet Founders addresses: zcashd 0512e9eb00f97172346e0fac854625d59771e4f7
// src/chainparams.cpp, Git blob cf47610f602c8d05a60b24485b1640abd24a8c61.
// Offline Base58Check decoding verified every prefix 1cba and SHA256d checksum.
// Only the 20-byte payload is stored; no runtime address parser or allocation.
const FOUNDERS_HASHES: [[u8; 20]; 48] = [
    [0xef, 0x77, 0x5f, 0x1f, 0x99, 0x7f, 0x12, 0x2a, 0x06, 0x2f, 0xff, 0x1a, 0x2d, 0x74, 0x43, 0xab, 0xd1, 0xf9, 0xc6, 0x42], // t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi
    [0xab, 0x13, 0xd4, 0x67, 0x56, 0x30, 0xd6, 0x9f, 0x9c, 0x90, 0x00, 0xc7, 0x01, 0xa9, 0x81, 0x93, 0x8b, 0x0d, 0x58, 0x5d], // t2N9PH9Wk9xjqYg9iin1Ua3aekJqfAtE543
    [0xac, 0x67, 0xf4, 0xc0, 0x72, 0x66, 0x81, 0x38, 0xd8, 0x8a, 0x86, 0xff, 0x21, 0xb2, 0x72, 0x07, 0xb2, 0x83, 0x21, 0x2f], // t2NGQjYMQhFndDHguvUw4wZdNdsssA6K7x2
    [0x55, 0xd6, 0x49, 0x28, 0xe6, 0x98, 0x29, 0xd9, 0x37, 0x6c, 0x77, 0x65, 0x50, 0xb6, 0xcc, 0x71, 0x0d, 0x42, 0x71, 0x53], // t2ENg7hHVqqs9JwU5cgjvSbxnT2a9USNfhy
    [0x39, 0x10, 0xcf, 0x6f, 0x8f, 0xbb, 0xa8, 0x3d, 0xf3, 0x70, 0x1c, 0x54, 0x5e, 0x98, 0x81, 0x6c, 0x98, 0xda, 0x68, 0x4d], // t2BkYdVCHzvTJJUTx4yZB8qeegD8QsPx8bo
    [0x7f, 0x18, 0x65, 0x48, 0x85, 0xa5, 0xe3, 0x4f, 0x2d, 0xc8, 0x37, 0x62, 0xb7, 0x94, 0x48, 0x35, 0xf0, 0xdf, 0x3d, 0xa2], // t2J8q1xH1EuigJ52MfExyyjYtN3VgvshKDf
    [0x45, 0x39, 0x39, 0x52, 0x66, 0x79, 0x3b, 0x8b, 0x28, 0xb3, 0xb5, 0xa3, 0xe8, 0x79, 0x35, 0x97, 0x50, 0x37, 0x0e, 0x6d], // t2Crq9mydTm37kZokC68HzT6yez3t2FBnFj
    [0x58, 0x0b, 0xa4, 0xe2, 0x60, 0xb6, 0x44, 0xda, 0x67, 0xb6, 0x92, 0x6e, 0x07, 0x1e, 0xe5, 0xb9, 0x8a, 0x73, 0xbf, 0xa3], // t2EaMPUiQ1kthqcP5UEkF42CAFKJqXCkXC9
    [0x5e, 0x57, 0x24, 0xaf, 0xa4, 0x84, 0x2d, 0xc5, 0x2f, 0x8b, 0x66, 0xcd, 0xbc, 0xea, 0xfd, 0xff, 0x2d, 0xcf, 0xfb, 0x14], // t2F9dtQc63JDDyrhnfpzvVYTJcr57MkqA12
    [0x97, 0xd9, 0xbe, 0xf6, 0x9a, 0x86, 0x3d, 0x2c, 0x1a, 0x65, 0x05, 0x8c, 0x45, 0xc5, 0x6b, 0x5f, 0xf6, 0x47, 0x22, 0xf7], // t2LPirmnfYSZc481GgZBa6xUGcoovfytBnC
    [0x04, 0x83, 0x4b, 0x51, 0x44, 0x48, 0xb1, 0xff, 0x51, 0x2e, 0x9a, 0x5b, 0x2f, 0xf8, 0xf0, 0xe3, 0x4a, 0x4b, 0x1d, 0x57], // t26xfxoSw2UV9Pe5o3C8V4YybQD4SESfxtp
    [0x47, 0x49, 0x8d, 0x56, 0x9e, 0x26, 0x89, 0x44, 0xc3, 0xb6, 0x99, 0x33, 0x76, 0x00, 0x9d, 0x36, 0x91, 0x40, 0xe3, 0x9a], // t2D3k4fNdErd66YxtvXEdft9xuLoKD7CcVo
    [0x4c, 0x5a, 0xde, 0x3c, 0x46, 0x53, 0x99, 0x98, 0x6b, 0x23, 0x0b, 0x7c, 0xdd, 0xc8, 0x77, 0xc7, 0x28, 0x77, 0xa0, 0x2e], // t2DWYBkxKNivdmsMiivNJzutaQGqmoRjRnL
    [0x3c, 0x51, 0x94, 0x20, 0xbe, 0x27, 0x73, 0x41, 0x56, 0xbf, 0x9e, 0xef, 0x95, 0x24, 0xca, 0xcd, 0xef, 0x28, 0xf0, 0x5a], // t2C3kFF9iQRxfc4B9zgbWo4dQLLqzqjpuGQ
    [0xa7, 0x1e, 0x45, 0x88, 0xc5, 0x0c, 0x86, 0xf4, 0x66, 0x9e, 0x0d, 0xa4, 0x3d, 0xb3, 0x7c, 0xbd, 0x74, 0x28, 0xa9, 0xf2], // t2MnT5tzu9HSKcppRyUNwoTp8MUueuSGNaB
    [0x2a, 0x71, 0xf5, 0x1b, 0x26, 0x8f, 0x74, 0xeb, 0x3e, 0xe5, 0x63, 0x10, 0x90, 0x58, 0x9b, 0xbf, 0x62, 0x39, 0xbc, 0x0c], // t2AREsWdoW1F8EQYsScsjkgqobmgrkKeUkK
    [0xfd, 0x79, 0xe0, 0xc8, 0x4a, 0xca, 0xc2, 0x23, 0x14, 0x2c, 0xf5, 0x03, 0xdc, 0x6a, 0xfd, 0xe2, 0x4a, 0xca, 0xc5, 0x0e], // t2Vf4wKcJ3ZFtLj4jezUUKkwYR92BLHn5UT
    [0x89, 0x16, 0x9b, 0x06, 0x6f, 0x07, 0xb6, 0x0f, 0x31, 0xca, 0x11, 0x62, 0x8b, 0x79, 0x64, 0x31, 0x31, 0x13, 0x68, 0x7e], // t2K3fdViH6R5tRuXLphKyoYXyZhyWGghDNY
    [0xf8, 0xe1, 0xca, 0x5c, 0x1c, 0x77, 0xbf, 0xdf, 0x91, 0x0c, 0xf6, 0x58, 0x1f, 0xf9, 0x6c, 0x8b, 0x08, 0x21, 0x6b, 0x04], // t2VEn3KiKyHSGyzd3nDw6ESWtaCQHwuv9WC
    [0x5e, 0x21, 0xa7, 0x72, 0x4b, 0x9d, 0xd0, 0xdd, 0x3f, 0x4d, 0xf9, 0x70, 0x3c, 0x07, 0x8d, 0xdd, 0xbf, 0xc9, 0x4d, 0x26], // t2F8XouqdNMq6zzEvxQXHV1TjwZRHwRg8gC
    [0x35, 0x94, 0x3a, 0xa4, 0x29, 0x27, 0x3f, 0xe3, 0xf7, 0x8d, 0x50, 0xa0, 0xf2, 0x4c, 0x09, 0xe4, 0xf7, 0x18, 0x4b, 0xde], // t2BS7Mrbaef3fA4xrmkvDisFVXVrRBnZ6Qj
    [0x66, 0xa0, 0x4f, 0xe5, 0xf6, 0xf1, 0xb5, 0xbb, 0x11, 0x49, 0xe6, 0xcd, 0x00, 0x79, 0x16, 0x7f, 0x57, 0x08, 0x80, 0x14], // t2FuSwoLCdBVPwdZuYoHrEzxAb9qy4qjbnL
    [0xdb, 0x0c, 0xf2, 0x66, 0x2b, 0x17, 0x2c, 0xf7, 0x8a, 0xe5, 0x17, 0x1f, 0x89, 0xbc, 0xfb, 0x4a, 0x60, 0x26, 0xd7, 0xa7], // t2SX3U8NtrT6gz5Db1AtQCSGjrpptr8JC6h
    [0xf7, 0x09, 0x04, 0xc3, 0xa9, 0xd3, 0xf0, 0xe8, 0x65, 0xb6, 0x7e, 0xc2, 0x37, 0x5c, 0x93, 0xa4, 0xeb, 0x66, 0x65, 0x39], // t2V51gZNSoJ5kRL74bf9YTtbZuv8Fcqx2FH
    [0x67, 0x62, 0xbf, 0x1d, 0x30, 0x27, 0xf7, 0xdb, 0xc7, 0x33, 0xb9, 0xdd, 0x29, 0xf8, 0xc9, 0x87, 0x2f, 0xe0, 0xf6, 0xd7], // t2FyTsLjjdm4jeVwir4xzj7FAkUidbr1b4R
    [0x57, 0xb6, 0x65, 0x61, 0x8c, 0xe4, 0x3b, 0xaa, 0x72, 0xeb, 0xf8, 0xb7, 0xe4, 0x19, 0x8e, 0x6c, 0xfa, 0x52, 0xc7, 0x66], // t2EYbGLekmpqHyn8UBF6kqpahrYm7D6N1Le
    [0xad, 0xed, 0xe3, 0x2e, 0x01, 0xa7, 0xfa, 0x31, 0x4a, 0xb6, 0xe1, 0xf5, 0x8e, 0x56, 0x4a, 0xb0, 0xab, 0xf8, 0xe1, 0x84], // t2NQTrStZHtJECNFT3dUBLYA9AErxPCmkka
    [0x6c, 0x80, 0x39, 0xd0, 0x8e, 0x06, 0xdf, 0xfc, 0x70, 0x90, 0x02, 0x36, 0xfa, 0x68, 0x73, 0xe3, 0x10, 0xa9, 0x89, 0xff], // t2GSWZZJzoesYxfPTWXkFn5UaxjiYxGBU2a
    [0xd3, 0x6a, 0x1c, 0x72, 0xea, 0x01, 0x3a, 0xe3, 0xa6, 0xaf, 0x5c, 0xe9, 0x86, 0x36, 0xa8, 0x6f, 0x25, 0xd7, 0x2d, 0xea], // t2RpffkzyLRevGM3w9aWdqMX6bd8uuAK3vn
    [0x88, 0x88, 0xd6, 0xe4, 0xcb, 0x24, 0xa0, 0x6e, 0x52, 0x18, 0xaa, 0xc0, 0x68, 0x48, 0x9f, 0xdb, 0x16, 0x67, 0x78, 0x99], // t2JzjoQqnuXtTGSN7k7yk5keURBGvYofh1d
    [0x28, 0x71, 0x3e, 0xa5, 0x06, 0xd7, 0x3d, 0x95, 0x6a, 0xe5, 0xc0, 0xc8, 0x89, 0x10, 0xab, 0xe1, 0x97, 0x1a, 0x04, 0xb2], // t2AEefc72ieTnsXKmgK2bZNckiwvZe3oPNL
    [0xad, 0xa0, 0x6a, 0x32, 0x43, 0x4d, 0x37, 0xab, 0xb8, 0xff, 0x7d, 0xff, 0x59, 0x05, 0x44, 0xd3, 0x24, 0x5c, 0xd1, 0xa1], // t2NNs3ZGZFsNj2wvmVd8BSwSfvETgiLrD8J
    [0x53, 0xda, 0xfe, 0x42, 0x0a, 0xc7, 0x03, 0xa7, 0xec, 0x9c, 0xc3, 0xf5, 0x93, 0x77, 0x80, 0x54, 0xb4, 0x59, 0xa8, 0x31], // t2ECCQPVcxUCSSQopdNquguEPE14HsVfcUn
    [0x83, 0xf7, 0xb0, 0x9d, 0xf1, 0x5c, 0xf1, 0x6c, 0x8a, 0x8c, 0x7d, 0x74, 0x43, 0x26, 0xed, 0x6f, 0xf2, 0x58, 0x51, 0x1f], // t2JabDUkG8TaqVKYfqDJ3rqkVdHKp6hwXvG
    [0x5f, 0xbb, 0x43, 0x7b, 0x1b, 0xc7, 0x3b, 0xc5, 0xdf, 0x9d, 0x4a, 0x96, 0xa6, 0x61, 0x2f, 0x8f, 0xf5, 0x01, 0x33, 0xbd], // t2FGzW5Zdc8Cy98ZKmRygsVGi6oKcmYir9n
    [0x4b, 0xea, 0x21, 0x40, 0x90, 0x5a, 0xe6, 0x5f, 0x6c, 0x25, 0x67, 0xbe, 0x04, 0x6d, 0x46, 0x27, 0x55, 0x80, 0x38, 0x92], // t2DUD8a21FtEFn42oVLp5NGbogY13uyjy9t
    [0xf3, 0x57, 0xdf, 0x3c, 0x93, 0x99, 0xce, 0x8a, 0x87, 0xf3, 0xde, 0xa9, 0x34, 0xe3, 0xac, 0x08, 0xd7, 0xce, 0xc5, 0xa6], // t2UjVSd3zheHPgAkuX8WQW2CiC9xHQ8EvWp
    [0xe2, 0x51, 0x5f, 0x17, 0xdd, 0x09, 0xa3, 0x45, 0x0d, 0x84, 0xda, 0x64, 0xf5, 0xb0, 0xa9, 0xcb, 0x66, 0x6d, 0xed, 0xa1], // t2TBUAhELyHUn8i6SXYsXz5Lmy7kDzA1uT5
    [0xeb, 0x20, 0xaa, 0x21, 0x8d, 0xd1, 0x8e, 0x13, 0xb5, 0x55, 0x7f, 0x24, 0xe9, 0x45, 0x17, 0x50, 0xc3, 0xa1, 0xc9, 0x88], // t2Tz3uCyhP6eizUWDc3bGH7XUC9GQsEyQNc
    [0xb4, 0x3f, 0x30, 0x0e, 0x15, 0x27, 0x6a, 0x0f, 0xa1, 0xa4, 0xd7, 0x32, 0xa1, 0xbf, 0xbe, 0x80, 0x39, 0x0d, 0x07, 0xbb], // t2NysJSZtLwMLWEJ6MH3BsxRh6h27mNcsSy
    [0x8e, 0x50, 0x9b, 0x85, 0xa4, 0x7e, 0xd7, 0x82, 0x2b, 0x0b, 0x2f, 0xb8, 0x79, 0x8b, 0x2b, 0x19, 0xa4, 0xb2, 0x8e, 0x31], // t2KXJVVyyrjVxxSeazbY9ksGyft4qsXUNm9
    [0x7f, 0x3b, 0x10, 0xdd, 0xe0, 0x8f, 0x11, 0x8f, 0xf7, 0x79, 0x03, 0x71, 0x20, 0xfa, 0x11, 0xc8, 0x85, 0x8f, 0xf9, 0xd0], // t2J9YYtH31cveiLZzjaE4AcuwVho6qjTNzp
    [0xc6, 0xfb, 0x0a, 0x1e, 0xa5, 0x88, 0x7b, 0x25, 0xb8, 0xe1, 0xa7, 0xb7, 0x1a, 0x1e, 0x13, 0xc7, 0x36, 0x95, 0x3a, 0x1c], // t2QgvW4sP9zaGpPMH1GRzy7cpydmuRfB4AZ
    [0xab, 0xd8, 0xd9, 0xb0, 0xe9, 0x55, 0x0a, 0xba, 0x61, 0xad, 0xcd, 0x57, 0xc0, 0x58, 0xc2, 0x0e, 0x82, 0x2c, 0x8d, 0x59], // t2NDTJP9MosKpyFPHJmfjc5pGCvAU58XGa4
    [0x23, 0xd5, 0x59, 0xf5, 0x78, 0x79, 0xbb, 0xcc, 0x06, 0xe5, 0x54, 0x02, 0x43, 0x80, 0xe3, 0x23, 0xaf, 0x49, 0xbd, 0x2e], // t29pHDBWq7qN4EjwSEHg8wEqYe9pkmVrtRP
    [0x5c, 0x8b, 0x8c, 0xf5, 0x1b, 0xa3, 0xb5, 0xe1, 0x0b, 0x63, 0xf7, 0x7e, 0x8b, 0x81, 0x32, 0xe0, 0x58, 0x72, 0x4f, 0xd2], // t2Ez9KM8VJLuArcxuEkNRAkhNvidKkzXcjJ
    [0x47, 0xb5, 0x46, 0x16, 0x06, 0x6b, 0xb1, 0x4a, 0xdc, 0x2f, 0x75, 0x64, 0x77, 0xa9, 0x7b, 0x38, 0x76, 0xba, 0xfb, 0x2b], // t2D5y7J5fpXajLbGrMBQkFg2mFN8fo3n8cX
    [0xf0, 0x9b, 0xee, 0x41, 0x28, 0xdd, 0x1e, 0x1c, 0xb2, 0xf4, 0xda, 0x3d, 0xc8, 0x64, 0x5e, 0xa1, 0x9c, 0xd3, 0x87, 0x22], // t2UV2wr1PTaUiybpkV3FdSdGxUJeZdZztyt
];

// Original ZIP214 Revision0 testnet BP recipients, all finite indices0..50.
// zcash/zips a735caf76ed8d3fa0a50e4f6b706ca9dac39079b, zip-0214.rst,
// Git blob014cedf0691f6d64d4b290f3a38effc1fa3dad5a; all source addresses were
// authenticated and Base58Check checksum/prefix1cba decoded before import.
// Constant ZF/MG and payload-only storage avoid runtime parsing/allocation.
const CANOPY_BP_HASHES: [[u8; 20]; 51] = [
    [0x02, 0xdb, 0x6b, 0xf7, 0xd5, 0x24, 0x26, 0x8b, 0x04, 0xed, 0xbb, 0x98, 0x6c, 0xa4, 0xb3, 0xba, 0x35, 0x28, 0x04, 0x5f], // 0 t26ovBdKAJLtrvBsE2QGF4nqBkEuptuPFZz
    [0x02, 0xdb, 0x6b, 0xf7, 0xd5, 0x24, 0x26, 0x8b, 0x04, 0xed, 0xbb, 0x98, 0x6c, 0xa4, 0xb3, 0xba, 0x35, 0x28, 0x04, 0x5f], // 1
    [0x02, 0xdb, 0x6b, 0xf7, 0xd5, 0x24, 0x26, 0x8b, 0x04, 0xed, 0xbb, 0x98, 0x6c, 0xa4, 0xb3, 0xba, 0x35, 0x28, 0x04, 0x5f], // 2
    [0x02, 0xdb, 0x6b, 0xf7, 0xd5, 0x24, 0x26, 0x8b, 0x04, 0xed, 0xbb, 0x98, 0x6c, 0xa4, 0xb3, 0xba, 0x35, 0x28, 0x04, 0x5f], // 3
    [0xad, 0x84, 0xb6, 0x15, 0xb3, 0x0f, 0x84, 0x09, 0x95, 0x96, 0x26, 0x29, 0x76, 0xe2, 0x80, 0x0b, 0x47, 0xbf, 0x63, 0x4a], // 4 t2NNHrgPpE388atmWSF4DxAb3xAoW5Yp45M
    [0xfa, 0x20, 0xa6, 0xa0, 0xb7, 0xed, 0xab, 0x06, 0xab, 0x51, 0x4c, 0xff, 0x36, 0xcb, 0x0b, 0xc5, 0x2e, 0xae, 0xd0, 0x41], // 5 t2VMN28itPyMeMHBEd9Z1hm6YLkQcGA1Wwe
    [0x3e, 0xee, 0xdb, 0x2e, 0x7c, 0xe2, 0xdf, 0x31, 0x04, 0x44, 0x92, 0x4b, 0xcf, 0x01, 0x91, 0x8e, 0x4f, 0x2a, 0x47, 0xe3], // 6 t2CHa1TtdfUV8UYhNm7oxbzRyfr8616BYh2
    [0x5d, 0xdd, 0x55, 0x4d, 0xe5, 0x02, 0xec, 0x31, 0xf9, 0xa3, 0x42, 0xf0, 0xef, 0x0b, 0x29, 0xae, 0x8c, 0x49, 0x15, 0xa1], // 7 t2F77xtr28U96Z2bC53ZEdTnQSUAyDuoa67
    [0x2a, 0x90, 0x1c, 0xb9, 0x18, 0x8a, 0x8d, 0x17, 0x58, 0xde, 0xa1, 0xc8, 0x4b, 0x7d, 0x8f, 0x92, 0x3d, 0xa5, 0x32, 0x9a], // 8 t2ARrzhbgcpoVBDPivUuj6PzXzDkTBPqfcT
    [0x06, 0x62, 0xcf, 0x50, 0x91, 0x03, 0xf7, 0xae, 0x8e, 0x09, 0x28, 0x57, 0xa3, 0xfb, 0x00, 0x19, 0x03, 0x8f, 0xda, 0xb5], // 9 t278aQ8XbvFR15mecRguiJDQQVRNnkU8kJw
    [0x4f, 0xa8, 0x78, 0x8f, 0x0e, 0x20, 0xcb, 0xf1, 0xf6, 0x74, 0xb6, 0x1d, 0x08, 0xcb, 0x5b, 0xc2, 0xd3, 0x72, 0x27, 0x9f], // 10 t2Dp1BGnZsrTXZoEWLyjHmg3EPvmwBnPDGB
    [0x93, 0x7c, 0xd2, 0x68, 0x62, 0x2a, 0xf1, 0xc2, 0x3a, 0x0c, 0xb0, 0x1a, 0xec, 0xdc, 0x2f, 0x10, 0x1d, 0x8e, 0x5f, 0xe9], // 11 t2KzeqXgf4ju33hiSqCuKDb8iHjPCjMq9iL
    [0xb4, 0x43, 0xd0, 0x81, 0x89, 0x61, 0x2d, 0x44, 0x2e, 0x38, 0x8f, 0xff, 0xcf, 0x53, 0x41, 0x56, 0x3b, 0x8d, 0x4e, 0xb9], // 12 t2Nyxqv1BiWY1eUSiuxVw36oveawYuo18tr
    [0x4a, 0x38, 0x91, 0x16, 0x97, 0x15, 0x05, 0x7e, 0x43, 0x63, 0x7c, 0x78, 0x84, 0xed, 0x87, 0xb5, 0x5b, 0x5e, 0x1d, 0xe4], // 13 t2DKFk5JRsVoiuinK8Ti6eM4Yp7v8BbfTyH
    [0x41, 0x03, 0x93, 0xed, 0x05, 0xc9, 0x60, 0x80, 0x7a, 0x08, 0x10, 0x1f, 0x2f, 0x48, 0x50, 0x63, 0x8f, 0x5b, 0x99, 0x8b], // 14 t2CUaBca4k1x36SC4q8Nc8eBoqkMpF3CaLg
    [0x1b, 0xeb, 0xd0, 0x2a, 0x60, 0x5b, 0x33, 0x93, 0xa9, 0xb4, 0x90, 0xf4, 0xb8, 0x4d, 0xe2, 0x1f, 0x4b, 0x39, 0xcf, 0x9c], // 15 t296SiKL7L5wvFmEdMxVLz1oYgd6fTfcbZj
    [0x22, 0x1c, 0x95, 0xf8, 0x3b, 0xf0, 0x73, 0xcf, 0xb7, 0x67, 0x24, 0xed, 0x23, 0xaf, 0x73, 0x7c, 0x1e, 0xe3, 0xbb, 0x49], // 16 t29fBCFbhgsjL3XYEZ1yk1TUh7eTusB6dPg
    [0x5f, 0xb2, 0x36, 0xe6, 0x1a, 0xa7, 0xe9, 0xec, 0x9a, 0xdb, 0x47, 0x64, 0x4c, 0xd4, 0xf5, 0x52, 0x60, 0x77, 0x91, 0xc1], // 17 t2FGofLJXa419A76Gpf5ncxQB4gQXiQMXjK
    [0x5c, 0x44, 0x36, 0xc0, 0x36, 0xab, 0xf9, 0xfe, 0x29, 0x31, 0xf3, 0x8d, 0x58, 0x46, 0x88, 0xac, 0xad, 0x25, 0x67, 0xf0], // 18 t2ExfrnRVnRiXDvxerQ8nZbcUQvNvAJA6Qu
    [0x13, 0x3a, 0x4f, 0x69, 0xdb, 0x2e, 0x68, 0x50, 0x9b, 0xbc, 0x4e, 0x7f, 0x5c, 0x3f, 0xe0, 0x82, 0x9d, 0x16, 0xe1, 0x79], // 19 t28JUffLp47eKPRHKvwSPzX27i9ow8LSXHx
    [0x83, 0x62, 0x6b, 0x0b, 0x62, 0xb6, 0x48, 0x4e, 0x60, 0x9e, 0xe3, 0x71, 0x5a, 0x68, 0x47, 0x22, 0xcf, 0x0b, 0xe0, 0x7b], // 20 t2JXWPtrtyL861rFWMZVtm3yfgxAf4H7uPA
    [0xc6, 0x5e, 0x2e, 0x32, 0x25, 0x1f, 0xe5, 0x13, 0x75, 0xf7, 0xcc, 0xf8, 0xd7, 0x86, 0xa3, 0xce, 0x73, 0xce, 0x4a, 0xa5], // 21 t2QdgbJoWfYHgyvEDEZBjHmgkr9yNJff3Hi
    [0xc4, 0xec, 0xc3, 0x89, 0x40, 0x6f, 0x3e, 0x3d, 0xf3, 0x96, 0xd8, 0xf6, 0x9c, 0x04, 0x02, 0x55, 0x4c, 0xab, 0x3e, 0x5e], // 22 t2QW43nkco8r32ZGRN6iw6eSzyDjkMwCV3n
    [0x4e, 0x3f, 0x0d, 0x9a, 0x33, 0xa2, 0x72, 0x16, 0x04, 0xcb, 0xae, 0x2d, 0xe8, 0xd9, 0x17, 0x1e, 0x21, 0xf8, 0xfb, 0xe4], // 23 t2DgYDXMJTYLwNcxighQ9RCgPxMVATRcUdC
    [0x39, 0xae, 0xfc, 0x11, 0x73, 0x8e, 0xbc, 0x25, 0x3b, 0xeb, 0x6b, 0x64, 0x23, 0xfa, 0x39, 0xb5, 0xa6, 0x16, 0x4e, 0xa8], // 24
    [0x78, 0x10, 0x02, 0x7b, 0xa4, 0x68, 0x97, 0xa9, 0x74, 0x62, 0xc9, 0x68, 0x39, 0xdf, 0x91, 0x26, 0x37, 0x61, 0x78, 0xa8], // 25
    [0x7d, 0x28, 0xda, 0x7f, 0x38, 0x18, 0x0a, 0x76, 0x99, 0xea, 0x58, 0x8c, 0xea, 0xea, 0x02, 0x42, 0x0b, 0x33, 0xf7, 0xa8], // 26
    [0xe3, 0xbd, 0x95, 0xae, 0x88, 0x54, 0x28, 0x2c, 0xa5, 0xb7, 0xe5, 0xe2, 0x34, 0xb8, 0x80, 0x33, 0x41, 0x1b, 0x52, 0xd6], // 27
    [0x23, 0xd9, 0x59, 0x6d, 0x1e, 0x09, 0xee, 0xfe, 0x57, 0x19, 0xb4, 0xbf, 0xc8, 0x28, 0x38, 0x5d, 0x99, 0xe4, 0x8a, 0x71], // 28
    [0xc1, 0x65, 0xcf, 0x3e, 0x05, 0xef, 0xf2, 0x86, 0xd3, 0x3a, 0x44, 0xbc, 0x19, 0xc9, 0x8e, 0x58, 0xb0, 0x5f, 0x73, 0x6a], // 29
    [0x5d, 0x8b, 0x6c, 0xb9, 0x4f, 0xb7, 0xd9, 0x93, 0x63, 0xae, 0x0e, 0x71, 0x14, 0xbe, 0x52, 0x08, 0xf4, 0x79, 0x24, 0x50], // 30
    [0x3f, 0x00, 0x5b, 0xce, 0x6d, 0x56, 0x65, 0x1c, 0xd3, 0x70, 0x8f, 0x88, 0x6a, 0x54, 0xd5, 0x73, 0xd3, 0x18, 0xa8, 0x40], // 31
    [0x35, 0x8e, 0xc4, 0x65, 0x36, 0xcd, 0xaa, 0x76, 0x46, 0x3e, 0xfa, 0x31, 0xd3, 0x00, 0xd3, 0x0e, 0x40, 0x70, 0x1f, 0x77], // 32
    [0x33, 0x9d, 0x5d, 0x90, 0x05, 0x07, 0x93, 0x0b, 0x53, 0x43, 0x9b, 0x17, 0xb0, 0xff, 0xed, 0x5e, 0x75, 0xaa, 0x4d, 0xfc], // 33
    [0xf5, 0x84, 0x4c, 0x0f, 0xf6, 0xa9, 0x79, 0x3e, 0xb1, 0xb8, 0xf0, 0x1d, 0xc5, 0x21, 0xdd, 0x9b, 0xb5, 0x19, 0x8f, 0x19], // 34
    [0x44, 0x2a, 0xd1, 0xb6, 0x24, 0xb7, 0xa7, 0xce, 0x11, 0xd3, 0x08, 0x40, 0xb4, 0x23, 0x81, 0xf0, 0xc1, 0x3a, 0xad, 0x7d], // 35
    [0x5b, 0x13, 0x94, 0xad, 0x17, 0xe5, 0x06, 0x37, 0x6f, 0x05, 0x7b, 0xd1, 0x2b, 0x1c, 0xa5, 0x68, 0x9c, 0xbf, 0xc3, 0xbc], // 36
    [0x6e, 0xbb, 0x10, 0x90, 0x75, 0x5c, 0x52, 0x22, 0xc1, 0x65, 0xea, 0xcf, 0x3a, 0xf9, 0x00, 0x4a, 0x42, 0xd1, 0xbd, 0xb2], // 37
    [0x93, 0xdd, 0x2b, 0x72, 0x6c, 0x3f, 0xa1, 0x47, 0x6a, 0x30, 0xcb, 0xc7, 0xa4, 0x2c, 0x7c, 0x71, 0x1f, 0x68, 0xc0, 0xe7], // 38
    [0x55, 0x25, 0xb6, 0x3b, 0xac, 0xc5, 0x74, 0x7c, 0x38, 0xb3, 0x51, 0xc9, 0x36, 0xc2, 0xe0, 0x19, 0xe5, 0x3c, 0x9d, 0xa8], // 39
    [0x4a, 0x01, 0x33, 0xec, 0xb1, 0x91, 0x1e, 0x08, 0xd5, 0x64, 0x0f, 0xcb, 0x2a, 0xfd, 0xf2, 0x34, 0x1e, 0xc8, 0xc2, 0x45], // 40
    [0x88, 0xbd, 0x34, 0x54, 0xa0, 0x85, 0xac, 0xaa, 0xc8, 0xb1, 0xea, 0x98, 0x07, 0x1a, 0xe6, 0x9c, 0x26, 0xf1, 0x4c, 0x81], // 41
    [0xe2, 0x3d, 0xd6, 0xed, 0xb4, 0x46, 0xbd, 0xba, 0xbc, 0x32, 0x93, 0x98, 0x59, 0xd7, 0x4c, 0x0c, 0x66, 0xd4, 0x04, 0xdc], // 42
    [0xbc, 0x34, 0xa2, 0x44, 0xb8, 0x12, 0x74, 0x10, 0xcd, 0x18, 0x9b, 0x8e, 0xa3, 0xa4, 0x83, 0xd3, 0x16, 0xa2, 0xb8, 0xb0], // 43
    [0xfa, 0xbb, 0x4a, 0xb1, 0x51, 0x92, 0xd0, 0xac, 0x76, 0xc9, 0x20, 0xd2, 0x65, 0xc7, 0x8f, 0x05, 0xa2, 0xfc, 0xd0, 0xe7], // 44
    [0xd2, 0x44, 0xb9, 0x8e, 0xe0, 0x3e, 0xd3, 0x99, 0x01, 0x9e, 0xf9, 0xe2, 0xa3, 0xd2, 0xb0, 0x96, 0xcb, 0x1b, 0x23, 0x79], // 45
    [0x86, 0xf6, 0xf0, 0xaa, 0x53, 0xc0, 0xe6, 0xee, 0x93, 0x80, 0x51, 0xa6, 0x78, 0x5a, 0xb8, 0x29, 0x10, 0x52, 0xed, 0x17], // 46
    [0xf2, 0xe6, 0x1e, 0x5d, 0xa3, 0xe8, 0x99, 0xbe, 0x0f, 0x27, 0x6d, 0xd5, 0xbd, 0xbc, 0x9a, 0x94, 0xff, 0x8f, 0xe8, 0x60], // 47
    [0x5f, 0x27, 0xc2, 0x5f, 0xb9, 0xa4, 0x81, 0x4b, 0x2f, 0x61, 0x27, 0x86, 0x66, 0x8c, 0x41, 0x70, 0x03, 0x2f, 0xf7, 0x19], // 48
    [0x62, 0x92, 0x07, 0xf9, 0x58, 0x70, 0xbb, 0x1b, 0xd4, 0xee, 0x16, 0x60, 0xb8, 0x1f, 0xbf, 0xec, 0x6f, 0xc6, 0x4f, 0x29], // 49
    [0x93, 0x91, 0x60, 0x98, 0xd2, 0xa1, 0x61, 0xa9, 0x1f, 0x3d, 0xde, 0xba, 0xb6, 0x9d, 0xd5, 0xdb, 0x95, 0x87, 0xb6, 0x24], // 50
];
const CANOPY_ZF_HASH: [u8; 20] = [0x0c, 0x0b, 0xcc, 0xa0, 0x2f, 0x3c, 0xba, 0x01, 0xa5, 0xd7, 0x42, 0x3a, 0xc3, 0x90, 0x3d, 0x40, 0x58, 0x63, 0x99, 0xeb];
const CANOPY_MG_HASH: [u8; 20] = [0x71, 0xe1, 0xdf, 0x05, 0x02, 0x42, 0x88, 0xa0, 0x08, 0x02, 0xde, 0x81, 0xe0, 0x8c, 0x43, 0x78, 0x59, 0x58, 0x6c, 0x87];

// Original NU6 testnet FPF/ZCG recipient t2HifwjUj9uyxr9bknR8LFuQbc98c3vkXtu,
// zcashd fefd6232f68438008e28eaf727dd2acf4c38d743 chainparams.cpp. All thirteen
// funding periods use this same Base58Check-authenticated P2SH payload.
const NU6_FPF_HASH: [u8; 20] = [0x7a, 0x86, 0xd6, 0xc7, 0xeb, 0x12, 0xce, 0x0a, 0xa3, 0x09, 0xd7, 0x39, 0x1a, 0x6f, 0x33, 0x8e, 0xba, 0x3c, 0x24, 0x2b];

// Original NU6.1 testnet activation disbursement: ten individual P2SH outputs,
// not one summed output. This transfers existing deferred issuance, not subsidy.
const NU61_DISBURSEMENT_HASH: [u8; 20] = [0xd2, 0xf1, 0xb4, 0x36, 0x49, 0x0d, 0x63, 0xfc, 0x07, 0x8d, 0x8a, 0xed, 0x2d, 0x96, 0x6b, 0xd3, 0xe4, 0x0d, 0x79, 0xf0];
const NU61_DEFERRED_WITHDRAWAL: u64 = 7_875_000_000_000;

/*
Funding consensus predicates translated from zcashd MIT source:
Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-2014 The Bitcoin Core developers
Copyright (c) 2015-2020 The Zcash developers
Copyright (c) 2009-2020 The Bitcoin Core developers
Copyright (c) 2016-2020 The Zcash developers
Copyright (c) 2009-2020 Bitcoin Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SproutLedgerError {
    UnsupportedEra,
    Body(BodyError),
    Header(HeaderError),
    WrongHeight,
    UnsupportedTransaction,
    InvalidTransaction,
    InvalidCoinbase,
    NonfinalTransaction,
    ExpiredTransaction,
    TransactionTooLarge,
    TooManySigops,
    ValueOutOfRange,
    CoinbaseRewardExceeded,
    MissingFoundersReward,
    MissingFundingStream { index: usize },
    MissingDeferredDisbursement,
    InsufficientDeferredBalance,
    SproutDepositDisabled,
    UnspentTransactionOverwrite,
    MissingTransparentInput,
    DuplicateTransparentInput,
    ImmatureCoinbase,
    UnshieldedCoinbaseSpend,
    InvalidTransparentScript,
    NegativeFee,
    UnknownSproutAnchor,
    SpentSproutNullifier,
    SproutTreeFull,
    UnknownSaplingAnchor,
    SpentSaplingNullifier,
    SaplingTreeFull,
    WrongSaplingRoot,
    UnknownOrchardAnchor,
    SpentOrchardNullifier,
    OrchardTreeFull,
    OrchardDisabled,
    Orchard(RawV5Error),
    UnknownIronwoodAnchor,
    SpentIronwoodNullifier,
    IronwoodTreeFull,
    NegativeOrchardBalance,
    PostNu63(PostNu63CryptoError),
    WrongHistoryRoot,
    History(HistoryError),
    CoinbaseRecovery { index: usize, error: CoinbaseRecoveryError },
    IronwoodCoinbaseRecovery { index: usize, error: CoinbaseRecoveryError },
    Sapling(SaplingCryptoError),
    JoinSplit(LegacyJoinSplitError),
}

impl fmt::Display for SproutLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(error) => write!(f, "invalid complete Sprout body: {error}"),
            Self::Header(error) => write!(f, "invalid connected Sprout header: {error}"),
            Self::JoinSplit(error) => write!(f, "invalid original JoinSplit authorization: {error}"),
            Self::Sapling(error) => write!(f, "invalid original Sapling authorization: {error}"),
            Self::Orchard(error) => write!(f, "invalid original Orchard authorization/recovery: {error}"),
            Self::PostNu63(error) => write!(f, "invalid NU6.3 shielded authorization: {error}"),
            Self::History(error) => write!(f, "invalid bounded history: {error}"),
            Self::CoinbaseRecovery { index, error } => write!(f, "invalid Sapling coinbase output {index} recovery: {error}"),
            Self::IronwoodCoinbaseRecovery { index, error } => write!(f, "invalid Ironwood coinbase output {index} recovery: {error}"),
            Self::MissingFundingStream { index } => write!(f, "coinbase lacks exact funding stream {index} output"),
            error => f.write_str(match error {
                Self::UnsupportedEra => "testnet ledger does not yet implement NU7 or later eras",
                Self::WrongHeight => "coinbase height does not match the authenticated parent",
                Self::UnsupportedTransaction => "not a compatible transaction for the authenticated testnet era",
                Self::InvalidTransaction => "invalid transaction input/output or value structure",
                Self::InvalidCoinbase => "invalid coinbase structure or canonical height prefix",
                Self::NonfinalTransaction => "transaction is not final at candidate height and time",
                Self::ExpiredTransaction => "noncoinbase transaction expiry precedes the candidate height",
                Self::TransactionTooLarge => "transaction exceeds its era-specific serialized size limit",
                Self::TooManySigops => "block exceeds 20000 signature operations",
                Self::ValueOutOfRange => "ledger amount or final total is outside the monetary range",
                Self::CoinbaseRewardExceeded => "coinbase claim violates scheduled subsidy, deferred issuance and actual fees",
                Self::MissingFoundersReward => "coinbase lacks an exact scheduled Founders reward output",
                Self::MissingDeferredDisbursement => "coinbase lacks ten distinct exact deferred disbursement outputs",
                Self::InsufficientDeferredBalance => "parent deferred pool cannot fund the activation withdrawal",
                Self::SproutDepositDisabled => "Canopy JoinSplit vpub_old must be zero",
                Self::UnspentTransactionOverwrite => "transaction would overwrite a parent unspent identity",
                Self::MissingTransparentInput => "transparent input is absent or already spent",
                Self::DuplicateTransparentInput => "transaction repeats a transparent outpoint",
                Self::ImmatureCoinbase => "transparent coinbase input has fewer than 100 confirmations",
                Self::UnshieldedCoinbaseSpend => "testnet coinbase spends require empty transparent outputs",
                Self::InvalidTransparentScript => "actual transparent prevout script authorization failed",
                Self::NegativeFee => "actual transparent and shielded credits do not cover debits",
                Self::UnknownSproutAnchor => "JoinSplit anchor is not historical or earlier in this transaction",
                Self::SpentSproutNullifier => "Sprout nullifier is already used",
                Self::SproutTreeFull => "Sprout commitment tree exceeds depth-29 capacity",
                Self::UnknownSaplingAnchor => "Sapling spend anchor is not an accepted historical parent root",
                Self::SpentSaplingNullifier => "Sapling nullifier is already used",
                Self::SaplingTreeFull => "Sapling commitment tree exceeds depth-32 capacity",
                Self::UnknownOrchardAnchor => "Orchard bundle anchor is not an accepted historical parent root",
                Self::SpentOrchardNullifier => "Orchard action nullifier is already used",
                Self::OrchardTreeFull => "Orchard commitment tree exceeds depth-32 capacity",
                Self::OrchardDisabled => "Orchard bundles are disabled at the candidate testnet height",
                Self::UnknownIronwoodAnchor => "Ironwood bundle anchor is not an accepted historical parent root",
                Self::SpentIronwoodNullifier => "Ironwood action nullifier is already used",
                Self::IronwoodTreeFull => "Ironwood commitment tree exceeds depth-32 capacity",
                Self::NegativeOrchardBalance => "NU6.3 Orchard value balance must be nonnegative",
                Self::WrongSaplingRoot => "header final Sapling root differs from the computed block frontier",
                Self::WrongHistoryRoot => "header commitment differs from the required parent history root",
                Self::Body(_) | Self::Header(_) | Self::JoinSplit(_) | Self::Sapling(_) | Self::Orchard(_) | Self::PostNu63(_) | Self::History(_) | Self::CoinbaseRecovery { .. } | Self::IronwoodCoinbaseRecovery { .. } | Self::MissingFundingStream { .. } => unreachable!("handled above"),
            }),
        }
    }
}

impl std::error::Error for SproutLedgerError {}

/// An actual retained output and its consensus maturity context.
#[derive(Debug)]
pub struct TransparentCoin {
    output: TxOut,
    created_height: u32,
    is_coinbase: bool,
}

impl TransparentCoin {
    pub fn output(&self) -> &TxOut {
        &self.output
    }

    pub fn created_height(&self) -> u32 {
        self.created_height
    }

    pub fn is_coinbase(&self) -> bool {
        self.is_coinbase
    }
}

/// Owns authenticated genesis state, never a caller snapshot or validity flag.
#[derive(Debug)]
pub struct SproutTestnetLedger {
    headers: HeaderChain,
    utxos: BTreeMap<([u8; 32], u32), TransparentCoin>,
    utxo_balance: u64,
    nullifiers: [BTreeSet<[u8; 32]>; 4],
    sprout_anchors: BTreeMap<[u8; 32], Frontier<SproutNode, 29>>,
    sapling_tree: Frontier<SaplingNode, 32>,
    sapling_anchors: BTreeSet<[u8; 32]>,
    orchard_tree: Frontier<MerkleHashOrchard, 32>,
    orchard_anchors: BTreeSet<[u8; 32]>,
    ironwood_tree: Frontier<MerkleHashOrchard, 32>,
    ironwood_anchors: BTreeSet<[u8; 32]>,
    shielded_roots: [[u8; 32]; 4],
    transparent_balance: u64,
    shielded_balances: [u64; 4],
    deferred_balance: u64,
    issued_supply: u64,
    history_root: Option<[u8; 32]>,
    chain_history: Option<ChainHistoryV1>,
    chain_history_v2: Option<ChainHistoryV2>,
    chain_history_v3: Option<ChainHistoryV3>,
}

impl SproutTestnetLedger {
    pub fn from_genesis(genesis: GenesisState) -> Self {
        let headers = HeaderChain::from_testnet_genesis(&genesis);
        let GenesisState {
            utxos, nullifiers, sprout_tree, shielded_roots, transparent_balance,
            shielded_balances, deferred_balance, issued_supply, history_root, ..
        } = genesis;
        // Authentic bootstrap has no UTXOs. Moving its map also keeps this seam
        // ownership-preserving without retaining a stale alternate genesis tip.
        let utxos = utxos.into_iter().map(|(key, (value, script))| {
            let mut lock = Script::default();
            lock.0.0 = script;
            (key, TransparentCoin {
                output: TxOut::new(Zatoshis::from_u64(value).expect("authenticated genesis value"), lock),
                created_height: 0,
                is_coinbase: true,
            })
        }).collect();
        let sprout_anchors = BTreeMap::from([(shielded_roots[0], sprout_tree)]);
        let sapling_tree = Frontier::<SaplingNode, 32>::empty();
        let sapling_anchors = BTreeSet::from([shielded_roots[1]]);
        let orchard_tree = Frontier::<MerkleHashOrchard, 32>::empty();
        let orchard_anchors = BTreeSet::from([shielded_roots[2]]);
        let ironwood_tree = Frontier::<MerkleHashOrchard, 32>::empty();
        let ironwood_anchors = BTreeSet::from([shielded_roots[3]]);
        Self {
            headers, utxos, utxo_balance: transparent_balance, nullifiers,
            sprout_anchors, sapling_tree, sapling_anchors, orchard_tree, orchard_anchors,
            ironwood_tree, ironwood_anchors,
            shielded_roots, transparent_balance, shielded_balances,
            deferred_balance, issued_supply, history_root, chain_history: None, chain_history_v2: None, chain_history_v3: None,
        }
    }

    pub fn tip(&self) -> HeaderTip {
        self.headers.tip()
    }

    pub fn utxo(&self, txid: &[u8; 32], output_index: u32) -> Option<&TransparentCoin> {
        self.utxos.get(&(*txid, output_index))
    }

    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }

    /// Sum of outputs retained by the exact pruning predicate, not IssuedSupply
    /// or an assertion that arbitrary retained locks are practically spendable.
    pub fn utxo_balance(&self) -> u64 {
        self.utxo_balance
    }

    /// Protocol transparent pool, including claimed outputs that are pruned.
    pub fn transparent_balance(&self) -> u64 {
        self.transparent_balance
    }

    /// Actual claimed issuance, including pruned outputs; not scheduled subsidy.
    pub fn issued_supply(&self) -> u64 {
        self.issued_supply
    }

    pub fn shielded_root(&self, pool: ShieldedPool) -> [u8; 32] {
        self.shielded_roots[pool.index()]
    }

    pub fn shielded_balance(&self, pool: ShieldedPool) -> u64 {
        self.shielded_balances[pool.index()]
    }

    pub fn nullifier_count(&self, pool: ShieldedPool) -> usize {
        self.nullifiers[pool.index()].len()
    }

    pub fn contains_nullifier(&self, pool: ShieldedPool, nullifier: &[u8; 32]) -> bool {
        self.nullifiers[pool.index()].contains(nullifier)
    }

    pub fn pool_is_active(&self, pool: ShieldedPool) -> bool {
        pool == ShieldedPool::Sprout
            || (pool == ShieldedPool::Sapling && self.tip().height() >= 280_000)
            || (pool == ShieldedPool::Orchard && self.tip().height() >= 1_842_420)
            || (pool == ShieldedPool::Ironwood && self.tip().height() >= 4_134_000)
    }

    pub fn sprout_tree_size(&self) -> u64 {
        self.sprout_anchors[&self.shielded_roots[0]].tree_size()
    }

    pub fn sapling_tree_size(&self) -> u64 {
        self.sapling_tree.tree_size()
    }

    pub fn orchard_tree_size(&self) -> u64 {
        self.orchard_tree.tree_size()
    }

    pub fn ironwood_tree_size(&self) -> u64 {
        self.ironwood_tree.tree_size()
    }

    // Replay borrows an authentic parent frontier; never imports or publishes a
    // checkpoint. The same bounded tracker is available to the shared guest.
    pub(crate) fn orchard_family_frontier(&self, pool: ShieldedPool) -> Option<&Frontier<MerkleHashOrchard, 32>> {
        match pool {
            ShieldedPool::Orchard => Some(&self.orchard_tree),
            ShieldedPool::Ironwood => Some(&self.ironwood_tree),
            ShieldedPool::Sprout | ShieldedPool::Sapling => None,
        }
    }

    pub fn deferred_balance(&self) -> u64 {
        self.deferred_balance
    }

    pub fn history_root(&self) -> Option<[u8; 32]> {
        // Preserved None before Heartwood; computed from admitted owned peaks after.
        self.history_root
    }

    /// Checks every transaction and the header from the SAME complete body.
    /// Only an entirely checked delta can change owned state.
    pub fn apply_block(&mut self, raw: &[u8]) -> Result<HeaderTip, SproutLedgerError> {
        let parent_tip = self.tip();
        let height = parent_tip.height().checked_add(1).ok_or(SproutLedgerError::UnsupportedEra)?;
        let branch = supported_branch(height)?;
        if matches!(branch, BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) {
            return self.apply_post_nu5_block(raw, height);
        }
        let body = ParsedBlockBody::parse(raw, &TEST_NETWORK).map_err(SproutLedgerError::Body)?;
        if u32::from(body.block().claimed_height()) != height {
            return Err(SproutLedgerError::WrongHeight);
        }
        let time = body.block().header().time;
        // This field switches from final Sapling root to parent history root
        // at Heartwood; it is NEVER the current leaf's Sapling metadata then.
        let commitment = body.block().header().final_sapling_root;
        let sapling_tx = if matches!(branch, BranchId::Heartwood | BranchId::Canopy) { sapling_transaction_count(body.block().vtx().iter()) } else { 0 };
        let mut headers = self.headers.clone();
        // Canonical complete testnet parsing proves the fixed header layout.
        let tip = headers.append(&raw[..HEADER_BYTES]).map_err(SproutLedgerError::Header)?;
        let (_, transactions) = body.into_block().into_parts();
        let delta = self.stage_block(transactions.head, transactions.tail, height, time)?;
        delta.check_sapling_root(height, &commitment)?;
        let history = if matches!(branch, BranchId::Heartwood | BranchId::Canopy) {
            let leaf = history_leaf(parent_tip, tip, delta.sapling_root, sapling_tx)?;
            Some(self.stage_history(&commitment, leaf)?)
        } else {
            None
        };
        // Headers, every ledger field and bounded MMR publish only after all
        // fallible body/header/crypto/pool/root/history checks have completed.
        self.commit(delta);
        self.headers = headers;
        if let Some(history) = history {
            self.history_root = Some(history.root());
            self.chain_history = Some(history);
        }
        Ok(tip)
    }

    fn apply_post_nu5_block(&mut self, raw: &[u8], height: u32) -> Result<HeaderTip, SproutLedgerError> {
        let parent_tip = self.tip();
        let body = PostNu5Block::parse(raw, height).map_err(SproutLedgerError::Body)?;
        let time = body.header().time;
        let commitment = body.header().final_sapling_root;
        let auth_root = body.auth_data_root();
        let sapling_tx = body.transactions().iter().filter(|transaction| transaction.sapling_bundle().is_some()).count() as u64;
        let orchard_tx = body.transactions().iter().filter(|transaction| has_orchard(transaction)).count() as u64;
        let ironwood_tx = body.transactions().iter().filter(|transaction| matches!(transaction, PostNu5Transaction::V6(transaction) if transaction.ironwood_bundle().is_some())).count() as u64;
        let mut headers = self.headers.clone();
        let tip = headers.append(&raw[..HEADER_BYTES]).map_err(SproutLedgerError::Header)?;
        let delta = self.stage_post_nu5_block(body.into_transactions(), height, time)?;
        let leaf = HistoryLeafV2 {
            v1: history_leaf(parent_tip, tip, delta.sapling_root, sapling_tx)?,
            start_orchard_root: delta.orchard_root,
            end_orchard_root: delta.orchard_root,
            orchard_tx,
        };
        let (history_v2, history_v3, root) = if supported_branch(height)? == BranchId::Nu6_3 {
            let history = self.stage_nu63_history(&commitment, &auth_root, HistoryLeafV3 {
                v2: leaf, start_ironwood_root: delta.ironwood_root,
                end_ironwood_root: delta.ironwood_root, ironwood_tx,
            })?;
            let root = history.root();
            (None, Some(history), root)
        } else {
            let history = self.stage_post_nu5_history(&commitment, &auth_root, leaf)?;
            let root = history.root();
            (Some(history), None, root)
        };
        self.commit(delta);
        self.headers = headers;
        self.history_root = Some(root);
        self.chain_history = None;
        self.chain_history_v2 = history_v2;
        self.chain_history_v3 = history_v3;
        Ok(tip)
    }

    fn stage_post_nu5_history(&self, commitment: &[u8; 32], auth_root: &[u8; 32], leaf: HistoryLeafV2) -> Result<ChainHistoryV2, SproutLedgerError> {
        let height = u32::try_from(leaf.v1.start_height).map_err(|_| SproutLedgerError::History(HistoryError::HeightOutOfRange))?;
        let branch = supported_branch(height)?;
        if !matches!(branch, BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2) || leaf.v1.consensus_branch_id != u32::from(branch) || self.chain_history_v3.is_some() {
            return Err(SproutLedgerError::History(HistoryError::BranchMismatch));
        }
        let parent_root = if height == 1_842_420 {
            let history = self.chain_history.as_ref().ok_or(SproutLedgerError::WrongHistoryRoot)?;
            if history.consensus_branch_id() != u32::from(BranchId::Canopy) || self.chain_history_v2.is_some() {
                return Err(SproutLedgerError::History(HistoryError::BranchMismatch));
            }
            if history.last_height() != 1_842_419 {
                return Err(SproutLedgerError::History(HistoryError::NonconsecutiveHeight));
            }
            history.root()
        } else if matches!(height, 2_976_000 | 3_536_500 | 4_052_000) {
            // Authenticate the LAST owned previous V2 epoch before resetting:
            // NU5 for NU6, NU6 for NU6.1, NU6.1 for NU6.2. Full auth stays bound.
            let history = self.chain_history_v2.as_ref().ok_or(SproutLedgerError::WrongHistoryRoot)?;
            let previous_branch = match height {
                2_976_000 => BranchId::Nu5,
                3_536_500 => BranchId::Nu6,
                _ => BranchId::Nu6_1,
            };
            if history.consensus_branch_id() != u32::from(previous_branch) || self.chain_history.is_some() {
                return Err(SproutLedgerError::History(HistoryError::BranchMismatch));
            }
            if history.last_height() != height - 1 {
                return Err(SproutLedgerError::History(HistoryError::NonconsecutiveHeight));
            }
            history.root()
        } else {
            let history = self.chain_history_v2.as_ref().ok_or(SproutLedgerError::WrongHistoryRoot)?;
            if history.consensus_branch_id() != u32::from(branch) || self.chain_history.is_some() {
                return Err(SproutLedgerError::History(HistoryError::BranchMismatch));
            }
            history.root()
        };
        if self.history_root != Some(parent_root) {
            return Err(SproutLedgerError::WrongHistoryRoot);
        }
        let computed = blake2b_simd::Params::new().hash_length(32).personal(b"ZcashBlockCommit")
            .to_state().update(&parent_root).update(auth_root).update(&[0; 32]).finalize();
        if computed.as_bytes() != commitment {
            return Err(SproutLedgerError::Body(BodyError::BlockCommitmentMismatch));
        }
        if matches!(height, 1_842_420 | 2_976_000 | 3_536_500 | 4_052_000) {
            return ChainHistoryV2::new(leaf).map_err(SproutLedgerError::History);
        }
        let mut history = self.chain_history_v2.as_ref().expect("owned parent checked above").clone();
        history.append(leaf).map_err(SproutLedgerError::History)?;
        Ok(history)
    }

    fn stage_nu63_history(&self, commitment: &[u8; 32], auth_root: &[u8; 32], leaf: HistoryLeafV3) -> Result<ChainHistoryV3, SproutLedgerError> {
        let height = u32::try_from(leaf.v2.v1.start_height).map_err(|_| SproutLedgerError::History(HistoryError::HeightOutOfRange))?;
        if supported_branch(height)? != BranchId::Nu6_3 || leaf.v2.v1.consensus_branch_id != 0x37a5_165b {
            return Err(SproutLedgerError::History(HistoryError::BranchMismatch));
        }
        let parent_root = if height == 4_134_000 {
            let history = self.chain_history_v2.as_ref().ok_or(SproutLedgerError::WrongHistoryRoot)?;
            if history.consensus_branch_id() != u32::from(BranchId::Nu6_2) || self.chain_history.is_some() || self.chain_history_v3.is_some() {
                return Err(SproutLedgerError::History(HistoryError::BranchMismatch));
            }
            if history.last_height() != 4_133_999 {
                return Err(SproutLedgerError::History(HistoryError::NonconsecutiveHeight));
            }
            history.root()
        } else {
            let history = self.chain_history_v3.as_ref().ok_or(SproutLedgerError::WrongHistoryRoot)?;
            if history.consensus_branch_id() != 0x37a5_165b || self.chain_history.is_some() || self.chain_history_v2.is_some() {
                return Err(SproutLedgerError::History(HistoryError::BranchMismatch));
            }
            history.root()
        };
        if self.history_root != Some(parent_root) { return Err(SproutLedgerError::WrongHistoryRoot); }
        let computed = blake2b_simd::Params::new().hash_length(32).personal(b"ZcashBlockCommit")
            .to_state().update(&parent_root).update(auth_root).update(&[0; 32]).finalize();
        if computed.as_bytes() != commitment {
            return Err(SproutLedgerError::Body(BodyError::BlockCommitmentMismatch));
        }
        if height == 4_134_000 { return ChainHistoryV3::new(leaf).map_err(SproutLedgerError::History); }
        let mut history = self.chain_history_v3.as_ref().expect("owned parent checked above").clone();
        history.append(leaf).map_err(SproutLedgerError::History)?;
        Ok(history)
    }

    fn stage_post_nu5_block(&self, transactions: Vec<PostNu5Transaction<'_>>, height: u32, time: u32) -> Result<BlockDelta, SproutLedgerError> {
        let branch = supported_branch(height)?;
        if !matches!(branch, BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) {
            return Err(SproutLedgerError::UnsupportedTransaction);
        }
        // Scan ALL actual transactions before any recovery or proof equation.
        // Raw parsing and financial admission are independent trust boundaries.
        if (4_048_500..4_052_000).contains(&height) && transactions.iter().any(has_orchard) {
            return Err(SproutLedgerError::OrchardDisabled);
        }
        for transaction in &transactions {
            // Validate actual variant/version and branch before any key choice
            // or candidate staging; a later mislabeled transaction cannot turn
            // an earlier valid coinbase into a wrong-era proof invocation.
            let version_ok = match transaction {
                PostNu5Transaction::V4(transaction) => transaction.version() == TxVersion::V4,
                PostNu5Transaction::V5(raw) => raw.version() == TxVersion::V5,
                PostNu5Transaction::V6(transaction) => branch == BranchId::Nu6_3 && transaction.version() == TxVersion::V6,
            };
            if !version_ok || transaction.consensus_branch_id() != branch {
                return Err(SproutLedgerError::UnsupportedTransaction);
            }
            let txid = transaction.effect_id();
            if self.utxos.range((txid, 0)..=(txid, u32::MAX)).next().is_some() {
                return Err(SproutLedgerError::UnspentTransactionOverwrite);
            }
        }
        let mut transactions = transactions.into_iter();
        let coinbase = transactions.next().ok_or(SproutLedgerError::InvalidCoinbase)?;
        let values = check_post_nu5_coinbase(&coinbase, height, time)?;
        let mut delta = BlockDelta::new(self);
        delta.sigops = values.sigops;
        delta.transparent = i128::from(values.transparent);
        delta.sapling = -i128::from(values.sapling_balance);
        delta.orchard = -i128::from(values.orchard_balance);
        delta.ironwood = -i128::from(values.ironwood_balance);
        delta.retained = i128::from(values.retained);
        delta.deferred = i128::from(deferred_subsidy(height)) - i128::from(deferred_withdrawal(height));
        match coinbase {
            PostNu5Transaction::V4(transaction) => {
                self.stage_sapling(&transaction, &mut delta)?;
                delta.insert_outputs(*transaction, height, true);
            }
            PostNu5Transaction::V5(raw) => {
                let orchard = raw.orchard().copied();
                let hashes = (*raw).into_signature_context(vec![]).map_err(|_| SproutLedgerError::UnsupportedTransaction)?;
                self.stage_sapling_bundle(hashes.transaction().sapling_bundle(), &mut delta)?;
                self.stage_orchard(orchard.as_ref(), &mut delta)?;
                verify_sapling_post_nu5_crypto(&hashes).map_err(SproutLedgerError::Sapling)?;
                if let Some(orchard) = orchard {
                    verify_raw_orchard(&orchard, branch, &hashes.shielded())?;
                }
                let txid = hashes.effect_id();
                delta.insert_output_vector(txid, take_v5_outputs(hashes.into_transaction()), height, true);
            }
            PostNu5Transaction::V6(transaction) => {
                let hashes = PostNu5SignatureHash::new(*transaction, vec![]).map_err(|_| SproutLedgerError::UnsupportedTransaction)?;
                self.stage_sapling_bundle(hashes.transaction().sapling_bundle(), &mut delta)?;
                self.stage_typed_pool(hashes.transaction().orchard_bundle(), ShieldedPool::Orchard, &mut delta)?;
                self.stage_typed_pool(hashes.transaction().ironwood_bundle(), ShieldedPool::Ironwood, &mut delta)?;
                verify_sapling_post_nu5_crypto(&hashes).map_err(SproutLedgerError::Sapling)?;
                verify_post_nu63_crypto(&hashes).map_err(SproutLedgerError::PostNu63)?;
                let txid = hashes.effect_id();
                delta.insert_output_vector(txid, take_v5_outputs(hashes.into_transaction()), height, true);
            }
        }
        for transaction in transactions {
            match transaction {
                PostNu5Transaction::V4(transaction) => self.stage_transaction(*transaction, height, time, &mut delta)?,
                PostNu5Transaction::V5(raw) => self.stage_v5_transaction(*raw, height, time, &mut delta)?,
                PostNu5Transaction::V6(transaction) => self.stage_v6_transaction(*transaction, height, time, &mut delta)?,
            }
        }
        self.finish_delta(delta, values, height)
    }

    fn stage_history(&self, commitment: &[u8; 32], leaf: HistoryLeaf) -> Result<ChainHistoryV1, SproutLedgerError> {
        let height = u32::try_from(leaf.start_height).map_err(|_| SproutLedgerError::History(HistoryError::HeightOutOfRange))?;
        let branch = supported_branch(height)?;
        if !matches!(branch, BranchId::Heartwood | BranchId::Canopy) {
            return Err(SproutLedgerError::History(HistoryError::UnsupportedBranch));
        }
        if leaf.consensus_branch_id != u32::from(branch) {
            return Err(SproutLedgerError::History(HistoryError::BranchMismatch));
        }
        if leaf.start_height == 903_800 {
            if *commitment != [0; 32] {
                return Err(SproutLedgerError::WrongHistoryRoot);
            }
            return ChainHistoryV1::new(leaf).map_err(SproutLedgerError::History);
        }
        let history = self.chain_history.as_ref().ok_or(SproutLedgerError::WrongHistoryRoot)?;
        // Compare the parent BEFORE appending. No supplied/cache-only root can
        // stand in for the owned accumulator's actual peaks and computed root.
        if *commitment != history.root() || self.history_root != Some(history.root()) {
            return Err(SproutLedgerError::WrongHistoryRoot);
        }
        if height == 1_028_500 {
            // The activation header commits the LAST Heartwood root. Only
            // after checking that owned root may we start the new V1 epoch.
            if history.consensus_branch_id() != u32::from(BranchId::Heartwood) {
                return Err(SproutLedgerError::History(HistoryError::BranchMismatch));
            }
            if history.last_height() != 1_028_499 {
                return Err(SproutLedgerError::History(HistoryError::NonconsecutiveHeight));
            }
            return ChainHistoryV1::new(leaf).map_err(SproutLedgerError::History);
        }
        // Only <=32 upstream metadata peaks are copied, never a retained tree.
        let mut candidate = history.clone();
        candidate.append(leaf).map_err(SproutLedgerError::History)?;
        Ok(candidate)
    }

    fn stage_block(&self, coinbase: Transaction, transactions: Vec<Transaction>, height: u32, time: u32) -> Result<BlockDelta, SproutLedgerError> {
        // BIP30 sees the UNMODIFIED parent for ALL candidate identities. An
        // earlier candidate spend must not make a later overwrite admissible.
        for transaction in std::iter::once(&coinbase).chain(&transactions) {
            let txid: [u8; 32] = transaction.txid().into();
            if self.utxos.range((txid, 0)..=(txid, u32::MAX)).next().is_some() {
                return Err(SproutLedgerError::UnspentTransactionOverwrite);
            }
        }
        let values = check_coinbase(&coinbase, height, time)?;
        let mut delta = BlockDelta::new(self);
        delta.sigops = values.sigops;
        delta.transparent = i128::from(values.transparent);
        delta.sapling = -i128::from(values.sapling_balance);
        delta.retained = i128::from(values.retained);
        // Coinbase outputs are the first Sapling leaves in consensus order.
        // stage_sapling still recognizes only the unmodified parent anchors.
        self.stage_sapling(&coinbase, &mut delta)?;
        delta.insert_outputs(coinbase, height, true);
        for transaction in transactions {
            self.stage_transaction(transaction, height, time, &mut delta)?;
        }
        self.finish_delta(delta, values, height)
    }

    fn finish_delta(&self, mut delta: BlockDelta, values: CoinbaseValues, height: u32) -> Result<BlockDelta, SproutLedgerError> {
        let branch = supported_branch(height)?;
        // ZIP271 requires the actual parent to fund W BEFORE crediting D. This
        // is acceptance-equivalent on reachable default-testnet history; it also
        // rejects synthetic/corrupted W-D <= parent < W instead of creating value.
        if self.deferred_balance < deferred_withdrawal(height) {
            return Err(SproutLedgerError::InsufficientDeferredBalance);
        }
        let reward = i128::from(subsidy(height)?).checked_add(delta.fees).ok_or(SproutLedgerError::ValueOutOfRange)?;
        // Original GetValueOut remains negative-only before NU6.3. The released
        // NU6.3 node instead subtracts every signed coinbase pool balance.
        // Neither route substitutes recovered plaintext sums for balance.
        let claim = if branch == BranchId::Nu6_3 {
            i128::from(values.transparent) - i128::from(values.sapling_balance)
                - i128::from(values.orchard_balance) - i128::from(values.ironwood_balance) + delta.deferred
        } else {
            i128::from(values.claimed).checked_add(delta.deferred).ok_or(SproutLedgerError::ValueOutOfRange)?
        };
        let exact_reward = matches!(branch, BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3);
        if (exact_reward && claim != reward) || (!exact_reward && claim > reward) {
            return Err(SproutLedgerError::CoinbaseRewardExceeded);
        }
        delta.transparent = final_money(self.transparent_balance, delta.transparent)?.into();
        delta.sprout = final_money(self.shielded_balances[0], delta.sprout)?.into();
        delta.sapling = final_money(self.shielded_balances[1], delta.sapling)?.into();
        delta.orchard = final_money(self.shielded_balances[2], delta.orchard)?.into();
        delta.ironwood = final_money(self.shielded_balances[3], delta.ironwood)?.into();
        let issuance = claim.checked_sub(delta.fees).ok_or(SproutLedgerError::ValueOutOfRange)?;
        delta.deferred = final_money(self.deferred_balance, delta.deferred)?.into();
        delta.retained = final_money(self.utxo_balance, delta.retained)?.into();
        delta.issued = final_money(self.issued_supply, issuance)?;
        let total = delta.transparent + delta.sprout + delta.sapling + delta.orchard + delta.ironwood + delta.deferred;
        if total > i128::from(MAX_MONEY) || total != i128::from(delta.issued) {
            return Err(SproutLedgerError::ValueOutOfRange);
        }
        if delta.sapling_tree.tree_size() != self.sapling_tree.tree_size() || matches!(branch, BranchId::Heartwood | BranchId::Canopy | BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) {
            delta.sapling_root = delta.sapling_tree.root().to_bytes();
        }
        if matches!(branch, BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) {
            delta.orchard_root = delta.orchard_tree.root().to_bytes();
        }
        if branch == BranchId::Nu6_3 { delta.ironwood_root = delta.ironwood_tree.root().to_bytes(); }
        Ok(delta)
    }

    fn stage_v5_transaction(&self, raw: RawV5<'_>, height: u32, time: u32, delta: &mut BlockDelta) -> Result<(), SproutLedgerError> {
        let values = check_v5_transaction(&raw, height, time)?;
        let (inputs, previous_outputs) = self.resolve_post_prevouts(raw.transparent_bundle(), height, delta)?;
        let orchard = raw.orchard().copied();
        let hashes = raw.into_signature_context(previous_outputs).map_err(|_| SproutLedgerError::UnsupportedTransaction)?;
        self.stage_post_transaction(hashes, values, inputs, orchard, height, delta)
    }

    fn stage_v6_transaction(&self, transaction: Transaction, height: u32, time: u32, delta: &mut BlockDelta) -> Result<(), SproutLedgerError> {
        let values = check_v6_transaction(&transaction, height, time)?;
        let (inputs, previous_outputs) = self.resolve_post_prevouts(transaction.transparent_bundle(), height, delta)?;
        let hashes = PostNu5SignatureHash::new(transaction, previous_outputs).map_err(|_| SproutLedgerError::UnsupportedTransaction)?;
        self.stage_post_transaction(hashes, values, inputs, None, height, delta)
    }

    fn resolve_post_prevouts(&self, bundle: Option<&zcash_transparent::bundle::Bundle<zcash_transparent::bundle::Authorized>>, height: u32, delta: &BlockDelta) -> Result<(u64, Vec<TxOut>), SproutLedgerError> {
        let mut inputs = 0;
        let mut previous_outputs = Vec::with_capacity(bundle.map_or(0, |bundle| bundle.vin.len()));
        if let Some(bundle) = bundle {
            let mut coinbase_spent = false;
            // Resolve ALL actual prevouts in original order before marking ANY
            // input spent. The same values/scripts bind mixed shielded ALL.
            for input in &bundle.vin {
                let key = (*input.prevout().hash(), input.prevout().n());
                let coin = delta.coin(&self.utxos, &key).ok_or(SproutLedgerError::MissingTransparentInput)?;
                inputs = money_add(inputs, u64::from(coin.output.value()))?;
                if coin.is_coinbase {
                    if height.checked_sub(coin.created_height).is_none_or(|depth| depth < 100) {
                        return Err(SproutLedgerError::ImmatureCoinbase);
                    }
                    coinbase_spent = true;
                }
                previous_outputs.push(coin.output.clone());
            }
            if coinbase_spent && !bundle.vout.is_empty() { return Err(SproutLedgerError::UnshieldedCoinbaseSpend); }
        }
        Ok((inputs, previous_outputs))
    }

    fn stage_post_transaction(&self, hashes: PostNu5SignatureHash, values: TransactionValues, inputs: u64, raw_orchard: Option<RawOrchard<'_>>, height: u32, delta: &mut BlockDelta) -> Result<(), SproutLedgerError> {
        delta.add_sigops(values.sigops)?;
        let balances = [values.sapling_balance, values.orchard_balance, values.ironwood_balance];
        let credit = balances.into_iter().try_fold(inputs, |sum, balance| money_add(sum, balance.max(0) as u64))?;
        let debit = balances.into_iter().try_fold(values.outputs, |sum, balance| money_add(sum, balance.min(0).unsigned_abs()))?;
        let fee = credit.checked_sub(debit).ok_or(SproutLedgerError::NegativeFee)?;
        if let Some(bundle) = hashes.transaction().transparent_bundle() {
            for (index, input) in bundle.vin.iter().enumerate() {
                let key = (*input.prevout().hash(), input.prevout().n());
                let coin = delta.coin(&self.utxos, &key).expect("all actual prevouts resolved above");
                let count = p2sh_sigops(input.script_sig().0.0.as_slice(), coin.output.script_pubkey().0.0.as_slice());
                verify_v5_transparent_input(&hashes, index, &coin.output)?;
                delta.add_sigops(count)?;
                delta.utxos.insert(key, None);
            }
        }
        self.stage_sapling_bundle(hashes.transaction().sapling_bundle(), delta)?;
        if hashes.transaction().version() == TxVersion::V6 {
            self.stage_typed_pool(hashes.transaction().orchard_bundle(), ShieldedPool::Orchard, delta)?;
            self.stage_typed_pool(hashes.transaction().ironwood_bundle(), ShieldedPool::Ironwood, delta)?;
            verify_sapling_post_nu5_crypto(&hashes).map_err(SproutLedgerError::Sapling)?;
            verify_post_nu63_crypto(&hashes).map_err(SproutLedgerError::PostNu63)?;
        } else {
            self.stage_orchard(raw_orchard.as_ref(), delta)?;
            verify_sapling_post_nu5_crypto(&hashes).map_err(SproutLedgerError::Sapling)?;
            if let Some(orchard) = raw_orchard { verify_raw_orchard(&orchard, supported_branch(height)?, &hashes.shielded())?; }
        }
        delta.fees = delta.fees.checked_add(i128::from(fee)).ok_or(SproutLedgerError::ValueOutOfRange)?;
        delta.transparent = delta.transparent.checked_add(i128::from(values.outputs) - i128::from(inputs)).ok_or(SproutLedgerError::ValueOutOfRange)?;
        delta.sapling = delta.sapling.checked_sub(i128::from(values.sapling_balance)).ok_or(SproutLedgerError::ValueOutOfRange)?;
        delta.orchard = delta.orchard.checked_sub(i128::from(values.orchard_balance)).ok_or(SproutLedgerError::ValueOutOfRange)?;
        delta.ironwood = delta.ironwood.checked_sub(i128::from(values.ironwood_balance)).ok_or(SproutLedgerError::ValueOutOfRange)?;
        delta.retained = delta.retained.checked_add(i128::from(values.retained) - i128::from(inputs)).ok_or(SproutLedgerError::ValueOutOfRange)?;
        let txid = hashes.effect_id();
        delta.insert_output_vector(txid, take_v5_outputs(hashes.into_transaction()), height, false);
        Ok(())
    }

    fn stage_transaction(&self, transaction: Transaction, height: u32, time: u32, delta: &mut BlockDelta) -> Result<(), SproutLedgerError> {
        let values = check_transaction(&transaction, height, time)?;
        let hashes = match transaction.consensus_branch_id() {
            BranchId::Sprout => None,
            BranchId::Overwinter => Some(TransactionSignatureHash::Overwinter(
                OverwinterSignatureHash::new(&transaction).map_err(|_| SproutLedgerError::UnsupportedTransaction)?,
            )),
            BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy | BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3 => Some(TransactionSignatureHash::Sapling(
                SaplingSignatureHash::new(&transaction).map_err(|_| SproutLedgerError::UnsupportedTransaction)?,
            )),
        };
        delta.add_sigops(values.sigops)?;
        let mut inputs = 0;
        if let Some(bundle) = transaction.transparent_bundle() {
            // All maturity/protection/value checks precede execution. The
            // actual original input index and THIS sequence feed each checker.
            let mut coinbase_spent = false;
            for input in &bundle.vin {
                let key = (*input.prevout().hash(), input.prevout().n());
                let coin = delta.coin(&self.utxos, &key).ok_or(SproutLedgerError::MissingTransparentInput)?;
                inputs = money_add(inputs, u64::from(coin.output.value()))?;
                if coin.is_coinbase {
                    if height.checked_sub(coin.created_height).is_none_or(|depth| depth < 100) {
                        return Err(SproutLedgerError::ImmatureCoinbase);
                    }
                    coinbase_spent = true;
                }
            }
            if coinbase_spent && !bundle.vout.is_empty() {
                return Err(SproutLedgerError::UnshieldedCoinbaseSpend);
            }
            for (index, input) in bundle.vin.iter().enumerate() {
                let key = (*input.prevout().hash(), input.prevout().n());
                let coin = delta.coin(&self.utxos, &key).expect("inputs checked above");
                let p2sh_count = p2sh_sigops(input.script_sig().0.0.as_slice(), coin.output.script_pubkey().0.0.as_slice());
                verify_transparent_input(&transaction, hashes.as_ref(), index, &coin.output)?;
                delta.add_sigops(p2sh_count)?;
                delta.utxos.insert(key, None);
            }
        }
        let credit = money_add(money_add(inputs, values.new)?, values.sapling_balance.max(0) as u64)?;
        let debit = money_add(money_add(values.outputs, values.old)?, values.sapling_balance.min(0).unsigned_abs())?;
        let fee = credit.checked_sub(debit).ok_or(SproutLedgerError::NegativeFee)?;
        self.stage_sprout(&transaction, delta)?;
        self.stage_sapling(&transaction, delta)?;
        // All actual signature/proof equations consume this same transaction;
        // no checkpoint, validity flag or caller-supplied digest can admit it.
        match &hashes {
            Some(TransactionSignatureHash::Overwinter(hashes)) => verify_overwinter_joinsplit_crypto(hashes),
            Some(TransactionSignatureHash::Sapling(hashes)) => verify_sapling_joinsplit_crypto(hashes),
            None => verify_legacy_joinsplit_crypto(&transaction),
        }.map_err(SproutLedgerError::JoinSplit)?;
        if let Some(TransactionSignatureHash::Sapling(hashes)) = &hashes {
            verify_sapling_v4_crypto(hashes).map_err(SproutLedgerError::Sapling)?;
        }
        delta.fees = delta.fees.checked_add(i128::from(fee)).ok_or(SproutLedgerError::ValueOutOfRange)?;
        delta.transparent = delta.transparent.checked_add(i128::from(values.outputs) - i128::from(inputs))
            .ok_or(SproutLedgerError::ValueOutOfRange)?;
        delta.sprout = delta.sprout.checked_add(i128::from(values.old) - i128::from(values.new))
            .ok_or(SproutLedgerError::ValueOutOfRange)?;
        delta.sapling = delta.sapling.checked_sub(i128::from(values.sapling_balance))
            .ok_or(SproutLedgerError::ValueOutOfRange)?;
        delta.retained = delta.retained.checked_add(i128::from(values.retained) - i128::from(inputs))
            .ok_or(SproutLedgerError::ValueOutOfRange)?;
        delta.insert_outputs(transaction, height, false);
        Ok(())
    }

    fn stage_sprout(&self, transaction: &Transaction, delta: &mut BlockDelta) -> Result<(), SproutLedgerError> {
        let Some(bundle) = transaction.sprout_bundle() else { return Ok(()) };
        // Fresh per transaction: another transaction's partial block/interstitial
        // root is NEVER an admissible anchor. Historical spentness is current.
        let mut intermediates = BTreeMap::new();
        for description in &bundle.joinsplits {
            for nullifier in description.nullifiers() {
                if self.nullifiers[0].contains(nullifier) || !delta.nullifiers.insert(*nullifier) {
                    return Err(SproutLedgerError::SpentSproutNullifier);
                }
            }
            let anchored = intermediates.get(description.anchor())
                .or_else(|| self.sprout_anchors.get(description.anchor()))
                .ok_or(SproutLedgerError::UnknownSproutAnchor)?;
            let mut interstitial = anchored.clone();
            append_commitments(&mut interstitial, description.commitments())?;
            // Original intermediates.insert keeps the first equal-root state;
            // distinct later descriptions may branch from that same state.
            intermediates.entry(interstitial.root().0).or_insert(interstitial);
            // Different operation: block state appends all leaves in original
            // transaction/description order, independent of each chosen anchor.
            append_commitments(&mut delta.tree, description.commitments())?;
        }
        Ok(())
    }

    fn stage_sapling(&self, transaction: &Transaction, delta: &mut BlockDelta) -> Result<(), SproutLedgerError> {
        self.stage_sapling_bundle(transaction.sapling_bundle(), delta)
    }

    fn stage_sapling_bundle(&self, bundle: Option<&sapling_crypto::Bundle<sapling_crypto::bundle::Authorized, zcash_protocol::value::ZatBalance>>, delta: &mut BlockDelta) -> Result<(), SproutLedgerError> {
        let Some(bundle) = bundle else { return Ok(()) };
        for spend in bundle.shielded_spends() {
            let nullifier = spend.nullifier().0;
            if self.nullifiers[1].contains(&nullifier) || !delta.sapling_nullifiers.insert(nullifier) {
                return Err(SproutLedgerError::SpentSaplingNullifier);
            }
            // Only accepted PARENT block-end roots. No same-transaction or
            // same-block interstitial anchor exception exists for Sapling.
            if !self.sapling_anchors.contains(&spend.anchor().to_bytes()) {
                return Err(SproutLedgerError::UnknownSaplingAnchor);
            }
        }
        for output in bundle.shielded_outputs() {
            if !delta.sapling_tree.append(SaplingNode::from_cmu(output.cmu())) {
                return Err(SproutLedgerError::SaplingTreeFull);
            }
        }
        Ok(())
    }

    fn stage_orchard(&self, bundle: Option<&RawOrchard<'_>>, delta: &mut BlockDelta) -> Result<(), SproutLedgerError> {
        let Some(bundle) = bundle else { return Ok(()) };
        // Required for EVERY nonempty bundle, even disabled/dummy spends.
        // Candidate/interstitial roots never enter the admitted parent set.
        if !self.orchard_anchors.contains(&bundle.anchor().to_bytes()) {
            return Err(SproutLedgerError::UnknownOrchardAnchor);
        }
        for action in bundle.actions().as_chunks::<820>().0 {
            let nullifier = <[u8; 32]>::try_from(&action[32..64]).expect("parsed Orchard nullifier");
            if self.nullifiers[2].contains(&nullifier) || !delta.orchard_nullifiers.insert(nullifier) {
                return Err(SproutLedgerError::SpentOrchardNullifier);
            }
            let cmx = <[u8; 32]>::try_from(&action[96..128]).expect("parsed Orchard commitment");
            let node = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&cmx)).expect("raw parser checked canonical cmx");
            if !delta.orchard_tree.append(node) {
                return Err(SproutLedgerError::OrchardTreeFull);
            }
        }
        Ok(())
    }

    fn stage_typed_pool(&self, bundle: Option<&orchard::Bundle<orchard::bundle::Authorized, ZatBalance>>, pool: ShieldedPool, delta: &mut BlockDelta) -> Result<(), SproutLedgerError> {
        let Some(bundle) = bundle else { return Ok(()) };
        let (anchors, current, nullifiers, tree, unknown, spent, full) = match pool {
            ShieldedPool::Orchard => (&self.orchard_anchors, &self.nullifiers[2], &mut delta.orchard_nullifiers, &mut delta.orchard_tree,
                SproutLedgerError::UnknownOrchardAnchor, SproutLedgerError::SpentOrchardNullifier, SproutLedgerError::OrchardTreeFull),
            ShieldedPool::Ironwood => (&self.ironwood_anchors, &self.nullifiers[3], &mut delta.ironwood_nullifiers, &mut delta.ironwood_tree,
                SproutLedgerError::UnknownIronwoodAnchor, SproutLedgerError::SpentIronwoodNullifier, SproutLedgerError::IronwoodTreeFull),
            _ => unreachable!("only Orchard-family typed bundles use this stage"),
        };
        // Even disabled and padding Actions consume their own pool's N and CMX.
        // Current-block/interstitial and other-pool anchors are never admitted.
        if !anchors.contains(&bundle.anchor().to_bytes()) { return Err(unknown); }
        for action in bundle.actions().iter() {
            let nullifier = action.nullifier().to_bytes();
            if current.contains(&nullifier) || !nullifiers.insert(nullifier) { return Err(spent); }
            if !tree.append(MerkleHashOrchard::from_cmx(action.cmx())) { return Err(full); }
        }
        Ok(())
    }

    fn commit(&mut self, delta: BlockDelta) {
        // No remaining fallible consensus checks after the first mutation.
        for (key, coin) in delta.utxos {
            if let Some(coin) = coin {
                self.utxos.insert(key, coin);
            } else {
                self.utxos.remove(&key);
            }
        }
        self.nullifiers[0].extend(delta.nullifiers);
        self.nullifiers[1].extend(delta.sapling_nullifiers);
        self.nullifiers[2].extend(delta.orchard_nullifiers);
        self.nullifiers[3].extend(delta.ironwood_nullifiers);
        let root = delta.tree.root().0;
        // Original PushAnchor skips the existing best root, otherwise replaces
        // its stored frontier even when this root has appeared historically.
        if root != self.shielded_roots[0] {
            self.sprout_anchors.insert(root, delta.tree);
            self.shielded_roots[0] = root;
        }
        let root = delta.sapling_root;
        // Same original PushAnchor predicate as Sprout: unchanged best root
        // does not replace its persisted frontier, even if leaves were appended.
        if root != self.shielded_roots[1] {
            self.sapling_anchors.insert(root);
            self.sapling_tree = delta.sapling_tree;
            self.shielded_roots[1] = root;
        }
        let root = delta.orchard_root;
        if root != self.shielded_roots[2] {
            self.orchard_anchors.insert(root);
            self.orchard_tree = delta.orchard_tree;
            self.shielded_roots[2] = root;
        }
        let root = delta.ironwood_root;
        if root != self.shielded_roots[3] {
            self.ironwood_anchors.insert(root);
            self.ironwood_tree = delta.ironwood_tree;
            self.shielded_roots[3] = root;
        }
        self.transparent_balance = delta.transparent as u64;
        self.shielded_balances[0] = delta.sprout as u64;
        self.shielded_balances[1] = delta.sapling as u64;
        self.shielded_balances[2] = delta.orchard as u64;
        self.shielded_balances[3] = delta.ironwood as u64;
        self.deferred_balance = delta.deferred as u64;
        self.utxo_balance = delta.retained as u64;
        self.issued_supply = delta.issued;
    }
}

struct BlockDelta {
    utxos: BTreeMap<([u8; 32], u32), Option<TransparentCoin>>,
    nullifiers: BTreeSet<[u8; 32]>,
    tree: Frontier<SproutNode, 29>,
    sapling_nullifiers: BTreeSet<[u8; 32]>,
    sapling_tree: Frontier<SaplingNode, 32>,
    sapling_root: [u8; 32],
    orchard_nullifiers: BTreeSet<[u8; 32]>,
    orchard_tree: Frontier<MerkleHashOrchard, 32>,
    orchard_root: [u8; 32],
    ironwood_nullifiers: BTreeSet<[u8; 32]>,
    ironwood_tree: Frontier<MerkleHashOrchard, 32>,
    ironwood_root: [u8; 32],
    transparent: i128,
    sprout: i128,
    sapling: i128,
    orchard: i128,
    ironwood: i128,
    deferred: i128,
    retained: i128,
    fees: i128,
    issued: u64,
    sigops: u32,
}

impl BlockDelta {
    fn new(parent: &SproutTestnetLedger) -> Self {
        Self {
            utxos: BTreeMap::new(), nullifiers: BTreeSet::new(),
            tree: parent.sprout_anchors[&parent.shielded_roots[0]].clone(),
            sapling_nullifiers: BTreeSet::new(), sapling_tree: parent.sapling_tree.clone(),
            sapling_root: parent.shielded_roots[1],
            orchard_nullifiers: BTreeSet::new(), orchard_tree: parent.orchard_tree.clone(),
            orchard_root: parent.shielded_roots[2],
            ironwood_nullifiers: BTreeSet::new(), ironwood_tree: parent.ironwood_tree.clone(),
            ironwood_root: parent.shielded_roots[3],
            transparent: 0, sprout: 0, sapling: 0, orchard: 0, ironwood: 0, deferred: 0, retained: 0, fees: 0, issued: 0, sigops: 0,
        }
    }

    fn check_sapling_root(&self, height: u32, header_root: &[u8; 32]) -> Result<(), SproutLedgerError> {
        if matches!(supported_branch(height)?, BranchId::Sapling | BranchId::Blossom) && self.sapling_root != *header_root {
            return Err(SproutLedgerError::WrongSaplingRoot);
        }
        Ok(())
    }

    fn coin<'a>(&'a self, parent: &'a BTreeMap<([u8; 32], u32), TransparentCoin>, key: &([u8; 32], u32)) -> Option<&'a TransparentCoin> {
        self.utxos.get(key).map_or_else(|| parent.get(key), Option::as_ref)
    }

    fn add_sigops(&mut self, count: u32) -> Result<(), SproutLedgerError> {
        self.sigops = self.sigops.checked_add(count).filter(|total| *total <= MAX_SIGOPS)
            .ok_or(SproutLedgerError::TooManySigops)?;
        Ok(())
    }

    fn insert_outputs(&mut self, transaction: Transaction, height: u32, is_coinbase: bool) {
        let txid = transaction.txid().into();
        self.insert_output_vector(txid, take_outputs(transaction), height, is_coinbase);
    }

    fn insert_output_vector(&mut self, txid: [u8; 32], outputs: Vec<TxOut>, height: u32, is_coinbase: bool) {
        // Moving actual outputs preserves original indices across pruned gaps.
        for (index, output) in (0_u32..).zip(outputs) {
            if !is_pruned(output.script_pubkey().0.0.as_slice()) {
                self.utxos.insert((txid, index), Some(TransparentCoin { output, created_height: height, is_coinbase }));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoinbaseValues {
    // Historical GetValueOut: negative shielded balances only. NU6.3 uses
    // transparent minus ALL signed coinbase balances in finish_delta instead.
    claimed: u64,
    transparent: u64,
    sapling_balance: i64,
    orchard_balance: i64,
    ironwood_balance: i64,
    retained: u64,
    sigops: u32,
}

struct TransactionValues {
    outputs: u64,
    retained: u64,
    old: u64,
    new: u64,
    sapling_balance: i64,
    orchard_balance: i64,
    ironwood_balance: i64,
    sigops: u32,
}

fn check_coinbase(transaction: &Transaction, height: u32, time: u32) -> Result<CoinbaseValues, SproutLedgerError> {
    let scheduled_subsidy = subsidy(height)?;
    check_format_and_finality(transaction, height, time)?;
    if transaction.sprout_bundle().is_some() || transaction.sapling_bundle().is_some_and(|bundle| {
        !matches!(transaction.consensus_branch_id(), BranchId::Heartwood | BranchId::Canopy | BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) || !bundle.shielded_spends().is_empty()
    }) {
        return Err(SproutLedgerError::InvalidCoinbase);
    }
    let bundle = transaction.transparent_bundle().ok_or(SproutLedgerError::InvalidCoinbase)?;
    if !bundle.is_coinbase() || (bundle.vout.is_empty() && transaction.sapling_bundle().is_none_or(|bundle| bundle.shielded_outputs().is_empty())) {
        return Err(SproutLedgerError::InvalidCoinbase);
    }
    let script = bundle.vin[0].script_sig().0.0.as_slice();
    let (prefix, length) = coinbase_height_prefix(height);
    if !(2..=100).contains(&script.len()) || !script.starts_with(&prefix[..length]) {
        return Err(SproutLedgerError::InvalidCoinbase);
    }
    let (transparent, retained, sigops) = output_values(transaction)?;
    let sapling_balance = transaction.sapling_bundle().map_or(0, |bundle| i64::from(*bundle.value_balance()));
    if !(-(MAX_MONEY as i64)..=MAX_MONEY as i64).contains(&sapling_balance) {
        return Err(SproutLedgerError::ValueOutOfRange);
    }
    // GetValueOut is transparent outputs plus negative valueBalance, NOT the
    // recovered plaintext sum. Actual binding/proofs enforce shielded values.
    // No extra positive-valueBalance ban or plaintext-total equality: no spends,
    // fixed output proofs and the actual binding equation are source predicates.
    let claimed = money_add(transparent, sapling_balance.min(0).unsigned_abs())?;
    check_reward_outputs(&bundle.vout, height, scheduled_subsidy)?;
    if let Some(bundle) = transaction.sapling_bundle() {
        for (index, output) in bundle.shielded_outputs().iter().enumerate() {
            recover_sapling_coinbase_output(output, height).map_err(|error| SproutLedgerError::CoinbaseRecovery { index, error })?;
        }
        let hashes = SaplingSignatureHash::new(transaction).map_err(|_| SproutLedgerError::UnsupportedTransaction)?;
        verify_sapling_v4_crypto(&hashes).map_err(SproutLedgerError::Sapling)?;
    }
    Ok(CoinbaseValues { claimed, transparent, sapling_balance, orchard_balance: 0, ironwood_balance: 0, retained, sigops })
}

// Post-NU5 formats share expiry and funding. Old GetValueOut remains intact;
// NU6.3's signed coinbase equation is applied only at finalization.

fn has_orchard(transaction: &PostNu5Transaction<'_>) -> bool {
    match transaction {
        PostNu5Transaction::V4(transaction) | PostNu5Transaction::V6(transaction) => transaction.orchard_bundle().is_some(),
        PostNu5Transaction::V5(raw) => raw.orchard().is_some(),
    }
}

fn verify_raw_orchard(bundle: &RawOrchard<'_>, branch: BranchId, sighash: &[u8; 32]) -> Result<(), SproutLedgerError> {
    match branch {
        BranchId::Nu6_3 => bundle.verify_orchard_post_nu63(&PostNu63OrchardVerifier::new(), sighash),
        BranchId::Nu6_2 => bundle.verify_orchard_fixed(&FixedOrchardVerifier::new(), sighash),
        BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 => bundle.verify_orchard(&OriginalOrchardVerifier::new(), sighash),
        _ => return Err(SproutLedgerError::UnsupportedTransaction),
    }.map_err(SproutLedgerError::Orchard)
}

fn check_post_nu5_coinbase(transaction: &PostNu5Transaction<'_>, height: u32, time: u32) -> Result<CoinbaseValues, SproutLedgerError> {
    match transaction {
        PostNu5Transaction::V4(transaction) => check_coinbase(transaction, height, time),
        PostNu5Transaction::V5(raw) => {
            check_v5_format_and_finality(raw, height, time)?;
            let transparent = raw.transparent_bundle().ok_or(SproutLedgerError::InvalidCoinbase)?;
            let sapling = raw.sapling_bundle();
            let orchard = raw.orchard();
            if raw.consensus_branch_id() == BranchId::Nu6_3 && orchard.is_some() {
                return Err(SproutLedgerError::InvalidCoinbase);
            }
            if !transparent.is_coinbase() || sapling.is_some_and(|bundle| !bundle.shielded_spends().is_empty())
                || orchard.is_some_and(|bundle| bundle.flags().spends_enabled())
                || (transparent.vout.is_empty() && sapling.is_none_or(|bundle| bundle.shielded_outputs().is_empty())
                    && orchard.is_none_or(|bundle| !bundle.flags().outputs_enabled())) {
                return Err(SproutLedgerError::InvalidCoinbase);
            }
            let script = transparent.vin[0].script_sig().0.0.as_slice();
            let (prefix, length) = coinbase_height_prefix(height);
            if !(2..=100).contains(&script.len()) || !script.starts_with(&prefix[..length]) {
                return Err(SproutLedgerError::InvalidCoinbase);
            }
            let (outputs, retained, sigops) = transparent_values(Some(transparent))?;
            let sapling_balance = sapling.map_or(0, |bundle| i64::from(*bundle.value_balance()));
            let orchard_balance = orchard.map_or(0, |bundle| i64::from(bundle.value_balance()));
            let claimed = money_add(money_add(outputs, sapling_balance.min(0).unsigned_abs())?, orchard_balance.min(0).unsigned_abs())?;
            money_add(sapling_balance.max(0) as u64, orchard_balance.max(0) as u64)?;
            check_reward_outputs(&transparent.vout, height, subsidy(height)?)?;
            if let Some(bundle) = sapling {
                for (index, output) in bundle.shielded_outputs().iter().enumerate() {
                    recover_sapling_coinbase_output(output, height).map_err(|error| SproutLedgerError::CoinbaseRecovery { index, error })?;
                }
            }
            if let Some(bundle) = orchard {
                bundle.verify_coinbase_outputs().map_err(SproutLedgerError::Orchard)?;
            }
            Ok(CoinbaseValues { claimed, transparent: outputs, sapling_balance, orchard_balance, ironwood_balance: 0, retained, sigops })
        }
        PostNu5Transaction::V6(transaction) => check_v6_coinbase(transaction, height, time),
    }
}

fn check_reward_outputs(outputs: &[TxOut], height: u32, scheduled_subsidy: u64) -> Result<(), SproutLedgerError> {
    if (1_028_500..2_796_000).contains(&height) {
        // Original FundingPeriodIndex: (1028500 - 1116000) mod35000 =17500.
        let period = ((height - 1_028_500 + 17_500) / 35_000) as usize;
        for (index, (payload, numerator)) in [(&CANOPY_BP_HASHES[period], 7), (&CANOPY_ZF_HASH, 5), (&CANOPY_MG_HASH, 8)].into_iter().enumerate() {
            let script = p2sh_script(payload);
            let value = scheduled_subsidy * numerator / 100;
            if !outputs.iter().any(|output| output.script_pubkey().0.0 == script && u64::from(output.value()) == value) {
                return Err(SproutLedgerError::MissingFundingStream { index });
            }
        }
    } else if height < 1_028_500 {
        let founder = founders_script(height);
        if !outputs.iter().any(|output| output.script_pubkey().0.0 == founder && u64::from(output.value()) == scheduled_subsidy / 5) {
            return Err(SproutLedgerError::MissingFoundersReward);
        }
    } else if (2_976_000..3_396_000).contains(&height) || (3_536_500..4_465_026).contains(&height) {
        let fpf = p2sh_script(&NU6_FPF_HASH);
        if !outputs.iter().any(|output| output.script_pubkey().0.0 == fpf && u64::from(output.value()) == 12_500_000) {
            return Err(SproutLedgerError::MissingFundingStream { index: 0 });
        }
    }
    if height == 3_536_500 {
        let script = p2sh_script(&NU61_DISBURSEMENT_HASH);
        // Consume each actual position at most once, stopping after the ten
        // required matches. Ordering and unrelated/extra outputs are unrestricted;
        // a reused or summed output cannot satisfy identical requirements.
        if outputs.iter().filter(|output| output.script_pubkey().0.0 == script && u64::from(output.value()) == 787_500_000_000).take(10).count() != 10 {
            return Err(SproutLedgerError::MissingDeferredDisbursement);
        }
    }
    // Deferred D has NO recipient/output. Streams pause3396000..3536499;
    // only the activation withdrawal W has separate required transparent outputs.
    Ok(())
}

fn check_v5_transaction(raw: &RawV5<'_>, height: u32, time: u32) -> Result<TransactionValues, SproutLedgerError> {
    check_v5_format_and_finality(raw, height, time)?;
    let transparent = raw.transparent_bundle();
    let sapling = raw.sapling_bundle();
    let orchard = raw.orchard();
    if (transparent.is_none_or(|bundle| bundle.vin.is_empty()) && sapling.is_none_or(|bundle| bundle.shielded_spends().is_empty())
        && orchard.is_none_or(|bundle| !bundle.flags().spends_enabled()))
        || (transparent.is_none_or(|bundle| bundle.vout.is_empty()) && sapling.is_none_or(|bundle| bundle.shielded_outputs().is_empty())
            && orchard.is_none_or(|bundle| !bundle.flags().outputs_enabled())) {
        return Err(SproutLedgerError::InvalidTransaction);
    }
    let mut outpoints = BTreeSet::new();
    if let Some(bundle) = transparent {
        for input in &bundle.vin {
            if input.prevout() == &zcash_transparent::bundle::OutPoint::NULL {
                return Err(SproutLedgerError::InvalidTransaction);
            }
            if !outpoints.insert((*input.prevout().hash(), input.prevout().n())) {
                return Err(SproutLedgerError::DuplicateTransparentInput);
            }
        }
    }
    let (outputs, retained, sigops) = transparent_values(transparent)?;
    let sapling_balance = sapling.map_or(0, |bundle| i64::from(*bundle.value_balance()));
    let orchard_balance = orchard.map_or(0, |bundle| i64::from(bundle.value_balance()));
    if raw.consensus_branch_id() == BranchId::Nu6_3 && orchard_balance < 0 { return Err(SproutLedgerError::NegativeOrchardBalance); }
    money_add(money_add(outputs, sapling_balance.min(0).unsigned_abs())?, orchard_balance.min(0).unsigned_abs())?;
    money_add(sapling_balance.max(0) as u64, orchard_balance.max(0) as u64)?;
    Ok(TransactionValues { outputs, retained, old: 0, new: 0, sapling_balance, orchard_balance, ironwood_balance: 0, sigops })
}

fn check_v5_format_and_finality(raw: &RawV5<'_>, height: u32, time: u32) -> Result<(), SproutLedgerError> {
    let branch = supported_branch(height)?;
    if !matches!(branch, BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) || raw.consensus_branch_id() != branch {
        return Err(SproutLedgerError::UnsupportedTransaction);
    }
    if (4_048_500..4_052_000).contains(&height) && raw.orchard().is_some() {
        return Err(SproutLedgerError::OrchardDisabled);
    }
    check_expiry_and_finality(branch, u32::from(raw.expiry_height()), raw.transparent_bundle().is_some_and(|bundle| bundle.is_coinbase()),
        raw.lock_time(), raw.transparent_bundle().is_none_or(|bundle| bundle.vin.iter().all(|input| input.sequence() == u32::MAX)), height, time)
}

fn check_v6_format_and_finality(transaction: &Transaction, height: u32, time: u32) -> Result<(), SproutLedgerError> {
    if supported_branch(height)? != BranchId::Nu6_3 || transaction.consensus_branch_id() != BranchId::Nu6_3
        || transaction.version() != TxVersion::V6 || transaction.sprout_bundle().is_some() {
        return Err(SproutLedgerError::UnsupportedTransaction);
    }
    if transaction.sapling_bundle().is_some_and(|bundle| bundle.shielded_spends().len() >= 65_536 || bundle.shielded_outputs().len() >= 65_536
        || (bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty())) {
        return Err(SproutLedgerError::InvalidTransaction);
    }
    for (bundle, version) in [(transaction.orchard_bundle(), orchard::bundle::BundleVersion::orchard_v3()),
        (transaction.ironwood_bundle(), orchard::bundle::BundleVersion::ironwood_v3())] {
        if let Some(bundle) = bundle
            && (bundle.bundle_version() != version || bundle.actions().len() >= 65_536
                || (!bundle.flags().spends_enabled() && !bundle.flags().outputs_enabled())
                || (version == orchard::bundle::BundleVersion::orchard_v3() && bundle.flags().cross_address_enabled())) {
            return Err(SproutLedgerError::InvalidTransaction);
        }
    }
    transaction.write(TransactionSize { written: 0, limit: MAX_SAPLING_TRANSACTION_BYTES }).map_err(|_| SproutLedgerError::TransactionTooLarge)?;
    check_expiry_and_finality(BranchId::Nu6_3, u32::from(transaction.expiry_height()), transaction.transparent_bundle().is_some_and(|bundle| bundle.is_coinbase()),
        transaction.lock_time(), transaction.transparent_bundle().is_none_or(|bundle| bundle.vin.iter().all(|input| input.sequence() == u32::MAX)), height, time)
}

fn check_v6_coinbase(transaction: &Transaction, height: u32, time: u32) -> Result<CoinbaseValues, SproutLedgerError> {
    check_v6_format_and_finality(transaction, height, time)?;
    let transparent = transaction.transparent_bundle().ok_or(SproutLedgerError::InvalidCoinbase)?;
    let sapling = transaction.sapling_bundle();
    let ironwood = transaction.ironwood_bundle();
    if !transparent.is_coinbase() || transaction.orchard_bundle().is_some()
        || sapling.is_some_and(|bundle| !bundle.shielded_spends().is_empty())
        || ironwood.is_some_and(|bundle| bundle.flags().spends_enabled())
        || (transparent.vout.is_empty() && sapling.is_none_or(|bundle| bundle.shielded_outputs().is_empty())
            && ironwood.is_none_or(|bundle| !bundle.flags().outputs_enabled())) {
        return Err(SproutLedgerError::InvalidCoinbase);
    }
    let (prefix, length) = coinbase_height_prefix(height);
    let script = transparent.vin[0].script_sig().0.0.as_slice();
    if !(2..=100).contains(&script.len()) || !script.starts_with(&prefix[..length]) { return Err(SproutLedgerError::InvalidCoinbase); }
    let (outputs, retained, sigops) = transparent_values(Some(transparent))?;
    let sapling_balance = sapling.map_or(0, |bundle| i64::from(*bundle.value_balance()));
    let ironwood_balance = ironwood.map_or(0, |bundle| i64::from(*bundle.value_balance()));
    let claimed = money_add(money_add(outputs, sapling_balance.min(0).unsigned_abs())?, ironwood_balance.min(0).unsigned_abs())?;
    money_add(sapling_balance.max(0) as u64, ironwood_balance.max(0) as u64)?;
    check_reward_outputs(&transparent.vout, height, subsidy(height)?)?;
    if let Some(bundle) = sapling {
        for (index, output) in bundle.shielded_outputs().iter().enumerate() {
            recover_sapling_coinbase_output(output, height).map_err(|error| SproutLedgerError::CoinbaseRecovery { index, error })?;
        }
    }
    if let Some(bundle) = ironwood {
        for (index, action) in bundle.actions().iter().enumerate() {
            recover_ironwood_coinbase_output(action, height).map_err(|error| SproutLedgerError::IronwoodCoinbaseRecovery { index, error })?;
        }
    }
    Ok(CoinbaseValues { claimed, transparent: outputs, sapling_balance, orchard_balance: 0, ironwood_balance, retained, sigops })
}

fn check_v6_transaction(transaction: &Transaction, height: u32, time: u32) -> Result<TransactionValues, SproutLedgerError> {
    check_v6_format_and_finality(transaction, height, time)?;
    let transparent = transaction.transparent_bundle();
    let sapling = transaction.sapling_bundle();
    let orchard = transaction.orchard_bundle();
    let ironwood = transaction.ironwood_bundle();
    if (transparent.is_none_or(|bundle| bundle.vin.is_empty()) && sapling.is_none_or(|bundle| bundle.shielded_spends().is_empty())
        && orchard.is_none_or(|bundle| !bundle.flags().spends_enabled()) && ironwood.is_none_or(|bundle| !bundle.flags().spends_enabled()))
        || (transparent.is_none_or(|bundle| bundle.vout.is_empty()) && sapling.is_none_or(|bundle| bundle.shielded_outputs().is_empty())
            && orchard.is_none_or(|bundle| !bundle.flags().outputs_enabled()) && ironwood.is_none_or(|bundle| !bundle.flags().outputs_enabled())) {
        return Err(SproutLedgerError::InvalidTransaction);
    }
    let mut outpoints = BTreeSet::new();
    if let Some(bundle) = transparent {
        for input in &bundle.vin {
            if input.prevout() == &zcash_transparent::bundle::OutPoint::NULL { return Err(SproutLedgerError::InvalidTransaction); }
            if !outpoints.insert((*input.prevout().hash(), input.prevout().n())) { return Err(SproutLedgerError::DuplicateTransparentInput); }
        }
    }
    let (outputs, retained, sigops) = transparent_values(transparent)?;
    let sapling_balance = sapling.map_or(0, |bundle| i64::from(*bundle.value_balance()));
    let orchard_balance = orchard.map_or(0, |bundle| i64::from(*bundle.value_balance()));
    let ironwood_balance = ironwood.map_or(0, |bundle| i64::from(*bundle.value_balance()));
    if orchard_balance < 0 { return Err(SproutLedgerError::NegativeOrchardBalance); }
    let balances = [sapling_balance, orchard_balance, ironwood_balance];
    balances.into_iter().try_fold(outputs, |sum, balance| money_add(sum, balance.min(0).unsigned_abs()))?;
    balances.into_iter().try_fold(0, |sum, balance| money_add(sum, balance.max(0) as u64))?;
    Ok(TransactionValues { outputs, retained, old: 0, new: 0, sapling_balance, orchard_balance, ironwood_balance, sigops })
}

fn check_transaction(transaction: &Transaction, height: u32, time: u32) -> Result<TransactionValues, SproutLedgerError> {
    check_format_and_finality(transaction, height, time)?;
    let transparent = transaction.transparent_bundle();
    let has_joinsplits = transaction.sprout_bundle().is_some();
    let sapling = transaction.sapling_bundle();
    if (!has_joinsplits && transparent.is_none_or(|bundle| bundle.vin.is_empty())
        && sapling.is_none_or(|bundle| bundle.shielded_spends().is_empty()))
        || (!has_joinsplits && transparent.is_none_or(|bundle| bundle.vout.is_empty())
            && sapling.is_none_or(|bundle| bundle.shielded_outputs().is_empty())) {
        return Err(SproutLedgerError::InvalidTransaction);
    }
    let mut outpoints = BTreeSet::new();
    if let Some(bundle) = transparent {
        for input in &bundle.vin {
            if input.prevout() == &zcash_transparent::bundle::OutPoint::NULL {
                return Err(SproutLedgerError::InvalidTransaction);
            }
            if !outpoints.insert((*input.prevout().hash(), input.prevout().n())) {
                return Err(SproutLedgerError::DuplicateTransparentInput);
            }
        }
    }
    let (outputs, retained, sigops) = output_values(transaction)?;
    let (mut old, mut new) = (0, 0);
    if let Some(bundle) = transaction.sprout_bundle() {
        for description in &bundle.joinsplits {
            let debit = u64::try_from(description.vpub_old()).map_err(|_| SproutLedgerError::ValueOutOfRange)?;
            let credit = u64::try_from(description.vpub_new()).map_err(|_| SproutLedgerError::ValueOutOfRange)?;
            if matches!(transaction.consensus_branch_id(), BranchId::Canopy | BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) && debit != 0 {
                return Err(SproutLedgerError::SproutDepositDisabled);
            }
            if debit != 0 && credit != 0 {
                return Err(SproutLedgerError::ValueOutOfRange);
            }
            old = money_add(old, debit)?;
            new = money_add(new, credit)?;
        }
    }
    let sapling_balance = sapling.map_or(0, |bundle| i64::from(*bundle.value_balance()));
    if !(-(MAX_MONEY as i64)..=MAX_MONEY as i64).contains(&sapling_balance) {
        return Err(SproutLedgerError::ValueOutOfRange);
    }
    money_add(money_add(outputs, old)?, sapling_balance.min(0).unsigned_abs())?;
    money_add(new, sapling_balance.max(0) as u64)?;
    Ok(TransactionValues { outputs, retained, old, new, sapling_balance, orchard_balance: 0, ironwood_balance: 0, sigops })
}

fn supported_branch(height: u32) -> Result<BranchId, SproutLedgerError> {
    // Installed protocol0.10.5 has no NU7 activation. The published schedule
    // must bound this lane independently of its otherwise unbounded lookup.
    if height >= 4_465_026 { return Err(SproutLedgerError::UnsupportedEra); }
    match BranchId::for_height(&TEST_NETWORK, height.into()) {
        branch @ (BranchId::Sprout | BranchId::Overwinter | BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy | BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) => Ok(branch),
    }
}

fn check_format_and_finality(transaction: &Transaction, height: u32, time: u32) -> Result<(), SproutLedgerError> {
    let branch = supported_branch(height)?;
    if transaction.consensus_branch_id() != branch {
        return Err(SproutLedgerError::UnsupportedTransaction);
    }
    match branch {
        BranchId::Sprout => check_legacy_transaction(transaction).map(|_| ()).map_err(|_| SproutLedgerError::UnsupportedTransaction),
        BranchId::Overwinter => check_overwinter_transaction(transaction).map_err(|_| SproutLedgerError::UnsupportedTransaction),
        BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy | BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3 => check_sapling_transaction(transaction).map_err(|_| SproutLedgerError::UnsupportedTransaction),
    }?;
    if matches!(branch, BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) && transaction.sapling_bundle().is_some_and(|bundle| bundle.shielded_spends().len() >= 65_536 || bundle.shielded_outputs().len() >= 65_536) {
        return Err(SproutLedgerError::InvalidTransaction);
    }
    let limit = if matches!(branch, BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy | BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) { MAX_SAPLING_TRANSACTION_BYTES } else { MAX_TRANSACTION_BYTES };
    transaction.write(TransactionSize { written: 0, limit }).map_err(|_| SproutLedgerError::TransactionTooLarge)?;
    check_expiry_and_finality(branch, u32::from(transaction.expiry_height()), transaction.transparent_bundle().is_some_and(|bundle| bundle.is_coinbase()),
        transaction.lock_time(), transaction.transparent_bundle().is_none_or(|bundle| bundle.vin.iter().all(|input| input.sequence() == u32::MAX)), height, time)?;
    Ok(())
}

fn check_expiry_and_finality(branch: BranchId, expiry: u32, coinbase: bool, lock: u32, all_final: bool, height: u32, time: u32) -> Result<(), SproutLedgerError> {
    if branch != BranchId::Sprout {
        if matches!(branch, BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) && coinbase {
            if expiry != height { return Err(SproutLedgerError::InvalidCoinbase); }
        } else {
            if expiry >= 500_000_000 { return Err(SproutLedgerError::InvalidTransaction); }
            if !coinbase && expiry != 0 && height > expiry { return Err(SproutLedgerError::ExpiredTransaction); }
        }
    }
    let reference = if lock < 500_000_000 { height } else { time };
    if lock != 0 && lock >= reference && !all_final { return Err(SproutLedgerError::NonfinalTransaction); }
    Ok(())
}

fn output_values(transaction: &Transaction) -> Result<(u64, u64, u32), SproutLedgerError> {
    transparent_values(transaction.transparent_bundle())
}

fn transparent_values(bundle: Option<&zcash_transparent::bundle::Bundle<zcash_transparent::bundle::Authorized>>) -> Result<(u64, u64, u32), SproutLedgerError> {
    let (mut outputs, mut retained, mut sigops) = (0, 0, 0_u32);
    if let Some(bundle) = bundle {
        for input in &bundle.vin {
            sigops = sigops.checked_add(legacy_sigops(input.script_sig().0.0.as_slice())).ok_or(SproutLedgerError::TooManySigops)?;
        }
        for output in &bundle.vout {
            outputs = money_add(outputs, u64::from(output.value()))?;
            let script = output.script_pubkey().0.0.as_slice();
            if !is_pruned(script) {
                retained = money_add(retained, u64::from(output.value()))?;
            }
            sigops = sigops.checked_add(legacy_sigops(script)).ok_or(SproutLedgerError::TooManySigops)?;
        }
    }
    if sigops > MAX_SIGOPS {
        return Err(SproutLedgerError::TooManySigops);
    }
    Ok((outputs, retained, sigops))
}

fn coinbase_height_prefix(height: u32) -> ([u8; 6], usize) {
    let mut prefix = [0; 6];
    if height <= 16 {
        prefix[0] = 0x50 + height as u8;
        return (prefix, 1);
    }
    let mut value = height;
    let mut length = 0;
    while value != 0 {
        length += 1;
        prefix[length] = value as u8;
        value >>= 8;
    }
    if prefix[length] & 0x80 != 0 { length += 1; }
    prefix[0] = length as u8;
    (prefix, length + 1)
}

fn subsidy(height: u32) -> Result<u64, SproutLedgerError> {
    supported_branch(height)?;
    match height {
        1..10_000 => Ok(62_500 * u64::from(height)),
        10_000..20_000 => Ok(62_500 * (u64::from(height) + 1)),
        20_000.. => {
            let height = u64::from(height);
            // ZIP208 adds rational pre/post intervals before flooring. u32
            // heights widen before scaling; never shift by64 or clamp halvings.
            let (base, halvings) = if height < 584_000 {
                (1_250_000_000_u64, (height - 10_000) / 840_000)
            } else {
                (625_000_000_u64, (2 * (584_000 - 10_000) + (height - 584_000)) / 1_680_000)
            };
            Ok(base.checked_shr(halvings as u32).unwrap_or(0))
        }
        _ => Err(SproutLedgerError::UnsupportedEra),
    }
}

fn deferred_subsidy(height: u32) -> u64 {
    if (2_976_000..3_396_000).contains(&height) || (3_536_500..4_465_026).contains(&height) { 18_750_000 } else { 0 }
}

fn deferred_withdrawal(height: u32) -> u64 {
    if height == 3_536_500 { NU61_DEFERRED_WITHDRAWAL } else { 0 }
}

fn founders_script(height: u32) -> [u8; 23] {
    // Called only before Canopy. ZIP208 stretches rotation, not its index size.
    let adjusted_height = if height < 584_000 { height } else { 584_000 + (height - 584_000) / 2 };
    p2sh_script(&FOUNDERS_HASHES[(adjusted_height / 17_709) as usize])
}

fn p2sh_script(payload: &[u8; 20]) -> [u8; 23] {
    let mut script = [0; 23];
    script[..2].copy_from_slice(&[0xa9, 0x14]);
    script[2..22].copy_from_slice(payload);
    script[22] = 0x87;
    script
}

fn sapling_transaction_count<'a>(transactions: impl Iterator<Item = &'a Transaction>) -> u64 {
    transactions.filter(|transaction| transaction.sapling_bundle().is_some_and(|bundle| {
        !bundle.shielded_spends().is_empty() || !bundle.shielded_outputs().is_empty()
    })).count() as u64
}

fn history_leaf(parent: HeaderTip, tip: HeaderTip, sapling_root: [u8; 32], sapling_tx: u64) -> Result<HistoryLeaf, SproutLedgerError> {
    let work = tip.cumulative_work().checked_sub(parent.cumulative_work())
        .ok_or(SproutLedgerError::Header(HeaderError::WorkOverflow))?;
    Ok(HistoryLeaf {
        consensus_branch_id: u32::from(BranchId::for_height(&TEST_NETWORK, tip.height().into())),
        subtree_commitment: tip.hash(),
        start_time: tip.time(), end_time: tip.time(),
        start_target: tip.bits(), end_target: tip.bits(),
        start_sapling_root: sapling_root, end_sapling_root: sapling_root,
        subtree_total_work: work,
        start_height: tip.height().into(), end_height: tip.height().into(),
        sapling_tx,
    })
}

enum TransactionSignatureHash<'tx> {
    Overwinter(OverwinterSignatureHash<'tx>),
    Sapling(SaplingSignatureHash<'tx>),
}

fn verify_transparent_input(transaction: &Transaction, hashes: Option<&TransactionSignatureHash<'_>>, index: usize, prevout: &TxOut) -> Result<(), SproutLedgerError> {
    let input = &transaction.transparent_bundle().expect("selected transparent input").vin[index];
    let sighash = |code: &Code, hash_type: &HashType| {
        match hashes {
            Some(TransactionSignatureHash::Overwinter(hashes)) => hashes.transparent(index, &code.0, prevout.value(), hash_type.raw_bits()).ok(),
            Some(TransactionSignatureHash::Sapling(hashes)) => hashes.transparent(index, &code.0, prevout.value(), hash_type.raw_bits()).ok(),
            None => legacy_signature_hash(transaction, index, &code.0, hash_type.raw_bits()).ok(),
        }
    };
    let checker = CallbackTransactionSignatureChecker {
        sighash: &sighash,
        lock_time: i64::from(transaction.lock_time()),
        is_final: input.sequence() == u32::MAX,
    };
    // ponytail: installed public Raw API requires these two owned copies;
    // replace only when upstream exposes equivalent borrowed full evaluation.
    match Raw::from_raw_parts(input.script_sig().0.0.clone(), prevout.script_pubkey().0.0.clone()).eval(SCRIPT_FLAGS, &checker) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(SproutLedgerError::InvalidTransparentScript),
    }
}

fn verify_v5_transparent_input(hashes: &PostNu5SignatureHash, index: usize, prevout: &TxOut) -> Result<(), SproutLedgerError> {
    let transaction = hashes.transaction();
    let input = &transaction.transparent_bundle().expect("selected actual transparent input").vin[index];
    // ZIP244 ignores evaluator scriptCode and hashes the actual locking script
    // stored in the resolved context, including P2SH rather than its redeem code.
    // Invalid hash/SINGLE maps to CHECKSIG=false, not a new StrictEnc abort.
    let sighash = |_code: &Code, hash_type: &HashType| {
        u8::try_from(hash_type.raw_bits()).ok().and_then(|hash_type| hashes.transparent(index, hash_type).ok())
    };
    let checker = CallbackTransactionSignatureChecker {
        sighash: &sighash,
        lock_time: i64::from(transaction.lock_time()),
        is_final: input.sequence() == u32::MAX,
    };
    match Raw::from_raw_parts(input.script_sig().0.0.clone(), prevout.script_pubkey().0.0.clone()).eval(SCRIPT_FLAGS, &checker) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(SproutLedgerError::InvalidTransparentScript),
    }
}

fn append_commitments(tree: &mut Frontier<SproutNode, 29>, commitments: &[[u8; 32]; 2]) -> Result<(), SproutLedgerError> {
    for commitment in commitments {
        if !tree.append(SproutNode(*commitment)) {
            return Err(SproutLedgerError::SproutTreeFull);
        }
    }
    Ok(())
}

fn final_money(parent: u64, delta: i128) -> Result<u64, SproutLedgerError> {
    let value = i128::from(parent).checked_add(delta).ok_or(SproutLedgerError::ValueOutOfRange)?;
    u64::try_from(value).ok().filter(|value| *value <= MAX_MONEY).ok_or(SproutLedgerError::ValueOutOfRange)
}

fn take_outputs(transaction: Transaction) -> Vec<TxOut> {
    let mut outputs = Vec::new();
    // Upstream has no consuming transparent accessor. Its existing bundle
    // mapping seam transfers the actual vector without copying any script.
    let _data = transaction.into_data().map_bundles::<Authorized>(|bundle| {
        if let Some(bundle) = bundle { outputs = bundle.vout; }
        None
    }, |bundle| bundle, |bundle| bundle);
    outputs
}

fn take_v5_outputs(transaction: TransactionData<PostNu5Authorization>) -> Vec<TxOut> {
    let mut outputs = Vec::new();
    let _data = transaction.map_bundles::<PostNu5Authorization>(|bundle| {
        if let Some(bundle) = bundle { outputs = bundle.vout; }
        None
    }, |bundle| bundle, |bundle| bundle);
    outputs
}

fn money_add(left: u64, right: u64) -> Result<u64, SproutLedgerError> {
    left.checked_add(right).filter(|value| *value <= MAX_MONEY)
        .ok_or(SproutLedgerError::ValueOutOfRange)
}

fn is_pruned(script: &[u8]) -> bool {
    script.first() == Some(&0x6a) || script.len() > 10_000
}

struct TransactionSize {
    written: usize,
    limit: usize,
}

impl Write for TransactionSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written = self.written.checked_add(bytes.len()).filter(|size| *size <= self.limit)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "era-specific transaction size"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Exact GetOp: no execution, allocations, disabled-opcode or 520-byte limits.
// The same scanner supplies legacy and accurate P2SH counts.
fn raw_op<'a>(script: &mut &'a [u8]) -> Option<(u8, &'a [u8])> {
    let (&opcode, rest) = script.split_first()?;
    *script = rest;
    let length = match opcode {
        0..=75 => usize::from(opcode),
        76..=78 => {
            let width = 1_usize << (opcode - 76);
            let bytes = script.get(..width)?;
            let mut length = [0; 4];
            length[..width].copy_from_slice(bytes);
            *script = &script[width..];
            u32::from_le_bytes(length) as usize
        }
        _ => return Some((opcode, &[])),
    };
    let data = script.get(..length)?;
    *script = &script[length..];
    Some((opcode, data))
}

fn sigops(mut script: &[u8], accurate: bool) -> u32 {
    let mut count = 0;
    let mut previous = 0;
    while let Some((opcode, _)) = raw_op(&mut script) {
        count += match opcode {
            0xac | 0xad => 1,
            0xae | 0xaf if accurate && (0x51..=0x60).contains(&previous) => u32::from(previous - 0x50),
            0xae | 0xaf => 20,
            _ => 0,
        };
        previous = opcode;
    }
    count
}

fn legacy_sigops(script: &[u8]) -> u32 {
    sigops(script, false)
}

fn p2sh_sigops(mut script_sig: &[u8], script_pubkey: &[u8]) -> u32 {
    if script_pubkey.len() != 23 || script_pubkey[..2] != [0xa9, 0x14] || script_pubkey[22] != 0x87 {
        return 0;
    }
    let mut redeem = &[][..];
    while !script_sig.is_empty() {
        let Some((opcode, data)) = raw_op(&mut script_sig) else { return 0 };
        if opcode > 0x60 { return 0; }
        redeem = data;
    }
    sigops(redeem, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_encoding::CompactSize;
    use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};
    use zcash_transparent::bundle::{OutPoint, TxIn};

    const FIRST: &[u8; 1618] = include_bytes!("../tests/fixtures/testnet-block-1.bin");
    const FOUNDERS: &[u8] = &[
        0xa9, 0x14, 0xef, 0x77, 0x5f, 0x1f, 0x99, 0x7f, 0x12, 0x2a, 0x06,
        0x2f, 0xff, 0x1a, 0x2d, 0x74, 0x43, 0xab, 0xd1, 0xf9, 0xc6, 0x42, 0x87,
    ];

    // Local mutations exercise ONLY the private contextual coinbase checker.
    // They are not mined bodies, connected histories, proof facts, or PoW mocks.
    pub(super) fn base() -> Transaction {
        Transaction::read(&FIRST[1488..], BranchId::Sprout).unwrap()
    }

    pub(super) fn changed(
        version: TxVersion,
        lock_time: u32,
        edit: impl FnOnce(&mut zcash_transparent::bundle::Bundle<zcash_transparent::bundle::Authorized>),
    ) -> Transaction {
        let coinbase = base();
        let mut transparent = coinbase.transparent_bundle().unwrap().clone();
        edit(&mut transparent);
        TransactionData::<Authorized>::from_parts(
            version, BranchId::Sprout, lock_time, 0_u32.into(),
            Some(transparent), None, None, None,
        ).freeze().unwrap()
    }

    pub(super) fn output(value: u64, script: &[u8]) -> TxOut {
        let mut raw = value.to_le_bytes().to_vec();
        CompactSize::write(&mut raw, script.len()).unwrap();
        raw.extend_from_slice(script);
        TxOut::read(&mut raw.as_slice()).unwrap()
    }

    pub(super) fn script_input(bundle: &mut zcash_transparent::bundle::Bundle<zcash_transparent::bundle::Authorized>, script: &[u8], sequence: u32) {
        let mut input_script = bundle.vin[0].script_sig().clone();
        input_script.0.0 = script.to_vec();
        bundle.vin[0] = TxIn::from_parts(OutPoint::NULL, input_script, sequence);
    }

    pub(super) fn state() -> SproutTestnetLedger {
        SproutTestnetLedger::from_genesis(super::super::bootstrap_testnet_genesis(include_bytes!("../tests/fixtures/testnet-genesis.bin")).unwrap())
    }

    fn checked_coinbase(transaction: Transaction, height: u32, time: u32) -> Result<(u64, u64), SproutLedgerError> {
        state().stage_block(transaction, vec![], height, time).map(|delta| (delta.transparent as u64, delta.retained as u64))
    }

    // These are isolated transaction/state requirements, not mined successors.
    #[test]
    fn sprout_coinbase_seventeen_requires_canonical_positive_scriptnum_prefix() {
        for (script, valid) in [
            (vec![0x01, 0x11], true),
            (vec![0x01, 0x11, 0xff, 0xab], true),
            (vec![0x61, 0x00], false),
            (vec![0x4c, 0x01, 0x11], false),
            (vec![0x02, 0x11, 0x00], false),
            (vec![0x01, 0x91], false),
            (vec![0x01, 0x10], false),
        ] {
            let tx = changed(TxVersion::Sprout(2), 0, |bundle| {
                script_input(bundle, &script, u32::MAX);
                bundle.vout = vec![output(850_000, &[]), output(212_500, FOUNDERS)];
            });
            let result = check_coinbase(&tx, 17, 1_477_680_000);
            if valid {
                assert_eq!(result.unwrap().claimed, 1_062_500);
            } else {
                assert_eq!(result, Err(SproutLedgerError::InvalidCoinbase));
            }
        }
        // A positive height whose most significant byte has bit seven set
        // requires a sign-padding byte, not a negative or redundant encoding.
        for (script, valid) in [
            (vec![0x02, 0x80, 0x00], true),
            (vec![0x01, 0x80], false),
            (vec![0x03, 0x80, 0x00, 0x00], false),
        ] {
            let tx = changed(TxVersion::Sprout(1), 0, |bundle| {
                script_input(bundle, &script, u32::MAX);
                bundle.vout = vec![output(6_400_000, &[]), output(1_600_000, FOUNDERS)];
            });
            let result = check_coinbase(&tx, 128, 1_477_680_000);
            if valid {
                assert_eq!(result.unwrap().claimed, 8_000_000);
            } else {
                assert_eq!(result, Err(SproutLedgerError::InvalidCoinbase));
            }
        }
    }

    #[test]
    fn sprout_subsidy_skips_the_midpoint_and_reaches_the_full_reward() {
        for (height, prefix, reward) in [
            (9_999, &[0x02, 0x0f, 0x27][..], 624_937_500),
            (10_000, &[0x02, 0x10, 0x27][..], 625_062_500),
            (19_999, &[0x02, 0x1f, 0x4e][..], 1_250_000_000),
            (20_000, &[0x02, 0x20, 0x4e][..], 1_250_000_000),
        ] {
            let founder = if height < 17_709 {
                FOUNDERS.to_vec()
            } else {
                // Testnet source index one; Base58Check prefix 1cba verified.
                vec![0xa9, 0x14, 0xab, 0x13, 0xd4, 0x67, 0x56, 0x30, 0xd6,
                     0x9f, 0x9c, 0x90, 0x00, 0xc7, 0x01, 0xa9, 0x81, 0x93,
                     0x8b, 0x0d, 0x58, 0x5d, 0x87]
            };
            for (extra, expected) in [(0, Ok(reward)), (1, Err(SproutLedgerError::CoinbaseRewardExceeded))] {
                let tx = changed(TxVersion::Sprout(1), 0, |bundle| {
                    script_input(bundle, prefix, u32::MAX);
                    bundle.vout = vec![output(reward - reward / 5 + extra, &[]), output(reward / 5, &founder)];
                });
                assert_eq!(checked_coinbase(tx, height, 1_500_000_000).map(|v| v.0), expected);
            }
        }
    }

    #[test]
    fn sprout_founder_schedule_switches_at_height_divided_by_17709() {
        let scripts = [
            FOUNDERS.to_vec(),
            vec![0xa9, 0x14, 0xab, 0x13, 0xd4, 0x67, 0x56, 0x30, 0xd6, 0x9f, 0x9c,
                 0x90, 0x00, 0xc7, 0x01, 0xa9, 0x81, 0x93, 0x8b, 0x0d, 0x58, 0x5d, 0x87],
            vec![0xa9, 0x14, 0xac, 0x67, 0xf4, 0xc0, 0x72, 0x66, 0x81, 0x38, 0xd8, 0x8a,
                 0x86, 0xff, 0x21, 0xb2, 0x72, 0x07, 0xb2, 0x83, 0x21, 0x2f, 0x87],
            vec![0xa9, 0x14, 0x55, 0xd6, 0x49, 0x28, 0xe6, 0x98, 0x29, 0xd9, 0x37, 0x6c,
                 0x77, 0x65, 0x50, 0xb6, 0xcc, 0x71, 0x0d, 0x42, 0x71, 0x53, 0x87],
        ];
        for (height, prefix, reward, correct, wrong) in [
            (17_708, &[0x02, 0x2c, 0x45][..], 1_106_812_500, 0, 1),
            (17_709, &[0x02, 0x2d, 0x45][..], 1_106_875_000, 1, 0),
            (53_126, &[0x03, 0x86, 0xcf, 0x00][..], 1_250_000_000, 2, 3),
            (53_127, &[0x03, 0x87, 0xcf, 0x00][..], 1_250_000_000, 3, 2),
        ] {
            for (index, accepted) in [(correct, true), (wrong, false)] {
                let tx = changed(TxVersion::Sprout(2), 0, |bundle| {
                    script_input(bundle, prefix, u32::MAX);
                    bundle.vout = vec![output(reward / 5, &scripts[index])];
                });
                let result = check_coinbase(&tx, height, 1_500_000_000);
                if accepted {
                    assert_eq!(result.unwrap().claimed, reward / 5);
                } else {
                    assert_eq!(result, Err(SproutLedgerError::MissingFoundersReward));
                }
            }
        }
    }

    #[test]
    fn every_legal_sprout_format_and_arbitrary_height_suffix_pass_the_native_checker() {
        for version in [1, 2, 3, 4, 100, 0x7fff_ffff] {
            let tx = changed(TxVersion::Sprout(version), 0, |bundle| {
                // Not a push-only spend script; coinbase suffix bytes are arbitrary.
                script_input(bundle, &[0x51, 0xff, 0xac, 0x00], 12);
            });
            let values = check_coinbase(&tx, 1, 1_477_674_473).unwrap();
            assert_eq!((values.claimed, values.retained), (62_500, 62_500));
        }
        for version in [TxVersion::Sprout(0), TxVersion::Sprout(0x8000_0001), TxVersion::V3, TxVersion::V4, TxVersion::V5, TxVersion::V6] {
            let tx = changed(version, 0, |_| {});
            assert_eq!(check_coinbase(&tx, 1, 1_477_674_473), Err(SproutLedgerError::UnsupportedTransaction));
        }
    }

    #[test]
    fn exact_height_opcode_and_coinbase_script_length_are_consensus_not_numeric_policy() {
        for script in [vec![0x51], vec![1, 1], vec![0x52, 0], vec![0x51; 101]] {
            let tx = changed(TxVersion::Sprout(1), 0, |bundle| script_input(bundle, &script, u32::MAX));
            assert_eq!(check_coinbase(&tx, 1, 1_477_674_473), Err(SproutLedgerError::InvalidCoinbase));
        }
        for length in [2, 100] {
            let script = vec![0x51; length];
            let tx = changed(TxVersion::Sprout(1), 0, |bundle| script_input(bundle, &script, 0));
            assert_eq!(check_coinbase(&tx, 1, 1_477_674_473).unwrap().claimed, 62_500);
        }
    }

    #[test]
    fn finality_uses_strict_parent_derived_height_or_candidate_time_not_mtp() {
        for (lock_time, sequence, time, final_tx) in [
            (0, 0, 1_477_674_473, true),
            (1, 0, 1_477_674_473, false),
            (1, u32::MAX, 1_477_674_473, true),
            (2, 0, 1_477_674_473, false),
            (499_999_999, 0, 1_477_674_473, false),
            (500_000_000, 0, 500_000_001, true),
            (500_000_000, 0, 500_000_000, false),
            (500_000_000, u32::MAX, 500_000_000, true),
            (1_477_674_472, 0, 1_477_674_473, true),
            (1_477_674_473, 0, 1_477_674_473, false),
            (1_477_674_474, 0, 1_477_674_473, false),
        ] {
            let tx = changed(TxVersion::Sprout(1), lock_time, |bundle| {
                script_input(bundle, &[0x51, 0], sequence);
            });
            let result = check_coinbase(&tx, 1, time);
            if final_tx {
                assert_eq!(result.unwrap().claimed, 62_500);
            } else {
                assert_eq!(result, Err(SproutLedgerError::NonfinalTransaction));
            }
        }
        let tx = changed(TxVersion::Sprout(1), 9, |bundle| {
            script_input(bundle, &[0x5a, 0], 0);
            bundle.vout = vec![output(500_000, &[]), output(125_000, FOUNDERS)];
        });
        assert_eq!(check_coinbase(&tx, 10, 1_477_678_977).unwrap().claimed, 625_000);
    }

    #[test]
    fn founders_requires_one_exact_output_anywhere_not_split_sum_or_unique_destination() {
        let cases = [
            (vec![output(12_500, FOUNDERS)], Ok((12_500, 12_500))),
            (vec![output(6_250, FOUNDERS), output(6_250, FOUNDERS)], Err(SproutLedgerError::MissingFoundersReward)),
            (vec![output(50_000, &[]), output(12_499, FOUNDERS)], Err(SproutLedgerError::MissingFoundersReward)),
            (vec![output(12_500, FOUNDERS), output(12_500, FOUNDERS)], Ok((25_000, 25_000))),
            (vec![output(50_001, &[]), output(12_500, FOUNDERS)], Err(SproutLedgerError::CoinbaseRewardExceeded)),
            (vec![output(0, &[]), output(12_500, FOUNDERS)], Ok((12_500, 12_500))),
        ];
        for (outputs, expected) in cases {
            let tx = changed(TxVersion::Sprout(1), 0, |bundle| bundle.vout = outputs);
            assert_eq!(checked_coinbase(tx, 1, 1_477_674_473), expected);
        }
        let mut wrong_script = FOUNDERS.to_vec();
        wrong_script[2] ^= 1;
        let tx = changed(TxVersion::Sprout(1), 0, |bundle| bundle.vout = vec![output(12_500, &wrong_script)]);
        assert_eq!(check_coinbase(&tx, 1, 1_477_674_473), Err(SproutLedgerError::MissingFoundersReward));
    }

    #[test]
    fn serialized_output_sum_is_checked_before_subsidy_and_zero_values_are_legal() {
        let tx = changed(TxVersion::Sprout(1), 0, |bundle| {
            bundle.vout = vec![output(2_100_000_000_000_000, &[]), output(12_500, FOUNDERS)];
        });
        assert_eq!(check_coinbase(&tx, 1, 1_477_674_473), Err(SproutLedgerError::ValueOutOfRange));
        for value in [i64::MIN as u64, u64::MAX, 2_100_000_000_000_001] {
            let mut raw = FIRST[1488..].to_vec();
            raw[50..58].copy_from_slice(&value.to_le_bytes());
            assert!(Transaction::read(raw.as_slice(), BranchId::Sprout).is_err());
        }
        let tx = changed(TxVersion::Sprout(1), 0, |bundle| bundle.vout.clear());
        assert_eq!(check_coinbase(&tx, 1, 1_477_674_473), Err(SproutLedgerError::InvalidCoinbase));
    }

    #[test]
    fn pruning_burns_count_as_claimed_issuance_but_underclaims_never_mint() {
        for (script, created, retained) in [
            (vec![0x6a], 62_500, 12_500),
            (vec![0; 10_001], 62_500, 12_500),
            (vec![0; 10_000], 62_500, 62_500),
            (vec![], 62_500, 62_500),
            (vec![0xff], 62_500, 62_500),
        ] {
            let tx = changed(TxVersion::Sprout(1), 0, |bundle| {
                bundle.vout = vec![output(50_000, &script), output(12_500, FOUNDERS), output(0, &[])];
            });
            let values = check_coinbase(&tx, 1, 1_477_674_473).unwrap();
            assert_eq!((values.claimed, values.retained), (created, retained));
            let mut state = SproutTestnetLedger::from_genesis(super::super::bootstrap_testnet_genesis(include_bytes!("../tests/fixtures/testnet-genesis.bin")).unwrap());
            let id: [u8; 32] = tx.txid().into();
            let delta = state.stage_block(tx, vec![], 1, 1_477_674_473).unwrap();
            state.commit(delta);
            assert_eq!(state.transparent_balance(), created);
            assert_eq!(state.issued_supply(), created);
            assert_eq!(state.utxo_balance(), retained);
            assert_eq!(state.utxo(&id, 0).is_some(), retained == 62_500);
            assert_eq!(u64::from(state.utxo(&id, 1).unwrap().output().value()), 12_500);
            assert_eq!(u64::from(state.utxo(&id, 2).unwrap().output().value()), 0);
            assert_eq!(state.utxo(&id, 2).unwrap().output().script_pubkey().0.0, Vec::<u8>::new());
            assert!(state.utxo(&id, 3).is_none());
        }
        let tx = changed(TxVersion::Sprout(1), 0, |bundle| bundle.vout = vec![output(12_500, FOUNDERS)]);
        let values = check_coinbase(&tx, 1, 1_477_674_473).unwrap();
        assert_eq!((values.claimed, values.retained), (12_500, 12_500));
        let id = tx.txid().into();
        let mut state = SproutTestnetLedger::from_genesis(super::super::bootstrap_testnet_genesis(include_bytes!("../tests/fixtures/testnet-genesis.bin")).unwrap());
        let delta = state.stage_block(tx, vec![], 1, 1_477_674_473).unwrap();
        state.commit(delta);
        assert_eq!(state.transparent_balance(), 12_500);
        assert_eq!(state.issued_supply(), 12_500);
        assert_eq!(state.utxo_balance(), 12_500);
        assert_eq!(u64::from(state.utxo(&id, 0).unwrap().output().value()), 12_500);
        assert!(state.utxo(&id, 1).is_none());
    }

    #[test]
    fn large_pushes_unknown_and_disabled_opcodes_do_not_hide_sigops_but_truncation_stops() {
        for (script, expected) in [
            (vec![0xac, 0xad, 0xae, 0xaf], 42),
            (vec![4, 0xac, 0xad, 0xae, 0xaf, 0xac], 1),
            (vec![0x7e, 0xab, 0xff, 0xae], 20),
            (vec![0xac, 0x4c], 1),
            (vec![0xac, 0x4d, 1], 1),
            (vec![0xac, 0x4e, 0, 0, 0], 1),
            (vec![0xac, 2, 0xad], 1),
            (vec![0xac, 0x4e, 0xff, 0xff, 0xff, 0xff], 1),
        ] {
            assert_eq!(legacy_sigops(&script), expected);
        }
        let mut long_push = vec![0x4d, 0x09, 0x02]; // 521-byte push, valid for counting.
        long_push.extend_from_slice(&[0xae; 521]);
        long_push.extend_from_slice(&[0xac, 0xaf]);
        assert_eq!(legacy_sigops(&long_push), 21);
        let mut longer_push = vec![0x4e, 0xe8, 0x03, 0, 0]; // 1000-byte PUSHDATA4.
        longer_push.extend_from_slice(&[0xac; 1_000]);
        longer_push.push(0xad);
        assert_eq!(legacy_sigops(&longer_push), 1);
        for script in [long_push, longer_push] {
            let tx = changed(TxVersion::Sprout(1), 0, |bundle| {
                bundle.vout[0] = output(50_000, &script);
            });
            let values = check_coinbase(&tx, 1, 1_477_674_473).unwrap();
            assert_eq!((values.claimed, values.retained), (62_500, 62_500));
        }
    }

    #[test]
    fn sigop_limit_counts_coinbase_input_and_outputs_even_when_pruned() {
        let input = [0x51, 0xac];
        for (suffix, accepted) in [(19, true), (20, false)] {
            let mut script = vec![0x6a];
            script.extend(std::iter::repeat_n(0xae, 999));
            script.extend(std::iter::repeat_n(0xac, suffix));
            let tx = changed(TxVersion::Sprout(1), 0, |bundle| {
                script_input(bundle, &input, 0);
                bundle.vout = vec![output(50_000, &script), output(12_500, FOUNDERS)];
            });
            let result = check_coinbase(&tx, 1, 1_477_674_473);
            if accepted {
                assert_eq!(result.unwrap().retained, 12_500);
            } else {
                assert_eq!(result, Err(SproutLedgerError::TooManySigops));
            }
        }
    }

    #[test]
    fn actual_native_transaction_size_accepts_exact_limit_and_rejects_one_byte_over() {
        // V1 original 130 bytes, replacing its 35-byte miner script with n bytes
        // uses a 5-byte CompactSize at this boundary: size = 130 - 36 + 5 + n.
        for (length, accepted) in [(99_901, true), (99_902, false)] {
            let tx = changed(TxVersion::Sprout(1), 0, |bundle| {
                bundle.vout[0] = output(50_000, &vec![0; length]);
            });
            let mut encoded = Vec::new();
            tx.write(&mut encoded).unwrap();
            assert_eq!(encoded.len(), if accepted { 100_000 } else { 100_001 });
            let result = check_coinbase(&tx, 1, 1_477_674_473);
            if accepted {
                let values = result.unwrap();
                assert_eq!((values.claimed, values.retained), (62_500, 12_500));
            } else {
                assert_eq!(result, Err(SproutLedgerError::TransactionTooLarge));
            }
        }
    }

    #[test]
    fn invalid_coinbase_inputs_and_nonempty_sprout_are_never_ignored() {
        let nonnull = changed(TxVersion::Sprout(1), 0, |bundle| {
            bundle.vin[0] = TxIn::from_parts(OutPoint::new([1; 32], 0), bundle.vin[0].script_sig().clone(), u32::MAX);
        });
        assert_eq!(check_coinbase(&nonnull, 1, 1_477_674_473), Err(SproutLedgerError::InvalidCoinbase));
        let multiple = changed(TxVersion::Sprout(1), 0, |bundle| bundle.vin.push(bundle.vin[0].clone()));
        assert_eq!(check_coinbase(&multiple, 1, 1_477_674_473), Err(SproutLedgerError::InvalidCoinbase));
        let coinbase = base();
        let joinsplit = zcash_primitives::transaction::components::sprout::JsDescription::read(&[0_u8; 1802][..], false).unwrap();
        let tx = TransactionData::<Authorized>::from_parts(
            TxVersion::Sprout(2), BranchId::Sprout, 0, 0_u32.into(),
            coinbase.transparent_bundle().cloned(),
            Some(zcash_primitives::transaction::components::sprout::Bundle { joinsplits: vec![joinsplit], joinsplit_pubkey: [0; 32], joinsplit_sig: [0; 64] }),
            None, None,
        ).freeze().unwrap();
        assert_eq!(check_coinbase(&tx, 1, 1_477_674_473), Err(SproutLedgerError::InvalidCoinbase));
    }

    #[test]
    fn transaction_wide_bip30_and_money_overflow_reject_before_any_output_commit() {
        let tx = base();
        check_coinbase(&tx, 1, 1_477_674_473).unwrap();
        let id: [u8; 32] = tx.txid().into();
        let mut state = SproutTestnetLedger::from_genesis(super::super::bootstrap_testnet_genesis(include_bytes!("../tests/fixtures/testnet-genesis.bin")).unwrap());
        let tip = state.tip();
        // Only an old HIGH output index remains; comparing incoming indices
        // 0/1 alone would wrongly allow this transaction identity overwrite.
        state.utxos.insert((id, 7), TransparentCoin { output: output(1, &[]), created_height: 0, is_coinbase: false });
        state.utxo_balance = 1;
        state.transparent_balance = 1;
        state.issued_supply = 1;
        assert!(matches!(state.stage_block(tx, vec![], 1, 1_477_674_473), Err(SproutLedgerError::UnspentTransactionOverwrite)));
        assert!(state.utxo(&id, 0).is_none());
        assert!(state.utxo(&id, 1).is_none());
        assert_eq!(u64::from(state.utxo(&id, 7).unwrap().output().value()), 1);
        assert_eq!(state.tip(), tip);
        assert_eq!((state.transparent_balance(), state.issued_supply(), state.utxo_balance(), state.deferred_balance()), (1, 1, 1, 0));

        for overflowing_total in 0..3 {
            let mut state = SproutTestnetLedger::from_genesis(super::super::bootstrap_testnet_genesis(include_bytes!("../tests/fixtures/testnet-genesis.bin")).unwrap());
            match overflowing_total {
                0 => state.transparent_balance = 2_100_000_000_000_000,
                1 => state.issued_supply = 2_100_000_000_000_000,
                _ => state.utxo_balance = 2_100_000_000_000_000,
            }
            let before = (state.transparent_balance(), state.issued_supply(), state.utxo_balance(), state.deferred_balance());
            assert!(matches!(state.stage_block(base(), vec![], 1, 1_477_674_473), Err(SproutLedgerError::ValueOutOfRange)));
            assert_eq!((state.transparent_balance(), state.issued_supply(), state.utxo_balance(), state.deferred_balance()), before);
            assert!(state.utxo(&id, 0).is_none());
            assert!(state.utxo(&id, 1).is_none());
            assert_eq!(state.tip(), tip);
        }
    }

    #[test]
    fn actual_native_sapling_orchard_and_ironwood_bundles_cannot_enter_the_early_ledger() {
        use zcash_protocol::value::ZatBalance;
        use zcash_primitives::transaction::components::orchard::{read_v5_bundle, read_v6_bundle};

        let sapling_output = sapling_crypto::bundle::OutputDescription::from_parts(
            sapling_crypto::value::ValueCommitment::derive(
                sapling_crypto::value::NoteValue::from_raw(0),
                sapling_crypto::value::ValueCommitTrapdoor::from_bytes([0; 32]).unwrap(),
            ),
            sapling_crypto::note::ExtractedNoteCommitment::from_bytes(&[0; 32]).unwrap(),
            zcash_note_encryption::EphemeralKeyBytes([0; 32]),
            [0; 580], [0; 80], [0; 192],
        );
        let sapling = sapling_crypto::Bundle::from_parts(
            vec![], vec![sapling_output], ZatBalance::zero(),
            sapling_crypto::bundle::Authorized { binding_sig: [0; 64].into() },
        );
        let sapling_tx = TransactionData::<Authorized>::from_parts(
            TxVersion::V4, BranchId::Sapling, 0, 0_u32.into(),
            base().transparent_bundle().cloned(), None, sapling, None,
        ).freeze().unwrap();
        assert!(sapling_tx.sapling_bundle().is_some());
        assert_eq!(check_coinbase(&sapling_tx, 1, 1_477_674_473), Err(SproutLedgerError::UnsupportedTransaction));
        assert_eq!(check_coinbase(&sapling_tx, 207_500, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction));
        assert!(matches!(OverwinterSignatureHash::new(&sapling_tx), Err(crate::overwinter::OverwinterSighashError::UnsupportedVersion)));

        // Only typed wire structure, NOT a proof/signature witness: every early
        // caller must reject these foreign bundles without consulting them.
        let mut scalar_one = [0; 32];
        scalar_one[0] = 1;
        let key = orchard::primitives::redpallas::SigningKey::<orchard::primitives::redpallas::SpendAuth>::try_from(scalar_one).unwrap();
        let point: [u8; 32] = orchard::primitives::redpallas::VerificationKey::from(&key).into();
        let encoded_bundle = |proof_size: usize| {
            let mut raw = vec![1]; // one native action
            raw.extend_from_slice(&[0; 64]); // value commitment and nullifier
            raw.extend_from_slice(&point); // non-identity rk
            raw.extend_from_slice(&[0; 32]); // extracted note commitment
            raw.extend_from_slice(&point); // non-identity ephemeral point
            raw.extend_from_slice(&[0; 660]); // ciphertexts
            raw.push(2); // outputs enabled
            raw.extend_from_slice(&[0; 40]); // value balance and anchor
            CompactSize::write(&mut raw, proof_size).unwrap();
            raw.resize(raw.len() + proof_size + 128, 0); // proof and signatures
            raw
        };
        let orchard = read_v5_bundle(encoded_bundle(0).as_slice(), BranchId::Nu5).unwrap();
        let orchard_tx = TransactionData::<Authorized>::from_parts(
            TxVersion::V5, BranchId::Nu5, 0, 0_u32.into(),
            base().transparent_bundle().cloned(), None, None, orchard,
        ).freeze().unwrap();
        assert!(orchard_tx.orchard_bundle().is_some());
        assert_eq!(check_coinbase(&orchard_tx, 1, 1_477_674_473), Err(SproutLedgerError::UnsupportedTransaction));
        assert_eq!(check_coinbase(&orchard_tx, 207_500, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction));
        assert!(matches!(OverwinterSignatureHash::new(&orchard_tx), Err(crate::overwinter::OverwinterSighashError::UnsupportedVersion)));

        let ironwood = read_v6_bundle(
            encoded_bundle(orchard::Proof::expected_proof_size(1)).as_slice(),
            BranchId::Nu6_3, orchard::ValuePool::Ironwood,
        ).unwrap();
        let ironwood_tx = TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu6_3, 0, 0_u32.into(),
            base().transparent_bundle().cloned(), None, None, ironwood,
        ).freeze().unwrap();
        assert!(ironwood_tx.ironwood_bundle().is_some());
        assert_eq!(check_coinbase(&ironwood_tx, 1, 1_477_674_473), Err(SproutLedgerError::UnsupportedTransaction));
        assert_eq!(check_coinbase(&ironwood_tx, 207_500, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction));
        assert!(matches!(OverwinterSignatureHash::new(&ironwood_tx), Err(crate::overwinter::OverwinterSighashError::UnsupportedVersion)));
    }
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod consensus_tests;
