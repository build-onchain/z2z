//! Recorded Overwinter PHGR transaction; not a connected history fixture.
// Original bytes and provenance copied unchanged from overwinter-primary.rs.
// All immutable sources retrieved2026-10-03; zero-based half-open offsets.
// https://raw.githubusercontent.com/ZcashFoundation/zebra/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-test/src/vectors/block-test-0-207-501.txt
// Original UTF8 bytes:7543; Git blob62a03fa9588358c3f501cbd7302b12bfce7b0e89.
// Original blob SHA256:368a80e92d71b96931f26cce89eb9b23547cb7a67ab954e07b02c330ddb8e40e.
// Decoded block3771bytes; SHA25686543feb898e975521cf14d338bd182a675a6f20253141e8df02dc951c801665.
// Header0..1487; tx count3; transaction ranges1488..1620,1620..1854,1854..3771.
// MINED_V3_TX_HEX copies original transaction2 range1854..3771, text3708..7542.
// It is NOT a reconstruction or typed reserialization. Original length1917bytes.
// Tx SHA256:7c7dc59bd131a5d5b25c37f49ac22f87a3e590e75d06b271fc6bacfbf09285f5.
// Display txid:58b072f17a88e5786bc0f13a6f790f1ce4eb7049699571a6c59c0ef607a47777.
// Original extraction faithfully translated cached maintained serializers:
// block.rs133..162; transaction/mod.rs82..106,736..841; components/sprout.rs89..165;
// transparent0.10.0 bundle.rs263..272,385..397; encoding0.4.0 CompactSize33..78.
// Extraction itself did no Rust build/test, crypto or block consensus validation.
// Zero vin/vout; one PHGR; vpub_old0/vpub_new10000; lock0; expiry207521.
// Description19..1821; pubkey1821..1853; original signature1853..1917.
// Fine-grained original byte positions are isolated in overwinter-offsets.rs.
//
// Zebra recorded block source: MIT (MIT selected).
// https://raw.githubusercontent.com/ZcashFoundation/zebra/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/LICENSE-MIT
// Copyright (c) 2019-2025 Zcash Foundation
//
// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

pub const MINED_V3_TX_HEX: &str = concat!(
    "030000807082c403000000000000a12a03000100000000000000001027000000000000f40a8d814502ef610c7ba6053c",
    "189bdd766b4111cbde107a169f587c3129d6c9f6740b9271ac3b91386777dfda44f29485d3c689ff5deef2fa2e593236",
    "f12103cbafbee6599e53d1d1ea3eb6c2225c6d5de09c2977fa372e594cc2531681e8f39ebc40ab52bf4ffce0daf1b454",
    "a36530485884ed77c28303b745a2bb81b04c537b4cdb336c43e8bbbd2bc1548ddb3666738117bab342fa7db86cf25954",
    "8db038aa6dda2992e992faf87044c359ad0a18ac712d460138507bc1e737db8ef07d63269f045052b4fca20504e4786a",
    "4af2fa7f6e3f13c7be9fa42a7ff8966c0fa991d5b36694f51627dc3ee877f119737beb9ca3f6d2033d4506c213e68964",
    "b4d408e3bf9dd45bcb315bcd0523a8f51745dd51867590cf4332eedce063f17af892220201139ad930291ae7a47b4ded",
    "2fdefdab2dee7f949a481ac95939c7b04b877e2a0209872161e2a30b9014d746b72f62454ef599367c3ccf3c6e668656",
    "d34730d43f0a00c18f0cf9675d3a9c1bad5344f17371d501866f633b0c5d30a59d0950272c83192608acb2cecbc01102",
    "1a4d8bb262df774811077422a9a9acc6bed4a1e065bf030b2e0b0c76d9bdd5aa3d4286e7e225db857776c4e2723e2c50",
    "537160f24a6fa50315b64c968205c701d30e980427717293fa9e19e6474ab20a1725ff5a93d2d0040328c1f467a27043",
    "83c4b4904b06b55cdaa95503bd878106460eee5800b127c7490327dc49228e9dcd746247b03ff986fd8e5280bfbce83d",
    "d4a1e11f95e3e29856c90216041a8e7f723024830a812fb6aaabeebe89c74fcb8b9bf70af2a6334540d2538c8298ccd3",
    "665eec7a843736c9d0d1d1605cd65a93dba5fc498f6ab53b53c2fcf084e23370740033980d24319df38c4fffef8d622b",
    "680d60b68645946e5b76dc11bd5cbae35feea40e9f52b12b5d60f4cc7f7630cc320f857fe05256b7993faebc797acb94",
    "79a6e3e1b1017caf9eaabdeb78f0f079b74ab8b22556291958d239ddffc5ed6ba263f122a85d0a152f07c3fc444ca8a4",
    "271bc24776a7e27273e193674c90ff1c82ec507c4499e68da8ff026ffcf7cd2a51e6eaa3f93b5add6230a0fc7dfe42fa",
    "3b7bbae1861a4c2aa369dc498ea0b1662a8f87726293c1e5279e7215c2c14e7fbff19f23348b08e5193fc014a2efad1c",
    "6c46bbdd95df4c3caec6b05463abce7a1ac09f35f24f42a4f202b88efbf901ad7293a58a8d1f31fd596a9f70b608cba5",
    "f1a7baf69785e29fda40df896b0ca9e461975b2d1d500ff1018132370ff662b9a8b7fa8947029fb1fd832f0d5720a573",
    "398efd3bfe8ea6856738cab6060ee57909214a7a9b5c22c7614cd96ef7a64194b28a578ed2057fa425d18b57f9e0d394",
    "6d54949949d4af89dc18eec5ce2e458e126a14a8eb38f7950728fbb8d7a4f0100ad5f07f1943147bf451b5db75e0c87c",
    "11dab4289ab8e826a762495c564c1b32c4a2ea8a57ef5ca1e3bee370c14472e41921b0e32d36d45efc47bcbb4d3ff995",
    "0c0d0b7e6f51e4ee9fdb358614309ab52c04263ace02bc48dd1e243a669d1213af8c738278e7a7e5c07f49b0c0445530",
    "7b65c4a51ac9da6ef78b72432313c4d6f83a7f33b457e5d144e3aac7e0ef8a5d25e8b6fe2511d4fe45cc3554778bf346",
    "326df373bce47b8539de6e3e63adeb521a3d4cab57210120f1373f7349f2e59eedd23997ea62f83d957d15d903f1513a",
    "178bb506649de89004e11864e0f0b53f145a24f7adabf08727f0fd61328ce27c743fd5dab1f78379efdf9162c5e434f0",
    "61d0cac9ab105a6c6a9a06ba0c16b2b124dc61fc27951e08d0204ea3fde92d306822607a649d5bcee5851a3e204cc65c",
    "de58ac7d8a983f1d80dc34dce6487fd08322f2ee697e5505b309e305d52b40e23ca603fea72b4f2b4bbc06bdbfac8496",
    "6730780ffb4aa76a7d61c25ae808fff9476d2e5cccfba99e3f6351944d6fe71bf17f6d72626acacb2bb2d9c4dcac0693",
    "861078180a276fdcaea617d7a5b94cc155130a84f8bf8bf4208954517c30af9f3da631de438493be26a9808e468a886e",
    "eb485c1176a0515ffb4fc67d64d4d99ffe60533bc12ae8c06d26b175b04b7ee735af9efd640ccd67a7175269c3018fec",
    "ad79936bcdf64a9166f35a082bb458000b266fe165f49813f5936dcea08c530308b293a1700a04dda1ca28376597146b",
    "51f91fad65d5616fd262c440699b33a9e639ee92bc12570565fe4c1f95fd47d10082ef27341195d5d294fb3b0e3d6e18",
    "310a75879f647075505eeaaf4fb48bd881883328b5830820b73c5ccd49abc2b6f0df1351c988cef4503f23f851695665",
    "3e3d42f29748564b244c00a9cf5f102844cca06b9295169f2cecfa5bbdca6e6c5ff2bf97c53289722faee3bb2adb6bcc",
    "4ba00eb904cbfc9f4dde734cc53b41105a1c0a56c4eceae9214fbf1200790a1e44d878c5b18e99427745b624367f9cc0",
    "24b1fc544bf53f5fe5dabdeb8cf4f941f9f8e94ef9d7e7afdc10efe2ee8ca573d3177ac23850f44c181a34daafdc0380",
    "119a6a219508133b8d480d569a1d596bf06a6e8ab1096f121eff1bfa2a18c00fae5c46c5b1663f08cbb23d06b8602d99",
    "55eef5f0047f62ba9710850b90b55dd187f139a7702b8d2ceb9fdab274640e14e456768b7c257e041987670a0c",
);
