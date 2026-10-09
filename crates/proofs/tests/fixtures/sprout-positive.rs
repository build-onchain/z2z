// Numeric public data, not GPL implementation or parser code. Mechanically
// transcribed from Parity commit d4f311c21ac67b68fd4e7e77f4be0eff227c1661:
// https://github.com/paritytech/parity-zcash/blob/d4f311c21ac67b68fd4e7e77f4be0eff227c1661/verification/src/sprout.rs
// tests::{sample_pghr_proof,smoky_pghr}. No raw hash is display-byte reversed.
// Independently literal public scalars are from crypto/src/pghr13.rs::tests::verification.
// Canonical key coordinates are from res/sprout-verifying-key.json at the same
// immutable commit; they are comparison data, NEVER the trusted key source.
// Source repository license (not a relicensing or license-free-data assertion):
// https://github.com/paritytech/parity-zcash/blob/d4f311c21ac67b68fd4e7e77f4be0eff227c1661/LICENSE
// GNU GPL version 3. Only numerical test observations are transcribed here;
// the verifier/decoder is independently translated from the cited MIT sources.
use super::LegacyJoinSplit;

pub(super) const PROOF_HEX: &str = "022cbbb59465c880f50d42d0d49d6422197b5f823c2b3ffdb341869b98ed2eb2fd031b271702bda61ff885788363a7cf980a134c09a24c9911dc94cbe970bd613b700b0891fe8b8b05d9d2e7e51df9d6959bdf0a3f2310164afb197a229486a0e8e3808d76c75662b568839ebac7fbf740db9d576523282e6cdd1adf8b0f9c183ae95b0301fa1146d35af869cc47c51cfd827b7efceeca3c55884f54a68e38ee7682b5d102131b9b1198ed371e7e3da9f5a8b9ad394ab5a29f67a1d9b6ca1b8449862c69a5022e5d671e6989d33c182e0a6bbbe4a9da491dbd93ca3c01490c8f74a780479c7c031fb473670cacde779713dcd8cbdad802b8d418e007335919837becf46a3b1d0e02120af9d926bed2b28ed8a2b8307b3da2a171b3ee1bc1e6196773b570407df6b4";

pub(super) fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), 2 * N);
    let mut result = [0; N];
    for (byte, pair) in result.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0.iter()) {
        let digit = |value| match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid fixture hex"),
        };
        *byte = digit(pair[0]) * 16 + digit(pair[1]);
    }
    result
}

pub(super) fn statement() -> LegacyJoinSplit {
    LegacyJoinSplit {
        anchor: bytes("d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd259"),
        nullifiers: [
            bytes("7ae7c48e86173b231e84fbdcb4d8f569f28f71ebf0f9b5867f9d4c12e031a2ac"),
            bytes("c0108235936d2fa2d2c968654fbea2a89fde8522ec7c227d2ff3c10bff9c1197"),
        ],
        macs: [
            bytes("9836fe673c246d8d0cb1d7e1cc94acfa5b8d76010db8d53a36a3f0e33f0ccbc0"),
            bytes("f861b5e3d0a92e1c05c6bca775ba7389f6444f0e6cbd34141953220718594664"),
        ],
        commitments: [
            bytes("d8a290cca91f23792df8e56aed6c142eaa322e66360b5c49132b940689fb2bc5"),
            bytes("e77f7877bba6d2c4425d9861515cbe8a5c87dfd7cf159e9d4ac9ff63c096fbcd"),
        ],
        vpub_old: 14_250_000,
        vpub_new: 0,
        random_seed: bytes("b1624b703774e138c706ba394698fd33c58424bb1a8d22be0d7bc8fe58d369e8"),
        joinsplit_pubkey: bytes("cdb0469ee67776480be090cad2c7adc0bf59551ef6f1ac3119e5c29ab3b82dd9"),
    }
}

#[allow(dead_code)] // Used by the private witness-map unit test, not integration tests.
pub(super) const PUBLIC_INPUT_DECIMAL: [&str; 9] = [
    "11893887518801564238850113243068155191401763535822078310914655246254174921707",
    "9039742628274832857146315176202079824763880684544058044764009859702372701908",
    "7864248849999267529324215987921491632294157863019983191999113732927809771441",
    "2886983623257678406932083534975273655277211437585781522465101031866117927530",
    "1639613592978633992206850322587892881255594351774222883941421746126476816445",
    "5902043119256669211364401966461491601894820710756687540191805850512824202436",
    "13692185839566206949758987046107079401517252355870659294323573892338548513162",
    "213567272714802366240312308317683913515756890632602759628885800370159516315",
    "170484577853289",
];

#[allow(dead_code)]
pub(super) const KEY_G2_HEX: [[&str; 4]; 5] = [
    [
        "209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7",
        "04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678",
        "2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d",
        "120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550",
    ],
    [
        "2e89718ad33c8bed92e210e81d1853435399a271913a6520736a4729cf0d51eb",
        "01a9e2ffa2e92599b68e44de5bcf354fa2642bd4f26b259daa6f7ce3ed57aeb3",
        "14a9a87b789a58af499b314e13c3d65bede56c07ea2d418d6874857b70763713",
        "178fb49a2d6cd347dc58973ff49613a20757d0fcc22079f9abd10c3baee24590",
    ],
    [
        "25f83c8b6ab9de74e7da488ef02645c5a16a6652c3c71a15dc37fe3a5dcb7cb1",
        "22acdedd6308e3bb230d226d16a105295f523a8a02bfc5e8bd2da135ac4c245d",
        "065bbad92e7c4e31bf3757f1fe7362a63fbfee50e7dc68da116e67d600d9bf68",
        "06d302580dc0661002994e7cd3a7f224e7ddc27802777486bf80f40e4ca3cfdb",
    ],
    [
        "1f39e4e4afc4bc74790a4a028aff2c3d2538731fb755edefd8cb48d6ea589b5e",
        "283f150794b6736f670d6a1033f9b46c6f5204f50813eb85c8dc4b59db1c5d39",
        "140d97ee4d2b36d99bc49974d18ecca3e7ad51011956051b464d9e27d46cc25e",
        "0764bb98575bd466d32db7b15f582b2d5c452b36aa394b789366e5e3ca5aabd4",
    ],
    [
        "217cee0a9ad79a4493b5253e2e4e3a39fc2df38419f230d341f60cb064a0ac29",
        "0a3d76f140db8418ba512272381446eb73958670f00cf46f1d9e64cba057b53c",
        "26f64a8ec70387a13e41430ed3ee4a7db2059cc5fc13c067194bcc0cb49a9855",
        "2fd72bd9edb657346127da132e5b82ab908f5816c826acb499e22f2412d1a2d7",
    ],
];

#[allow(dead_code)]
pub(super) const KEY_G1_HEX: [[&str; 2]; 12] = [
    [
        "2eca0c7238bf16e83e7a1e6c5d49540685ff51380f309842a98561558019fc02",
        "03d3260361bb8451de5ff5ecd17f010ff22f5c31cdf184e9020b06fa5997db84",
    ],
    [
        "15794ab061441e51d01e94640b7e3084a07e02c78cf3103c542bc5b298669f21",
        "14db745c6780e9df549864cec19c2daf4531f6ec0c89cc1c7436cc4d8d300c6d",
    ],
    [
        "0aee46a7ea6e80a3675026dfa84019deee2a2dedb1bbe11d7fe124cb3efb4b5a",
        "044747b6e9176e13ede3a4dfd0d33ccca6321b9acd23bf3683a60adc0366ebaf",
    ],
    [
        "1e39e9f0f91fa7ff8047ffd90de08785777fe61c0e3434e728fce4cf35047ddc",
        "2e0b64d75ebfa86d7f8f8e08abbe2e7ae6e0a1c0b34d028f19fa56e9450527cb",
    ],
    [
        "1c36e713d4d54e3a9644dffca1fc524be4868f66572516025a61ca542539d43f",
        "042dcc4525b82dfb242b09cb21909d5c22643dcdbe98c4d082cc2877e96b24db",
    ],
    [
        "17d5d09b4146424bff7e6fb01487c477bbfcd0cdbbc92d5d6457aae0b6717cc5",
        "02b5636903efbf46db9235bbe74045d21c138897fda32e079040db1a16c1a7a1",
    ],
    [
        "0f103f14a584d4203c27c26155b2c955f8dfa816980b24ba824e1972d6486a5d",
        "0c4165133b9f5be17c804203af781bcf168da7386620479f9b885ecbcd27b17b",
    ],
    [
        "232063b584fb76c8d07995bee3a38fa7565405f3549c6a918ddaa90ab971e7f8",
        "2ac9b135a81d96425c92d02296322ad56ffb16299633233e4880f95aafa7fda7",
    ],
    [
        "09b54f111d3b2d1b2fe1ae9669b3db3d7bf93b70f00647e65c849275de6dc7fe",
        "18b2e77c63a3e400d6d1f1fbc6e1a1167bbca603d34d03edea231eb0ab7b14b4",
    ],
    [
        "0c54b42137b67cc268cbb53ac62b00ecead23984092b494a88befe58445a244a",
        "18e3723d37fae9262d58b548a0575f59d9c3266db7afb4d5739555837f6b8b3e",
    ],
    [
        "0a6de0e2240aa253f46ce0da883b61976e3588146e01c9d8976548c145fe6e4a",
        "04fbaa3a4aed4bb77f30ebb07a3ec1c7d77a7f2edd75636babfeff97b1ea686e",
    ],
    [
        "111e2e2a5f8828f80ddad08f9f74db56dac1cc16c1cb278036f79a84cf7a116f",
        "1d7d62e192b219b9808faa906c5ced871788f6339e8d91b83ac1343e20a16b30",
    ],
];
