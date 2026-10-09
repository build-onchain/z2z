//! Genesis-derived deterministic testnet header ancestry, not SPV settlement.
//!
//! Every retained timestamp/target comes from authentic genesis or a successful
//! connected append. No checkpoint/window constructor or validity flag exists.
//! This validates header encoding, Equihash, PoW, contextual difficulty and MTP;
//! it does not validate transactions, pool/UTXO/history transitions, competing
//! forks, global canonicality, finality/freshness, or local-clock admission
//! (`header.time <= now + 7200`). None of its observations authorize settlement.
//!
//! Rules: zcashd commit 86451a18b016af09a4e33c9acc1aa5577e25af17,
//! `src/pow.cpp`, `src/chain.h::GetMedianTimePast`, and testnet chainparams.

use std::fmt;

use primitive_types::U256;
use sha2::{Digest, Sha256};
use zcash_encoding::CompactSize;
use zcash_primitives::block::equihash;
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters, TEST_NETWORK};

use crate::{
    genesis::{GenesisState, TESTNET_POW_LIMIT, block_work, testnet_target_from_compact},
    history::CanonicalBytes,
};

const HEADER_LENGTH: usize = 1487;
const SOLUTION_LENGTH: usize = 1344;
const CONTEXT_LENGTH: usize = 28;
const AVERAGING_WINDOW: usize = 17;
const LIMIT_BITS: u32 = 0x2007_ffff;
const MIN_DIFFICULTY_PARENT_HEIGHT: u32 = 299_187;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderError {
    MalformedHeader,
    TrailingBytes,
    NoncanonicalEncoding,
    InvalidVersion,
    WrongParent,
    InvalidTarget,
    UnexpectedDifficulty,
    TimeTooEarly,
    TimeTooLate,
    InvalidEquihash,
    InsufficientWork,
    HeightOverflow,
    WorkOverflow,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MalformedHeader => "malformed or incomplete testnet header",
            Self::TrailingBytes => "trailing bytes after testnet header",
            Self::NoncanonicalEncoding => "noncanonical Equihash solution encoding",
            Self::InvalidVersion => "header signed version is below four",
            Self::WrongParent => "header does not extend the authenticated tip",
            Self::InvalidTarget => "header compact target is outside the testnet range",
            Self::UnexpectedDifficulty => "header bits differ from contextual difficulty",
            Self::TimeTooEarly => "header timestamp does not exceed median time past",
            Self::TimeTooLate => "header timestamp exceeds the activated median-time bound",
            Self::InvalidEquihash => "invalid Equihash solution",
            Self::InsufficientWork => "header hash exceeds its target",
            Self::HeightOverflow => "header height overflow",
            Self::WorkOverflow => "cumulative header work overflow",
        })
    }
}

impl std::error::Error for HeaderError {}

/// Derived header observations, never a full source-validity or settlement fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderTip {
    height: u32,
    hash: [u8; 32],
    cumulative_work: U256,
    time: u32,
    bits: u32,
}

impl HeaderTip {
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Internal/wire order; reverse these bytes for the RPC display hash.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn cumulative_work(&self) -> U256 {
        self.cumulative_work
    }

    pub fn time(&self) -> u32 {
        self.time
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }
}

/// A connected genesis-derived header prefix. This never updates the base ledger
/// and cannot be initialized from caller-supplied metadata or an arbitrary fork.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderChain {
    tip: HeaderTip,
    history: HeaderHistory,
}

impl HeaderChain {
    pub fn from_testnet_genesis(genesis: &GenesisState) -> Self {
        let mut history = HeaderHistory::empty();
        history.push(HeaderContext {
            time: genesis.time(),
            target: testnet_target_from_compact(genesis.bits())
                .expect("authenticated genesis has a checked target"),
        });
        Self {
            tip: HeaderTip {
                height: genesis.height(),
                hash: genesis.tip(),
                cumulative_work: genesis.cumulative_work(),
                time: genesis.time(),
                bits: genesis.bits(),
            },
            history,
        }
    }

    pub fn tip(&self) -> HeaderTip {
        self.tip
    }

    /// All checks and derived-work arithmetic complete before any state changes.
    pub fn append(&mut self, raw: &[u8]) -> Result<HeaderTip, HeaderError> {
        let height = self
            .tip
            .height
            .checked_add(1)
            .ok_or(HeaderError::HeightOverflow)?;
        let header = ParsedHeader::parse(raw)?;
        validate_version(header.version)?;
        if *header.parent != self.tip.hash {
            return Err(HeaderError::WrongParent);
        }
        let target =
            testnet_target_from_compact(header.bits).map_err(|_| HeaderError::InvalidTarget)?;
        let expected_bits = next_work_required(&self.history, height, header.time)?;
        if header.bits != expected_bits {
            return Err(HeaderError::UnexpectedDifficulty);
        }
        validate_time(height, header.time, self.history.median_time_past(0))?;
        equihash::is_valid_solution(200, 9, &raw[..108], header.nonce, header.solution)
            .map_err(|_| HeaderError::InvalidEquihash)?;
        let hash: [u8; 32] = Sha256::digest(Sha256::digest(raw)).into();
        check_hash_target(&hash, target)?;
        let work = block_work(target).map_err(|_| HeaderError::InvalidTarget)?;
        let cumulative_work = self
            .tip
            .cumulative_work
            .checked_add(work)
            .ok_or(HeaderError::WorkOverflow)?;
        let tip = HeaderTip {
            height,
            hash,
            cumulative_work,
            time: header.time,
            bits: header.bits,
        };

        self.history.push(HeaderContext {
            time: header.time,
            target,
        });
        self.tip = tip;
        Ok(tip)
    }
}

struct ParsedHeader<'a> {
    version: i32,
    parent: &'a [u8; 32],
    time: u32,
    bits: u32,
    nonce: &'a [u8; 32],
    solution: &'a [u8],
}

impl<'a> ParsedHeader<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self, HeaderError> {
        if raw.len() < HEADER_LENGTH {
            return Err(HeaderError::MalformedHeader);
        }
        if raw.len() > HEADER_LENGTH {
            return Err(HeaderError::TrailingBytes);
        }
        // The only variable-width header field is the Equihash solution. Its
        // fixed consensus length must encode as fd4005, not an alternate size
        // prefix. Round-trip through the existing allocation-free writer.
        let mut canonical = CanonicalBytes {
            remaining: &raw[140..],
        };
        CompactSize::write(&mut canonical, SOLUTION_LENGTH)
            .map_err(|_| HeaderError::NoncanonicalEncoding)?;
        let version = i32::from_le_bytes(
            raw[..4]
                .try_into()
                .map_err(|_| HeaderError::MalformedHeader)?,
        );
        let parent = raw[4..36]
            .try_into()
            .map_err(|_| HeaderError::MalformedHeader)?;
        let time = u32::from_le_bytes(
            raw[100..104]
                .try_into()
                .map_err(|_| HeaderError::MalformedHeader)?,
        );
        let bits = u32::from_le_bytes(
            raw[104..108]
                .try_into()
                .map_err(|_| HeaderError::MalformedHeader)?,
        );
        let nonce = raw[108..140]
            .try_into()
            .map_err(|_| HeaderError::MalformedHeader)?;
        Ok(Self {
            version,
            parent,
            time,
            bits,
            nonce,
            solution: canonical.remaining,
        })
    }
}

// Host admission inspects only the bounded canonical header prefix. Every body
// and contextual/cryptographic rule still belongs to the actual ledger append.
#[cfg(not(target_os = "zkvm"))]
pub(crate) fn block_header_time(raw: &[u8]) -> Result<u32, HeaderError> {
    if raw.is_empty() || raw.len() > zcash_protocol::constants::MAX_BLOCK_BYTES {
        return Err(HeaderError::MalformedHeader);
    }
    let header = raw.get(..HEADER_LENGTH).ok_or(HeaderError::MalformedHeader)?;
    Ok(ParsedHeader::parse(header)?.time)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeaderContext {
    time: u32,
    target: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HeaderHistory {
    entries: [HeaderContext; CONTEXT_LENGTH],
    next: usize,
    len: usize,
}

impl HeaderHistory {
    fn empty() -> Self {
        Self {
            entries: [HeaderContext {
                time: 0,
                target: U256::zero(),
            }; CONTEXT_LENGTH],
            next: 0,
            len: 0,
        }
    }

    fn push(&mut self, context: HeaderContext) {
        self.entries[self.next] = context;
        self.next = (self.next + 1) % CONTEXT_LENGTH;
        self.len = (self.len + 1).min(CONTEXT_LENGTH);
    }

    fn recent(&self, offset: usize) -> &HeaderContext {
        debug_assert!(offset < self.len);
        &self.entries[(self.next + CONTEXT_LENGTH - 1 - offset) % CONTEXT_LENGTH]
    }

    fn median_time_past(&self, offset: usize) -> u32 {
        let count = (self.len - offset).min(11);
        debug_assert!(count > 0);
        let mut times = [0; 11];
        for (index, time) in times[..count].iter_mut().enumerate() {
            *time = self.recent(offset + index).time;
        }
        times[..count].sort_unstable();
        times[count / 2]
    }
}

fn spacing(height: u32) -> u32 {
    if TEST_NETWORK.is_nu_active(NetworkUpgrade::Blossom, BlockHeight::from(height)) {
        75
    } else {
        150
    }
}

fn next_work_required(history: &HeaderHistory, height: u32, time: u32) -> Result<u32, HeaderError> {
    let parent = history.recent(0);
    if height > MIN_DIFFICULTY_PARENT_HEIGHT
        && u64::from(time) > u64::from(parent.time) + 6 * u64::from(spacing(height))
    {
        return Ok(LIMIT_BITS);
    }
    // zcashd advances to the predecessor AFTER summing all seventeen targets.
    // Genesis plus sixteen successors is still insufficient: candidate18 is
    // the first normal retarget, and its comparison ancestor is actual genesis.
    if history.len <= AVERAGING_WINDOW {
        return Ok(LIMIT_BITS);
    }
    let mut total = U256::zero();
    for offset in 0..AVERAGING_WINDOW {
        total = total
            .checked_add(history.recent(offset).target)
            .ok_or(HeaderError::InvalidTarget)?;
    }
    let average = total / U256::from(AVERAGING_WINDOW);
    Ok(retarget(
        average,
        history.median_time_past(0),
        history.median_time_past(AVERAGING_WINDOW),
        height,
    ))
}

fn retarget(average: U256, last_median: u32, first_median: u32, height: u32) -> u32 {
    let expected = i64::from(spacing(height)) * 17;
    let actual = i64::from(last_median) - i64::from(first_median);
    // Rust signed integer division truncates toward zero, exactly like zcashd.
    let damped = expected + (actual - expected) / 4;
    let timespan = damped.clamp(expected * 84 / 100, expected * 132 / 100);
    let target = (average / U256::from(expected as u64)) * U256::from(timespan as u64);
    compact_from_target(target.min(TESTNET_POW_LIMIT))
}

fn compact_from_target(target: U256) -> u32 {
    let mut size = target.bits().div_ceil(8);
    let mut word = if size <= 3 {
        target.low_u32() << (8 * (3 - size))
    } else {
        (target >> (8 * (size - 3))).low_u32()
    };
    if word & 0x0080_0000 != 0 {
        word >>= 8;
        size += 1;
    }
    word | ((size as u32) << 24)
}

fn validate_version(version: i32) -> Result<(), HeaderError> {
    if version < 4 {
        Err(HeaderError::InvalidVersion)
    } else {
        Ok(())
    }
}

fn validate_time(height: u32, time: u32, median: u32) -> Result<(), HeaderError> {
    if time <= median {
        return Err(HeaderError::TimeTooEarly);
    }
    // zcashd testnet chainparams activates the +5400 MTP bound at Blossom+6,
    // not mainnet's Blossom height and not the Blossom spacing change itself.
    let upper_bound_active = TEST_NETWORK
        .activation_height(NetworkUpgrade::Blossom)
        .is_some_and(|activation| u64::from(height) >= u64::from(activation) + 6);
    if upper_bound_active && u64::from(time) > u64::from(median) + 5400 {
        return Err(HeaderError::TimeTooLate);
    }
    Ok(())
}

fn check_hash_target(hash: &[u8; 32], target: U256) -> Result<(), HeaderError> {
    if U256::from_little_endian(hash) > target {
        Err(HeaderError::InsufficientWork)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::GenesisError;

    // Synthetic timestamps/targets exercise PRIVATE arithmetic only. They do
    // not create authenticated headers, bypass genesis, or exercise append.
    fn arithmetic_history(times: &[u32], bits: u32) -> HeaderHistory {
        let target = testnet_target_from_compact(bits).unwrap();
        let mut history = HeaderHistory::empty();
        for &time in times {
            history.push(HeaderContext { time, target });
        }
        history
    }

    #[test]
    fn startup_requires_seventeen_targets_and_their_actual_predecessor() {
        let times: Vec<_> = (0..18).map(|height| 1_000_000 + height * 150).collect();
        for candidate_height in 1..=17 {
            let history = arithmetic_history(&times[..candidate_height], 0x1d00_ffff);
            assert_eq!(
                next_work_required(
                    &history,
                    u32::try_from(candidate_height).unwrap(),
                    1_003_000
                )
                .unwrap(),
                0x2007_ffff,
            );
        }
        let history = arithmetic_history(&times, 0x1d00_ffff);
        // MTP(17)=time(12), MTP(0)=time(0); A=2550, D=1800, damped=2363.
        assert_eq!(
            next_work_required(&history, 18, 1_003_000).unwrap(),
            0x1d00_ed39
        );
    }

    #[test]
    fn median_uses_upper_middle_of_the_actual_prefix_and_last_eleven_only() {
        for (times, expected) in [
            (&[100][..], 100),
            (&[100, 200][..], 200),
            (&[300, 100, 200][..], 200),
            (&[400, 100, 300, 200][..], 300),
        ] {
            let history = arithmetic_history(times, 0x2007_ffff);
            assert_eq!(history.median_time_past(0), expected);
        }
        let history = arithmetic_history(&[4_000, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], 0x2007_ffff);
        assert_eq!(history.median_time_past(0), 6);
        assert_eq!(history.median_time_past(1), 6);
    }

    #[test]
    fn bounded_context_retains_all_twenty_eight_entries_needed_by_retarget_medians() {
        let times: Vec<_> = (0..100).map(|height| 1_000_000 + height * 150).collect();
        let history = arithmetic_history(&times, 0x1d00_ffff);
        assert_eq!(history.median_time_past(0), 1_014_100);
        assert_eq!(history.median_time_past(17), 1_011_550);
        // Both medians have eleven real entries, exactly a 2550-second interval.
        assert_eq!(
            next_work_required(&history, 100, 1_015_000).unwrap(),
            0x1d00_fffe
        );
    }

    #[test]
    fn retarget_matches_literal_primary_vectors_and_testnet_full_limit_cap() {
        // zcashd commit 86451a18b016af09a4e33c9acc1aa5577e25af17,
        // src/test/pow_tests.cpp::{get_next_work,*actual,*actual_blossom}.
        // Header timestamps are not involved: these are the upstream literal
        // median inputs, with the published expected bits, not mirrored math.
        for (average, first, last, height, expected) in [
            (0x1d00_ffff, 1_000_000_000, 1_000_003_570, 18, 0x1d01_1998),
            (0x1c05_a3f4, 1_000_000_000, 100_000_917, 18, 0x1c04_bceb),
            (
                0x1c05_a3f4,
                1_000_000_000,
                1_000_000_458,
                584_000,
                0x1c04_bceb,
            ),
            (0x1c38_7f6f, 1_000_000_000, 1_000_005_815, 18, 0x1c4a_93bb),
            (
                0x1c38_7f6f,
                1_000_000_000,
                1_000_002_908,
                584_000,
                0x1c4a_93bb,
            ),
            (0x2007_ffff, 1_231_006_505, 1_233_061_996, 18, 0x2007_ffff),
        ] {
            assert_eq!(
                retarget(
                    testnet_target_from_compact(average).unwrap(),
                    last,
                    first,
                    height
                ),
                expected,
            );
        }
    }

    #[test]
    fn retarget_uses_signed_truncation_and_divides_before_multiplying() {
        // Small literal targets make the loss from reversing integer operations
        // observable rather than hiding it below compact's mantissa precision.
        assert_eq!(retarget(U256::from(5_101), 2_547, 0, 18), 0x0213_ec00);
        assert_eq!(retarget(U256::from(5_101), 2_546, 0, 18), 0x0213_ea00);
        assert_eq!(retarget(U256::from(5_101), 0, 100, 18), 0x0210_bc00);
        assert_eq!(retarget(U256::from(2_551), 1_274, 0, 584_000), 0x0209_f600);
    }

    #[test]
    fn target_average_is_floored_after_all_seventeen_targets_are_added() {
        let mut history = arithmetic_history(&[0; 18], 0x0209_fc00); // 2556 each.
        // A tiny retarget quotient edge distinguishes floor(sum/17) from
        // summing individually divided targets, without compact rounding hiding it.
        for offset in 0..17 {
            history.entries[offset].target = U256::from(2_549);
        }
        history.entries[17].target = U256::from(2_566);
        // The seventeen candidates exclude entry0: average=(2549*16+2566)/17=2550.
        assert_eq!(next_work_required(&history, 18, 1).unwrap(), 0x0208_5e00);
    }

    #[test]
    fn testnet_min_difficulty_activation_and_delay_are_strict_with_no_restore_scan() {
        let history = arithmetic_history(&[1_000_000; 28], 0x1d00_ffff);
        for (height, time, expected) in [
            (299_187, 1_000_901, 0x1d00_d709),
            (299_188, 1_000_900, 0x1d00_d709),
            (299_188, 1_000_901, 0x2007_ffff),
            (583_999, 1_000_900, 0x1d00_d709),
            (583_999, 1_000_901, 0x2007_ffff),
            (584_000, 1_000_450, 0x1d00_d709),
            (584_000, 1_000_451, 0x2007_ffff),
        ] {
            assert_eq!(
                next_work_required(&history, height, time).unwrap(),
                expected
            );
        }
        let mut mixed = history;
        mixed.push(HeaderContext {
            time: 1_000_000,
            target: testnet_target_from_compact(0x2007_ffff).unwrap(),
        });
        // No Bitcoin-style scan back to the last non-minimum bits.
        assert_eq!(
            next_work_required(&mixed, 299_188, 1_000_900).unwrap(),
            0x1f65_31f2
        );
    }

    #[test]
    fn timestamp_lower_bound_and_correct_testnet_upper_activation_are_exact() {
        assert_eq!(
            validate_time(584_005, 1_000_000, 1_000_000),
            Err(HeaderError::TimeTooEarly)
        );
        assert!(validate_time(584_005, 1_000_001, 1_000_000).is_ok());
        assert!(validate_time(584_005, 1_005_401, 1_000_000).is_ok());
        assert!(validate_time(584_006, 1_005_400, 1_000_000).is_ok());
        assert_eq!(
            validate_time(584_006, 1_005_401, 1_000_000),
            Err(HeaderError::TimeTooLate)
        );
        // Widen additions instead of wrapping near the header timestamp limit.
        assert!(validate_time(584_006, u32::MAX, u32::MAX - 1).is_ok());
        let history = arithmetic_history(&[u32::MAX - 1; 28], 0x1d00_ffff);
        assert_eq!(
            next_work_required(&history, 299_188, u32::MAX).unwrap(),
            0x1d00_d709
        );
    }

    #[test]
    fn compact_range_work_and_little_endian_hash_boundary_are_exact() {
        for bits in [0, 0x0100_0001, 0x2087_ffff, 0x2300_0001, 0x2008_0000] {
            assert_eq!(
                testnet_target_from_compact(bits),
                Err(GenesisError::InvalidTarget)
            );
        }
        let target = testnet_target_from_compact(0x2007_ffff).unwrap();
        assert!(target < TESTNET_POW_LIMIT);
        assert_eq!(block_work(target).unwrap(), U256::from(32));
        assert_eq!(
            block_work(testnet_target_from_compact(0x1f07_ffff).unwrap()).unwrap(),
            U256::from(8_192)
        );
        let mut equal_hash = [0; 32];
        target.to_little_endian(&mut equal_hash);
        assert!(check_hash_target(&equal_hash, target).is_ok());
        let mut greater_hash = [0; 32];
        (target + U256::one()).to_little_endian(&mut greater_hash);
        assert_eq!(
            check_hash_target(&greater_hash, target),
            Err(HeaderError::InsufficientWork)
        );
        assert_eq!(compact_from_target(TESTNET_POW_LIMIT), 0x2007_ffff);
        assert_eq!(compact_from_target(U256::from(0x80)), 0x0200_8000);
        assert_eq!(compact_from_target(U256::from(0x7f_ffff)), 0x037f_ffff);
        assert_eq!(compact_from_target(U256::from(0x80_0000)), 0x0400_8000);
    }

    #[test]
    fn signed_version_minimum_is_not_an_exact_version_four_gate() {
        for version in [4, 5, i32::MAX] {
            assert!(validate_version(version).is_ok());
        }
        for version in [3, -1, i32::MIN] {
            assert_eq!(validate_version(version), Err(HeaderError::InvalidVersion));
        }
    }

    #[test]
    fn cumulative_work_overflow_and_height_overflow_do_not_publish_a_header() {
        let genesis = crate::genesis::bootstrap_testnet_genesis(include_bytes!(
            "../tests/fixtures/testnet-genesis.bin"
        ))
        .unwrap();
        let raw = include_bytes!("../tests/fixtures/testnet-header-1.bin");
        let mut chain = HeaderChain::from_testnet_genesis(&genesis);
        chain.tip.cumulative_work = U256::MAX - U256::from(31);
        let before = chain.clone();
        assert_eq!(chain.append(raw), Err(HeaderError::WorkOverflow));
        assert_eq!(chain, before);
        chain.tip.height = u32::MAX;
        let before_height = chain.clone();
        assert_eq!(chain.append(raw), Err(HeaderError::HeightOverflow));
        assert_eq!(chain, before_height);
    }
}
