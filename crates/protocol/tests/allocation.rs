use primitive_types::U256;
use ziquid_protocol::{AllocationError, AmountError, NativeAmount, SourceAmount, allocate};

fn source(value: u64) -> SourceAmount {
    SourceAmount::new(value).unwrap()
}

fn native(value: U256) -> NativeAmount {
    NativeAmount::new(value)
}

fn hex(value: &str) -> U256 {
    U256::from_str_radix(value, 16).unwrap()
}

#[test]
fn partial_allocation_floors_user_share_and_preserves_solver_dust() {
    for (consideration, user, solver) in [(1_u64, 3_u64, 7_u64), (2, 6, 4), (0, 0, 10), (3, 10, 0)]
    {
        let allocation =
            allocate(source(3), native(U256::from(10_u64)), source(consideration)).unwrap();
        assert_eq!(allocation.user.get(), U256::from(user));
        assert_eq!(allocation.solver.get(), U256::from(solver));
        assert_eq!(
            allocation.user.get() + allocation.solver.get(),
            U256::from(10_u64)
        );
    }
}

#[test]
fn quote_and_funding_must_be_nonzero_but_zero_consideration_is_valid() {
    assert_eq!(
        allocate(source(0), native(U256::from(10_u64)), source(0)),
        Err(AllocationError::ZeroQuote),
    );
    assert_eq!(
        allocate(source(3), native(U256::zero()), source(0)),
        Err(AllocationError::ZeroFunding),
    );
    assert_eq!(
        allocate(source(3), native(U256::from(10_u64)), source(4)),
        Err(AllocationError::ExcessConsideration),
    );
}

#[test]
fn allocation_preserves_bits_above_u128() {
    let funded = hex("0000000000000000000000000000000100000000000000000000000000000001");
    let allocation = allocate(source(3), native(funded), source(2)).unwrap();
    assert_eq!(
        allocation.user.get(),
        hex("00000000000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"),
    );
    assert_eq!(
        allocation.solver.get(),
        hex("0000000000000000000000000000000055555555555555555555555555555556"),
    );
    assert_eq!(allocation.user.get() + allocation.solver.get(), funded);
}

#[test]
fn full_u256_maximum_product_is_not_truncated() {
    let funded = U256::MAX;
    let allocation = allocate(source(3), native(funded), source(2)).unwrap();
    assert_eq!(
        allocation.user.get(),
        hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    );
    assert_eq!(
        allocation.solver.get(),
        hex("5555555555555555555555555555555555555555555555555555555555555555"),
    );
    assert_eq!(allocation.user.get() + allocation.solver.get(), funded);

    // These independent literals exercise the maximum source bound as well as a
    // product wider than 256 bits; exact consideration must return all funding.
    let maximum_source = 2_100_000_000_000_000;
    let allocation = allocate(
        source(maximum_source),
        native(funded),
        source(maximum_source - 1),
    )
    .unwrap();
    assert_eq!(
        allocation.user.get(),
        hex("ffffffffffffddafd60e475c079b8e916cceede9fd9a95cc12f5e83b9496daab"),
    );
    assert_eq!(
        allocation.solver.get(),
        hex("000000000000225029f1b8a3f864716e9331121602656a33ed0a17c46b692554"),
    );
    assert_eq!(allocation.user.get() + allocation.solver.get(), funded);
    let exact = allocate(
        source(maximum_source),
        native(funded),
        source(maximum_source),
    )
    .unwrap();
    assert_eq!(exact.user.get(), funded);
    assert_eq!(exact.solver.get(), U256::zero());
}

#[test]
fn source_amount_rejects_negative_and_out_of_money_range_without_wrapping() {
    assert_eq!(SourceAmount::try_from(-1_i64), Err(AmountError::Negative));
    assert_eq!(SourceAmount::try_from(i64::MIN), Err(AmountError::Negative));
    assert_eq!(SourceAmount::try_from(0_i64).unwrap().get(), 0);
    assert_eq!(
        SourceAmount::new(2_100_000_000_000_000).unwrap().get(),
        2_100_000_000_000_000
    );
    assert_eq!(
        SourceAmount::new(2_100_000_000_000_001),
        Err(AmountError::SourceOutOfRange)
    );
    assert_eq!(
        SourceAmount::new(u64::MAX),
        Err(AmountError::SourceOutOfRange)
    );
    assert_eq!(
        SourceAmount::try_from(i64::MAX),
        Err(AmountError::SourceOutOfRange)
    );
}
