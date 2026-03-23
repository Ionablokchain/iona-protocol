/// EIP-1559 baseFee update rule (London).
///
/// Implements the formula:
///
/// ```
/// target_gas = gas_limit / 2
/// if gas_used == target_gas:
///     base_fee = parent_base_fee
/// elif gas_used > target_gas:
///     delta = parent_base_fee * (gas_used - target_gas) / target_gas / 8
///     base_fee = parent_base_fee + max(1, delta)
/// else:
///     delta = parent_base_fee * (target_gas - gas_used) / target_gas / 8
///     base_fee = parent_base_fee - delta
/// ```
///
/// The gas limit is the block gas limit, typically `30_000_000`.
/// The target gas is exactly half of the gas limit.
///
/// # Panics
/// This function does not panic, but `gas_limit` must be > 0 to avoid division by zero.
/// If `gas_limit` is 0, the function returns the input `base_fee`.
pub fn next_base_fee(base_fee: u64, gas_used: u64, gas_limit: u64) -> u64 {
    if gas_limit == 0 {
        return base_fee;
    }
    let target = gas_limit / 2;
    if target == 0 {
        return base_fee;
    }

    if gas_used == target {
        return base_fee;
    }

    // Compute the absolute change using 128‑bit arithmetic to avoid overflow.
    let gas_delta = if gas_used > target {
        gas_used - target
    } else {
        target - gas_used
    };
    let mut change = (base_fee as u128) * (gas_delta as u128);
    change /= target as u128;
    change /= 8u128;

    if gas_used > target {
        // Increase: at least 1 wei
        let change_u = change as u64;
        base_fee.saturating_add(std::cmp::max(1, change_u))
    } else {
        // Decrease: can go down to zero
        let change_u = change as u64;
        base_fee.saturating_sub(change_u)
    }
}

/// Convenience function to compute next base fee from a previous block header.
pub fn next_base_fee_from_header(prev: &BlockHeader, next_gas_limit: u64) -> u64 {
    next_base_fee(prev.base_fee_per_gas, prev.gas_used, next_gas_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_base_fee_equal() {
        let base_fee = 1_000_000_000;
        let gas_used = 15_000_000; // target = 15_000_000
        let gas_limit = 30_000_000;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit), base_fee);
    }

    #[test]
    fn test_next_base_fee_increase() {
        let base_fee = 1_000_000_000;
        let gas_used = 25_000_000; // above target
        let gas_limit = 30_000_000;
        // target = 15_000_000, delta = 10_000_000
        // change = 1e9 * 10e6 / 15e6 / 8 = 1e9 * 0.6666666 / 8 ≈ 83_333_333
        let expected = base_fee + 83_333_333;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit), expected);
    }

    #[test]
    fn test_next_base_fee_decrease() {
        let base_fee = 1_000_000_000;
        let gas_used = 5_000_000; // below target
        let gas_limit = 30_000_000;
        // target = 15_000_000, delta = 10_000_000
        // change = 1e9 * 10e6 / 15e6 / 8 = 83_333_333
        let expected = base_fee - 83_333_333;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit), expected);
    }

    #[test]
    fn test_next_base_fee_min_increase() {
        let base_fee = 1;
        let gas_used = gas_limit; // full block
        let gas_limit = 30_000_000;
        // change = 1 * 30e6 / 15e6 / 8 = 0 (integer division)
        // but increase must be at least 1
        let expected = base_fee + 1;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit), expected);
    }

    #[test]
    fn test_next_base_fee_zero_limit() {
        let base_fee = 100;
        assert_eq!(next_base_fee(base_fee, 50, 0), base_fee);
    }

    #[test]
    fn test_next_base_fee_target_zero() {
        let base_fee = 100;
        assert_eq!(next_base_fee(base_fee, 1, 1), base_fee); // target = 0
    }

    #[test]
    fn test_next_base_fee_zero_base() {
        let base_fee = 0;
        let gas_used = 30_000_000;
        let gas_limit = 30_000_000;
        // change = 0 * ... / ... = 0
        // increase: max(1,0) = 1
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit), 1);
    }

    #[test]
    fn test_next_base_fee_saturation() {
        let base_fee = u64::MAX;
        let gas_used = 30_000_000;
        let gas_limit = 30_000_000;
        let result = next_base_fee(base_fee, gas_used, gas_limit);
        assert_eq!(result, u64::MAX); // saturates
    }
}
