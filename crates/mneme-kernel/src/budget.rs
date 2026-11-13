//! Work and size budgets.
//!
//! A budget is charged before the work it pays for is done. A charge that
//! would overflow or pass the limit is refused, so the amount recorded as used
//! never exceeds the limit and never wraps.

/// Charge `cost` against a budget that has `used` of `limit` consumed.
///
/// Returns the new amount used, or `None` when the charge would overflow or
/// exceed the limit. The caller must stop and report the limit on `None`.
pub fn charge(used: u64, cost: u64, limit: u64) -> Option<u64> {
    match used.checked_add(cost) {
        Some(total) => {
            if total <= limit {
                Some(total)
            } else {
                None
            }
        }
        None => None,
    }
}
