//! Confidential inputs and enclave-local Zama SDK integration.
use zz_core::AtomicAmount;

pub mod evm;
pub mod fhe;
pub mod mint;
pub mod permit;

#[derive(Debug, PartialEq, Eq)]
pub enum ActualResultError {
    Zero,
    ExceedsRequested,
}

/// Reconcile a verified finalized result; receipt success alone is insufficient.
pub fn reconcile_actual(
    requested: AtomicAmount,
    actual: AtomicAmount,
) -> Result<AtomicAmount, ActualResultError> {
    if actual.0 == 0 {
        return Err(ActualResultError::Zero);
    }
    if actual > requested {
        return Err(ActualResultError::ExceedsRequested);
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconciles_actual_entitlement_within_requested_bound() {
        assert_eq!(
            reconcile_actual(AtomicAmount(5), AtomicAmount(0)),
            Err(ActualResultError::Zero)
        );
        assert_eq!(
            reconcile_actual(AtomicAmount(5), AtomicAmount(6)),
            Err(ActualResultError::ExceedsRequested)
        );
        assert_eq!(
            reconcile_actual(AtomicAmount(5), AtomicAmount(3)),
            Ok(AtomicAmount(3))
        );
    }
}

alloy::sol!(
    #[allow(missing_docs)]
    Bridge,
    "abi/Bridge.json"
);
