//! Enclave-local Zama boundary. No SDK or chain integration is implied by this interface.
use zz_core::{AtomicAmount, Domain, Id};

#[derive(Clone, PartialEq, Eq)]
pub struct InputDomain {
    pub chain_id: u64,
    pub contract: [u8; 20],
    pub caller: [u8; 20],
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedInput {
    pub domain: InputDomain,
    pub handle: [u8; 32],
    pub proof: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InputError {
    DomainMismatch,
    EmptyProof,
    ZeroActual,
    ExcessActual,
}

impl EncryptedInput {
    pub fn validate(&self, expected: &InputDomain) -> Result<(), InputError> {
        if &self.domain != expected {
            return Err(InputError::DomainMismatch);
        }
        if self.proof.is_empty() {
            return Err(InputError::EmptyProof);
        }
        Ok(())
    }
}

/// Implement using the actual Zama SDK inside the enclave, never a host plaintext sidecar.
pub trait EnclaveFhe {
    type Error;
    fn encrypt_amount(
        &self,
        amount: AtomicAmount,
        domain: &InputDomain,
    ) -> Result<EncryptedInput, Self::Error>;
    fn decrypt_authorized(
        &self,
        handle: [u8; 32],
        domain: &InputDomain,
    ) -> Result<AtomicAmount, Self::Error>;
}

/// A finalized operation's actual result, not the requested input, defines entitlement.
pub fn reconcile_actual(
    requested: AtomicAmount,
    actual: AtomicAmount,
) -> Result<AtomicAmount, InputError> {
    if actual.0 == 0 {
        return Err(InputError::ZeroActual);
    }
    if actual > requested {
        return Err(InputError::ExcessActual);
    }
    Ok(actual)
}

/// Transaction bytes are signed inside the enclave and must be journaled before relay.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedOperation {
    pub domain: Domain,
    pub operation_id: Id,
    pub nonce: u64,
    pub signed_bytes: Vec<u8>,
    pub tx_hash: Id,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_wrong_input_domain_and_zero_actual() {
        let domain = InputDomain {
            chain_id: 1,
            contract: [1; 20],
            caller: [2; 20],
        };
        let input = EncryptedInput {
            domain: domain.clone(),
            handle: [3; 32],
            proof: vec![4],
        };
        assert_eq!(input.validate(&domain), Ok(()));
        let mut wrong = domain;
        wrong.caller[0] ^= 1;
        assert_eq!(input.validate(&wrong), Err(InputError::DomainMismatch));
        assert_eq!(
            reconcile_actual(AtomicAmount(5), AtomicAmount(0)),
            Err(InputError::ZeroActual)
        );
        assert_eq!(
            reconcile_actual(AtomicAmount(5), AtomicAmount(3)),
            Ok(AtomicAmount(3))
        );
    }
}

pub mod mint;

pub mod fhe;
pub mod permit;
