//! Nitro transport and recovery boundary. Bridge actions remain disabled until authenticated
//! chain verification and independent payout fencing are implemented.
pub mod attestation;
pub mod backup;
pub mod deposits;
pub mod kms;
pub mod mints;
pub mod observation;
pub mod prover;
pub mod redemptions;
