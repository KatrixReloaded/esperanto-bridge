use anyhow::{bail, ensure, Result};
use openssl::{
    asn1::Asn1Time,
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509NameBuilder, X509},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

pub const TYPE: &str = "CWXMRNitroBinding(uint256 chainId,address registry,address bridge,bytes32 vaultId,address signingKey,address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash,uint64 policyVersion,bytes32 challenge)";

/// Private DER keys are serialized only into an authenticated encrypted backup, inside the enclave.
#[derive(Serialize, Deserialize)]
pub struct Identity {
    mint: Vec<u8>,
    decrypt: Vec<u8>,
    auth: Vec<u8>,
    tls: Vec<u8>,
    certificate: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingDomain {
    pub chain_id: u64,
    pub registry: String,
    pub bridge: String,
    pub policy_version: u64,
}
#[derive(Debug, Serialize)]
pub struct PublicIdentity {
    pub vault_id: String,
    pub signing_key: String,
    pub decrypt_key: String,
    pub tls_key_hash: String,
    pub auth_key_hash: String,
    pub public_key: String,
}
fn ec_key(curve: Nid) -> Result<PKey<Private>> {
    Ok(PKey::from_ec_key(EcKey::generate(
        EcGroup::from_curve_name(curve)?.as_ref(),
    )?)?)
}
fn raw(key: &PKey<Private>) -> Result<Vec<u8>> {
    let ec = key.ec_key()?;
    let mut ctx = BigNumContext::new()?;
    Ok(ec
        .public_key()
        .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)?[1..]
        .to_vec())
}
pub fn decode<const N: usize>(s: &str) -> Result<[u8; N]> {
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong byte length"))?)
}
fn addr(key: &PKey<Private>) -> Result<[u8; 20]> {
    Ok(Keccak256::digest(raw(key)?)[12..].try_into()?)
}
impl Identity {
    pub fn generate() -> Result<Self> {
        let mint = ec_key(Nid::SECP256K1)?;
        let decrypt = ec_key(Nid::SECP256K1)?;
        let auth = PKey::generate_ed25519()?;
        let tls = ec_key(Nid::X9_62_PRIME256V1)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "cwxmr-enclave")?;
        let name = name.build();
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        let mut serial = openssl::bn::BigNum::new()?;
        serial.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
        cert.set_serial_number(serial.to_asn1_integer()?.as_ref())?;
        cert.set_subject_name(&name)?;
        cert.set_issuer_name(&name)?;
        cert.set_pubkey(&tls)?;
        cert.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        cert.set_not_after(Asn1Time::days_from_now(30)?.as_ref())?;
        cert.sign(&tls, MessageDigest::sha256())?;
        Ok(Self {
            mint: mint.private_key_to_der()?,
            decrypt: decrypt.private_key_to_der()?,
            auth: auth.private_key_to_der()?,
            tls: tls.private_key_to_der()?,
            certificate: cert.build().to_der()?,
        })
    }
    pub fn tls_key(&self) -> Result<PKey<Private>> {
        Ok(PKey::private_key_from_der(&self.tls)?)
    }
    pub fn certificate(&self) -> Result<X509> {
        Ok(X509::from_der(&self.certificate)?)
    }
    pub fn public(&self) -> Result<PublicIdentity> {
        let mint = PKey::private_key_from_der(&self.mint)?;
        let decrypt = PKey::private_key_from_der(&self.decrypt)?;
        let auth = PKey::private_key_from_der(&self.auth)?;
        let raw = raw(&mint)?;
        Ok(PublicIdentity {
            vault_id: hex::encode(Keccak256::digest(&raw)),
            signing_key: hex::encode(addr(&mint)?),
            decrypt_key: hex::encode(addr(&decrypt)?),
            public_key: hex::encode(raw),
            tls_key_hash: hex::encode(Sha256::digest(self.tls_key()?.public_key_to_der()?)),
            auth_key_hash: hex::encode(Sha256::digest(auth.raw_public_key()?)),
        })
    }
    pub fn binding(&self, domain: &BindingDomain, challenge: [u8; 32]) -> Result<[u8; 32]> {
        let public = self.public()?;
        let mut words = vec![Keccak256::digest(TYPE.as_bytes()).to_vec()];
        let mut chain = [0u8; 32];
        chain[24..].copy_from_slice(&domain.chain_id.to_be_bytes());
        words.push(chain.to_vec());
        for address in [&domain.registry, &domain.bridge] {
            let mut word = [0u8; 32];
            word[12..].copy_from_slice(&decode::<20>(address)?);
            words.push(word.to_vec());
        }
        words.push(decode::<32>(&public.vault_id)?.to_vec());
        for address in [&public.signing_key, &public.decrypt_key] {
            let mut word = [0u8; 32];
            word[12..].copy_from_slice(&decode::<20>(address)?);
            words.push(word.to_vec());
        }
        words.push(decode::<32>(&public.tls_key_hash)?.to_vec());
        words.push(decode::<32>(&public.auth_key_hash)?.to_vec());
        let mut policy = [0u8; 32];
        policy[24..].copy_from_slice(&domain.policy_version.to_be_bytes());
        words.push(policy.to_vec());
        words.push(challenge.to_vec());
        Ok(Keccak256::digest(words.concat()).into())
    }
    pub fn attest(&self, domain: &BindingDomain, challenge: [u8; 32]) -> Result<Vec<u8>> {
        attest(
            &decode::<64>(&self.public()?.public_key)?,
            &self.binding(domain, challenge)?,
            &challenge,
        )
    }
}
impl Drop for Identity {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.mint.zeroize();
        self.decrypt.zeroize();
        self.auth.zeroize();
        self.tls.zeroize();
    }
}
/// No mock document is ever returned. Native development cannot enroll in a registry.
pub fn attest(public_key: &[u8], user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !public_key.is_empty()
            && public_key.len() <= 1024
            && user_data.len() <= 512
            && nonce.len() <= 512,
        "NSM field bound exceeded"
    );
    #[cfg(all(feature = "nitro", target_os = "linux"))]
    {
        use aws_nitro_enclaves_nsm_api::{
            api::{Request, Response},
            driver::{nsm_exit, nsm_init, nsm_process_request},
        };
        let fd = nsm_init();
        ensure!(fd >= 0, "NSM is unavailable");
        let result = nsm_process_request(
            fd,
            Request::Attestation {
                public_key: Some(public_key.to_vec().into()),
                user_data: Some(user_data.to_vec().into()),
                nonce: Some(nonce.to_vec().into()),
            },
        );
        nsm_exit(fd);
        if let Response::Attestation { document } = result {
            return Ok(document);
        }
        bail!("NSM attestation failed");
    }
    #[cfg(not(all(feature = "nitro", target_os = "linux")))]
    bail!("real Nitro NSM attestation requires Linux and the nitro feature")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_bundle_and_domain_binding() {
        let id = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let mut domain = BindingDomain {
            chain_id: 11155111,
            registry: "11".repeat(20),
            bridge: "22".repeat(20),
            policy_version: 1,
        };
        let public = id.public().unwrap();
        assert_eq!(hex::decode(&public.public_key).unwrap().len(), 64);
        assert_eq!(&public.vault_id[24..], public.signing_key);
        let a = id.binding(&domain, [3; 32]).unwrap();
        assert_ne!(a, id.binding(&domain, [4; 32]).unwrap());
        assert_ne!(a, other.binding(&domain, [3; 32]).unwrap());
        domain.chain_id += 1;
        assert_ne!(a, id.binding(&domain, [3; 32]).unwrap());
        let cert_key = id
            .certificate()
            .unwrap()
            .public_key()
            .unwrap()
            .public_key_to_der()
            .unwrap();
        assert_eq!(hex::encode(Sha256::digest(cert_key)), public.tls_key_hash);
        let encoded = serde_json::to_vec(&id).unwrap();
        let restored: Identity = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored.public().unwrap().vault_id, public.vault_id);
    }
    #[test]
    fn no_native_attestation() {
        #[cfg(not(all(feature = "nitro", target_os = "linux")))]
        assert!(attest(&[1; 64], &[2; 32], &[3; 32]).is_err());
    }
}
