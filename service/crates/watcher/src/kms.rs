//! KMS TLS and SigV4 terminate inside the enclave. Parent forwards TLS ciphertext only.
//! KMS's CMS recipient encryption uses a fresh RSA key, separate from registry secp256k1 keys.
use crate::{attestation, backup::DataKey};
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use openssl::{
    cms::CmsContentInfo,
    pkey::{PKey, Private},
    rsa::Rsa,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::Read, net::SocketAddr, time::Duration};
use time::{format_description, OffsetDateTime};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub token: String,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_access_key.zeroize();
        self.token.zeroize();
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub region: String,
    pub key_arn: String,
    pub forward_port: u16,
}
pub struct Kms {
    config: Config,
    http: Client,
    host: String,
}
fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut h = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    h.update(data.as_bytes());
    h.finalize().into_bytes().to_vec()
}
impl Kms {
    pub fn new(config: Config) -> Result<Self> {
        ensure!(
            !config.region.is_empty()
                && config
                    .region
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
            "invalid AWS region"
        );
        ensure!(
            config
                .key_arn
                .starts_with(&format!("arn:aws:kms:{}:", config.region))
                && config.key_arn.contains(":key/"),
            "KMS key must be an ARN in the configured region"
        );
        let host = format!("kms.{}.amazonaws.com", config.region);
        let http = Client::builder()
            .timeout(Duration::from_secs(20))
            .no_proxy()
            .resolve(
                &host,
                SocketAddr::from(([127, 0, 0, 1], config.forward_port)),
            )
            .https_only(true)
            .build()?;
        Ok(Self { config, http, host })
    }
    fn request(&self, action: &str, payload: Value, credentials: &Credentials) -> Result<Value> {
        let body = serde_json::to_string(&payload)?;
        let now = OffsetDateTime::now_utc();
        let date = now.format(&format_description::parse_borrowed::<2>(
            "[year][month][day]",
        )?)?;
        let stamp = now.format(&format_description::parse_borrowed::<2>(
            "[year][month][day]T[hour][minute][second]Z",
        )?)?;
        let target = format!("TrentService.{action}");
        let headers=format!("content-type:application/x-amz-json-1.1\nhost:{}\nx-amz-date:{}\nx-amz-security-token:{}\nx-amz-target:{}\n",self.host,stamp,credentials.token,target);
        let names = "content-type;host;x-amz-date;x-amz-security-token;x-amz-target";
        let canonical = format!(
            "POST\n/\n\n{headers}\n{names}\n{}",
            hex::encode(Sha256::digest(body.as_bytes()))
        );
        let scope = format!("{date}/{}/kms/aws4_request", self.config.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical))
        );
        let initial = Zeroizing::new(format!("AWS4{}", credentials.secret_access_key));
        let date_key = Zeroizing::new(hmac(initial.as_bytes(), &date));
        let region_key = Zeroizing::new(hmac(&date_key, &self.config.region));
        let service_key = Zeroizing::new(hmac(&region_key, "kms"));
        let signing_key = Zeroizing::new(hmac(&service_key, "aws4_request"));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={}",
            credentials.access_key_id,
            hex::encode(hmac(&signing_key, &to_sign))
        );
        let response = self
            .http
            .post(format!("https://{}/", self.host))
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amz-date", stamp)
            .header("x-amz-security-token", &credentials.token)
            .header("x-amz-target", target)
            .header("authorization", authorization)
            .body(body)
            .send()
            .context("KMS TLS request failed")?;
        ensure!(
            response.status().is_success(),
            "KMS rejected attested request (HTTP {})",
            response.status()
        );
        let mut bytes = Vec::new();
        response.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1024 * 1024, "KMS response bound exceeded");
        Ok(serde_json::from_slice(&bytes)?)
    }
    /// `wrapped` is absent only for an explicitly initialized new vault.
    pub fn recover(
        &self,
        wrapped: Option<&str>,
        context: &str,
        credentials: &Credentials,
    ) -> Result<(DataKey, String)> {
        let recipient = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut nonce = [0u8; 32];
        openssl::rand::rand_bytes(&mut nonce)?;
        let document = attestation::attest(
            &recipient.public_key_to_der()?,
            &Sha256::digest(context.as_bytes()),
            &nonce,
        )?;
        let mut payload = json!({"KeyId":self.config.key_arn,"EncryptionContext":{"cwxmr-domain":context},
            "Recipient":{"KeyEncryptionAlgorithm":"RSAES_OAEP_SHA_256","AttestationDocument":STANDARD.encode(document)}});
        let action = if let Some(blob) = wrapped {
            payload["CiphertextBlob"] = Value::String(blob.to_owned());
            "Decrypt"
        } else {
            payload["KeySpec"] = Value::String("AES_256".into());
            "GenerateDataKey"
        };
        let response = self.request(action, payload, credentials)?;
        ensure!(
            response.get("Plaintext").is_none(),
            "KMS returned plaintext; attested-recipient policy is broken"
        );
        ensure!(
            response["KeyId"].as_str() == Some(&self.config.key_arn),
            "KMS key ARN mismatch"
        );
        let ciphertext = response["CiphertextForRecipient"]
            .as_str()
            .context("KMS recipient ciphertext missing")?;
        let key = decrypt_recipient(&recipient, &STANDARD.decode(ciphertext)?)?;
        let wrapped = match wrapped {
            Some(s) => s.to_owned(),
            None => response["CiphertextBlob"]
                .as_str()
                .context("KMS wrapped key missing")?
                .to_owned(),
        };
        Ok((key, wrapped))
    }
}
fn decrypt_recipient(recipient: &PKey<Private>, ciphertext: &[u8]) -> Result<DataKey> {
    let plaintext = Zeroizing::new(
        CmsContentInfo::from_der(ciphertext)?.decrypt_without_cert_check(recipient)?,
    );
    if plaintext.len() != 32 {
        bail!("KMS data key has unexpected size");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(DataKey(Zeroizing::new(key)))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kms_region_and_arn_are_pinned() {
        assert!(Kms::new(Config {
            region: "../evil".into(),
            key_arn: "x".into(),
            forward_port: 8445
        })
        .is_err());
        assert!(Kms::new(Config {
            region: "us-east-1".into(),
            key_arn: "alias/unsafe".into(),
            forward_port: 8445
        })
        .is_err());
    }
}
