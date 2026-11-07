#![allow(dead_code)]
use std::sync::Arc;
use futures::io::{AsyncRead, AsyncWrite};
use futures_rustls::TlsConnector;
use rustls::pki_types::ServerName;
use rustls::{CipherSuite, ClientConfig};
#[derive(Debug)]
enum FetchError { Http(String), Io(std::io::Error) }
struct MaybeCloseNotify<S>(S);
impl<S> MaybeCloseNotify<S> { fn new(stream: S) -> Self { Self(stream) } }
// The exact verifier module copied into Nym by build.sh, not a test implementation.
#[path = "../../pinned-tls.rs"]
mod pinned;

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::PublicKeyData;
    use rustls::{ClientConnection, ServerConfig, ServerConnection, SignatureScheme, SignatureAlgorithm};
    use rustls::sign::{CertifiedKey, SigningKey, Signer};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use sha2::{Digest, Sha256};
    use std::io::Cursor;

    #[derive(Debug)]
    struct InvalidSignature;
    impl SigningKey for InvalidSignature {
        fn choose_scheme(&self, _: &[SignatureScheme]) -> Option<Box<dyn Signer>> { Some(Box::new(Self)) }
        fn algorithm(&self) -> SignatureAlgorithm { SignatureAlgorithm::ECDSA }
    }
    impl Signer for InvalidSignature {
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, rustls::Error> { Ok(vec![0;64]) }
        fn scheme(&self) -> SignatureScheme { SignatureScheme::ECDSA_NISTP256_SHA256 }
    }
    #[derive(Debug)]
    struct Certificate(Arc<CertifiedKey>);
    impl rustls::server::ResolvesServerCert for Certificate {
        fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> { Some(self.0.clone()) }
    }
    fn handshake(wrong_pin: bool, bad_signature: bool, expired: bool) -> Result<(), rustls::Error> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["unrelated.invalid".into()]).unwrap();
        // Deliberately no matching SAN: the registry SPKI, not public CA/DNS, authenticates this peer.
        if expired { params.not_after = rcgen::date_time_ymd(2020,1,1); params.not_before = rcgen::date_time_ymd(2019,1,1); }
        let cert = params.self_signed(&key).unwrap();
        let mut pin: [u8;32] = Sha256::digest(key.subject_public_key_info()).into();
        if wrong_pin { pin[0] ^= 1; }
        let name = ServerName::try_from("enclave.example".to_owned()).unwrap();
        let mut client = ClientConnection::new(pinned::pinned_config(name.clone(),pin).unwrap(),name).unwrap();
        let provider = Arc::new(rustls_rustcrypto::provider());
        let signer = if bad_signature { Arc::new(InvalidSignature) as Arc<dyn SigningKey> }
            else { provider.key_provider.load_private_key(PrivatePkcs8KeyDer::from(key.serialize_der()).into()).unwrap() };
        let resolver = Certificate(Arc::new(CertifiedKey::new(vec![cert.der().clone()], signer)));
        let config = ServerConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .with_no_client_auth().with_cert_resolver(Arc::new(resolver));
        let mut server = ServerConnection::new(Arc::new(config)).unwrap();
        for _ in 0..10 {
            let mut bytes=Vec::new(); client.write_tls(&mut bytes).unwrap();
            server.read_tls(&mut Cursor::new(bytes)).unwrap(); server.process_new_packets()?;
            let mut bytes=Vec::new(); server.write_tls(&mut bytes).unwrap();
            client.read_tls(&mut Cursor::new(bytes)).unwrap(); client.process_new_packets()?;
            if !client.is_handshaking() && !server.is_handshaking() { return Ok(()); }
        }
        panic!("TLS handshake did not complete")
    }
    #[test] fn matching_registry_key_completes_real_tls13_handshake() { assert!(handshake(false,false,false).is_ok()); }
    #[test] fn wrong_spki_fails_before_http() { assert!(handshake(true,false,false).is_err()); }
    #[test] fn copied_pinned_certificate_without_private_key_fails() { assert!(handshake(false,true,false).is_err()); }
    #[test] fn expired_certificate_fails() { assert!(handshake(false,false,true).is_err()); }
}
