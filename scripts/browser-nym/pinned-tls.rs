// Copyright 2026 - cwXMR contributors
// SPDX-License-Identifier: Apache-2.0
//! Explicit registry-SPKI authentication; never used for ordinary fetch/DoH.
use super::*;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode, Encode};

#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    name: ServerName<'static>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>],
        server_name: &ServerName<'_>, _: &[u8], now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let invalid = || Error::General("enclave TLS identity mismatch".into());
        if server_name != &self.name { return Err(invalid()); }
        let cert = x509_cert::Certificate::from_der(end_entity.as_ref()).map_err(|_| invalid())?;
        let spki = cert.tbs_certificate.subject_public_key_info.to_der().map_err(|_| invalid())?;
        let hash: [u8; 32] = Sha256::digest(spki).into();
        let validity = cert.tbs_certificate.validity;
        if hash != self.pin || now.as_secs() < validity.not_before.to_unix_duration().as_secs()
            || now.as_secs() > validity.not_after.to_unix_duration().as_secs() {
            return Err(invalid());
        }
        // Pin is the trust anchor. Possession is checked separately by rustls below.
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("enclave requires TLS 1.3".into()))
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub(crate) async fn connect_pinned<S>(stream: S, hostname: &str, pin: [u8; 32])
    -> Result<MaybeCloseNotify<futures_rustls::client::TlsStream<S>>, FetchError>
where S: AsyncRead + AsyncWrite + Unpin {
    let name = ServerName::try_from(hostname.to_owned()).map_err(|_| FetchError::Http("invalid TLS name".into()))?;
    TlsConnector::from(pinned_config(name.clone(), pin)?).connect(name, stream).await
        .map(MaybeCloseNotify::new).map_err(FetchError::Io)
}

pub(crate) fn pinned_config(name: ServerName<'static>, pin: [u8; 32]) -> Result<Arc<ClientConfig>, FetchError> {
    let mut provider = rustls_rustcrypto::provider();
    provider.cipher_suites.retain(|suite| matches!(suite.suite(),
        CipherSuite::TLS13_AES_128_GCM_SHA256 | CipherSuite::TLS13_AES_256_GCM_SHA384 |
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256));
    let provider = Arc::new(provider);
    let verifier = Arc::new(PinnedVerifier { pin, name: name.clone(), provider: provider.clone() });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| FetchError::Http("pinned TLS configuration failed".into()))?
        .dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}
