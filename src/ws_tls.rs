use std::{fmt, sync::Arc};

use rustls23::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use tokio_tungstenite::Connector;

pub fn insecure_connector(accept_invalid: bool) -> Option<Connector> {
    accept_invalid.then(|| Connector::Rustls(client_config(true)))
}

/// A TLS client for an upstream connection: certificates are checked against
/// the public roots unless the session accepts invalid ones, as HTTP does.
pub(crate) fn client_config(accept_invalid: bool) -> Arc<rustls23::ClientConfig> {
    let config = if accept_invalid {
        let provider = Arc::new(rustls23::crypto::ring::default_provider());
        rustls23::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptInvalidServerCerts { provider }))
            .with_no_client_auth()
    } else {
        let roots =
            rustls23::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls23::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    Arc::new(config)
}

struct AcceptInvalidServerCerts {
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for AcceptInvalidServerCerts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcceptInvalidServerCerts")
    }
}

impl ServerCertVerifier for AcceptInvalidServerCerts {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls23::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls23::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
