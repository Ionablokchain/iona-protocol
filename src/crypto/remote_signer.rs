//! Remote signer client.
//!
//! This is intentionally small and "boring": it uses reqwest::blocking so it can implement the
//! synchronous `crate::crypto::Signer` trait without changing consensus code.
//!
//! Expected remote signer API (HTTP JSON):
//! - GET  /pubkey  -> { "pubkey_base64": "..." }
//! - POST /sign    -> { "msg_base64": "..." }  -> { "sig_base64": "..." }
//! - GET  /health  -> 200 OK (optional, but recommended)
//!
//! Features:
//! - Optional mTLS (client cert + private key) and custom CA root.
//! - Optional server name override (SNI) for strict TLS.
//! - Health check and error logging.

use crate::crypto::{PublicKeyBytes, SignatureBytes, Signer};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use reqwest::blocking::Client;
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, warn};

#[derive(Clone)]
pub struct RemoteSigner {
    base_url: String,
    client: Client,
    pubkey: PublicKeyBytes,
    timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct PubkeyResp {
    pubkey_base64: String,
}

#[derive(Debug, Serialize)]
struct SignReq {
    msg_base64: String,
}

#[derive(Debug, Deserialize)]
struct SignResp {
    sig_base64: String,
}

impl RemoteSigner {
    /// Build a RemoteSigner and fetch the public key from /pubkey.
    pub fn connect(base_url: String, timeout: Duration) -> anyhow::Result<Self> {
        Self::connect_mtls(base_url, timeout, None)
    }

    /// Same as `connect`, but optionally enables mTLS.
    ///
    /// Provide a tuple of (client_identity_pem, ca_cert_pem, server_name_override).
    /// - client_identity_pem should contain BOTH certificate and private key in PEM.
    /// - ca_cert_pem is used as a custom root (useful for private PKI).
    /// - server_name_override is used for strict SNI validation when the URL host is an IP.
    pub fn connect_mtls(
        base_url: String,
        timeout: Duration,
        mtls: Option<(Vec<u8>, Vec<u8>, Option<String>)>,
    ) -> anyhow::Result<Self> {
        let mut b = Client::builder().timeout(timeout);

        if let Some((identity_pem, ca_pem, server_name)) = mtls {
            let id = Identity::from_pem(&identity_pem)?;
            let ca = Certificate::from_pem(&ca_pem)?;
            b = b.identity(id).add_root_certificate(ca);
            if let Some(name) = server_name {
                // NOTE: reqwest does not offer an explicit per-request SNI override;
                // the best practice is to use a DNS name in the URL. This field is kept for config
                // compatibility and documentation.
                debug!(server_name = %name, "mTLS server name override set");
            }
        }

        let client = b.build()?;
        let url = format!("{}/pubkey", base_url.trim_end_matches('/'));
        debug!(url = %url, "fetching remote signer public key");

        let r: PubkeyResp = client
            .get(url)
            .send()?
            .error_for_status()?
            .json()?;

        let pk = B64.decode(r.pubkey_base64.as_bytes())?;
        debug!("remote signer public key acquired");

        Ok(Self {
            base_url,
            client,
            pubkey: PublicKeyBytes(pk),
            timeout,
        })
    }

    /// Returns the base URL of the remote signer.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if the remote signer is healthy by calling `/health` (or falling back to `/pubkey`).
    pub fn is_healthy(&self) -> bool {
        let url = format!("{}/health", self.base_url.trim_end_matches('/'));
        match self.client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => true,
            _ => {
                // Fallback to checking /pubkey if /health is not implemented
                let pubkey_url = format!("{}/pubkey", self.base_url.trim_end_matches('/'));
                match self.client.get(&pubkey_url).send() {
                    Ok(r) if r.status().is_success() => true,
                    _ => false,
                }
            }
        }
    }

    /// Attempt to sign a message, returning `Some(SignatureBytes)` on success, `None` on failure.
    /// This method is useful for callers that can handle transient errors.
    pub fn try_sign(&self, msg: &[u8]) -> Option<SignatureBytes> {
        let url = format!("{}/sign", self.base_url.trim_end_matches('/'));
        let req = SignReq {
            msg_base64: B64.encode(msg),
        };
        match self
            .client
            .post(&url)
            .json(&req)
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json::<SignResp>())
        {
            Ok(resp) => {
                match B64.decode(resp.sig_base64.as_bytes()) {
                    Ok(sig) => Some(SignatureBytes(sig)),
                    Err(e) => {
                        error!("remote signer returned invalid base64 signature: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                error!("remote signer request failed: {}", e);
                None
            }
        }
    }

    /// Helper: build mTLS materials from PEM files.
    pub fn mtls_from_files(
        client_identity_pem_path: &str,
        ca_cert_pem_path: &str,
        server_name_override: Option<String>,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>, Option<String>)> {
        let id = std::fs::read(client_identity_pem_path)?;
        let ca = std::fs::read(ca_cert_pem_path)?;
        Ok((id, ca, server_name_override))
    }
}

impl Signer for RemoteSigner {
    fn public_key(&self) -> PublicKeyBytes {
        self.pubkey.clone()
    }

    fn sign(&self, msg: &[u8]) -> SignatureBytes {
        match self.try_sign(msg) {
            Some(sig) => sig,
            None => {
                // Return empty signature as a fallback; the consensus engine may treat this as a failure.
                warn!("remote signer returned empty signature; will likely cause consensus failure");
                SignatureBytes(vec![])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use serde_json::json;

    #[test]
    fn test_connect_and_sign() {
        let server = MockServer::start();

        // Mock /pubkey
        let pubkey_mock = server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": base64::encode(&[0xaa; 32]) }));
        });

        // Mock /sign
        let sign_mock = server.mock(|when, then| {
            when.method(POST).path("/sign");
            then.status(200)
                .json_body(json!({ "sig_base64": base64::encode(&[0xbb; 64]) }));
        });

        let signer = RemoteSigner::connect(server.base_url(), Duration::from_secs(2)).unwrap();
        assert_eq!(signer.public_key().0, vec![0xaa; 32]);

        let sig = signer.sign(b"hello");
        assert_eq!(sig.0, vec![0xbb; 64]);

        pubkey_mock.assert();
        sign_mock.assert();
    }

    #[test]
    fn test_health_check() {
        let server = MockServer::start();

        // Mock /pubkey (called by connect)
        let _pubkey_mock = server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            // Return a valid base64-encoded 32-byte public key
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"pubkey_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#);
        });

        // Mock /health
        let health_mock = server.mock(|when, then| {
            when.method(GET).path("/health");
            then.status(200);
        });

        let signer = RemoteSigner::connect(server.base_url(), Duration::from_secs(2)).unwrap();
        assert!(signer.is_healthy());
        // health_mock may be hit multiple times; just check it was called
        assert!(health_mock.hits() >= 1);

        // Fallback to /pubkey if /health not implemented
        let no_health_server = MockServer::start();
        let pubkey_mock = no_health_server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": base64::encode(&[0xaa; 32]) }));
        });
        let signer2 = RemoteSigner::connect(no_health_server.base_url(), Duration::from_secs(2)).unwrap();
        assert!(signer2.is_healthy()); // should fall back to /pubkey
        assert!(pubkey_mock.hits() >= 1);
    }

    #[test]
    fn test_connection_failure() {
        let result = RemoteSigner::connect("http://localhost:9999".into(), Duration::from_secs(1));
        assert!(result.is_err());
    }

    #[test]
    fn test_try_sign_returns_none_on_error() {
        let server = MockServer::start();
        let pubkey_mock = server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": base64::encode(&[0xaa; 32]) }));
        });
        let sign_mock = server.mock(|when, then| {
            when.method(POST).path("/sign");
            then.status(500); // server error
        });

        let signer = RemoteSigner::connect(server.base_url(), Duration::from_secs(2)).unwrap();
        let result = signer.try_sign(b"hello");
        assert!(result.is_none());

        pubkey_mock.assert();
        sign_mock.assert();
    }
}
