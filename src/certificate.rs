use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Days, Utc};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{Certificate as RustlsCertificate, PrivateKey, ServerConfig};
use serde::{Deserialize, Serialize};
use tokio_rustls::TlsAcceptor;

const CERTIFICATE_DIR: &str = "certificates";
const ROOT_CERT_PEM: &str = "sniper-root-ca.pem";
const ROOT_CERT_DER: &str = "sniper-root-ca.der";
const ROOT_KEY_PEM: &str = "sniper-root-ca.key";
const ROOT_METADATA: &str = "sniper-root-ca.json";
pub const SPECIAL_HOST: &str = "sniper";

pub struct CertificateAuthority {
    root_cert_pem: String,
    root_cert_der: Vec<u8>,
    root_key_pem: String,
    export: CertificateExport,
    special_host_tls: Arc<ServerConfig>,
    host_tls_cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertificateExport {
    pub common_name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub pem_path: String,
    pub der_path: String,
    pub pem_download_path: String,
    pub der_download_path: String,
    pub special_host_https: String,
    pub special_host_http: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CertificateMetadata {
    common_name: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

struct CertificateFiles {
    cert_dir: PathBuf,
    cert_pem_path: PathBuf,
    cert_der_path: PathBuf,
    key_pem_path: PathBuf,
    metadata_path: PathBuf,
}

struct LoadedCaMaterial {
    root_cert_pem: String,
    root_cert_der: Vec<u8>,
    root_key_pem: String,
    metadata: CertificateMetadata,
    files: CertificateFiles,
}

impl CertificateAuthority {
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let files = certificate_files(data_dir);
        fs::create_dir_all(&files.cert_dir).with_context(|| {
            format!(
                "failed to create certificate directory {}",
                files.cert_dir.display()
            )
        })?;

        let material = if files.cert_pem_path.exists()
            && files.cert_der_path.exists()
            && files.key_pem_path.exists()
        {
            load_existing(files)?
        } else {
            generate_new(files)?
        };

        Self::from_material(material)
    }

    pub fn export(&self) -> &CertificateExport {
        &self.export
    }

    pub fn root_pem_bytes(&self) -> &[u8] {
        self.root_cert_pem.as_bytes()
    }

    pub fn root_der_bytes(&self) -> &[u8] {
        &self.root_cert_der
    }

    pub fn tls_acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.special_host_tls.clone())
    }

    pub fn tls_acceptor_for_host(&self, host: &str) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor::from(self.server_config_for_host(host)?))
    }

    fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>> {
        if host.eq_ignore_ascii_case(SPECIAL_HOST) {
            return Ok(self.special_host_tls.clone());
        }

        if let Some(config) = self
            .host_tls_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("host TLS cache lock poisoned"))?
            .get(host)
            .cloned()
        {
            return Ok(config);
        }

        let config = build_host_tls_config(
            host,
            &self.root_cert_pem,
            &self.root_key_pem,
            &self.root_cert_der,
            self.export.expires_at,
        )?;

        self.host_tls_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("host TLS cache lock poisoned"))?
            .insert(host.to_string(), config.clone());

        Ok(config)
    }
}

pub fn default_data_dir() -> PathBuf {
    if let Some(value) = env::var_os("SNIPER_DATA_DIR") {
        return PathBuf::from(value);
    }

    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join(".sniper");
    }

    PathBuf::from(".sniper")
}

fn certificate_files(data_dir: &Path) -> CertificateFiles {
    let cert_dir = data_dir.join(CERTIFICATE_DIR);
    CertificateFiles {
        cert_pem_path: cert_dir.join(ROOT_CERT_PEM),
        cert_der_path: cert_dir.join(ROOT_CERT_DER),
        key_pem_path: cert_dir.join(ROOT_KEY_PEM),
        metadata_path: cert_dir.join(ROOT_METADATA),
        cert_dir,
    }
}

fn load_existing(files: CertificateFiles) -> Result<LoadedCaMaterial> {
    let root_cert_pem = fs::read_to_string(&files.cert_pem_path)
        .with_context(|| format!("failed to read {}", files.cert_pem_path.display()))?;
    let root_cert_der = fs::read(&files.cert_der_path)
        .with_context(|| format!("failed to read {}", files.cert_der_path.display()))?;
    let root_key_pem = fs::read_to_string(&files.key_pem_path)
        .with_context(|| format!("failed to read {}", files.key_pem_path.display()))?;
    let metadata = if files.metadata_path.exists() {
        serde_json::from_slice::<CertificateMetadata>(
            &fs::read(&files.metadata_path)
                .with_context(|| format!("failed to read {}", files.metadata_path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", files.metadata_path.display()))?
    } else {
        let now = Utc::now();
        CertificateMetadata {
            common_name: "Sniper Root CA".to_string(),
            created_at: now,
            expires_at: now,
        }
    };

    Ok(LoadedCaMaterial {
        root_cert_pem,
        root_cert_der,
        root_key_pem,
        metadata,
        files,
    })
}

fn generate_new(files: CertificateFiles) -> Result<LoadedCaMaterial> {
    let created_at = Utc::now();
    let expires_at = created_at
        .checked_add_days(Days::new(3650))
        .context("failed to calculate certificate expiration")?;

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.not_before = rcgen::date_time_ymd(
        created_at.year(),
        created_at.month() as u8,
        created_at.day() as u8,
    );
    params.not_after = rcgen::date_time_ymd(
        expires_at.year(),
        expires_at.month() as u8,
        expires_at.day() as u8,
    );

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::OrganizationName, "Sniper");
    distinguished_name.push(DnType::CommonName, "Sniper Root CA");
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];

    let key_pair = KeyPair::generate().context("failed to generate root CA key pair")?;
    let certificate = params
        .self_signed(&key_pair)
        .context("failed to self-sign root CA certificate")?;
    let root_cert_pem = certificate.pem();
    let root_cert_der = certificate.der().as_ref().to_vec();
    let root_key_pem = key_pair.serialize_pem();
    let metadata = CertificateMetadata {
        common_name: "Sniper Root CA".to_string(),
        created_at,
        expires_at,
    };

    fs::write(&files.cert_pem_path, &root_cert_pem)
        .with_context(|| format!("failed to write {}", files.cert_pem_path.display()))?;
    fs::write(&files.cert_der_path, &root_cert_der)
        .with_context(|| format!("failed to write {}", files.cert_der_path.display()))?;
    fs::write(&files.key_pem_path, &root_key_pem)
        .with_context(|| format!("failed to write {}", files.key_pem_path.display()))?;
    fs::write(
        &files.metadata_path,
        serde_json::to_vec_pretty(&metadata).context("failed to serialize certificate metadata")?,
    )
    .with_context(|| format!("failed to write {}", files.metadata_path.display()))?;

    Ok(LoadedCaMaterial {
        root_cert_pem,
        root_cert_der,
        root_key_pem,
        metadata,
        files,
    })
}

impl CertificateAuthority {
    fn from_material(material: LoadedCaMaterial) -> Result<Self> {
        let ca_params = CertificateParams::from_ca_cert_pem(&material.root_cert_pem)
            .context("failed to load root CA certificate parameters")?;
        let ca_key_pair =
            KeyPair::from_pem(&material.root_key_pem).context("failed to load root CA key pair")?;
        let issuer_certificate = ca_params
            .self_signed(&ca_key_pair)
            .context("failed to rebuild issuer certificate for signing")?;
        let special_host_tls = build_special_host_tls_config(
            &issuer_certificate,
            &ca_key_pair,
            &material.root_cert_der,
            material.metadata.expires_at,
        )?;

        Ok(Self {
            root_cert_pem: material.root_cert_pem,
            root_cert_der: material.root_cert_der,
            root_key_pem: material.root_key_pem,
            export: CertificateExport {
                common_name: material.metadata.common_name,
                created_at: material.metadata.created_at,
                expires_at: material.metadata.expires_at,
                pem_path: material.files.cert_pem_path.display().to_string(),
                der_path: material.files.cert_der_path.display().to_string(),
                pem_download_path: "/api/certificates/root.pem".to_string(),
                der_download_path: "/api/certificates/root.der".to_string(),
                special_host_https: format!("https://{SPECIAL_HOST}"),
                special_host_http: format!("http://{SPECIAL_HOST}"),
            },
            special_host_tls,
            host_tls_cache: Mutex::new(HashMap::new()),
        })
    }
}

fn build_special_host_tls_config(
    issuer_certificate: &Certificate,
    issuer_key: &KeyPair,
    root_cert_der: &[u8],
    root_expires_at: DateTime<Utc>,
) -> Result<Arc<ServerConfig>> {
    let now = Utc::now();
    let leaf_expires_at = now
        .checked_add_days(Days::new(825))
        .map(|date| date.min(root_expires_at))
        .unwrap_or(root_expires_at);

    let mut params = CertificateParams::new(vec![SPECIAL_HOST.to_string()])?;
    params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
    params.not_after = rcgen::date_time_ymd(
        leaf_expires_at.year(),
        leaf_expires_at.month() as u8,
        leaf_expires_at.day() as u8,
    );

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::OrganizationName, "Sniper");
    distinguished_name.push(DnType::CommonName, SPECIAL_HOST);
    params.distinguished_name = distinguished_name;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let leaf_key = KeyPair::generate().context("failed to generate special host key pair")?;
    let leaf_certificate = params
        .signed_by(&leaf_key, issuer_certificate, issuer_key)
        .context("failed to sign special host certificate")?;

    let mut server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                RustlsCertificate(leaf_certificate.der().as_ref().to_vec()),
                RustlsCertificate(root_cert_der.to_vec()),
            ],
            PrivateKey(leaf_key.serialize_der()),
        )
        .context("failed to build special host TLS config")?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(server_config))
}

fn build_host_tls_config(
    host: &str,
    root_cert_pem: &str,
    root_key_pem: &str,
    root_cert_der: &[u8],
    root_expires_at: DateTime<Utc>,
) -> Result<Arc<ServerConfig>> {
    let ca_params = CertificateParams::from_ca_cert_pem(root_cert_pem)
        .context("failed to load root CA certificate parameters")?;
    let ca_key_pair = KeyPair::from_pem(root_key_pem).context("failed to load root CA key pair")?;
    let issuer_certificate = ca_params
        .self_signed(&ca_key_pair)
        .context("failed to rebuild issuer certificate for signing")?;

    build_signed_host_tls_config(
        host,
        &issuer_certificate,
        &ca_key_pair,
        root_cert_der,
        root_expires_at,
    )
}

fn build_signed_host_tls_config(
    host: &str,
    issuer_certificate: &Certificate,
    issuer_key: &KeyPair,
    root_cert_der: &[u8],
    root_expires_at: DateTime<Utc>,
) -> Result<Arc<ServerConfig>> {
    let now = Utc::now();
    let leaf_expires_at = now
        .checked_add_days(Days::new(825))
        .map(|date| date.min(root_expires_at))
        .unwrap_or(root_expires_at);

    let mut params = CertificateParams::new(vec![host.to_string()])?;
    params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
    params.not_after = rcgen::date_time_ymd(
        leaf_expires_at.year(),
        leaf_expires_at.month() as u8,
        leaf_expires_at.day() as u8,
    );

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::OrganizationName, "Sniper");
    distinguished_name.push(DnType::CommonName, host);
    params.distinguished_name = distinguished_name;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let leaf_key = KeyPair::generate().context("failed to generate host MITM key pair")?;
    let leaf_certificate = params
        .signed_by(&leaf_key, issuer_certificate, issuer_key)
        .context("failed to sign host MITM certificate")?;

    let mut server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                RustlsCertificate(leaf_certificate.der().as_ref().to_vec()),
                RustlsCertificate(root_cert_der.to_vec()),
            ],
            PrivateKey(leaf_key.serialize_der()),
        )
        .context("failed to build host MITM TLS config")?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(server_config))
}
