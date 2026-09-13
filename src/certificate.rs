use std::{
    collections::HashMap,
    env,
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Datelike, Days, Utc};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{Certificate as RustlsCertificate, PrivateKey, ServerConfig};
use serde::{Deserialize, Serialize};
use tokio_rustls::TlsAcceptor;
use tracing::warn;
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

const CERTIFICATE_DIR: &str = "certificates";
const ROOT_CERT_PEM: &str = "sniper-root-ca.pem";
const ROOT_CERT_DER: &str = "sniper-root-ca.der";
const ROOT_KEY_PEM: &str = "sniper-root-ca.key";
const ROOT_METADATA: &str = "sniper-root-ca.json";
pub const SPECIAL_HOST: &str = "sniper";
const MAX_HOST_TLS_CACHE_ENTRIES: usize = 1024;

pub struct CertificateAuthority {
    root_cert_pem: String,
    root_cert_der: Vec<u8>,
    root_key_pem: String,
    export: CertificateExport,
    special_host_tls: Mutex<CachedTlsConfig>,
    host_tls_cache: Mutex<HashMap<String, CachedTlsConfig>>,
}

#[derive(Clone)]
struct CachedTlsConfig {
    config: Arc<ServerConfig>,
    expires_at: DateTime<Utc>,
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
        ensure_certificate_directory(&files.cert_dir)?;
        tighten_private_key_permissions(&files.key_pem_path)?;

        let has_pem = files.cert_pem_path.exists();
        let has_der = files.cert_der_path.exists();
        let has_key = files.key_pem_path.exists();
        let material = if has_pem && has_key {
            load_existing(files)?
        } else if !has_pem && !has_der && !has_key {
            generate_new(files)?
        } else {
            bail!(
                "incomplete root CA material in {}; missing: {}",
                files.cert_dir.display(),
                missing_root_ca_files(has_pem, has_der, has_key).join(", ")
            );
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

    pub fn tls_acceptor(&self) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor::from(self.special_host_server_config()?))
    }

    pub fn tls_acceptor_for_host(&self, host: &str) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor::from(self.server_config_for_host(host)?))
    }

    fn special_host_server_config(&self) -> Result<Arc<ServerConfig>> {
        let now = Utc::now();
        if let Some(config) = self
            .special_host_tls
            .lock()
            .map_err(|_| anyhow::anyhow!("special host TLS cache lock poisoned"))?
            .fresh_config(now)
        {
            return Ok(config);
        }

        let config = build_host_tls_config(
            SPECIAL_HOST,
            &self.root_cert_pem,
            &self.root_key_pem,
            &self.root_cert_der,
            self.export.expires_at,
        )?;
        let mut cached = self
            .special_host_tls
            .lock()
            .map_err(|_| anyhow::anyhow!("special host TLS cache lock poisoned"))?;
        *cached = config.clone();
        Ok(config.config)
    }

    fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let normalized_host = normalize_certificate_host(host);
        if normalized_host.eq_ignore_ascii_case(SPECIAL_HOST) {
            return self.special_host_server_config();
        }

        let now = Utc::now();
        if let Some(config) = self
            .host_tls_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("host TLS cache lock poisoned"))?
            .get(&normalized_host)
            .and_then(|cached| cached.fresh_config(now))
        {
            return Ok(config);
        }

        let config = build_host_tls_config(
            &normalized_host,
            &self.root_cert_pem,
            &self.root_key_pem,
            &self.root_cert_der,
            self.export.expires_at,
        )?;

        let mut cache = self
            .host_tls_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("host TLS cache lock poisoned"))?;
        reserve_host_tls_cache_slot(&mut cache, now, MAX_HOST_TLS_CACHE_ENTRIES);
        cache.insert(normalized_host, config.clone());

        Ok(config.config)
    }
}

impl CachedTlsConfig {
    fn fresh_config(&self, now: DateTime<Utc>) -> Option<Arc<ServerConfig>> {
        is_tls_cache_fresh(self.expires_at, now).then(|| self.config.clone())
    }
}

fn normalize_certificate_host(host: &str) -> String {
    let trimmed = host.trim();
    let without_ipv6_brackets = trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(trimmed);

    if let Ok(ip) = without_ipv6_brackets.parse::<IpAddr>() {
        ip.to_string()
    } else {
        without_ipv6_brackets.to_ascii_lowercase()
    }
}

pub fn default_data_dir() -> PathBuf {
    if let Some(value) = env::var_os("SNIPER_DATA_DIR").filter(|value| !value.is_empty()) {
        return PathBuf::from(value);
    }

    crate::platform::default_data_dir()
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

fn ensure_certificate_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create certificate directory {}", path.display()))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to secure certificate directory {}", path.display()))?;
    Ok(())
}

fn tighten_private_key_permissions(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    if _path.exists() {
        fs::set_permissions(_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to secure private key {}", _path.display()))?;
    }
    Ok(())
}

fn write_private_file(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(contents.as_ref())
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    tighten_private_key_permissions(path)?;
    Ok(())
}

fn write_public_file(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(contents.as_ref())
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    Ok(())
}

fn missing_root_ca_files(has_pem: bool, has_der: bool, has_key: bool) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !has_pem {
        missing.push(ROOT_CERT_PEM);
    }
    if !has_der {
        missing.push(ROOT_CERT_DER);
    }
    if !has_key {
        missing.push(ROOT_KEY_PEM);
    }
    missing
}

fn load_existing(files: CertificateFiles) -> Result<LoadedCaMaterial> {
    let root_cert_pem = fs::read_to_string(&files.cert_pem_path)
        .with_context(|| format!("failed to read {}", files.cert_pem_path.display()))?;
    let root_cert_der = if files.cert_der_path.exists() {
        Some(
            fs::read(&files.cert_der_path)
                .with_context(|| format!("failed to read {}", files.cert_der_path.display()))?,
        )
    } else {
        None
    };
    let root_key_pem = fs::read_to_string(&files.key_pem_path)
        .with_context(|| format!("failed to read {}", files.key_pem_path.display()))?;
    let root_cert_der =
        validate_or_repair_root_material(&files, &root_cert_pem, root_cert_der, &root_key_pem)?;
    let ca_params = CertificateParams::from_ca_cert_pem(&root_cert_pem)
        .context("failed to load existing root CA certificate parameters")?;
    let certificate_metadata = certificate_metadata_from_params(&ca_params)?;
    let mut metadata = if files.metadata_path.exists() {
        let mut metadata = serde_json::from_slice::<CertificateMetadata>(
            &fs::read(&files.metadata_path)
                .with_context(|| format!("failed to read {}", files.metadata_path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", files.metadata_path.display()))?;
        metadata.created_at = certificate_metadata.created_at;
        metadata.expires_at = certificate_metadata.expires_at;
        metadata
    } else {
        certificate_metadata
    };
    if metadata.common_name.trim().is_empty() {
        metadata.common_name = "Sniper Root CA".to_string();
    }
    if let Err(error) = fs::write(
        &files.metadata_path,
        serde_json::to_vec_pretty(&metadata).context("failed to serialize certificate metadata")?,
    ) {
        warn!(
            ?error,
            path = %files.metadata_path.display(),
            "failed to repair root CA metadata"
        );
    }

    Ok(LoadedCaMaterial {
        root_cert_pem,
        root_cert_der,
        root_key_pem,
        metadata,
        files,
    })
}

fn validate_or_repair_root_material(
    files: &CertificateFiles,
    root_cert_pem: &str,
    root_cert_der: Option<Vec<u8>>,
    root_key_pem: &str,
) -> Result<Vec<u8>> {
    let (remaining, pem) = parse_x509_pem(root_cert_pem.as_bytes())
        .map_err(|_| anyhow::anyhow!("failed to parse existing root CA PEM certificate"))?;
    if pem.label != "CERTIFICATE" {
        bail!("existing root CA PEM block is not a certificate");
    }
    if !remaining.iter().all(|byte| byte.is_ascii_whitespace()) {
        bail!("existing root CA PEM contains trailing non-whitespace data");
    }

    let (_, certificate) = parse_x509_certificate(&pem.contents)
        .map_err(|_| anyhow::anyhow!("failed to parse existing root CA certificate"))?;
    let root_key_pair =
        KeyPair::from_pem(root_key_pem).context("failed to load existing root CA key pair")?;
    let key_public_der = root_key_pair.public_key_der();
    if certificate.tbs_certificate.subject_pki.raw != key_public_der.as_slice() {
        bail!("existing root CA certificate and private key do not match");
    }
    let basic_constraints = certificate
        .basic_constraints()
        .map_err(|_| anyhow::anyhow!("failed to parse existing root CA BasicConstraints"))?
        .ok_or_else(|| {
            anyhow::anyhow!("existing root CA certificate is missing BasicConstraints")
        })?;
    if !basic_constraints.value.ca {
        bail!("existing root CA certificate is not marked as a CA");
    }
    let key_usage = certificate
        .key_usage()
        .map_err(|_| anyhow::anyhow!("failed to parse existing root CA KeyUsage"))?
        .ok_or_else(|| anyhow::anyhow!("existing root CA certificate is missing KeyUsage"))?;
    if !key_usage.value.key_cert_sign() {
        bail!("existing root CA certificate does not permit keyCertSign");
    }

    let needs_der_repair = root_cert_der
        .as_ref()
        .map(|der| der != &pem.contents)
        .unwrap_or(true);
    if needs_der_repair {
        write_public_file(&files.cert_der_path, &pem.contents)
            .with_context(|| format!("failed to repair {}", files.cert_der_path.display()))?;
    }

    Ok(pem.contents)
}

fn certificate_metadata_from_params(params: &CertificateParams) -> Result<CertificateMetadata> {
    let created_at = DateTime::<Utc>::from_timestamp(params.not_before.unix_timestamp(), 0)
        .context("failed to convert root CA not_before timestamp")?;
    let expires_at = DateTime::<Utc>::from_timestamp(params.not_after.unix_timestamp(), 0)
        .context("failed to convert root CA not_after timestamp")?;
    Ok(CertificateMetadata {
        common_name: "Sniper Root CA".to_string(),
        created_at,
        expires_at,
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
    write_private_file(&files.key_pem_path, &root_key_pem)?;
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
            special_host_tls: Mutex::new(special_host_tls),
            host_tls_cache: Mutex::new(HashMap::new()),
        })
    }
}

fn is_tls_cache_fresh(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    let refresh_threshold = now.checked_add_days(Days::new(1)).unwrap_or(now);
    expires_at > refresh_threshold
}

fn reserve_host_tls_cache_slot(
    cache: &mut HashMap<String, CachedTlsConfig>,
    now: DateTime<Utc>,
    max_entries: usize,
) {
    if max_entries == 0 {
        cache.clear();
        return;
    }

    cache.retain(|_, cached| is_tls_cache_fresh(cached.expires_at, now));
    while cache.len() >= max_entries {
        let Some(host) = cache
            .iter()
            .min_by_key(|(_, cached)| cached.expires_at)
            .map(|(host, _)| host.clone())
        else {
            break;
        };
        cache.remove(&host);
    }
}

fn leaf_expiration(root_expires_at: DateTime<Utc>, now: DateTime<Utc>) -> Result<DateTime<Utc>> {
    if !is_tls_cache_fresh(root_expires_at, now) {
        bail!("root CA expires too soon to issue a fresh leaf certificate");
    }
    let desired_expires_at = now
        .checked_add_days(Days::new(825))
        .map(|date| date.min(root_expires_at))
        .unwrap_or(root_expires_at);
    let not_after = rcgen::date_time_ymd(
        desired_expires_at.year(),
        desired_expires_at.month() as u8,
        desired_expires_at.day() as u8,
    );
    DateTime::<Utc>::from_timestamp(not_after.unix_timestamp(), 0)
        .context("failed to convert leaf certificate expiration timestamp")
}

fn build_special_host_tls_config(
    issuer_certificate: &Certificate,
    issuer_key: &KeyPair,
    root_cert_der: &[u8],
    root_expires_at: DateTime<Utc>,
) -> Result<CachedTlsConfig> {
    let now = Utc::now();
    let leaf_expires_at = leaf_expiration(root_expires_at, now)?;

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
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(CachedTlsConfig {
        config: Arc::new(server_config),
        expires_at: leaf_expires_at,
    })
}

fn build_host_tls_config(
    host: &str,
    root_cert_pem: &str,
    root_key_pem: &str,
    root_cert_der: &[u8],
    root_expires_at: DateTime<Utc>,
) -> Result<CachedTlsConfig> {
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
) -> Result<CachedTlsConfig> {
    let now = Utc::now();
    let leaf_expires_at = leaf_expiration(root_expires_at, now)?;

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
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(CachedTlsConfig {
        config: Arc::new(server_config),
        expires_at: leaf_expires_at,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        certificate_files, default_data_dir, normalize_certificate_host, CertificateAuthority,
    };
    use std::{
        ffi::OsString,
        fs,
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set<K: Into<OsString>>(key: &'static str, value: K) -> Self {
            let guard = Self {
                key,
                previous: std::env::var_os(key),
            };
            std::env::set_var(key, value.into());
            guard
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn temp_data_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("sniper-cert-test-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn default_data_dir_ignores_empty_sniper_data_dir_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _data_dir_guard = EnvVarGuard::set("SNIPER_DATA_DIR", "");

        assert!(!default_data_dir().as_os_str().is_empty());
    }

    #[test]
    fn root_ca_private_key_is_created_private() {
        let data_dir = temp_data_dir();
        let authority =
            CertificateAuthority::load_or_create(&data_dir).expect("certificate should load");
        let files = certificate_files(&data_dir);

        assert!(authority.export().pem_path.ends_with("sniper-root-ca.pem"));
        assert_eq!(
            fs::metadata(&files.cert_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&files.key_pem_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn existing_root_ca_private_key_permissions_are_tightened() {
        let data_dir = temp_data_dir();
        CertificateAuthority::load_or_create(&data_dir).expect("certificate should be generated");
        let files = certificate_files(&data_dir);
        fs::set_permissions(&files.cert_dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&files.key_pem_path, fs::Permissions::from_mode(0o644)).unwrap();

        CertificateAuthority::load_or_create(&data_dir).expect("certificate should reload");

        assert_eq!(
            fs::metadata(&files.cert_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&files.key_pem_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn missing_root_ca_metadata_is_repaired_from_certificate_validity() {
        let data_dir = temp_data_dir();
        CertificateAuthority::load_or_create(&data_dir).expect("certificate should be generated");
        let files = certificate_files(&data_dir);
        fs::remove_file(&files.metadata_path).unwrap();

        let authority =
            CertificateAuthority::load_or_create(&data_dir).expect("certificate should reload");

        assert!(authority.export().expires_at > chrono::Utc::now());
        assert!(files.metadata_path.exists());

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn missing_root_ca_der_is_repaired_from_pem_without_rotating_root() {
        let data_dir = temp_data_dir();
        let authority =
            CertificateAuthority::load_or_create(&data_dir).expect("certificate should generate");
        let files = certificate_files(&data_dir);
        let original_der = authority.root_der_bytes().to_vec();
        fs::remove_file(&files.cert_der_path).unwrap();

        let reloaded =
            CertificateAuthority::load_or_create(&data_dir).expect("certificate should reload");

        assert_eq!(reloaded.root_der_bytes(), original_der.as_slice());
        assert_eq!(fs::read(&files.cert_der_path).unwrap(), original_der);

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn stale_root_ca_der_is_repaired_from_pem_without_rotating_root() {
        let data_dir = temp_data_dir();
        let other_data_dir = temp_data_dir();
        let authority =
            CertificateAuthority::load_or_create(&data_dir).expect("certificate should generate");
        CertificateAuthority::load_or_create(&other_data_dir).expect("other cert should generate");
        let files = certificate_files(&data_dir);
        let other_files = certificate_files(&other_data_dir);
        let original_der = authority.root_der_bytes().to_vec();
        fs::copy(&other_files.cert_der_path, &files.cert_der_path).unwrap();

        let reloaded =
            CertificateAuthority::load_or_create(&data_dir).expect("certificate should reload");

        assert_eq!(reloaded.root_der_bytes(), original_der.as_slice());
        assert_eq!(fs::read(&files.cert_der_path).unwrap(), original_der);

        let _ = fs::remove_dir_all(&data_dir);
        let _ = fs::remove_dir_all(&other_data_dir);
    }

    #[test]
    fn mismatched_root_ca_private_key_is_rejected() {
        let data_dir = temp_data_dir();
        let other_data_dir = temp_data_dir();
        CertificateAuthority::load_or_create(&data_dir).expect("certificate should generate");
        CertificateAuthority::load_or_create(&other_data_dir).expect("other cert should generate");
        let files = certificate_files(&data_dir);
        let other_files = certificate_files(&other_data_dir);
        fs::copy(&other_files.key_pem_path, &files.key_pem_path).unwrap();

        let error = match CertificateAuthority::load_or_create(&data_dir) {
            Ok(_) => panic!("mismatched private key should fail"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("certificate and private key do not match"));

        let _ = fs::remove_dir_all(&data_dir);
        let _ = fs::remove_dir_all(&other_data_dir);
    }

    #[test]
    fn existing_root_ca_material_must_be_ca() {
        let data_dir = temp_data_dir();
        CertificateAuthority::load_or_create(&data_dir).expect("certificate should generate");
        let files = certificate_files(&data_dir);
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["not-a-ca.local".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::NoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let certificate = params.self_signed(&key_pair).unwrap();
        fs::write(&files.cert_pem_path, certificate.pem()).unwrap();
        fs::write(&files.cert_der_path, certificate.der().as_ref()).unwrap();
        fs::write(&files.key_pem_path, key_pair.serialize_pem()).unwrap();

        let error = match CertificateAuthority::load_or_create(&data_dir) {
            Ok(_) => panic!("non-CA root material should fail"),
            Err(error) => error,
        };

        let message = error.to_string();
        assert!(message.contains("BasicConstraints") || message.contains("is not marked as a CA"));

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn existing_root_ca_material_must_permit_key_cert_sign() {
        let data_dir = temp_data_dir();
        CertificateAuthority::load_or_create(&data_dir).expect("certificate should generate");
        let files = certificate_files(&data_dir);
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let certificate = params.self_signed(&key_pair).unwrap();
        fs::write(&files.cert_pem_path, certificate.pem()).unwrap();
        fs::write(&files.cert_der_path, certificate.der().as_ref()).unwrap();
        fs::write(&files.key_pem_path, key_pair.serialize_pem()).unwrap();

        let error = match CertificateAuthority::load_or_create(&data_dir) {
            Ok(_) => panic!("root CA without keyCertSign should fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("does not permit keyCertSign"));

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn missing_unrepairable_root_ca_material_is_rejected_without_rotation() {
        let data_dir = temp_data_dir();
        let authority =
            CertificateAuthority::load_or_create(&data_dir).expect("certificate should generate");
        let files = certificate_files(&data_dir);
        let original_pem = authority.root_pem_bytes().to_vec();
        fs::remove_file(&files.key_pem_path).unwrap();

        let error = match CertificateAuthority::load_or_create(&data_dir) {
            Ok(_) => panic!("missing private key should fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("incomplete root CA material"));
        assert_eq!(fs::read(&files.cert_pem_path).unwrap(), original_pem);

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn fresh_host_tls_cache_is_reused() {
        let data_dir = temp_data_dir();
        let authority =
            CertificateAuthority::load_or_create(&data_dir).expect("certificate should generate");

        let first = authority
            .server_config_for_host("example.com")
            .expect("host cert should build");
        let second = authority
            .server_config_for_host("example.com")
            .expect("host cert should be cached");

        assert!(Arc::ptr_eq(&first, &second));

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn expired_host_tls_cache_is_reissued() {
        let data_dir = temp_data_dir();
        let authority =
            CertificateAuthority::load_or_create(&data_dir).expect("certificate should generate");
        let first = authority
            .server_config_for_host("example.com")
            .expect("host cert should build");
        {
            let mut cache = authority.host_tls_cache.lock().unwrap();
            cache.get_mut("example.com").unwrap().expires_at = chrono::Utc::now()
                .checked_sub_days(chrono::Days::new(1))
                .unwrap();
        }

        let second = authority
            .server_config_for_host("example.com")
            .expect("host cert should be reissued");

        assert!(!Arc::ptr_eq(&first, &second));

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn host_tls_cache_reserves_slot_by_pruning_expired_and_oldest() {
        let data_dir = temp_data_dir();
        let authority =
            CertificateAuthority::load_or_create(&data_dir).expect("certificate should generate");
        let shared_config = authority
            .server_config_for_host("seed.example")
            .expect("host cert should build");
        let now = chrono::Utc::now();
        let mut cache = std::collections::HashMap::new();
        cache.insert(
            "expired.example".to_string(),
            super::CachedTlsConfig {
                config: shared_config.clone(),
                expires_at: now.checked_sub_days(chrono::Days::new(1)).unwrap(),
            },
        );
        cache.insert(
            "old.example".to_string(),
            super::CachedTlsConfig {
                config: shared_config.clone(),
                expires_at: now.checked_add_days(chrono::Days::new(10)).unwrap(),
            },
        );
        cache.insert(
            "new.example".to_string(),
            super::CachedTlsConfig {
                config: shared_config,
                expires_at: now.checked_add_days(chrono::Days::new(20)).unwrap(),
            },
        );

        super::reserve_host_tls_cache_slot(&mut cache, now, 2);

        assert_eq!(cache.len(), 1);
        assert!(!cache.contains_key("expired.example"));
        assert!(!cache.contains_key("old.example"));
        assert!(cache.contains_key("new.example"));

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn expired_special_host_tls_cache_is_reissued() {
        let data_dir = temp_data_dir();
        let authority =
            CertificateAuthority::load_or_create(&data_dir).expect("certificate should generate");
        let first = authority.special_host_tls.lock().unwrap().config.clone();
        {
            let mut cached = authority.special_host_tls.lock().unwrap();
            cached.expires_at = chrono::Utc::now()
                .checked_sub_days(chrono::Days::new(1))
                .unwrap();
        }

        authority
            .tls_acceptor()
            .expect("special host cert should be reissued");
        let second = authority.special_host_tls.lock().unwrap().config.clone();

        assert!(!Arc::ptr_eq(&first, &second));

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn leaf_expiration_rejects_root_ca_inside_refresh_window() {
        let now = chrono::Utc::now();
        let root_expires_at = now.checked_add_days(chrono::Days::new(1)).unwrap();

        let error =
            super::leaf_expiration(root_expires_at, now).expect_err("stale root should fail");

        assert!(error
            .to_string()
            .contains("root CA expires too soon to issue a fresh leaf certificate"));
    }

    #[test]
    fn certificate_host_normalization_handles_ipv6_and_dns_case() {
        assert_eq!(normalize_certificate_host("[::1]"), "::1");
        assert_eq!(normalize_certificate_host("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(normalize_certificate_host("ExAmPle.COM"), "example.com");
    }
}
