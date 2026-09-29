use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamProxy {
    pub enabled: bool,
    pub url: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamProxy")
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl UpstreamProxy {
    pub fn validate(&self) -> Result<()> {
        if self.username.len() > 255 || self.password.len() > 255 {
            bail!("Proxy credentials cannot exceed 255 bytes");
        }
        if self.username.contains(':') || (self.username.is_empty() && !self.password.is_empty()) {
            bail!("Proxy username is required with a password and cannot contain a colon");
        }
        if !self.enabled && self.url.is_empty() {
            return Ok(());
        }
        let url = self.parsed_url()?;
        if !matches!(url.scheme(), "http" | "socks5" | "socks5h")
            || url.host_str().is_none()
            || url.port_or_known_default().unwrap_or(0) == 0
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
            || self.url.len() > 2048
            || self.url.chars().any(char::is_whitespace)
        {
            bail!("Proxy address must be http://host:port or socks5h://host:port; enter credentials separately");
        }
        if self.enabled
            && url.scheme().starts_with("socks")
            && !self.username.is_empty()
            && self.password.is_empty()
        {
            bail!("SOCKS5 authentication requires both username and password");
        }
        Ok(())
    }

    fn parsed_url(&self) -> Result<url::Url> {
        url::Url::parse(&self.url).map_err(|_| anyhow::anyhow!("Invalid upstream proxy address"))
    }

    pub fn apply(&self, builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        let builder = builder.no_proxy();
        if !self.enabled {
            return Ok(builder);
        }
        self.validate()?;
        // Both SOCKS spellings resolve destination names at the proxy, including replay.
        let mut url = self.parsed_url()?;
        if url.scheme() == "socks5" {
            url.set_scheme("socks5h").expect("valid SOCKS scheme");
        }
        let mut proxy = reqwest::Proxy::all(url)
            .map_err(|_| anyhow::anyhow!("Invalid upstream proxy address"))?;
        if !self.username.is_empty() {
            proxy = proxy.basic_auth(&self.username, &self.password);
        }
        Ok(builder.proxy(proxy))
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        tokio::time::timeout(
            Duration::from_secs(10),
            self.connect_inner(host.trim_matches(['[', ']']), port),
        )
        .await
        .context("Upstream proxy connection timed out")?
    }

    async fn connect_inner(&self, host: &str, port: u16) -> Result<TcpStream> {
        if !self.enabled {
            return TcpStream::connect((host, port))
                .await
                .context("Upstream connection failed");
        }
        self.validate()?;
        let url = self.parsed_url()?;
        let mut stream = TcpStream::connect((
            url.host_str().unwrap().trim_matches(['[', ']']),
            url.port_or_known_default().unwrap(),
        ))
        .await
        .context("Cannot connect to upstream proxy")?;
        if url.scheme() == "http" {
            let authority = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
            if !self.username.is_empty() {
                request.push_str(&format!(
                    "Proxy-Authorization: Basic {}\r\n",
                    STANDARD.encode(format!("{}:{}", self.username, self.password))
                ));
            }
            request.push_str("\r\n");
            stream.write_all(request.as_bytes()).await?;
            // Read only the header: bytes following it belong to the tunneled protocol.
            let mut header = Vec::new();
            loop {
                header.push(stream.read_u8().await?);
                if header.ends_with(b"\r\n\r\n") {
                    break;
                }
                if header.len() >= 16384 {
                    bail!("Upstream proxy CONNECT response is too large");
                }
            }
            let status = std::str::from_utf8(&header)
                .ok()
                .and_then(|s| s.lines().next())
                .and_then(|s| s.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u16>().ok());
            if !status.is_some_and(|s| (200..300).contains(&s)) {
                bail!("Upstream proxy rejected CONNECT");
            }
        } else {
            let method = if self.username.is_empty() { 0 } else { 2 };
            stream.write_all(&[5, 1, method]).await?;
            let mut reply = [0; 2];
            stream.read_exact(&mut reply).await?;
            if reply != [5, method] {
                bail!("SOCKS5 proxy rejected authentication method");
            }
            if method == 2 {
                let mut auth = vec![1, self.username.len() as u8];
                auth.extend_from_slice(self.username.as_bytes());
                auth.push(self.password.len() as u8);
                auth.extend_from_slice(self.password.as_bytes());
                stream.write_all(&auth).await?;
                stream.read_exact(&mut reply).await?;
                if reply != [1, 0] {
                    bail!("SOCKS5 authentication failed");
                }
            }
            let mut request = vec![5, 1, 0];
            match host.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(ip)) => {
                    request.push(1);
                    request.extend_from_slice(&ip.octets());
                }
                Ok(std::net::IpAddr::V6(ip)) => {
                    request.push(4);
                    request.extend_from_slice(&ip.octets());
                }
                Err(_) => {
                    if host.len() > 255 {
                        bail!("SOCKS5 destination name is too long");
                    }
                    request.extend_from_slice(&[3, host.len() as u8]);
                    request.extend_from_slice(host.as_bytes());
                }
            }
            request.extend_from_slice(&port.to_be_bytes());
            stream.write_all(&request).await?;
            let mut head = [0; 4];
            stream.read_exact(&mut head).await?;
            if head[..3] != [5, 0, 0] {
                bail!("SOCKS5 proxy rejected connection");
            }
            let len = match head[3] {
                1 => 4,
                4 => 16,
                3 => stream.read_u8().await? as usize,
                _ => bail!("Invalid SOCKS5 response"),
            };
            stream.read_exact(&mut vec![0; len + 2]).await?;
        }
        Ok(stream)
    }
}
