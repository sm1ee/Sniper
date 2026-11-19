use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::model::ObservedSocketPeerRoute;

/// Only the routing inputs needed to label an existing response. Proxy URLs and
/// credentials are deliberately not retained in the observation context.
pub(crate) struct UpstreamProxyRouteSnapshot {
    route: ObservedSocketPeerRoute,
    bypass_hosts: Vec<String>,
}

impl UpstreamProxyRouteSnapshot {
    pub(crate) fn route_for(&self, destination: &url::Url) -> ObservedSocketPeerRoute {
        if bypasses_destination(destination, &self.bypass_hosts) {
            ObservedSocketPeerRoute::Direct
        } else {
            self.route
        }
    }
}

fn bypasses_destination(destination: &url::Url, bypass_hosts: &[String]) -> bool {
    destination
        .host_str()
        .is_some_and(|host| crate::scope::host_matches_any(host, bypass_hosts))
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamProxy {
    pub enabled: bool,
    pub url: String,
    pub username: String,
    pub password: String,
    /// Hosts reached directly instead of through the chain, in scope-pattern form.
    /// Stored beside the proxy as `upstream_bypass_hosts`, not in its JSON, so a
    /// client that replaces `upstream_proxy` cannot wipe the list and an older
    /// Sniper, which rejects unknown proxy fields, can still load the session.
    /// `RuntimeSettings::upstream_proxy` attaches it.
    #[serde(skip)]
    pub bypass_hosts: Vec<String>,
    /// Sniper's own listeners, attached with the bypass list. A chain whose
    /// address is one of them is refused when it is used: the setting is
    /// checked when it is saved, and a session port can open there afterwards.
    #[serde(skip)]
    pub own_listeners: crate::session_ports::OwnListeners,
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

    /// Whether `host` skips the chain. The scope matcher decides, so a pattern means
    /// the same here as in scope and TLS passthrough.
    pub fn bypasses(&self, host: &str) -> bool {
        crate::scope::host_matches_any(host, &self.bypass_hosts)
    }

    fn parsed_url(&self) -> Result<url::Url> {
        url::Url::parse(&self.url).map_err(|_| anyhow::anyhow!("Invalid upstream proxy address"))
    }

    /// A request sent through one of Sniper's own proxy listeners comes back
    /// in and goes out through the chain again, until the process is out of
    /// sockets.
    fn refuse_own_listener(&self) -> Result<()> {
        let loops = self.url.parse::<http::Uri>().is_ok_and(|uri| {
            self.own_listeners
                .proxies()
                .iter()
                .any(|addr| crate::proxy::request_targets_own_listener(&uri, *addr))
        });
        if loops {
            bail!("Upstream proxy cannot be Sniper's own listener");
        }
        Ok(())
    }

    pub(crate) fn route_snapshot(&self) -> UpstreamProxyRouteSnapshot {
        let route = if !self.enabled {
            ObservedSocketPeerRoute::Direct
        } else {
            match self.parsed_url().ok().as_ref().map(url::Url::scheme) {
                Some("http") => ObservedSocketPeerRoute::HttpProxy,
                Some("socks5" | "socks5h") => ObservedSocketPeerRoute::SocksProxy,
                _ => ObservedSocketPeerRoute::Unknown,
            }
        };
        UpstreamProxyRouteSnapshot {
            route,
            bypass_hosts: self.bypass_hosts.clone(),
        }
    }

    pub fn apply(&self, builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        let builder = builder.no_proxy();
        if !self.enabled {
            return Ok(builder);
        }
        self.validate()?;
        self.refuse_own_listener()?;
        // Both SOCKS spellings resolve destination names at the proxy, including replay.
        let mut url = self.parsed_url()?;
        if url.scheme() == "socks5" {
            url.set_scheme("socks5h").expect("valid SOCKS scheme");
        }
        // Credentials ride in the URL, which is where `Proxy::basic_auth` put them
        // for both HTTP and SOCKS; a custom proxy has no other place for SOCKS ones.
        if !self.username.is_empty() {
            url.set_username(&self.username)
                .and_then(|()| url.set_password(Some(&self.password)))
                .map_err(|()| anyhow::anyhow!("Invalid upstream proxy address"))?;
        }
        // A client is built before its destination is known, so the list is checked
        // per request against the host reqwest is about to dial.
        let bypass_hosts = self.bypass_hosts.clone();
        let proxy = reqwest::Proxy::custom(move |destination| {
            let direct = bypasses_destination(destination, &bypass_hosts);
            (!direct).then(|| url.clone())
        });
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
        if !self.enabled || self.bypasses(host) {
            return TcpStream::connect((host, port))
                .await
                .context("Upstream connection failed");
        }
        self.validate()?;
        self.refuse_own_listener()?;
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

#[cfg(test)]
mod peer_route_tests {
    use super::*;

    #[test]
    fn observed_route_uses_shared_bypass_and_final_destination() {
        let proxy = UpstreamProxy {
            enabled: true,
            url: "http://192.0.2.10:8080".into(),
            bypass_hosts: vec!["*.example.com".into(), "[2001:db8::1]".into()],
            ..Default::default()
        };
        let snapshot = proxy.route_snapshot();
        for destination in [
            "https://edited.example.com/path",
            "https://example.com:8443/",
            "http://[2001:db8::1]/",
            "https://192.0.2.5/",
        ] {
            let destination = url::Url::parse(destination).unwrap();
            let expected = if bypasses_destination(&destination, &proxy.bypass_hosts) {
                ObservedSocketPeerRoute::Direct
            } else {
                ObservedSocketPeerRoute::HttpProxy
            };
            assert_eq!(snapshot.route_for(&destination), expected);
        }
        assert_eq!(
            snapshot.route_for(&url::Url::parse("https://edited.example.com/").unwrap()),
            ObservedSocketPeerRoute::Direct
        );
        assert_eq!(
            snapshot.route_for(&url::Url::parse("https://192.0.2.5/").unwrap()),
            ObservedSocketPeerRoute::HttpProxy
        );
    }

    #[test]
    fn observed_route_snapshots_do_not_follow_later_proxy_edits() {
        let destination = url::Url::parse("https://example.com/").unwrap();
        let mut proxy = UpstreamProxy::default();
        let initial = proxy.route_snapshot();
        proxy.enabled = true;
        proxy.url = "socks5://192.0.2.10:1080".into();
        let retry = proxy.route_snapshot();
        proxy.url = "http://192.0.2.20:8080".into();
        assert_eq!(
            initial.route_for(&destination),
            ObservedSocketPeerRoute::Direct
        );
        assert_eq!(
            retry.route_for(&destination),
            ObservedSocketPeerRoute::SocksProxy
        );
        assert_eq!(
            proxy.route_snapshot().route_for(&destination),
            ObservedSocketPeerRoute::HttpProxy
        );
        proxy.url = "socks5h://192.0.2.10:1080".into();
        assert_eq!(
            proxy.route_snapshot().route_for(&destination),
            ObservedSocketPeerRoute::SocksProxy
        );
        proxy.url = "unrecognized".into();
        assert_eq!(
            proxy.route_snapshot().route_for(&destination),
            ObservedSocketPeerRoute::Unknown
        );
    }
}
