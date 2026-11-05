use crate::{Denial, Result};
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::net::SocketAddr;
use url::Url;

/// A proxy address cannot trigger system DNS or refer to a public proxy host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProxyEndpoint(SocketAddr);
impl ProxyEndpoint {
    pub fn parse(value: &str) -> Result<Self> {
        let address: SocketAddr = value.parse().map_err(|_| Denial::InvalidConfiguration)?;
        let result = Self(address);
        result.validate()?;
        Ok(result)
    }
    pub fn validate(self) -> Result<()> {
        if !self.0.ip().is_loopback() || self.0.port() == 0 {
            return Err(Denial::InvalidConfiguration);
        }
        Ok(())
    }
    pub fn address(self) -> SocketAddr {
        self.0
    }
    #[cfg(feature = "transport")]
    pub(crate) fn socks_url(self) -> String {
        format!("socks5h://{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    Onion,
    I2p,
    Https,
}

/// Canonical remote destination. Private fields prevent constructing unchecked URLs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    url: Url,
    kind: EndpointKind,
}
impl Endpoint {
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() > 512
            || !value.is_ascii()
            || value.trim() != value
            || value.contains(['\\', '%', '\r', '\n'])
        {
            return Err(Denial::InvalidEndpoint);
        }
        let url = Url::parse(value).map_err(|_| Denial::InvalidEndpoint)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.port() == Some(0)
        {
            return Err(Denial::InvalidEndpoint);
        }
        let host = url.host_str().ok_or(Denial::InvalidEndpoint)?;
        let kind = if host.ends_with(".onion") {
            validate_onion(host)?;
            EndpointKind::Onion
        } else if host.ends_with(".i2p") {
            validate_i2p(host)?;
            EndpointKind::I2p
        } else {
            if url.scheme() != "https" {
                return Err(Denial::TlsRequired);
            }
            if !matches!(url.host(), Some(url::Host::Domain(_)))
                || host.ends_with('.')
                || !host.contains('.')
                || host.ends_with(".localhost")
                || host.ends_with(".local")
                || host.split('.').any(|p| {
                    p.is_empty()
                        || p.starts_with('-')
                        || p.ends_with('-')
                        || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return Err(Denial::InvalidEndpoint);
            }
            EndpointKind::Https
        };
        Ok(Self { url, kind })
    }
    pub fn kind(&self) -> EndpointKind {
        self.kind
    }
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or_default()
    }
    pub fn port(&self) -> u16 {
        self.url.port_or_known_default().unwrap_or(0)
    }
    pub fn uses_tls(&self) -> bool {
        self.url.scheme() == "https"
    }
    pub fn canonical(&self) -> &str {
        self.url.as_str()
    }
}

/// Validate Tor v3 encoding, version and checksum using standard SHA3-256.
pub fn validate_onion(host: &str) -> Result<()> {
    let name = host.strip_suffix(".onion").ok_or(Denial::InvalidOnion)?;
    if name.len() != 56
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        return Err(Denial::InvalidOnion);
    }
    let data = BASE32_NOPAD
        .decode(name.to_ascii_uppercase().as_bytes())
        .map_err(|_| Denial::InvalidOnion)?;
    if data.len() != 35 || data[34] != 3 {
        return Err(Denial::InvalidOnion);
    }
    let mut hash = Sha3_256::new();
    hash.update(b".onion checksum");
    hash.update(&data[..32]);
    hash.update([3]);
    if hash.finalize()[..2] != data[32..34] {
        return Err(Denial::InvalidOnion);
    }
    Ok(())
}
pub fn validate_i2p(host: &str) -> Result<()> {
    let name = host.strip_suffix(".b32.i2p").ok_or(Denial::InvalidI2p)?;
    if name.len() != 52
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        return Err(Denial::InvalidI2p);
    }
    let data = BASE32_NOPAD
        .decode(name.to_ascii_uppercase().as_bytes())
        .map_err(|_| Denial::InvalidI2p)?;
    if data.len() != 32 || BASE32_NOPAD.encode(&data).to_ascii_lowercase() != name {
        return Err(Denial::InvalidI2p);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn onion(seed: u8) -> String {
    let mut bytes = vec![seed; 32];
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(&bytes);
    h.update([3]);
    bytes.extend_from_slice(&h.finalize()[..2]);
    bytes.push(3);
    format!("{}.onion", BASE32_NOPAD.encode(&bytes).to_ascii_lowercase())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn onion_checksum_and_version_required() {
        assert!(validate_onion(&onion(7)).is_ok());
        for bad in [
            "a.onion".into(),
            format!("{}.onion", "a".repeat(56)),
            format!("sub.{}", onion(7)),
            "abcdefghijklmnop.onion".into(),
        ] {
            assert_eq!(validate_onion(&bad), Err(Denial::InvalidOnion));
        }
    }
    #[test]
    fn endpoint_rejects_url_ambiguity_and_credentials() {
        for v in [
            "https://u:p@example.org",
            "https://example.org/path",
            "https://example.org/?x=1",
            "https://example.org/#x",
            "https://127.0.0.1",
            "https://[::1]",
            "https://localhost",
            "https://example.org:0",
            "https://example.org\\@evil.org",
            "https://%65xample.org",
            " https://example.org",
        ] {
            assert!(Endpoint::parse(v).is_err(), "{v}");
        }
        assert!(Endpoint::parse("https://node.example.org:38081").is_ok());
    }
    #[test]
    fn proxy_uses_only_literal_loopback_and_i2p_is_canonical() {
        for p in [
            "localhost:9050",
            "192.168.1.1:9050",
            "127.0.0.1:0",
            "socks5h://127.0.0.1:9050",
        ] {
            assert!(ProxyEndpoint::parse(p).is_err());
        }
        assert!(ProxyEndpoint::parse("127.0.0.1:9050").is_ok());
        assert!(ProxyEndpoint::parse("[::1]:9050").is_ok());
        assert!(validate_i2p(&format!("{}.b32.i2p", "a".repeat(52))).is_ok());
        assert!(validate_i2p("name.i2p").is_err());
    }
}
