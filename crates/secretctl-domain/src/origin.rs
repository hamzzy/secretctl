use crate::error::DomainError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use url::Url;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalOrigin {
    scheme: String,
    host: String,
    port: u16,
}

impl CanonicalOrigin {
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        let url = Url::parse(s).map_err(|e| DomainError::InvalidOrigin(format!("{}: {}", s, e)))?;

        let scheme = url.scheme().to_ascii_lowercase();
        if scheme != "https" && scheme != "http" {
            return Err(DomainError::InvalidOrigin(format!(
                "Unsupported scheme: {}",
                scheme
            )));
        }

        let host = url
            .host_str()
            .ok_or_else(|| DomainError::InvalidOrigin("Missing host".to_string()))?
            .to_ascii_lowercase();

        if host.contains('*') {
            return Err(DomainError::InvalidOrigin(
                "Wildcard host is not permitted in canonical origin".to_string(),
            ));
        }

        let default_port = if scheme == "https" { 443 } else { 80 };
        let port = url.port().unwrap_or(default_port);

        Ok(Self { scheme, host, port })
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn as_str(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }

    pub fn matches(&self, other: &CanonicalOrigin) -> bool {
        self.scheme == other.scheme && self.host == other.host && self.port == other.port
    }
}

impl fmt::Display for CanonicalOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

impl fmt::Debug for CanonicalOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CanonicalOrigin({}://{}:{})",
            self.scheme, self.host, self.port
        )
    }
}

impl FromStr for CanonicalOrigin {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for CanonicalOrigin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> Deserialize<'de> for CanonicalOrigin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CanonicalOrigin::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_origin() {
        let o1 = CanonicalOrigin::parse("https://github.com").unwrap();
        assert_eq!(o1.scheme(), "https");
        assert_eq!(o1.host(), "github.com");
        assert_eq!(o1.port(), 443);
        assert_eq!(o1.as_str(), "https://github.com:443");

        let o2 = CanonicalOrigin::parse("https://github.com:443/login?foo=bar").unwrap();
        assert_eq!(o1, o2);

        let o3 = CanonicalOrigin::parse("http://localhost:8080/test").unwrap();
        assert_eq!(o3.port(), 8080);
        assert_eq!(o3.as_str(), "http://localhost:8080");

        assert!(CanonicalOrigin::parse("https://*.github.com").is_err());
        assert!(CanonicalOrigin::parse("ftp://example.com").is_err());
    }
}
