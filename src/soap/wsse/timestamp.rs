use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::soap::wsse::{Error, Result};

const DEFAULT_TTL_SECONDS: i64 = 5 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamp {
    #[serde(rename(serialize = "@wsu:Id", deserialize = "@Id"))]
    pub id: String,

    #[serde(rename(serialize = "wsu:Created", deserialize = "Created"))]
    pub created: String,

    #[serde(rename(serialize = "wsu:Expires", deserialize = "Expires"))]
    pub expires: String,
}

impl Timestamp {
    /// Create a new timestamp with the given ID and TTL
    pub fn new(id: String, ttl_seconds: Option<i64>) -> Result<Self> {
        let now = OffsetDateTime::now_utc();
        let ttl = Duration::seconds(ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS));
        let expires = now + ttl;

        let created = now.format(&Rfc3339)?;
        let expires = expires.format(&Rfc3339)?;

        Ok(Self {
            id,
            created,
            expires,
        })
    }

    /// Validate that the timestamp is still valid
    pub fn validate(&self) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let created = OffsetDateTime::parse(&self.created, &Rfc3339)?;
        let expires = OffsetDateTime::parse(&self.expires, &Rfc3339)?;

        // Check if timestamp is from the future (with 30s tolerance for clock skew)
        let tolerance = Duration::seconds(30);
        if created > now + tolerance {
            return Err(Error::Invalid(
                "Timestamp created time is in the future".into(),
            ));
        }
        // Check if timestamp has expired
        if now > expires {
            return Err(Error::Invalid("Timestamp has expired".into()));
        }
        // Check that created < expires
        if created >= expires {
            return Err(Error::Invalid(
                "Timestamp created time must be before expires time".into(),
            ));
        }
        Ok(())
    }
}
