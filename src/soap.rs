mod config;
mod de;
mod ser;
#[cfg(test)]
mod tests;

pub use config::XmlConfig;
pub use de::from_str;
pub use ser::to_string;

use serde::{Deserialize, Serialize};

use crate::impl_serialize;

pub mod ns {
    pub const SOAP_ENV: &str = "http://schemas.xmlsoap.org/soap/envelope/";
    pub const EID: &str = "http://bsi.bund.de/eID/";
    pub const DSS: &str = "urn:oasis:names:tc:dss:1.0:core:schema";
}

pub mod prefix {
    pub const SOAP_ENV: &str = "soapenv";
    pub const EID: &str = "eid";
    pub const DSS: &str = "dss";
}

/// A SOAP envelope
#[derive(Debug, Clone, Deserialize)]
pub struct Envelope<T> {
    #[serde(rename = "Header")]
    header: Option<Header>,
    #[serde(rename = "Body")]
    body: Body<T>,
}

impl<T> Envelope<T> {
    /// Creates a new envelope with the given body
    pub fn new(body: T) -> Self {
        Self {
            header: None,
            body: Body { content: body },
        }
    }

    /// Set the envelope header
    pub fn with_header(mut self, header: Header) -> Self {
        self.header = Some(header);
        self
    }

    /// Returns the body of the envelope
    pub fn body(&self) -> &T {
        &self.body.content
    }

    /// Consumes the envelope and returns the body
    pub fn into_body(self) -> T {
        self.body.content
    }

    /// Returns the header of the envelope
    pub fn header(&self) -> &Option<Header> {
        &self.header
    }
}

impl<T: for<'a> Deserialize<'a>> Envelope<T> {
    /// Parse the envelope from a SOAP payload
    pub fn parse(xml: &str) -> Result<Self, quick_xml::DeError> {
        from_str(xml)
    }
}

impl<T: Serialize> Envelope<T> {
    /// Serialize this envelope into a SOAP string with optional pretty printing
    pub fn serialize_soap(&self, pretty: bool) -> Result<String, quick_xml::SeError> {
        let conf = if pretty {
            XmlConfig::new().pretty(true)
        } else {
            XmlConfig::default()
        };
        let config = conf
            .namespace(prefix::SOAP_ENV, ns::SOAP_ENV)
            .namespace(prefix::EID, ns::EID)
            .namespace(prefix::DSS, ns::DSS);

        let env = SoapEnvRef(self);
        to_string(&config, &env)
    }
}

/// Represents a SOAP header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header;

/// Represents a SOAP body
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body<T> {
    #[serde(rename = "$value")]
    pub content: T,
}

struct SoapEnvRef<'a, T>(&'a Envelope<T>);
impl_serialize!(SoapEnvRef, "soapenv");
