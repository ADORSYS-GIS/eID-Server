use std::collections::BTreeMap;

const UTF8: &str = "UTF-8";

/// Configuration for XML serialization
#[derive(Debug, Clone)]
pub struct XmlConfig {
    pub pretty: bool,
    pub indent: (char, usize),
    pub xml_decl: bool,
    pub encoding: String,
    pub namespaces: BTreeMap<String, String>,
}

impl Default for XmlConfig {
    fn default() -> Self {
        Self {
            pretty: false,
            indent: (' ', 2),
            xml_decl: true,
            encoding: UTF8.to_string(),
            namespaces: BTreeMap::new(),
        }
    }
}

impl XmlConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set this flag to true to enable pretty printing. Default is false.
    pub fn pretty(mut self, pretty: bool) -> Self {
        self.pretty = pretty;
        self
    }

    /// Set the indent character and size. Default is (' ', 2).
    pub fn indent(mut self, indent_char: char, indent_size: usize) -> Self {
        self.indent = (indent_char, indent_size);
        self
    }

    /// Set this flag to true to include the XML declaration. Default is true.
    pub fn xml_decl(mut self, decl: bool) -> Self {
        self.xml_decl = decl;
        self
    }

    /// Set the encoding of the XML document. Default is "UTF-8".
    pub fn encoding<S: ToString>(mut self, encoding: S) -> Self {
        self.encoding = encoding.to_string();
        self
    }

    /// Add namespace declaration to the XML document.
    pub fn namespace<S: ToString>(mut self, prefix: S, uri: S) -> Self {
        self.namespaces.insert(prefix.to_string(), uri.to_string());
        self
    }
}
