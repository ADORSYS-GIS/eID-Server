use crate::pki::truststore::TrustStore;
use crate::session::SessionManager;

#[derive(Debug, Clone)]
pub struct EidService<T: TrustStore> {
    pub session_manager: SessionManager,
    pub trust_store: T,
}

impl<T: TrustStore> EidService<T> {
    pub fn new(session_manager: SessionManager, trust_store: T) -> Self {
        Self {
            session_manager,
            trust_store,
        }
    }
}
