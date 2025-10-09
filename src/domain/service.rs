use crate::pki::crl::CrlManager;
use crate::pki::truststore::TrustStore;
use crate::{pki::identity::Identity, session::SessionManager};

#[derive(Debug, Clone)]
pub struct Service<T: TrustStore> {
    pub session_manager: SessionManager,
    pub identity: Identity,
    pub trust_store: T,
    pub crl_manager: CrlManager,
}

impl<T: TrustStore> Service<T> {
    pub fn new(
        session_manager: SessionManager,
        trust_store: T,
        identity: Identity,
        crl_manager: CrlManager,
    ) -> Self {
        Self {
            session_manager,
            trust_store,
            identity,
            crl_manager,
        }
    }
}
