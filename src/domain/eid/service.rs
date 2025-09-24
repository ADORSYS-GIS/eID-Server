use crate::{
    pki::identity::Identity,
    session::{SessionManager, SessionStore},
};

#[derive(Debug, Clone)]
pub struct EidService<S: SessionStore> {
    pub session_manager: SessionManager<S>,
    pub identity: Identity,
}

impl<S: SessionStore> EidService<S> {
    pub fn new(session_manager: SessionManager<S>, identity: Identity) -> Self {
        Self {
            session_manager,
            identity,
        }
    }
}
