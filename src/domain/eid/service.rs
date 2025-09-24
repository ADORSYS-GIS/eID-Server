use crate::session::{SessionManager, SessionStore};


#[derive(Debug, Clone)]
pub struct EidService<S: SessionStore> {
    pub session_manager: SessionManager<S>,
}

impl<S: SessionStore> EidService<S> {
    pub fn new(session_manager: SessionManager<S>) -> Self {
        Self { session_manager }
    }
}
