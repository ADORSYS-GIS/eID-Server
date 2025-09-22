use crate::session::SessionManager;

#[derive(Debug, Clone)]
pub struct EidService {
    pub session_manager: SessionManager,
}

impl EidService {
    pub fn new(session_manager: SessionManager) -> Self {
        Self { session_manager }
    }
}
