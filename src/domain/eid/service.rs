use super::csca::{CscaValidationError, CscaValidationService};
use crate::session::{SessionManager, SessionStore};

#[derive(Debug)]
pub struct EidService<S: SessionStore> {
    pub session_manager: SessionManager<S>,
    pub csca_validator: CscaValidationService,
}

impl<S: SessionStore> Clone for EidService<S> {
    fn clone(&self) -> Self {
        Self {
            session_manager: self.session_manager.clone(),
            csca_validator: self.csca_validator.clone(),
        }
    }
}

impl<S: SessionStore> EidService<S> {
    pub fn new(session_manager: SessionManager<S>) -> Result<Self, CscaValidationError> {
        let csca_validator = CscaValidationService::new()?;
        Ok(Self {
            session_manager,
            csca_validator,
        })
    }

    /// Get reference to the CSCA validation service
    pub fn csca_validator(&self) -> &CscaValidationService {
        &self.csca_validator
    }

    /// Get mutable reference to the CSCA validation service
    pub fn csca_validator_mut(&mut self) -> &mut CscaValidationService {
        &mut self.csca_validator
    }
}
