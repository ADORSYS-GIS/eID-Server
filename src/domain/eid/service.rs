use crate::config::Config;
use crate::pki::master_list::{CscaValidationError, CscaValidationService};
use crate::session::{SessionManager, SessionStore};

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
        let config = Config::load().map_err(|e| {
            CscaValidationError::MasterListParse(format!("Failed to load config: {e}"))
        })?;
        let csca_validator = CscaValidationService::new(config.master_list)?;
        Ok(Self {
            session_manager,
            csca_validator,
        })
    }

    pub fn with_config(
        session_manager: SessionManager<S>,
        config: &Config,
    ) -> Result<Self, CscaValidationError> {
        let csca_validator = CscaValidationService::new(config.master_list.clone())?;
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
