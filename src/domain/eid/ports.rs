//! interface that external modules use to interact with the domain.

use crate::eid::use_id::model::{UseIDRequest, UseIDResponse};
use color_eyre::Result;

pub trait UseIdService: Clone + Send + Sync + 'static {
    fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse>;
}

pub trait UserRegistrationService: Clone + Send + Sync + 'static {
    fn register_user(&self, user: String) -> Result<(), String>;
}
