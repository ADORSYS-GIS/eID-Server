//! interface that external modules use to interact with the domain.

use crate::domain::eid::models::use_id::model::{UseIDRequest, UseIDResponse};
use color_eyre::Result;

pub trait EidService: Clone + Send + Sync + 'static {
    fn use_id_register(user: String) -> Result<(), String>;
    fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse>;
}
