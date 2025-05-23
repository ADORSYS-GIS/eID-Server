//! interface that external modules use to interact with the domain.

use crate::eid::use_id::model::{UseIDRequest, UseIDResponse};
use color_eyre::Result;

pub trait EIDService: Clone + Send + Sync + 'static {
    fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse>;
}
