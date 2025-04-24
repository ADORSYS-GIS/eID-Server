//! Service layer that provides the business logic of the domain.

use super::ports::EidService;

// TODO : Implement the service layer.
#[derive(Debug, Clone)]
pub struct Service;

// Will need to implement this later
impl Service {
    pub fn new() -> Self {
        Self
    }
}

impl EidService for Service {}
