pub struct TransmitConfig {
    pub timeout_secs: u64,
    pub max_sessions: usize,
}

impl Default for TransmitConfig {
    fn default() -> Self {
        TransmitConfig {
            timeout_secs: 30,
            max_sessions: 100,
        }
    }
} 