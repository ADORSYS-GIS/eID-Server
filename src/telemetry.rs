use std::sync::OnceLock;
use tracing_subscriber::{
    EnvFilter,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt as _,
    util::SubscriberInitExt as _,
};

static INIT: OnceLock<()> = OnceLock::new();

pub fn init_tracing() {
    let _ = INIT.get_or_init(|| {
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info"));
        let span_event = fmt::layer().with_span_events(FmtSpan::ENTER | FmtSpan::EXIT);
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(span_event)
            .with(env_filter)
            .try_init();
    });
}
