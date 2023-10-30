use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;

use super::configs::env_var_default;

pub fn init() {
    let file_appender = tracing_appender::rolling::hourly(
        env_var_default::<String>("LOG", "./log".to_string()),
        format!("{}.log", env!("CARGO_PKG_NAME")),
    );
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let _ = tracing::subscriber::set_global_default(
        tracing_subscriber::fmt::Subscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish()
            .with(
                tracing_subscriber::fmt::Layer::default()
                    .with_writer(non_blocking),
            ),
    );
}
