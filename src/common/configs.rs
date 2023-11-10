use serde::{de::Deserialize, Deserializer};

pub fn env_var<T>(name: &str) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    std::env::var(name).unwrap().parse::<T>().unwrap()
}

pub fn env_var_default<T>(name: &str, default_value: T) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    match std::env::var(name) {
        Ok(var) => var.parse::<T>().unwrap_or_else(|_| {
            tracing::warn!("{} env variable parse failed", name);
            default_value
        }),
        Err(_) => {
            tracing::warn!("{} env variable load failed", name);
            default_value
        }
    }
}

pub trait Patch<T> {
    fn patched(&mut self, patched: T) -> &mut Self;
}

pub fn patch<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}
