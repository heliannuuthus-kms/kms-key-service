use anyhow::{anyhow, Context};
use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine,
};
use ring::rand::{SecureRandom, SystemRandom};

use super::errors::{Result, ServiceError};

lazy_static::lazy_static! {
    static ref BASE62_CHARSETS: Vec<char> = vec![
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
      'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
      'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
      'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  ];
}
pub fn generate_b62(size: usize) -> Result<String> {
    Ok(encode62(&generate_key(size)?))
}

pub fn generate_b64(size: usize) -> Result<String> {
    Ok(encode64(&generate_key(size)?))
}

pub fn generate_key(size: usize) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut dest: Vec<u8> = vec![0; size];
    rng.fill(&mut dest)
        .map_err(|e| ServiceError::InternalServer(anyhow!("rng error")));
    Ok(dest)
}

pub fn encode62(source: &[u8]) -> String {
    let base: usize = BASE62_CHARSETS.len();
    let mut result = String::new();
    source.iter().for_each(|i| {
        result.push(BASE62_CHARSETS[(*i as usize) % base]);
    });
    result.clone()
}

pub fn encode64(source: &[u8]) -> String {
    STANDARD_NO_PAD.encode(source)
}

pub fn decode64(source: &str) -> Result<Vec<u8>> {
    Ok(STANDARD_NO_PAD
        .decode(source)
        .context("base64url decode failed".to_string())?)
}

pub fn encode64url(source: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(source)
}

pub fn decode64url(source: &str) -> Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD
        .decode(source)
        .context("base64url decode failed".to_string())?)
}
