use std::cmp::Ordering;

pub fn desensitize_email(email: &str) -> String {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() == 2 {
        let username = &parts[0];
        let domain = &parts[1];
        if username.len() > 4 {
            format!(
                "{}@{}",
                format_args!("{}****{}", &username[..2], &username[username.len() - 2..]),
                domain
            )
        } else {
            format!(
                "{}@{}",
                format_args!("{}****{}", &username[..1], &username[username.len() - 1..]),
                domain
            )
        }
    } else {
        email.to_string()
    }
}

pub fn desensitize_text(name: &str) -> String {
    let mut left = 1;
    while !name.is_char_boundary(left) {
        left += 1
    }
    match name.chars().count().cmp(&2) {
        Ordering::Equal => format!("{}*", &name[..left]),
        Ordering::Less => name.to_string(),
        Ordering::Greater => {
            let mut right = name.len() - 1;
            while !name.is_char_boundary(right) {
                right -= 1
            }
            format!("{}*{}", &name[..left], &name[right..])
        }
    }
}

lazy_static::lazy_static! {
    static ref BASE62_CHARSETS: Vec<char> = vec![
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
      'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
      'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
      'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  ];
}
use anyhow::Context;
use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine,
};
use ring::rand::{SecureRandom, SystemRandom};

use super::errors::Result;

pub fn gen_id(size: usize) -> String {
    let rng = SystemRandom::new();
    let mut dest: Vec<u8> = vec![0; size];
    rng.fill(&mut dest).unwrap();
    encode62(&dest)
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