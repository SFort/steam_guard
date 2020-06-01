//Simple crate for authenticating with steams TOTP
//!# steam_guard
//!Is used to easily get steam guards authentication code.
//!provided you have the shared secret
//!#### Usage:
//!```
//!extern crate steam_guard;
//!let secret = "123123123Ab=";
//!println!("Expires in:{}s", steam_guard::expires_in_sec());
//!println!("Login with:{:?}", steam_guard::from_secret(secret));
//!println!("Next login code:{:?}", steam_guard::from_secret_future(secret, 1));
//!
//!```
#[cfg(feature = "base64")]
extern crate base64;
extern crate sha1;
pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");
#[cfg(feature = "steam_web")]
pub mod web;
pub fn totp_to_steam_code(mut totp_result: u32) -> String {
    let steam_chars = [
        "2", "3", "4", "5", "6", "7", "8", "9", "B", "C", "D", "F", "G", "H", "J", "K", "M", "N",
        "P", "Q", "R", "T", "V", "W", "X", "Y",
    ];
    let mut steam_result = String::new();
    for _ in 0..5 {
        steam_result += steam_chars[totp_result as usize % steam_chars.len()];
        totp_result /= steam_chars.len() as u32;
    }
    steam_result
}
pub fn from_bytes(key: &[u8], time: &u64) -> u32 {
    let hmac: &[u8; 8] = &[
        ((time >> 56) & 255u64) as u8,
        ((time >> 48) & 255u64) as u8,
        ((time >> 40) & 255u64) as u8,
        ((time >> 32) & 255u64) as u8,
        ((time >> 24) & 255u64) as u8,
        ((time >> 16) & 255u64) as u8,
        ((time >> 8) & 255u64) as u8,
        (time & 255u64) as u8,
    ];
    let hash = {
        let mut sha1 = sha1::Sha1::new();
        let auth_key: &mut [u8; 64] = &mut [0; 64];
        if key.len() > 64 {
            sha1.update(key);
            auth_key[..20].copy_from_slice(&(sha1.digest().bytes()));
            sha1.reset();
        } else {
            auth_key[..key.len()].copy_from_slice(key);
        }
        let mut inner_padding: [u8; 64] = [0x36; 64];
        let mut outer_padding: [u8; 64] = [0x5c; 64];
        for offset in 0..auth_key.len() {
            inner_padding[offset] ^= auth_key[offset];
            outer_padding[offset] ^= auth_key[offset];
        }
        sha1.update(&inner_padding);
        sha1.update(hmac);
        let inner_hash = sha1.digest().bytes();
        sha1.reset();

        sha1.update(&outer_padding);
        sha1.update(&inner_hash);
        sha1.digest().bytes()
    };
    let offset = (hash[19] & 0xf) as usize;
    (((hash[offset] as u32) & 0x7f) << 24
        | (hash[offset + 1] as u32) << 16
        | (hash[offset + 2] as u32) << 8
        | (hash[offset + 3] as u32)) as u32
}
///returns the time in seconds in which the currently valid authentication code will expire
///and the next one will be valid
pub fn expires_in_sec() -> u64 {
    30 - (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        % 30)
}
///takes steams Base64 encoded shared_secret value decodes it and generates the 5 digit code that
///steam requires in order to authenticate your login
#[cfg(feature = "base64")]
pub fn from_secret(secret: &str) -> Result<String, base64::DecodeError> {
    let key = base64::decode(secret)?;
    let time: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    Ok(totp_to_steam_code(from_bytes(&key, &time)))
}
///same as from_secret
///but the second argument allows you to get codes that will be valid in the future
///setting the second argument to 0 would be the same as calling from_secret
#[cfg(feature = "base64")]
pub fn from_secret_future(secret: &str, offset: u64) -> Result<String, base64::DecodeError> {
    let key = base64::decode(secret)?;
    let time: u64 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30)
        + offset;
    Ok(totp_to_steam_code(from_bytes(&key, &time)))
}
