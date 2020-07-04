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
#[cfg(feature = "version")]
pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");
#[cfg(not(feature = "root"))]
mod root;
#[cfg(feature = "root")]
pub mod root;
///handles anything related to http
///
///it is very modular due to it including functions like [get_time_offset](web/fn.get_time_offset.html)
///which you migth need for [totp_from_bytes](../fn.totp_from_bytes.html)
///in case you want to handle SysTime being out of sync
pub mod web;
///takes the shared seacret bytes and seconds since unix epoch /30
///returns the steam guard code for said time
pub fn totp_from_bytes(key: &[u8], time: &u64) -> String {
    root::crypto::to_steam_code(root::crypto::from_bytes(&key, &time))
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
    Ok(totp_from_bytes(&key, &time))
}
///same as [from_secret](fn.from_secret.html)
///but the second argument allows you to get codes that will be valid in the future
///setting the second argument to 0 would be the same as calling [from_secret](fn.from_secret.html)
#[cfg(feature = "base64")]
pub fn from_secret_future(secret: &str, offset: u64) -> Result<String, base64::DecodeError> {
    let key = base64::decode(secret)?;
    let time: u64 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30)
        + offset;
    Ok(totp_from_bytes(&key, &time))
}
