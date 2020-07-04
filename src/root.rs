//!Contains functions that should not be pub
//!but can be made so in case there is an unforseen usecase
#[cfg(feature = "getrandom")]
extern crate getrandom;
#[cfg(feature = "num-bigint")]
extern crate num_bigint;
#[cfg(feature = "tinyjson")]
extern crate tinyjson;

pub mod crypto {
    pub fn to_steam_code(mut totp_result: u32) -> String {
        let steam_chars = [
            "2", "3", "4", "5", "6", "7", "8", "9", "B", "C", "D", "F", "G", "H", "J", "K", "M",
            "N", "P", "Q", "R", "T", "V", "W", "X", "Y",
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
    pub fn add_rand_bytes(vec: &mut Vec<u8>, range: usize) {
        #[cfg(feature = "getrandom")]
        {
            let mut buf = vec![0u8; range];
            if getrandom::getrandom(&mut buf).is_ok() {
                for i in 0..range {
                    if buf[i] == 0 {
                        buf[i] = 1;
                    }
                }
                vec.extend(buf);
            }
        }
        #[cfg(not(feature = "getrandom"))]
        for i in 0..range {
            // ( SysTime | i ) ^ 571 % 255 + 1
            // Eather of these are a bad source of rng getrandom should be used
            vec.push(
                ((if let Ok(time) =
                    std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH)
                {
                    time.as_nanos() % 256
                } else {
                    i as u128
                } ^ 571)
                    % 255) as u8
                    + 1,
            );
        }
    }
    #[cfg(feature = "num-bigint")]
    pub fn pad_encrypt(
        password: &str,
        exponent: &super::num_bigint::BigUint,
        modulus: &super::num_bigint::BigUint,
    ) -> String {
        let mut padding = std::vec::Vec::with_capacity(modulus.bits() / 8);
        padding.push(0);
        padding.push(2);
        add_rand_bytes(&mut padding, (modulus.bits() / 8) - 3 - password.len());
        padding.push(0);
        padding.extend_from_slice(password.as_bytes());
        super::web::urlencode(&base64::encode(
            &(super::num_bigint::BigUint::from_bytes_be(&padding).modpow(exponent, modulus))
                .to_bytes_be(),
        ))
    }
}
#[allow(dead_code)]
pub mod web {
    #[cfg(feature = "tinyjson")]
    use super::tinyjson::JsonValue;
    use std::{collections::HashMap, io};

    //TODO this seems wrong, re-do it again
    #[cfg(feature = "tinyjson")]
    pub fn get_json_string(json: &JsonValue, key: &str) -> Result<String, super::error::JsonNull> {
        Ok(json[key]
            .get::<String>()
            .ok_or(super::error::JsonNull { key: key.into() })?
            .into())
    }

    pub fn send_request<S: io::Read + io::Write>(
        stream: &mut S,
        start: &[u8],
        host: &[u8],
        cookies: &HashMap<Vec<u8>, Vec<u8>>,
        body: &[u8],
    ) -> Result<Vec<u8>, io::Error> {
        stream.write_all(
            &[
                start,
                b"\r\nHost: ",
                host,
                b"\nX-Requested-With: com.valvesoftware.android.steam.community",
                if cookies.is_empty() {
                    &[]
                } else {
                    b"\nCookie:"
                },
                &cookies.iter().fold(Vec::new(), |rez, (key, value)| {
                    let mut key = key.clone();
                    key.push(b'=');
                    key.extend(value);
                    if rez.is_empty() {
                        [rez, vec![b' '], key].concat().clone()
                    } else {
                        [rez, vec![b';', b' '], key].concat().clone()
                    }
                }),
                &if start.starts_with(b"POST") {
                    format!(
            "\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\nContent-Length: {}",
            body.len()
        )
                    .into_bytes()
                } else {
                    Vec::new()
                },
                b"\r\n\r\n",
                body,
            ]
            .concat(),
        )?;
        let mut res = vec![];
        stream.read_to_end(&mut res)?;
        Ok(res)
    }
    pub fn urlencode(data: &str) -> String {
        data.chars()
            .fold(String::with_capacity(data.len()), |rez, x| match x {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => rez + &x.to_string(),
                _ => format!("{}%{:02X}", rez, x as u8),
            })
    }
    //TODO needs optimization
    #[cfg(feature = "tinyjson")]
    pub fn parse_response(bytes: &Vec<u8>) -> (HashMap<Vec<u8>, Vec<u8>>, JsonValue) {
        let mut result = HashMap::new();
        for x in 12..bytes.len() {
            if bytes[x - 11] == b'\n' {
                if b"Set-Cookie" == &bytes[(x - 10)..(x)] {
                    let mut end_row = None;
                    let mut split = None;
                    for i in x..bytes.len() {
                        if split.is_none() {
                            if bytes[i] == b'=' {
                                split = Some(i)
                            }
                        }
                        if bytes[i] == b'\n' || bytes[i] == b';' {
                            end_row = Some(i);
                            break;
                        };
                    }
                    if let Some(split) = split {
                        if let Some(end_row) = end_row {
                            result.insert(
                                bytes[(x + 1)..(split)].to_vec(),
                                bytes[(split + 1)..(end_row)].to_vec(),
                            );
                        }
                    }
                }
                if (bytes[x - 12], bytes[x - 10], bytes[x - 9]) == (13, 13, 10) {
                    return (
                        result,
                        String::from_utf8_lossy(&bytes[(x - 8)..bytes.len()])
                            .parse::<JsonValue>()
                            .unwrap_or(JsonValue::Null),
                    );
                }
            }
        }
        (result, JsonValue::Null)
    }
}
pub mod error {
    #[derive(Debug, Clone)]
    pub struct JsonNull {
        pub key: String,
    }
    impl std::fmt::Display for JsonNull {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "No json value with key: {}", self.key)
        }
    }
    impl std::error::Error for JsonNull {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            None
        }
    }
}
