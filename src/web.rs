//Used to obtain the required cookies and OAuth token
#[cfg(feature = "base64")]
extern crate base64;
#[cfg(feature = "getrandom")]
extern crate getrandom;
#[cfg(feature = "num-bigint")]
extern crate num_bigint;
#[cfg(feature = "tinyjson")]
extern crate tinyjson;
use self::num_bigint::BigUint;
use self::tinyjson::JsonValue;
use std::{
    collections::HashMap,
    io,
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Default)]
pub struct UserLogin {
    pub name: String,
    pub pass: String,
    pub id: u64,
    pub cid: Option<String>,
    pub web_cookies: HashMap<Vec<u8>, Vec<u8>>,
    pub web_login: Option<JsonValue>,
    pub req_mail: Option<(String, String)>,
    pub req_captcha: Option<(String, String)>,
    pub req_totp: Option<String>,
    pub server_time: Option<i64>,
}
impl UserLogin {
    pub const IP_COMM: &'static str = "steamcommunity.com";
    pub const IP_API: &'static str = "api.steampowered.com";
    pub fn new<S>(name: S, pass: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            name: name.into(),
            pass: pass.into(),
            ..Default::default()
        }
    }

    //TODO test some more
    ///As far as I can tell the session is irrelavent and should be avoided
    ///stream should link to UserLogin::IP_COMM
    pub fn set_session<S: io::Read + io::Write>(
        &mut self,
        stream: &mut S,
    ) -> Result<(), io::Error> {
        self.web_cookies
            .insert(b"mobileClientVersion".to_vec(), b"0 (2.1.3)".to_vec());
        self.web_cookies
            .insert(b"mobileClient".to_vec(), b"android".to_vec());
        self.web_cookies
            .insert(b"Steam_Language".to_vec(), b"english".to_vec());
        match send_request(
            stream,
            b"GET /login HTTP/1.0",
            Self::IP_COMM.as_bytes(),
            &self.web_cookies,
            b"",
        ) {
            Ok(r) => {
                self.web_cookies.extend(parse_response(&r).0);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    ///Should be called if there is any doubt that sys time is accurate
    ///stream should link to UserLogin::IP_API
    pub fn set_offset<S: io::Read + io::Write>(
        &mut self,
        stream: &mut S,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.server_time = Some(get_time_offset(stream)?);
        Ok(())
    }

    pub fn get_rsa<S: io::Read + io::Write>(
        &self,
        stream: &mut S,
    ) -> Result<(BigUint, BigUint, String), Box<dyn std::error::Error>> {
        let json = parse_response(&send_request(
            stream,
            b"POST /login/getrsakey HTTP/1.0",
            b"steamcommunity.com",
            &self.web_cookies,
            &format!(
                "donotcache={}&username={}",
                if let Ok(time) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                {
                    time.as_secs()
                } else {
                    1
                },
                &self.name
            )
            .into_bytes(),
        )?)
        .1;
        Ok((
            //TODO handle parse_bytes unwrap
            BigUint::parse_bytes(get_json_string(&json, "publickey_exp")?.as_bytes(), 16).unwrap(),
            BigUint::parse_bytes(get_json_string(&json, "publickey_mod")?.as_bytes(), 16).unwrap(),
            get_json_string(&json, "timestamp")?,
        ))
    }
    //TODO test, no clue if this works
    pub fn login<S: io::Read + io::Write + std::clone::Clone>(
        &mut self,
        stream: &mut S,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rsa = self.get_rsa(&mut stream.clone())?;
        let request = send_request(
        stream,
    b"POST /login/dologin HTTP/1.0",
    b"steamcommunity.com",
    &self.web_cookies,
    &format!(
        "donotcache={}&password={}&username={}&twofactorcode=&emailauth=&loginfriendlyname=&captchagid=-1&captcha_text=&emailsteamid=&rsatimestamp={}&remember_login=true",
        if let Ok(time) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            time.as_secs()
        } else {
            1
        },
        pad_encrypt(&self.pass,&rsa.0,&rsa.1),
        &self.name,
        &rsa.2,
    )
    .into_bytes(),
    );
        //TODO handle the boat load of  possible errors here
        Ok(())
    }
    pub fn login_with_enc_pass<S: io::Read + io::Write>(
        &mut self,
        stream: &mut S,
        encrypted_pass: &str,
        timestamp: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        parse_response(&send_request(
        stream,
    b"POST /login/dologin HTTP/1.0",
    b"steamcommunity.com",
    &self.web_cookies,
    &format!(
        "donotcache={}&password={}&username={}&twofactorcode=&emailauth=&loginfriendlyname=&captchagid=-1&captcha_text=&emailsteamid=&rsatimestamp={}&remember_login=true",
        if let Ok(time) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            time.as_secs()
        } else {
            1
        },
        encrypted_pass,
        &self.name,
        timestamp
    )
    .into_bytes(),
)?);
        Ok(())
    }
}
pub fn get_time_offset<S: io::Read + io::Write>(
    stream: &mut S,
) -> Result<i64, Box<dyn std::error::Error>> {
    Ok((get_json_string(
        &parse_response(&send_request(
            stream,
            b"POST /ITwoFactorService/QueryTime/v0001 HTTP/1.0",
            UserLogin::IP_API.as_bytes(),
            &HashMap::new(),
            b"",
        )?)
        .1["response"],
        "server_time",
    )?
    .parse::<i128>()?
    .saturating_sub(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i128)) as i64)
}
fn pad_encrypt(password: &str, exponent: &BigUint, modulus: &BigUint) -> String {
    let mut padding = std::vec::Vec::with_capacity(modulus.bits() / 8);
    padding.push(0);
    padding.push(2);
    add_rand_bytes(&mut padding, (modulus.bits() / 8) - 3 - password.len());
    padding.push(0);
    padding.extend_from_slice(password.as_bytes());
    urlencode(&base64::encode(
        &(BigUint::from_bytes_be(&padding).modpow(exponent, modulus)).to_bytes_be(),
    ))
}
//TODO this seems wrong, re-do it again
fn get_json_string(json: &JsonValue, key: &str) -> Result<String, error::JsonNull> {
    Ok(json[key]
        .get::<String>()
        .ok_or(error::JsonNull { key: key.into() })?
        .into())
}

fn add_rand_bytes(vec: &mut Vec<u8>, range: usize) {
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
            return;
        }
    }
    for i in 0..range {
        vec.push(
            ((if let Ok(time) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                time.as_nanos() % 256
            } else {
                i as u128
            } ^ 571)
                % 255) as u8
                + 1,
        );
    }
}
fn urlencode(data: &str) -> String {
    data.chars()
        .fold(String::with_capacity(data.len()), |rez, x| match x {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => rez + &x.to_string(),
            _ => format!("{}%{:02X}", rez, x as u8),
        })
}

fn send_request<S: io::Read + io::Write>(
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
//TODO needs optimization
fn parse_response(bytes: &Vec<u8>) -> (HashMap<Vec<u8>, Vec<u8>>, JsonValue) {
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
mod error {
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
