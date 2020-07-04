//Used to obtain the required cookies and OAuth token
#[cfg(feature = "base64")]
extern crate base64;
#[cfg(feature = "num-bigint")]
extern crate num_bigint;
#[cfg(feature = "tinyjson")]
extern crate tinyjson;
#[cfg(feature = "num-bigint")]
use self::num_bigint::BigUint;
#[cfg(feature = "tinyjson")]
use self::tinyjson::JsonValue;
use root::web::{send_request, urlencode};
use std::{collections::HashMap, io};

#[derive(Default)]
#[cfg(feature = "steam_web")]
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
/// steamcommunity.com
pub const IP_COMM: &'static str = "steamcommunity.com";
/// api.steampowered.com
pub const IP_API: &'static str = "api.steampowered.com";
#[cfg(feature = "steam_web")]
impl UserLogin {
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
    ///
    ///stream should link to [IP_COMM](constant.IP_COMM.html)
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
            IP_COMM.as_bytes(),
            &self.web_cookies,
            b"",
        ) {
            Ok(r) => {
                self.web_cookies
                    .extend(super::root::web::parse_response(&r).0);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    ///Should be called if there is any doubt that sys time is accurate
    ///
    ///stream should link to [UserLogin::IP_API](constant.IP_API.html)
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
        let json = super::root::web::parse_response(&send_request(
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
            BigUint::parse_bytes(
                super::root::web::get_json_string(&json, "publickey_exp")?.as_bytes(),
                16,
            )
            .unwrap(),
            BigUint::parse_bytes(
                super::root::web::get_json_string(&json, "publickey_mod")?.as_bytes(),
                16,
            )
            .unwrap(),
            super::root::web::get_json_string(&json, "timestamp")?,
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
        super::root::crypto::pad_encrypt(&self.pass,&rsa.0,&rsa.1),
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
        super::root::web::parse_response(&send_request(
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
//TODO
//maybe get rid of tinyjson dep by adding an alternate compile in root
//this is getting overcomplicated but importing a library for this one function
//does not sit well with me
#[cfg(feature = "tinyjson")]
pub fn get_time_offset<S: io::Read + io::Write>(
    stream: &mut S,
) -> Result<i64, Box<dyn std::error::Error>> {
    use std::time::SystemTime;
    Ok((super::root::web::get_json_string(
        &super::root::web::parse_response(&send_request(
            stream,
            b"POST /ITwoFactorService/QueryTime/v0001 HTTP/1.0",
            IP_API.as_bytes(),
            &HashMap::new(),
            b"",
        )?)
        .1["response"],
        "server_time",
    )?
    .parse::<i128>()?
    .saturating_sub(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as i128,
    )) as i64)
}
