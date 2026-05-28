use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::PyzorError;
use crate::message::Message;
use crate::{ANONYMOUS_USER, MAX_TIMESTAMP_DIFFERENCE, Result, sha1};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    pub username: String,
    pub salt: Option<String>,
    pub key: String,
}

impl Account {
    pub fn new(username: impl Into<String>, salt: Option<String>, key: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            salt,
            key: key.into(),
        }
    }

    pub fn anonymous() -> Self {
        Self::new(ANONYMOUS_USER, None, "")
    }
}

pub fn hash_key(key: &str, user: &str) -> String {
    sha1::hexdigest(format!("{}:{}", user, key.to_lowercase()).as_bytes())
}

pub fn sign_msg(hashed_key: &str, timestamp: i64, msg: &Message) -> String {
    let stripped = msg.as_string().trim().as_bytes().to_vec();
    let first = sha1::digest(&stripped);
    let mut second_input = Vec::with_capacity(first.len() + hashed_key.len() + 32);
    second_input.extend_from_slice(&first);
    second_input.extend_from_slice(format!(":{}:{}", timestamp, hashed_key).as_bytes());
    sha1::hexdigest(&second_input)
}

pub fn sign_for_account(msg: &mut Message, account: &Account, timestamp: i64) {
    msg.set_header("User", &account.username);
    msg.set_header("Time", timestamp.to_string());
    let hashed_key = hash_key(&account.key, &account.username);
    let sig = sign_msg(&hashed_key, timestamp, msg);
    msg.set_header("Sig", sig);
}

pub fn verify_signature(msg: &Message, user_key: &str) -> Result<()> {
    let timestamp: i64 = msg
        .get("Time")
        .ok_or_else(|| PyzorError::Signature("Missing timestamp.".to_string()))?
        .parse()
        .map_err(|_| PyzorError::Signature("Invalid timestamp.".to_string()))?;
    let user = msg
        .get("User")
        .ok_or_else(|| PyzorError::Signature("Missing user.".to_string()))?;
    let provided = msg
        .get("Sig")
        .ok_or_else(|| PyzorError::Signature("Missing signature.".to_string()))?;

    if (now_timestamp() - timestamp).abs() > MAX_TIMESTAMP_DIFFERENCE {
        return Err(PyzorError::Signature(
            "Timestamp not within allowed range.".to_string(),
        ));
    }

    let hashed_user_key = hash_key(user_key, user);
    let mut unsigned = msg.clone();
    unsigned.remove_all("Sig");
    let correct = sign_msg(&hashed_user_key, timestamp, &unsigned);
    if correct != provided {
        return Err(PyzorError::Signature("Invalid signature.".to_string()));
    }
    Ok(())
}

pub fn key_from_hexstr(value: &str) -> std::result::Result<(String, String), String> {
    let mut parts = value.split(',');
    let Some(salt) = parts.next() else {
        return Err(invalid_key_parts());
    };
    let Some(key) = parts.next() else {
        return Err(invalid_key_parts());
    };
    if parts.next().is_some() {
        return Err(invalid_key_parts());
    }
    Ok((salt.to_string(), key.to_string()))
}

pub fn now_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn invalid_key_parts() -> String {
    "Invalid number of parts for key; perhaps you forgot the comma at the beginning for the salt divider?".to_string()
}

#[cfg(test)]
mod tests {
    use super::{hash_key, sign_msg};
    use crate::message::Message;

    #[test]
    fn hash_key_matches_python() {
        assert_eq!(
            hash_key("testkey", "testuser"),
            "0957bd79b58263657127a39762879098286d8477"
        );
    }

    #[test]
    fn sign_msg_matches_python() {
        let timestamp = 1_381_219_396;
        let mut msg = Message::new();
        msg.add_header("Op", "ping");
        msg.add_header("Thread", "14941");
        msg.add_header("PV", "2.1");
        msg.add_header("User", "anonymous");
        msg.add_header("Time", timestamp.to_string());
        assert_eq!(
            sign_msg("00942f4668670f34c5943cf52c7ef3139fe2b8d6", timestamp, &msg),
            "2ab1bad2aae6fd80c656a896c82eef0ec1ec38a0"
        );
    }
}
