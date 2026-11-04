//! Fixed-origin HTTP boundary. No tokens or raw server responses reach IPC.
use reqwest::{blocking::Client, redirect::Policy, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{sync::Mutex, time::Duration};
use zeroize::Zeroizing;

const ORIGIN: &str = "https://vault.wannian.fun";
const MAX_RESPONSE: usize = 256 * 1024;
const INVALID: &str = "invalid_input";
const RESPONSE: &str = "invalid_server_response";

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum Expiry {
    Text(String),
    Number(serde_json::Number),
}

#[derive(Clone, Default, Serialize, Debug, PartialEq)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_alias: Option<String>,
}

#[derive(Clone, Serialize, Debug, PartialEq)]
pub struct SafeResponse {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Expiry>,
    #[serde(flatten)]
    pub metadata: Metadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<Vec<Metadata>>,
}

impl SafeResponse {
    fn new(state: &'static str) -> Self {
        Self {
            state,
            username: None,
            expires_at: None,
            metadata: Metadata::default(),
            candidates: None,
        }
    }
}

// Zeroizing owns sensitive native strings. No Debug implementation for session/service.
struct Session {
    token: Zeroizing<String>,
    username: String,
    expires_at: Option<Expiry>,
}

pub struct VaultService {
    client: Client,
    session: Mutex<Option<Session>>,
    // Only the test constructor can change this; no runtime config, env or IPC override.
    origin: &'static str,
}

impl VaultService {
    pub fn new() -> Result<Self, String> {
        Self::with_client(true, ORIGIN)
    }

    fn with_client(https_only: bool, origin: &'static str) -> Result<Self, String> {
        let client = Client::builder()
            .https_only(https_only)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(12))
            .no_proxy()
            .build()
            .map_err(|_| "client_unavailable".to_owned())?;
        Ok(Self {
            client,
            session: Mutex::new(None),
            origin,
        })
    }

    // Serialize requests with session changes: logout cannot be undone by a pending login.
    // All methods run on the blocking pool, never on the native UI thread.
    pub fn login(
        &self,
        username: String,
        password: Zeroizing<String>,
    ) -> Result<SafeResponse, String> {
        let mut session = self.session.lock().map_err(|_| "session_unavailable")?;
        *session = None;
        text(&username, 256)?;
        text(&password, 16384)?;
        let body = LoginBody {
            username: &username,
            password: &password,
        };
        let response = self
            .client
            .post(format!("{}/api/v1/auth/login", self.origin))
            .json(&body)
            .send()
            .map_err(|_| "vault_unreachable")?;
        if response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::FORBIDDEN
        {
            return Err("login_rejected".into());
        }
        let value = read_json(response)?;
        require_status(&value, "authenticated")?;
        let token = value
            .get("token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 16384)
            .ok_or(RESPONSE)?;
        if token.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
            return Err(RESPONSE.into());
        }
        let expires_at = match value.get("expires_at") {
            None | Some(Value::Null) => None,
            Some(value) => {
                Some(serde_json::from_value::<Expiry>(value.clone()).map_err(|_| RESPONSE)?)
            }
        };
        let expires_at = expires_at.filter(|v| match v {
            Expiry::Text(s) => {
                s.len() <= 128 && !s.contains(token) && !s.contains(password.as_str())
            }
            _ => true,
        });
        let result = SafeResponse {
            username: Some(username.clone()),
            expires_at: expires_at.clone(),
            ..SafeResponse::new("connected")
        };
        *session = Some(Session {
            token: Zeroizing::new(token.to_owned()),
            username,
            expires_at,
        });
        Ok(result)
    }

    pub fn logout(&self) -> Result<SafeResponse, String> {
        *self.session.lock().map_err(|_| "session_unavailable")? = None;
        Ok(SafeResponse::new("disconnected"))
    }

    pub fn status(&self) -> Result<SafeResponse, String> {
        let mut session = self.session.lock().map_err(|_| "session_unavailable")?;
        let Some(current) = session.as_ref() else {
            return Ok(SafeResponse::new("disconnected"));
        };
        let response = match self.request(Method::GET, "/api/v1/auth/status", &current.token, None)
        {
            Ok(value) => value,
            Err(error) if error == "vault_unreachable" => {
                return Ok(SafeResponse::new("unreachable"))
            }
            Err(error) => return Err(error),
        };
        if unauthorized(&response) {
            *session = None;
            return Ok(SafeResponse::new("expired"));
        }
        let value = read_json(response)?;
        require_status(&value, "authenticated")?;
        Ok(SafeResponse {
            username: Some(current.username.clone()),
            expires_at: current.expires_at.clone(),
            ..SafeResponse::new("connected")
        })
    }

    pub fn save(
        &self,
        service_id: String,
        account_alias: String,
        secret: Zeroizing<String>,
        credential_type: String,
    ) -> Result<SafeResponse, String> {
        text(&service_id, 256)?;
        text(&account_alias, 256)?;
        text(&secret, 65536)?;
        if !["password", "api_key", "token"].contains(&credential_type.as_str()) {
            return Err(INVALID.into());
        }
        let mut session = self.session.lock().map_err(|_| "session_unavailable")?;
        let current = session.as_ref().ok_or("not_connected")?;
        let body = SaveBody {
            service_id: &service_id,
            account_alias: &account_alias,
            secret: &secret,
            credential_type: &credential_type,
            allowed_operations: ["login", "read", "fill"],
        };
        let response = self
            .client
            .post(format!("{}/api/v1/credentials", self.origin))
            .bearer_auth(current.token.as_str())
            .json(&body)
            .send()
            .map_err(|_| "vault_unreachable")?;
        if unauthorized(&response) {
            *session = None;
            return Ok(SafeResponse::new("expired"));
        }
        let value = read_json(response)?;
        require_status(&value, "saved")?;
        let connection_id = metadata(&value, &[secret.as_str(), current.token.as_str()])?
            .connection_id
            .ok_or(RESPONSE)?;
        Ok(SafeResponse {
            metadata: Metadata {
                connection_id: Some(connection_id),
                service_id: Some(service_id),
                account_alias: Some(account_alias),
            },
            ..SafeResponse::new("saved")
        })
    }

    pub fn resolve(
        &self,
        service_id: String,
        account_alias: Option<String>,
    ) -> Result<SafeResponse, String> {
        text(&service_id, 256)?;
        if let Some(alias) = &account_alias {
            text(alias, 256)?;
        }
        let mut session = self.session.lock().map_err(|_| "session_unavailable")?;
        let current = session.as_ref().ok_or("not_connected")?;
        let body =
            json!({ "mode": "auto", "service_id": service_id, "account_alias": account_alias });
        let response = self.request(
            Method::POST,
            "/api/v1/credentials/resolve",
            &current.token,
            Some(&body),
        )?;
        if unauthorized(&response) {
            *session = None;
            return Ok(SafeResponse::new("expired"));
        }
        let value = read_json(response)?;
        require_status(&value, "resolved")?;
        let candidate = value.get("candidate").ok_or(RESPONSE)?;
        let selected = metadata(candidate, &[current.token.as_str()])?;
        if selected.connection_id.is_none() {
            return Err(RESPONSE.into());
        }
        Ok(SafeResponse {
            metadata: selected,
            ..SafeResponse::new("resolved")
        })
    }

    fn request(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<reqwest::blocking::Response, String> {
        let mut request = self
            .client
            .request(method, format!("{}{}", self.origin, path))
            .bearer_auth(token);
        if let Some(body) = body {
            request = request.json(body);
        }
        request.send().map_err(|_| "vault_unreachable".into())
    }
}

#[derive(Serialize)]
struct LoginBody<'a> {
    username: &'a str,
    password: &'a str,
}
#[derive(Serialize)]
struct SaveBody<'a> {
    service_id: &'a str,
    account_alias: &'a str,
    secret: &'a str,
    credential_type: &'a str,
    allowed_operations: [&'a str; 3],
}

fn text(value: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > max || value.contains('\0') {
        Err(INVALID.into())
    } else {
        Ok(())
    }
}
fn unauthorized(response: &reqwest::blocking::Response) -> bool {
    matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    )
}
fn read_json(response: reqwest::blocking::Response) -> Result<Value, String> {
    use std::io::Read;
    if !response.status().is_success() {
        return Err("vault_request_failed".into());
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE as u64)
    {
        return Err(RESPONSE.into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take((MAX_RESPONSE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "vault_unreachable")?;
    if bytes.len() > MAX_RESPONSE {
        return Err(RESPONSE.into());
    }
    serde_json::from_slice(&bytes).map_err(|_| RESPONSE.into())
}
fn reject_declared_error(value: &Value) -> Result<(), String> {
    if !value.is_object() {
        return Err(RESPONSE.into());
    }
    if value.get("error").is_some_and(|v| !v.is_null())
        || value
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|s| ["error", "not_found", "not_connected"].contains(&s))
    {
        return Err("vault_request_failed".into());
    }
    Ok(())
}
fn require_status(value: &Value, expected: &str) -> Result<(), String> {
    reject_declared_error(value)?;
    if value.get("status").and_then(Value::as_str) != Some(expected) {
        return Err(RESPONSE.into());
    }
    Ok(())
}
fn metadata(value: &Value, secrets: &[&str]) -> Result<Metadata, String> {
    if !value.is_object() {
        return Err(RESPONSE.into());
    }
    let field = |key: &str| -> Result<Option<String>, String> {
        match value.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s))
                if !s.is_empty()
                    && s.len() <= 256
                    && !s.chars().any(char::is_control)
                    && !secrets
                        .iter()
                        .any(|secret| !secret.is_empty() && s.contains(secret)) =>
            {
                Ok(Some(s.clone()))
            }
            _ => Err(RESPONSE.into()),
        }
    };
    Ok(Metadata {
        connection_id: field("connection_id")?,
        service_id: field("service_id")?,
        account_alias: field("account_alias")?,
    })
}

#[cfg(test)]
mod tests;
