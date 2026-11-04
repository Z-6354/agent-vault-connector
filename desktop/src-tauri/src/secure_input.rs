//! Loopback secure-input server for the vault MCP `request_secure_input` tool.
//!
//! Contract (loopback only, `127.0.0.1`, ephemeral port):
//! - `POST /vault/secure-input` with JSON `{request_id, service, account, prompt, timeout_s}`
//!   registers a pending request, notifies the main window (event `secure-input`),
//!   and answers `200 {"status":"pending"}`.
//! - `GET /vault/secure-input/<request_id>` polls; terminal answers are
//!   `{"status":"completed","secret":...}` (one-shot, then the entry is dropped),
//!   `{"status":"declined"}`, or `{"status":"expired"}` after `timeout_s`.
//! - Every request must carry `X-Vault-Local-Token` matching the per-session
//!   32-byte random token; anything else gets `401`.
//! - URL + token are exchanged to the MCP parent through a key=value env file
//!   (default `%TEMP%\agent-vault-secure-input.env`, override via
//!   `VAULT_SECURE_INPUT_ENV_FILE`): lines `VAULT_SECURE_INPUT_URL=...` and
//!   `X_VAULT_LOCAL_TOKEN=...`.
//! - The listener only starts after the token exchange succeeds; failures are
//!   fixed error codes. Secrets are held in `Zeroizing` buffers, never logged
//!   and never persisted.
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const NOTIFY_EVENT: &str = "secure-input";
pub type Notify = Arc<dyn Fn(&SecureInputRequest) + Send + Sync + 'static>;

const MAX_PENDING: usize = 16;
const MAX_HEADERS: usize = 8 * 1024;
const MAX_BODY: usize = 64 * 1024;
const MAX_SECRET: usize = 65536;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_POLL: Duration = Duration::from_millis(10);
const REAP_GRACE: Duration = Duration::from_secs(60);
const SWEEP_EVERY: u32 = 25;
const ENV_FILE_VAR: &str = "VAULT_SECURE_INPUT_ENV_FILE";
const ENV_FILE_NAME: &str = "agent-vault-secure-input.env";
const PATH_PREFIX: &str = "/vault/secure-input";
const PATH_ID_PREFIX: &str = "/vault/secure-input/";

/// Payload shown on the masked card. No secret material; sent to the main window only.
#[derive(Clone, Serialize, Debug)]
pub struct SecureInputRequest {
    pub request_id: String,
    pub service: String,
    pub account: String,
    pub prompt: String,
    pub timeout_s: u64,
}

enum Slot {
    Waiting,
    Completed(Zeroizing<String>),
    Declined,
}

struct Pending {
    deadline: Instant,
    slot: Slot,
}

struct Inner {
    token: Zeroizing<String>,
    requests: Mutex<HashMap<String, Pending>>,
}

/// Managed Tauri state. Server threads live for the process lifetime.
pub struct SecureInput {
    inner: Arc<Inner>,
    port: u16,
    env_file: PathBuf,
}

impl SecureInput {
    pub fn start(notify: Notify) -> Result<Self, &'static str> {
        Self::start_with_env_file(env_file_path(), notify)
    }

    fn start_with_env_file(env_file: PathBuf, notify: Notify) -> Result<Self, &'static str> {
        let token = random_token_hex()?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "listener_unavailable")?;
        let port = listener
            .local_addr()
            .map_err(|_| "listener_unavailable")?
            .port();
        let url = format!("http://127.0.0.1:{}/vault/secure-input", port);
        // Token exchange must succeed before any listener thread starts: no silent
        // open listener without a way for the parent to authenticate.
        write_env_file(&env_file, &url, token.as_str()).map_err(|_| "token_exchange_failed")?;
        listener.set_nonblocking(true).map_err(|_| "listener_unavailable")?;
        let inner = Arc::new(Inner {
            token,
            requests: Mutex::new(HashMap::new()),
        });
        let accept_inner = inner.clone();
        let spawned = thread::Builder::new()
            .name("secure-input-accept".to_owned())
            .spawn(move || accept_loop(listener, accept_inner, notify));
        match spawned {
            Ok(_) => Ok(SecureInput { inner, port, env_file }),
            Err(_) => {
                let _ = std::fs::remove_file(&env_file);
                Err("listener_unavailable")
            }
        }
    }

    /// Resolve a pending request with the user-supplied secret (frontend command).
    pub fn submit(&self, request_id: &str, secret: Zeroizing<String>) -> Result<(), &'static str> {
        if !valid_id(request_id)
            || secret.is_empty()
            || secret.len() > MAX_SECRET
            || secret.contains('\0')
        {
            return Err("invalid_input");
        }
        let mut requests = self.inner.requests.lock().map_err(|_| "state_unavailable")?;
        let Some(pending) = requests.get_mut(request_id) else {
            return Err("not_found");
        };
        if pending.deadline <= Instant::now() {
            return Err("not_found");
        }
        match pending.slot {
            Slot::Waiting => {
                pending.slot = Slot::Completed(secret);
                Ok(())
            }
            _ => Err("not_found"),
        }
    }

    /// Resolve a pending request as declined (frontend command).
    pub fn decline(&self, request_id: &str) -> Result<(), &'static str> {
        if !valid_id(request_id) {
            return Err("invalid_input");
        }
        let mut requests = self.inner.requests.lock().map_err(|_| "state_unavailable")?;
        let Some(pending) = requests.get_mut(request_id) else {
            return Err("not_found");
        };
        if pending.deadline <= Instant::now() {
            return Err("not_found");
        }
        match pending.slot {
            Slot::Waiting => {
                pending.slot = Slot::Declined;
                Ok(())
            }
            _ => Err("not_found"),
        }
    }

    /// Remove the env exchange file (app exit). Stale files only cause refused
    /// connections for the parent.
    pub fn remove_env_file(&self) {
        let _ = std::fs::remove_file(&self.env_file);
    }

    fn port(&self) -> u16 {
        self.port
    }
}

fn env_file_path() -> PathBuf {
    if let Some(path) = std::env::var_os(ENV_FILE_VAR) {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            return path;
        }
    }
    std::env::temp_dir().join(ENV_FILE_NAME)
}

fn write_env_file(path: &Path, url: &str, token: &str) -> Result<(), ()> {
    let content = Zeroizing::new(format!(
        "VAULT_SECURE_INPUT_URL={}\nX_VAULT_LOCAL_TOKEN={}\n",
        url, token
    ));
    // Atomic replace so a concurrently reading parent never sees a torn file.
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    std::fs::write(&temporary, content.as_bytes()).map_err(|_| ())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&temporary, path).map_err(|_| ())?;
    Ok(())
}

fn random_token_hex() -> Result<Zeroizing<String>, &'static str> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *bytes).map_err(|_| "entropy_unavailable")?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut token = Zeroizing::new(String::with_capacity(64));
    for byte in bytes.iter() {
        token.push(HEX[(byte >> 4) as usize] as char);
        token.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(token)
}

fn accept_loop(listener: TcpListener, inner: Arc<Inner>, notify: Notify) {
    let mut tick: u32 = 0;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let inner = inner.clone();
                let notify = notify.clone();
                let _ = thread::Builder::new()
                    .name("secure-input-conn".to_owned())
                    .spawn(move || handle_connection(stream, &inner, &notify));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
        tick = tick.wrapping_add(1);
        if tick % SWEEP_EVERY == 0 {
            sweep(&inner);
        }
        thread::sleep(ACCEPT_POLL);
    }
}

/// Drop finished/expired entries so unobserved secrets are zeroized promptly.
fn sweep(inner: &Inner) {
    if let Ok(mut requests) = inner.requests.lock() {
        let now = Instant::now();
        requests.retain(|_, pending| now < pending.deadline + REAP_GRACE);
    }
}

struct RawRequest {
    method: String,
    target: String,
    token: Option<String>,
    body: Vec<u8>,
}

fn handle_connection(mut stream: TcpStream, inner: &Inner, notify: &Notify) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
    let raw = match read_request(&mut stream) {
        Ok(raw) => raw,
        Err(code) => {
            let (code, body) = json_response(code, parse_error_body(code));
            write_response(&mut stream, code, &body);
            return;
        }
    };
    let received = raw.token.as_deref().unwrap_or("");
    if !token_matches(received, inner.token.as_str()) {
        let (code, body) = json_response(401, json!({ "error": "unauthorized" }));
        write_response(&mut stream, code, &body);
        return;
    }
    let path = raw.target.split('?').next().unwrap_or("").to_owned();
    let (code, body) = if path.contains("..") {
        json_response(404, json!({ "error": "not_found" }))
    } else if path == PATH_PREFIX {
        if raw.method == "POST" {
            handle_post(inner, notify, &raw.body)
        } else {
            json_response(405, json!({ "error": "method_not_allowed" }))
        }
    } else if let Some(id) = path.strip_prefix(PATH_ID_PREFIX) {
        if raw.method == "GET" {
            handle_get(inner, id)
        } else {
            json_response(405, json!({ "error": "method_not_allowed" }))
        }
    } else {
        json_response(404, json!({ "error": "not_found" }))
    };
    write_response(&mut stream, code, &body);
}

fn handle_post(inner: &Inner, notify: &Notify, body: &[u8]) -> (u16, Zeroizing<String>) {
    let invalid = || json_response(400, json!({ "error": "invalid_input" }));
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return invalid();
    };
    if !value.is_object() {
        return invalid();
    }
    let Some(request_id) = value.get("request_id").and_then(Value::as_str) else {
        return invalid();
    };
    if !valid_id(request_id) {
        return invalid();
    }
    let service = valid_text(value.get("service").and_then(Value::as_str), 256, true);
    let account = valid_text(value.get("account").and_then(Value::as_str), 256, false);
    let prompt = valid_text(value.get("prompt").and_then(Value::as_str), 2048, true);
    let timeout_s = value
        .get("timeout_s")
        .and_then(Value::as_u64)
        .filter(|timeout| (1..=3600).contains(timeout));
    let (Some(service), Some(account), Some(prompt), Some(timeout_s)) =
        (service, account, prompt, timeout_s)
    else {
        return invalid();
    };
    let request = SecureInputRequest {
        request_id: request_id.to_owned(),
        service,
        account,
        prompt,
        timeout_s,
    };
    let deadline = Instant::now() + Duration::from_secs(timeout_s);
    let mut requests = match inner.requests.lock() {
        Ok(requests) => requests,
        Err(_) => return json_response(500, json!({ "error": "state_unavailable" })),
    };
    // Replace only a dead entry carrying the same id; live duplicates conflict.
    if let Some(pending) = requests.get(request_id) {
        if pending.deadline <= Instant::now() {
            requests.remove(request_id);
        } else {
            return json_response(409, json!({ "error": "duplicate" }));
        }
    }
    if requests.len() >= MAX_PENDING {
        return json_response(429, json!({ "error": "busy" }));
    }
    requests.insert(
        request.request_id.clone(),
        Pending {
            deadline,
            slot: Slot::Waiting,
        },
    );
    drop(requests);
    notify(&request);
    json_response(200, json!({ "status": "pending" }))
}

fn handle_get(inner: &Inner, id: &str) -> (u16, Zeroizing<String>) {
    if !valid_id(id) {
        return json_response(404, json!({ "error": "not_found" }));
    }
    let now = Instant::now();
    let mut requests = match inner.requests.lock() {
        Ok(requests) => requests,
        Err(_) => return json_response(500, json!({ "error": "state_unavailable" })),
    };
    let Some(pending) = requests.get_mut(id) else {
        return json_response(404, json!({ "error": "not_found" }));
    };
    if pending.deadline <= now {
        requests.remove(id);
        return json_response(200, json!({ "status": "expired" }));
    }
    let mut secret: Option<Zeroizing<String>> = None;
    let mut declined = false;
    match pending.slot {
        Slot::Waiting => {}
        Slot::Declined => {
            declined = true;
        }
        Slot::Completed(ref mut value) => {
            secret = Some(std::mem::replace(value, Zeroizing::new(String::new())));
        }
    }
    if declined {
        requests.remove(id);
        return json_response(200, json!({ "status": "declined" }));
    }
    if let Some(secret) = secret {
        // One-shot handoff: the entry (and its secret) is dropped with this response.
        requests.remove(id);
        return (
            200,
            Zeroizing::new(
                serde_json::to_string(&json!({ "status": "completed", "secret": secret.as_str() }))
                    .unwrap_or_else(|_| "{}".to_owned()),
            ),
        );
    }
    json_response(200, json!({ "status": "pending" }))
}

fn read_request(stream: &mut TcpStream) -> Result<RawRequest, u16> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if let Some(end) = find_terminator(&bytes) {
            break end;
        }
        if bytes.len() > MAX_HEADERS {
            return Err(431);
        }
        let read = stream.read(&mut chunk).map_err(|_| 400u16)?;
        if read == 0 {
            return Err(400u16);
        }
        bytes.extend_from_slice(&chunk[..read]);
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).map_err(|_| 400u16)?;
    let mut lines = headers.split("\r\n");
    let request_line = lines.next().ok_or(400u16)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(400u16)?.to_owned();
    let target = parts.next().ok_or(400u16)?.to_owned();
    let version = parts.next().ok_or(400u16)?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Err(400);
    }
    if target.is_empty() || !target.starts_with('/') {
        return Err(400);
    }
    let mut token = None;
    let mut content_length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(400);
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "x-vault-local-token" => token = Some(value.to_owned()),
            "content-length" => content_length = value.parse::<usize>().map_err(|_| 400u16)?,
            _ => {}
        }
    }
    if content_length > MAX_BODY {
        return Err(413);
    }
    let mut body = bytes[header_end + 4..].to_vec();
    if body.len() > content_length {
        body.truncate(content_length);
    }
    while body.len() < content_length {
        let read = stream.read(&mut chunk).map_err(|_| 400u16)?;
        if read == 0 {
            return Err(400u16);
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > MAX_BODY {
            return Err(413);
        }
    }
    Ok(RawRequest {
        method,
        target,
        token,
        body,
    })
}

fn find_terminator(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn token_matches(received: &str, expected: &str) -> bool {
    let received = received.as_bytes();
    let expected = expected.as_bytes();
    if received.len() != expected.len() {
        return false;
    }
    let mut difference = 0u8;
    for index in 0..expected.len() {
        difference |= received[index] ^ expected[index];
    }
    difference == 0
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|byte| {
            matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_')
        })
}

fn valid_text(value: Option<&str>, max: usize, required: bool) -> Option<String> {
    match value {
        None => {
            if required {
                None
            } else {
                Some(String::new())
            }
        }
        Some(text) => {
            if !text.contains('\0') && text.len() <= max && (!required || !text.is_empty()) {
                Some(text.to_owned())
            } else {
                None
            }
        }
    }
}

fn json_response(code: u16, value: Value) -> (u16, Zeroizing<String>) {
    (
        code,
        Zeroizing::new(serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_owned())),
    )
}

fn parse_error_body(code: u16) -> Value {
    match code {
        413 => json!({ "error": "payload_too_large" }),
        431 => json!({ "error": "headers_too_large" }),
        _ => json!({ "error": "bad_request" }),
    }
}

fn write_response(stream: &mut TcpStream, code: u16, body: &str) {
    let reason = reason(code);
    let wire = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        code,
        reason,
        body.len()
    );
    let _ = stream.write_all(wire.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests;
