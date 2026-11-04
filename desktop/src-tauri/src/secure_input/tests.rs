use super::*;
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    server: SecureInput,
    port: u16,
    token: String,
    env_file: std::path::PathBuf,
    requests: mpsc::Receiver<SecureInputRequest>,
}

impl Fixture {
    fn new() -> Self {
        let (sender, requests) = mpsc::channel();
        let notify: Notify = Arc::new(move |request: &SecureInputRequest| {
            let _ = sender.send(request.clone());
        });
        let unique = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let env_file = std::env::temp_dir().join(format!(
            "agent-vault-secure-input-test-{}-{}.env",
            std::process::id(),
            unique
        ));
        let server =
            SecureInput::start_with_env_file(env_file.clone(), notify).expect("server start");
        let port = server.port();
        // The token is learned through the exchange file, exactly like the parent MCP does.
        let content = std::fs::read_to_string(&env_file).expect("env exchange file readable");
        let token = content
            .lines()
            .find_map(|line| line.strip_prefix("X_VAULT_LOCAL_TOKEN="))
            .expect("token line")
            .to_owned();
        Self {
            server,
            port,
            token,
            env_file,
            requests,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.env_file);
    }
}

fn exchange(port: u16, token: Option<&str>, request: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("loopback connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let header = match token {
        Some(token) => format!("X-Vault-Local-Token: {}\r\n", token),
        None => String::new(),
    };
    let wire = request.replace("{TOKEN}", &header);
    stream.write_all(wire.as_bytes()).expect("request written");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

fn post(port: u16, token: Option<&str>, body: &str) -> (u16, String) {
    exchange(
        port,
        token,
        &format!(
            "POST /vault/secure-input HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{{TOKEN}}Connection: close\r\n\r\n{}",
            body.len(),
            body
        ),
    )
}

fn get(port: u16, token: Option<&str>, id: &str) -> (u16, String) {
    exchange(
        port,
        token,
        &format!(
            "GET /vault/secure-input/{} HTTP/1.1\r\nHost: 127.0.0.1\r\n{{TOKEN}}Connection: close\r\n\r\n",
            id
        ),
    )
}

fn request_body(id: &str, timeout_s: u64) -> String {
    serde_json::to_string(&json!({
        "request_id": id,
        "service": "github",
        "account": "work",
        "prompt": "Enter the vault secret",
        "timeout_s": timeout_s
    }))
    .unwrap()
}

#[test]
fn remove_env_file_deletes_the_exchange_file() {
    // main.rs calls this on RunEvent::Exit (tray quit); the graceful path must clear the token file.
    let fixture = Fixture::new();
    assert!(fixture.env_file.exists());
    fixture.server.remove_env_file();
    assert!(!fixture.env_file.exists());
}

#[test]
fn token_is_required_on_every_request() {
    let fixture = Fixture::new();
    let body = request_body("req-auth", 30);
    let wrong = "1".repeat(64);
    for token in [None, Some("short"), Some(wrong.as_str())] {
        let (status, response) = post(fixture.port, token, &body);
        assert_eq!(status, 401);
        assert!(response.contains("unauthorized"));
        let (status, _) = get(fixture.port, token, "req-auth");
        assert_eq!(status, 401);
    }
    let (status, _) = get(fixture.port, Some(&fixture.token), "req-auth");
    assert_eq!(status, 404);
}

#[test]
fn submit_flow_delivers_secret_exactly_once() {
    let fixture = Fixture::new();
    let token = Some(fixture.token.as_str());
    let (status, response) = post(fixture.port, token, &request_body("req-submit", 30));
    assert_eq!(status, 200);
    assert!(response.contains("pending"));
    let request = fixture
        .requests
        .recv_timeout(Duration::from_secs(3))
        .expect("notify missing");
    assert_eq!(request.request_id, "req-submit");
    assert_eq!(request.service, "github");
    assert_eq!(request.account, "work");
    assert_eq!(request.prompt, "Enter the vault secret");
    assert_eq!(request.timeout_s, 30);
    let (status, response) = get(fixture.port, token, "req-submit");
    assert_eq!(status, 200);
    assert!(response.contains("pending"));
    fixture
        .server
        .submit("req-submit", Zeroizing::new("synthetic_secret_local".to_owned()))
        .expect("submit accepted");
    let (status, response) = get(fixture.port, token, "req-submit");
    assert_eq!(status, 200);
    let value: Value = serde_json::from_str(&response).expect("completed json");
    assert_eq!(value["status"], json!("completed"));
    assert_eq!(value["secret"], json!("synthetic_secret_local"));
    // Completed is one-shot: the entry is gone and never echoes the secret again.
    let (status, response) = get(fixture.port, token, "req-submit");
    assert_eq!(status, 404);
    assert!(!response.contains("synthetic_secret_local"));
}

#[test]
fn decline_flow_returns_declined_once() {
    let fixture = Fixture::new();
    let token = Some(fixture.token.as_str());
    let (status, _) = post(fixture.port, token, &request_body("req-decline", 30));
    assert_eq!(status, 200);
    fixture.server.decline("req-decline").expect("decline accepted");
    let (status, response) = get(fixture.port, token, "req-decline");
    assert_eq!(status, 200);
    assert!(response.contains("declined"));
    assert!(!response.contains("secret"));
    let (status, _) = get(fixture.port, token, "req-decline");
    assert_eq!(status, 404);
    // A resolved request can no longer be re-submitted or re-declined.
    assert_eq!(
        fixture
            .server
            .submit("req-decline", Zeroizing::new("late_secret".to_owned()))
            .unwrap_err(),
        "not_found"
    );
}

#[test]
fn pending_request_expires_after_timeout() {
    let fixture = Fixture::new();
    let token = Some(fixture.token.as_str());
    let (status, _) = post(fixture.port, token, &request_body("req-exp", 1));
    assert_eq!(status, 200);
    thread::sleep(Duration::from_millis(1300));
    assert_eq!(
        fixture
            .server
            .submit("req-exp", Zeroizing::new("late_secret".to_owned()))
            .unwrap_err(),
        "not_found"
    );
    let (status, response) = get(fixture.port, token, "req-exp");
    assert_eq!(status, 200);
    assert!(response.contains("expired"));
    assert!(!response.contains("late_secret"));
    let (status, _) = get(fixture.port, token, "req-exp");
    assert_eq!(status, 404);
}

#[test]
fn invalid_requests_and_routing_are_rejected() {
    let fixture = Fixture::new();
    let token = Some(fixture.token.as_str());
    let (status, _) = post(fixture.port, token, "{ not json");
    assert_eq!(status, 400);
    let traversal = serde_json::to_string(&json!({
        "request_id": "../escape",
        "service": "github",
        "prompt": "p",
        "timeout_s": 30
    }))
    .unwrap();
    assert_eq!(post(fixture.port, token, &traversal).0, 400);
    for timeout in [0u64, 3601] {
        let out_of_range = serde_json::to_string(&json!({
            "request_id": "req-range",
            "service": "github",
            "prompt": "p",
            "timeout_s": timeout
        }))
        .unwrap();
        assert_eq!(post(fixture.port, token, &out_of_range).0, 400);
    }
    let missing_prompt = serde_json::to_string(&json!({
        "request_id": "req-missing",
        "service": "github",
        "timeout_s": 30
    }))
    .unwrap();
    assert_eq!(post(fixture.port, token, &missing_prompt).0, 400);
    let (status, _) = exchange(
        fixture.port,
        token,
        "GET /other HTTP/1.1\r\nHost: 127.0.0.1\r\n{TOKEN}Connection: close\r\n\r\n",
    );
    assert_eq!(status, 404);
    let (status, _) = exchange(
        fixture.port,
        token,
        "GET /vault/secure-input HTTP/1.1\r\nHost: 127.0.0.1\r\n{TOKEN}Connection: close\r\n\r\n",
    );
    assert_eq!(status, 405);
    let (status, _) = exchange(
        fixture.port,
        token,
        "POST /vault/secure-input/req-x HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n{TOKEN}Connection: close\r\n\r\n",
    );
    assert_eq!(status, 405);
    let (status, _) = get(fixture.port, token, "never-seen");
    assert_eq!(status, 404);
    // An id with invalid (but URL-safe) characters still routes to a plain 404 miss.
    let (status, _) = get(fixture.port, token, "bad-id!");
    assert_eq!(status, 404);
    // A raw space in the request target is malformed HTTP and rejected at the parser level.
    let (status, _) = exchange(
        fixture.port,
        token,
        "GET /vault/secure-input/bad id! HTTP/1.1\r\nHost: 127.0.0.1\r\n{TOKEN}Connection: close\r\n\r\n",
    );
    assert_eq!(status, 400);
    // Live duplicate ids conflict.
    let (status, _) = post(fixture.port, token, &request_body("req-dup", 30));
    assert_eq!(status, 200);
    let (status, _) = post(fixture.port, token, &request_body("req-dup", 30));
    assert_eq!(status, 409);
}

#[test]
fn concurrent_requests_resolve_independently() {
    let fixture = Fixture::new();
    let token = Some(fixture.token.as_str());
    for id in ["req-a", "req-b", "req-c"] {
        let (status, _) = post(fixture.port, token, &request_body(id, 30));
        assert_eq!(status, 200);
    }
    assert!(fixture.requests.recv_timeout(Duration::from_secs(3)).is_ok());
    fixture
        .server
        .submit("req-b", Zeroizing::new("secret_b".to_owned()))
        .expect("submit b");
    fixture.server.decline("req-c").expect("decline c");
    let (status, response) = get(fixture.port, token, "req-a");
    assert_eq!(status, 200);
    assert!(response.contains("pending"));
    let (status, response) = get(fixture.port, token, "req-b");
    assert_eq!(status, 200);
    assert!(response.contains("completed"));
    let (status, response) = get(fixture.port, token, "req-c");
    assert_eq!(status, 200);
    assert!(response.contains("declined"));
}

#[test]
fn env_exchange_and_capacity_limits_hold() {
    let fixture = Fixture::new();
    let token = Some(fixture.token.as_str());
    let content = std::fs::read_to_string(&fixture.env_file).expect("env file");
    let url = content
        .lines()
        .find_map(|line| line.strip_prefix("VAULT_SECURE_INPUT_URL="))
        .expect("url line");
    assert_eq!(
        url,
        &format!("http://127.0.0.1:{}/vault/secure-input", fixture.port)
    );
    assert_eq!(fixture.token.len(), 64);
    assert!(fixture.token.bytes().all(|byte| byte.is_ascii_hexdigit()));
    // The local token never appears in any non-handoff response body.
    let (status, response) = get(fixture.port, token, "no-such-id");
    assert_eq!(status, 404);
    assert!(!response.contains(&fixture.token));
    let (status, response) = post(fixture.port, None, &request_body("req-sec", 30));
    assert_eq!(status, 401);
    assert!(!response.contains(&fixture.token));
    // Capacity: the first MAX_PENDING requests register, the next is refused.
    for index in 0..(MAX_PENDING + 1) {
        let (status, _) = post(
            fixture.port,
            token,
            &request_body(&format!("cap-{}", index), 30),
        );
        if index < MAX_PENDING {
            assert_eq!(status, 200);
        } else {
            assert_eq!(status, 429);
        }
    }
    // Frontend validation mirrors the HTTP surface.
    assert_eq!(
        fixture
            .server
            .submit("bad id!", Zeroizing::new("synthetic".to_owned()))
            .unwrap_err(),
        "invalid_input"
    );
    assert_eq!(
        fixture
            .server
            .submit("cap-0", Zeroizing::new(String::new()))
            .unwrap_err(),
        "invalid_input"
    );
}
