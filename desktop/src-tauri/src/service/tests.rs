use super::*;
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

struct Reply {
    status: u16,
    body: String,
    headers: &'static str,
}
impl Reply {
    fn json(body: Value) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
            headers: "Content-Type: application/json\r\n",
        }
    }
    fn status(status: u16) -> Self {
        Self {
            status,
            body: "{\"detail\":\"private server diagnostic\"}".into(),
            headers: "Content-Type: application/json\r\n",
        }
    }
}
struct Server {
    origin: &'static str,
    requests: mpsc::Receiver<(String, Value)>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn new(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin =
            Box::leak(format!("http://{}", listener.local_addr().unwrap()).into_boxed_str());
        let (tx, requests) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let ended = stop.clone();
        let thread = thread::spawn(move || {
            let mut replies: VecDeque<_> = replies.into();
            while !ended.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Windows accepts inherit listener nonblocking mode.
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        if let Some(request) = read_request(&mut stream) {
                            let _ = tx.send(request);
                        }
                        let reply = replies.pop_front().unwrap_or_else(|| Reply::status(500));
                        let wire = format!("HTTP/1.1 {} Fixture\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", reply.status, reply.headers, reply.body.len(), reply.body);
                        let _ = stream.write_all(wire.as_bytes());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            origin,
            requests,
            stop,
            thread: Some(thread),
        }
    }
    fn service(&self) -> VaultService {
        VaultService::with_client(false, self.origin).unwrap()
    }
    fn request(&self) -> (String, Value) {
        self.requests
            .recv_timeout(Duration::from_secs(3))
            .expect("fixture request missing")
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
fn read_request(stream: &mut TcpStream) -> Option<(String, Value)> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end]).ok()?;
            let length = headers
                .lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                let line = headers.lines().next()?.to_owned();
                let body = if length == 0 {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes[end + 4..end + 4 + length]).ok()?
                };
                return Some((line, body));
            }
        }
    }
}
fn login_reply() -> Reply {
    Reply::json(
        json!({ "status":"authenticated", "token": "synthetic_native_session_only", "username":"fixture-user", "expires_at": "2099-01-01T00:00:00Z" }),
    )
}
fn authenticate(service: &VaultService) -> SafeResponse {
    service
        .login(
            "fixture-user".into(),
            Zeroizing::new("synthetic_login_private".into()),
        )
        .expect("fixture login failed")
}

#[test]
fn session_save_resolve_and_logout_over_real_tcp() {
    let server = Server::new(vec![
        login_reply(),
        Reply::json(json!({"status":"authenticated", "username":"fixture-user"})),
        Reply::json(
            json!({"status":"saved","connection_id":"connection-1", "service_id":"github","account_alias":"work", "secret":"synthetic_credential_private", "token":"synthetic_native_session_only"}),
        ),
        Reply::json(
            json!({"status":"resolved","candidate":{"connection_id":"connection-1", "service_id":"github", "account_alias":"work", "secret":"synthetic_credential_private"}}),
        ),
    ]);
    let service = server.service();
    assert_eq!(service.status().unwrap().state, "disconnected");
    assert_eq!(authenticate(&service).state, "connected");
    let (line, body) = server.request();
    assert_eq!(line, "POST /api/v1/auth/login HTTP/1.1");
    assert!(body["password"] == "synthetic_login_private");
    assert_eq!(
        service.status().unwrap().username.as_deref(),
        Some("fixture-user")
    );
    assert_eq!(server.request().0, "GET /api/v1/auth/status HTTP/1.1");
    let saved = service
        .save(
            "github".into(),
            "work".into(),
            Zeroizing::new("synthetic_credential_private".into()),
            "api_key".into(),
        )
        .unwrap();
    assert_eq!(saved.state, "saved");
    assert_eq!(
        saved.metadata.connection_id.as_deref(),
        Some("connection-1")
    );
    let (line, body) = server.request();
    assert_eq!(line, "POST /api/v1/credentials HTTP/1.1");
    assert!(body["allowed_operations"] == json!(["login", "read", "fill"]));
    assert!(body["secret"] == "synthetic_credential_private");
    let resolved = service
        .resolve("github".into(), Some("work".into()))
        .unwrap();
    assert_eq!(resolved.metadata.account_alias.as_deref(), Some("work"));
    let (line, body) = server.request();
    assert_eq!(line, "POST /api/v1/credentials/resolve HTTP/1.1");
    assert!(body["mode"] == "auto");
    for response in [saved, resolved] {
        let serialized = serde_json::to_string(&response).unwrap();
        for secret in [
            "synthetic_login_private",
            "synthetic_credential_private",
            "synthetic_native_session_only",
        ] {
            assert!(
                !serialized.contains(secret),
                "private material crossed safe response"
            );
        }
    }
    assert_eq!(service.logout().unwrap().state, "disconnected");
    assert_eq!(service.status().unwrap().state, "disconnected");
    assert!(service.resolve("github".into(), None).unwrap_err() == "not_connected");
}

#[test]
fn expiry_clears_session_for_status_save_and_resolve() {
    for operation in ["status", "save", "resolve"] {
        let server = Server::new(vec![login_reply(), Reply::status(401)]);
        let service = server.service();
        authenticate(&service);
        let response = match operation {
            "status" => service.status(),
            "save" => service.save(
                "github".into(),
                "work".into(),
                Zeroizing::new("synthetic_private".into()),
                "password".into(),
            ),
            _ => service.resolve("github".into(), None),
        }
        .unwrap();
        assert_eq!(response.state, "expired");
        assert_eq!(service.status().unwrap().state, "disconnected");
    }
}

#[test]
fn redirect_malformed_oversize_and_server_errors_are_fixed() {
    let cases = vec![
        (
            Reply {
                status: 302,
                body: String::new(),
                headers: "Location: http://127.0.0.1:1/private\r\n",
            },
            "vault_request_failed",
        ),
        (
            Reply {
                status: 200,
                body: "private malformed body".into(),
                headers: "",
            },
            "invalid_server_response",
        ),
        (
            Reply {
                status: 200,
                body: "x".repeat(MAX_RESPONSE + 1),
                headers: "",
            },
            "invalid_server_response",
        ),
        (Reply::status(500), "vault_request_failed"),
        (Reply::status(401), "login_rejected"),
    ];
    for (reply, expected) in cases {
        let server = Server::new(vec![reply]);
        let service = server.service();
        let error = service
            .login(
                "fixture-user".into(),
                Zeroizing::new("synthetic_private".into()),
            )
            .unwrap_err();
        assert_eq!(error, expected);
        assert_eq!(service.status().unwrap().state, "disconnected");
    }
}

#[test]
fn auto_resolution_requires_resolved_single_candidate() {
    let responses = [
        json!({"status":"found","candidates":[{"connection_id":"c1"}]}),
        json!({"status":"resolved","connection_id":"c1"}),
        json!({"status":"resolved","candidate":{"id":"c1"}}),
        json!({"status":"resolved","candidate":{"connection_id":"synthetic_native_session_only"}}),
    ];
    for response in responses {
        let server = Server::new(vec![login_reply(), Reply::json(response)]);
        let service = server.service();
        authenticate(&service);
        assert!(service.resolve("github".into(), None).unwrap_err() == "invalid_server_response");
    }
}

#[test]
fn login_requires_authenticated_status_even_with_token() {
    for status in [None, Some("denied"), Some("saved")] {
        let mut reply = json!({"token":"synthetic_native_session_only"});
        if let Some(status) = status {
            reply["status"] = json!(status);
        }
        let server = Server::new(vec![Reply::json(reply)]);
        let service = server.service();
        let result = service.login(
            "fixture-user".into(),
            Zeroizing::new("synthetic_private".into()),
        );
        assert!(result.unwrap_err() == "invalid_server_response");
        assert_eq!(service.status().unwrap().state, "disconnected");
    }
}

#[test]
fn status_requires_authenticated_business_receipt() {
    let server = Server::new(vec![
        login_reply(),
        Reply::json(json!({"username":"fixture-user"})),
    ]);
    let service = server.service();
    authenticate(&service);
    assert!(service.status().unwrap_err() == "invalid_server_response");
}

#[test]
fn save_requires_saved_status_and_connection_id() {
    let responses = [
        json!({}),
        json!({"status":"saved"}),
        json!({"status":"denied","connection_id":"c1"}),
        json!({"status":"saved","id":"c1"}),
    ];
    for response in responses {
        let server = Server::new(vec![login_reply(), Reply::json(response)]);
        let service = server.service();
        authenticate(&service);
        let result = service.save(
            "github".into(),
            "work".into(),
            Zeroizing::new("synthetic_private".into()),
            "password".into(),
        );
        assert!(result.unwrap_err() == "invalid_server_response");
    }
}

#[test]
fn unreachable_is_safe_and_retains_session_until_logout() {
    let server = Server::new(vec![login_reply()]);
    let service = server.service();
    authenticate(&service);
    drop(server);
    assert_eq!(service.status().unwrap().state, "unreachable");
    assert_eq!(service.logout().unwrap().state, "disconnected");
    assert_eq!(service.status().unwrap().state, "disconnected");
}

#[test]
fn numeric_expiry_and_status_diagnostics_stay_safe() {
    let server = Server::new(vec![
        Reply::json(
            json!({"status":"authenticated", "token":"synthetic_native_session_only", "expires_at":4070908800.25}),
        ),
        Reply::json(json!({"status":"error", "detail":"synthetic_private_diagnostic"})),
    ]);
    let service = server.service();
    let result = authenticate(&service);
    assert!(serde_json::to_value(&result).unwrap()["expires_at"] == json!(4070908800.25));
    assert!(service.status().unwrap_err() == "vault_request_failed");
}

#[test]
fn invalid_inputs_do_not_reach_transport() {
    let service = VaultService::new().unwrap();
    assert!(
        service
            .login("".into(), Zeroizing::new("synthetic_private".into()))
            .unwrap_err()
            == "invalid_input"
    );
    assert!(
        service
            .save(
                "github".into(),
                "work".into(),
                Zeroizing::new("synthetic_private".into()),
                "unsupported".into()
            )
            .unwrap_err()
            == "invalid_input"
    );
    assert_eq!(service.status().unwrap().state, "disconnected");
}
