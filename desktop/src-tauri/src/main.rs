#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod icon;
mod secure_input;
mod service;

use secure_input::{Notify, SecureInput, NOTIFY_EVENT};
use service::{SafeResponse, VaultService};
use std::{collections::HashMap, sync::{Arc, Mutex}};
type CardRequests = Mutex<HashMap<String, secure_input::SecureInputRequest>>;
use tauri::{Emitter, Manager};
use zeroize::Zeroizing;

type NativeState = Arc<VaultService>;
type CommandResult = Result<SafeResponse, String>;
type SecureInputState = Arc<SecureInput>;

async fn blocking<F>(f: F) -> CommandResult
where
    F: FnOnce() -> CommandResult + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|_| "native_task_failed".to_owned())?
}

#[tauri::command]
async fn login(
    state: tauri::State<'_, NativeState>,
    username: String,
    password: String,
) -> CommandResult {
    let service = state.inner().clone();
    let password = Zeroizing::new(password);
    blocking(move || service.login(username, password)).await
}

#[tauri::command]
async fn logout(state: tauri::State<'_, NativeState>) -> CommandResult {
    let service = state.inner().clone();
    blocking(move || service.logout()).await
}

#[tauri::command]
async fn connection_status(state: tauri::State<'_, NativeState>) -> CommandResult {
    let service = state.inner().clone();
    blocking(move || service.status()).await
}

#[tauri::command]
async fn save_credential(
    state: tauri::State<'_, NativeState>,
    service_id: String,
    account_alias: String,
    secret: String,
    credential_type: String,
) -> CommandResult {
    let service = state.inner().clone();
    let secret = Zeroizing::new(secret);
    blocking(move || service.save(service_id, account_alias, secret, credential_type)).await
}

#[tauri::command]
async fn resolve(
    state: tauri::State<'_, NativeState>,
    service_id: String,
    account_alias: Option<String>,
) -> CommandResult {
    let service = state.inner().clone();
    blocking(move || service.resolve(service_id, account_alias)).await
}

/// Resolve a pending secure-input request with the user-supplied secret.
/// The secret is zeroized after the one-shot HTTP handoff to the vault MCP.
#[tauri::command]
async fn submit_secure_input(
    state: tauri::State<'_, SecureInputState>,
    window: tauri::WebviewWindow,
    request_id: String,
    secret: String,
) -> Result<serde_json::Value, String> {
    if window.label() != format!("secure-card-{}", request_id) {
        return Err("wrong_request_window".into());
    }
    let secret = Zeroizing::new(secret);
    state
        .inner()
        .submit(&request_id, secret)
        .map(|()| {
            let _ = window.destroy();
            serde_json::json!({ "status": "submitted" })
        })
        .map_err(|error| error.to_owned())
}

/// Resolve a pending secure-input request as declined.
#[tauri::command]
async fn decline_secure_input(
    state: tauri::State<'_, SecureInputState>,
    window: tauri::WebviewWindow,
    request_id: String,
) -> Result<serde_json::Value, String> {
    if window.label() != format!("secure-card-{}", request_id) {
        return Err("wrong_request_window".into());
    }
    state
        .inner()
        .decline(&request_id)
        .map(|()| {
            let _ = window.destroy();
            serde_json::json!({ "status": "declined" })
        })
        .map_err(|error| error.to_owned())
}

#[tauri::command]
fn secure_card_ready(window: tauri::WebviewWindow, cards: tauri::State<'_, CardRequests>) -> Result<(), String> {
    let requests = cards.lock().map_err(|_| "card_unavailable".to_owned())?;
    let request = requests.get(window.label()).ok_or("card_unavailable")?;
    window.emit(NOTIFY_EVENT, request).map_err(|_| "card_unavailable".to_owned())?;
    let _ = window.center();
    let _ = window.show();
    let _ = window.set_focus();
    Ok(())
}

fn reveal(app: &tauri::AppHandle) {
    for (label, window) in app.webview_windows() {
        if label.starts_with("secure-card-") {
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

fn open_card(app: &tauri::AppHandle, request: &secure_input::SecureInputRequest) {
    let label = format!("secure-card-{}", request.request_id);
    let Some(mut config) = app.config().app.windows.iter().find(|w| w.label == "secure-card").cloned() else { return; };
    config.label = label.clone();
    if let Ok(mut cards) = app.state::<CardRequests>().lock() {
        cards.insert(label.clone(), request.clone());
    }
    let built = tauri::WebviewWindowBuilder::from_config(app, &config)
        .and_then(|builder| Ok(builder
            .on_navigation(|url| url.username().is_empty() && url.password().is_none() && url.port().is_none()
                && ((url.scheme() == "http" && url.host_str() == Some("tauri.localhost"))
                    || (url.scheme() == "tauri" && url.host_str() == Some("localhost"))))
            .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
            .build()?));
    if built.is_err() {
        if let Ok(mut cards) = app.state::<CardRequests>().lock() { cards.remove(&label); }
        if let Some(secure) = app.try_state::<SecureInputState>() { let _ = secure.decline(&request.request_id); }
    }
}

fn tray_image() -> tauri::image::Image<'static> {
    tauri::image::Image::new_owned(icon::rgba(), 32, 32)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Construct the blocking HTTP client outside the async runtime.
    let service = Arc::new(VaultService::new().map_err(|_| "Native client unavailable")?);
    let shutdown_service = service.clone();
    let app = tauri::Builder::default()
        .manage(service)
        .manage(CardRequests::default())
        .invoke_handler(tauri::generate_handler![
            login,
            logout,
            connection_status,
            save_credential,
            resolve,
            submit_secure_input,
            decline_secure_input,
            secure_card_ready
        ])
        .setup(|app| {
            use tauri::{
                menu::{Menu, MenuItem},
                tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
            };
            let toggle = MenuItem::with_id(app, "toggle", "显示/隐藏", true, None::<&str>)?;
            let status = MenuItem::with_id(app, "status", "状态检查", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&toggle, &status, &quit])?;
            TrayIconBuilder::with_id("vault")
                .icon(tray_image())
                .tooltip("Agent Vault")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "toggle" => {
                        reveal(app);
                    }
                    "status" => {
                        let handle = app.clone();
                        let service = app.state::<NativeState>().inner().clone();
                        tauri::async_runtime::spawn(async move {
                            let response = blocking(move || service.status())
                                .await
                                .unwrap_or_else(|_| service_error_status());
                            if let Some(window) = handle.get_webview_window("main") {
                                let _ = window.emit("vault-status", response);
                            }
                        });
                    }
                    "quit" => {
                        let _ = app.state::<NativeState>().logout();
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } | TrayIconEvent::DoubleClick {
                            button: MouseButton::Left,
                            ..
                        }
                    ) {
                        reveal(tray.app_handle());
                    }
                })
                .build(app)?;
            // Loopback secure-input server: 127.0.0.1 only, per-session token,
            // env-file exchange for the vault MCP parent. Refuses (fixed error)
            // when the token exchange is impossible; never a silent open listener.
            let notify = {
                let handle = app.handle().clone();
                Arc::new(move |request: &secure_input::SecureInputRequest| {
                    let ui = handle.clone();
                    let request = request.clone();
                    let _ = handle.run_on_main_thread(move || open_card(&ui, &request));
                }) as Notify
            };
            match SecureInput::start(notify) {
                Ok(secure) => {
                    let _ = app.manage(Arc::new(secure));
                }
                Err(error) => {
                    // Fixed diagnostic code only; no token or request data is logged.
                    eprintln!("secure_input_unavailable: {}", error);
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let Some(id) = window.label().strip_prefix("secure-card-") {
                if matches!(event, tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed) {
                    if let Some(secure) = window.app_handle().try_state::<SecureInputState>() { let _ = secure.decline(id); }
                    if let Ok(mut cards) = window.app_handle().state::<CardRequests>().lock() { cards.remove(window.label()); }
                }
            }
        })
        .build(tauri::generate_context!())?;
    app.run(move |app, event| {
        if let tauri::RunEvent::ExitRequested { code: None, ref api, .. } = event {
            api.prevent_exit(); // Card destruction must leave the tray companion available.
        }
        if matches!(event, tauri::RunEvent::Exit) {
            let _ = shutdown_service.logout();
            if let Some(secure) = app.try_state::<SecureInputState>() {
                secure.remove_env_file();
            }
        }
    });
    Ok(())
}

fn service_error_status() -> SafeResponse {
    SafeResponse {
        state: "unreachable",
        username: None,
        expires_at: None,
        metadata: Default::default(),
        candidates: None,
    }
}

fn main() {
    // Intentionally omit underlying error diagnostics: server bodies and tokens are private.
    if run().is_err() {
        std::process::exit(1);
    }
}
