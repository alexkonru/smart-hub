mod automation;
mod cameras;
mod cloud_sync;
mod db;
mod discovery;
mod ewelink;
mod remote;
mod state;
mod tuya;

use anyhow::{Result, anyhow};
use axum::{
    Json, Router,
    extract::{Path, State},
    middleware,
    response::Html,
    routing::{delete, get, post, put},
};
use cameras::{CameraConfig, encode_camera_version};
use cloud_sync::{SavedAuthSession, TuyaOpenApiClient};
use db::{AutomationRule, TelemetryDb};
use remote::{RemoteManager, hash_token};
use serde::Deserialize;
use serde_json::{Value, json};
use state::{AppState, DiscoveredDevice, Vendor};
use std::net::{IpAddr, SocketAddr};
use std::path::Path as FsPath;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::Mutex;
use tuya::TuyaClient;

const EMBEDDED_INDEX_HTML: &str = include_str!("../static/index.html");

fn load_dotenv() {
    let Ok(content) = std::fs::read_to_string(".env") else {
        return;
    };
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim();
            let val = v.trim().trim_matches('"').trim_matches('\'');
            if std::env::var(key).is_err() {
                unsafe {
                    std::env::set_var(key, val);
                }
            }
        }
    }
}

static LAN_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Clone)]
struct ServerContext {
    state: AppState,
    db: TelemetryDb,
    remote: RemoteManager,
}

#[derive(Deserialize)]
struct OpenApiSyncReq {
    region: String,
    access_id: String,
    access_secret: String,
}

#[derive(Deserialize)]
struct EWeLinkSyncReq {
    region: String,
    login: String,
    password: String,
}

#[derive(Deserialize)]
struct SetKeyReq {
    name: Option<String>,
    category: Option<String>,
    local_key: String,
}

#[derive(Deserialize)]
struct SaveCameraConfigReq {
    name: Option<String>,
    preset: String,
    #[serde(default = "default_cam_user")]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default = "default_rtsp_port")]
    rtsp_port: u16,
    #[serde(default = "default_sub_stream")]
    stream_quality: String,
    #[serde(default)]
    custom_url: String,
    #[serde(default)]
    detect_enabled: bool,
    #[serde(default = "default_sensitivity")]
    sensitivity: f64,
}

#[derive(Deserialize)]
struct AddCameraReq {
    ip: String,
    name: Option<String>,
    #[serde(default = "default_cam_preset")]
    preset: String,
    #[serde(default = "default_cam_user")]
    username: String,
    #[serde(default)]
    password: String,
}

fn default_cam_preset() -> String {
    "icsee".to_string()
}
fn default_cam_user() -> String {
    "admin".to_string()
}
fn default_rtsp_port() -> u16 {
    554
}
fn default_sub_stream() -> String {
    "sub".to_string()
}
fn default_sensitivity() -> f64 {
    1.5
}

#[derive(Debug, Deserialize)]
struct ControlRequest {
    code: Option<String>,
    dp_id: Option<u32>,
    value: Value,
}

#[derive(Deserialize)]
struct SwitchProfileReq {
    profile_id: String,
}

#[derive(Deserialize)]
struct CreateProfileReq {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct RenameProfileReq {
    name: String,
}

#[derive(Deserialize)]
struct ToggleRuleReq {
    enabled: bool,
}

#[derive(Deserialize)]
struct ResetRequest {
    scope: String,
}

#[derive(Deserialize)]
struct LoginReq {
    password: String,
}

#[derive(Deserialize)]
struct SaveRemoteConfigReq {
    vps_url: String,
    #[serde(default)]
    vps_secret: String,
    new_password: Option<String>,
    #[serde(default)]
    stun_server: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

pub fn cache_file_for_profile(profile_id: &str) -> String {
    format!("devices_cache_{}.json", profile_id)
}

/// Читает сохраненные ключи Tuya OpenAPI строго для указанного профиля (без пересечения аккаунтов)
fn resolve_cloud_credentials(
    db: &TelemetryDb,
    profile_id: &str,
) -> Option<(String, String, String)> {
    let cache_file = cache_file_for_profile(profile_id);
    if let Ok(content) = std::fs::read_to_string(&cache_file) {
        if let Ok(saved) = serde_json::from_str::<SavedAuthSession>(&content) {
            if !saved.access_id.trim().is_empty() && !saved.access_secret.trim().is_empty() {
                let ep = if saved.endpoint.is_empty() {
                    "eu".to_string()
                } else {
                    saved.endpoint
                };
                db.set_setting(&format!("cloud_ep_{}", profile_id), &ep);
                db.set_setting(&format!("cloud_id_{}", profile_id), &saved.access_id);
                db.set_setting(&format!("cloud_sec_{}", profile_id), &saved.access_secret);
                return Some((ep, saved.access_id, saved.access_secret));
            }
        }
    }

    if let (Some(id), Some(sec)) = (
        db.get_setting(&format!("cloud_id_{}", profile_id)),
        db.get_setting(&format!("cloud_sec_{}", profile_id)),
    ) {
        if !id.is_empty() && !sec.is_empty() {
            let ep = db
                .get_setting(&format!("cloud_ep_{}", profile_id))
                .unwrap_or_else(|| "eu".to_string());
            return Some((ep, id, sec));
        }
    }

    if profile_id == "home" && FsPath::new("devices_cache.json").exists() {
        if let Ok(content) = std::fs::read_to_string("devices_cache.json") {
            if let Ok(saved) = serde_json::from_str::<SavedAuthSession>(&content) {
                if !saved.access_id.trim().is_empty() && !saved.access_secret.trim().is_empty() {
                    let ep = if saved.endpoint.is_empty() {
                        "eu".to_string()
                    } else {
                        saved.endpoint
                    };
                    db.set_setting("cloud_ep_home", &ep);
                    db.set_setting("cloud_id_home", &saved.access_id);
                    db.set_setting("cloud_sec_home", &saved.access_secret);
                    return Some((ep, saved.access_id, saved.access_secret));
                }
            }
        }
    }

    None
}

pub fn load_profile_cache_into_state(state: &AppState, db: &TelemetryDb, profile_id: &str) {
    state.set_profile(profile_id);
    db.save_active_profile(profile_id);
    let _ = resolve_cloud_credentials(db, profile_id);
    let file_path = cache_file_for_profile(profile_id);

    if profile_id == "home"
        && !FsPath::new(&file_path).exists()
        && FsPath::new("devices_cache.json").exists()
    {
        let _ = std::fs::copy("devices_cache.json", &file_path);
    }

    if FsPath::new(&file_path).exists() {
        if let Ok(content) = std::fs::read_to_string(&file_path) {
            if let Ok(saved) = serde_json::from_str::<SavedAuthSession>(&content) {
                for hid in &saved.hidden_ids {
                    state.hidden_ids.insert(hid.clone());
                }
                tracing::info!(
                    "📂 Профиль [{}]: загружено {} устройств из {}",
                    profile_id,
                    saved.devices.len(),
                    file_path
                );
                state.merge_from_cloud(saved.devices);
                record_all_devices_to_db(state, db);
            }
        }
    } else {
        tracing::info!(
            "🆕 Активирован профиль [{}]. Нажмите «Сканировать сеть» или подключите облако.",
            profile_id
        );
    }
}

pub fn persist_current_profile_cache(state: &AppState, db: &TelemetryDb) {
    let prof = state.current_profile();
    let cache_file = cache_file_for_profile(&prof);

    let (ep, aid, asec) = resolve_cloud_credentials(db, &prof)
        .unwrap_or_else(|| ("eu".to_string(), String::new(), String::new()));

    let session = SavedAuthSession {
        mode: "openapi".to_string(),
        endpoint: ep,
        access_id: aid,
        access_secret: asec,
        devices: state.export_devices_for_cache(),
        hidden_ids: state.hidden_ids.iter().map(|i| i.clone()).collect(),
    };

    if let Ok(s) = serde_json::to_string_pretty(&session) {
        let _ = std::fs::write(&cache_file, s);
    }
}

fn build_profile_diagnostics(state: &AppState, db: &TelemetryDb, profile_id: &str) -> Value {
    let creds = resolve_cloud_credentials(db, profile_id);
    let has_cloud_credentials = creds.is_some();
    let cloud_region = creds.map(|c| c.0).unwrap_or_else(|| "eu".to_string());

    let has_ewelink_credentials = db
        .get_setting(&format!("ewelink_login_{}", profile_id))
        .map(|l| !l.is_empty())
        .unwrap_or(false);

    let mut total_devices = 0usize;
    let mut lan_devices = 0usize;
    let mut configured_keys = 0usize;
    let mut cameras_count = 0usize;
    let mut missing_key_devices = Vec::new();

    for entry in state.devices.iter() {
        let d = entry.value();
        if format!("{:?}", d.vendor).starts_with("Camera") {
            cameras_count += 1;
            continue;
        }
        total_devices += 1;
        if d.ip.is_some() {
            lan_devices += 1;
        }
        let has_valid_key = d
            .local_key
            .as_deref()
            .map(|k| k.len() == 16 || (d.vendor == Vendor::EWeLink && !k.is_empty()))
            .unwrap_or(false);

        if has_valid_key {
            configured_keys += 1;
        } else {
            missing_key_devices.push(json!({
                "device_id": d.device_id,
                "ip": d.ip,
                "version": d.version
            }));
        }
    }

    json!({
        "profile_id": profile_id,
        "has_cloud_credentials": has_cloud_credentials,
        "has_ewelink_credentials": has_ewelink_credentials,
        "cloud_region": cloud_region,
        "total_devices": total_devices,
        "lan_devices": lan_devices,
        "cameras_count": cameras_count,
        "configured_keys": configured_keys,
        "unconfigured_count": missing_key_devices.len(),
        "unconfigured_devices": missing_key_devices
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    load_dotenv();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let db_file = std::env::var("DB_FILE").unwrap_or_else(|_| "smart_hub.db".to_string());
    let hub_port: u16 = std::env::var("HUB_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let state = AppState::new();
    let db = TelemetryDb::new(&db_file)?;
    let remote = RemoteManager::new(&db);

    let initial_profile = db.get_saved_active_profile();
    load_profile_cache_into_state(&state, &db, &initial_profile);

    discovery::spawn_discovery_workers(state.clone());
    spawn_local_poller(state.clone(), db.clone());
    spawn_periodic_cloud_poller(state.clone(), db.clone());
    cameras::spawn_camera_worker(state.clone(), db.clone());
    automation::spawn_automation_worker(state.clone(), db.clone());
    remote::spawn_adaptive_network_worker(remote.clone(), state.clone());
    spawn_db_maintenance_worker(db.clone(), state.clone());

    let ctx = ServerContext {
        state: state.clone(),
        db: db.clone(),
        remote: remote.clone(),
    };

    let app = Router::new()
        .route("/", get(index_page))
        .route("/api/ping", get(ping_beacon))
        .route("/api/auth/login", post(auth_login))
        .route(
            "/api/remote/config",
            get(get_remote_info).post(save_remote_info),
        )
        .route("/api/devices", get(list_devices))
        .route("/api/devices/:id/history", get(get_device_history))
        .route("/api/scan/lan", post(trigger_lan_scan))
        .route("/api/sync/openapi", post(sync_openapi))
        .route("/api/sync/ewelink", post(sync_ewelink))
        .route("/api/devices/:id", delete(delete_device))
        .route("/api/devices/:id/key", post(set_device_key))
        .route("/api/devices/:id/status", get(get_device_status))
        .route("/api/devices/:id/control", post(control_device))
        .route("/api/cameras/add", post(add_manual_camera))
        .route("/api/cameras/:id/config", post(save_camera_config))
        .route(
            "/api/cameras/:id/snapshot",
            get(get_camera_snapshot).post(refresh_camera_snapshot),
        )
        .route("/api/profiles", get(get_profiles_info).post(create_profile))
        .route("/api/profiles/switch", post(switch_profile))
        .route(
            "/api/profiles/:id",
            put(rename_profile).delete(delete_profile),
        )
        .route("/api/db/reset", post(reset_database))
        .route(
            "/api/automations",
            get(list_automations).post(save_automation),
        )
        .route("/api/automations/:id/toggle", post(toggle_automation))
        .route("/api/automations/:id", delete(delete_automation))
        .layer(middleware::from_fn_with_state(
            remote,
            remote::adaptive_cors_and_auth_middleware,
        ))
        .with_state(ctx);

    let addr = SocketAddr::from(([0, 0, 0, 0], hub_port));
    tracing::info!("🚀 SmartHub запущен: http://127.0.0.1:{}", hub_port);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    let shutdown_state = state.clone();
    let shutdown_db = db.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("💾 Сохраняем кэш профиля перед выключением...");
        persist_current_profile_cache(&shutdown_state, &shutdown_db);
        tracing::info!("👋 SmartHub остановлен.");
        std::process::exit(0);
    });

    axum::serve(listener, app).await?;

    Ok(())
}

async fn index_page() -> Html<String> {
    let html = std::fs::read_to_string("static/index.html")
        .unwrap_or_else(|_| EMBEDDED_INDEX_HTML.to_string());
    Html(html)
}

async fn ping_beacon(State(ctx): State<ServerContext>) -> Json<Value> {
    let (hub_id, auth_required) = {
        let cfg = ctx.remote.config.read().unwrap();
        (cfg.hub_id.clone(), !cfg.auth_password_hash.is_empty())
    };
    let net = ctx.remote.net_status.read().unwrap().clone();

    Json(json!({
        "ok": true,
        "hub_id": hub_id,
        "active_profile": ctx.state.current_profile(),
        "auth_required": auth_required,
        "local_endpoint": net.local_endpoint,
        "stun_public_endpoint": net.stun_public_endpoint,
        "vps_relay_connected": net.vps_relay_connected,
        "ts": AppState::now()
    }))
}

async fn auth_login(State(ctx): State<ServerContext>, Json(req): Json<LoginReq>) -> Json<Value> {
    if ctx.remote.verify_token_or_password(&req.password) {
        let token = hash_token(req.password.trim());
        Json(json!({ "ok": true, "token": token }))
    } else {
        Json(json!({ "ok": false, "error": "Неверный пароль" }))
    }
}

async fn get_remote_info(State(ctx): State<ServerContext>) -> Json<Value> {
    let cfg = ctx.remote.config.read().unwrap().clone();
    let net = ctx.remote.net_status.read().unwrap().clone();
    Json(json!({
        "hub_id": cfg.hub_id,
        "vps_url": cfg.vps_url,
        "has_vps_secret": !cfg.vps_secret.is_empty(),
        "has_password": !cfg.auth_password_hash.is_empty(),
        "stun_server": cfg.stun_server,
        "enabled": cfg.enabled,
        "network": net
    }))
}

async fn save_remote_info(
    State(ctx): State<ServerContext>,
    Json(req): Json<SaveRemoteConfigReq>,
) -> Json<Value> {
    ctx.remote.save_config(
        &ctx.db,
        req.vps_url,
        req.vps_secret,
        req.new_password,
        req.stun_server,
        req.enabled,
    );
    Json(json!({ "ok": true }))
}

fn spawn_db_maintenance_worker(db: TelemetryDb, state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            persist_current_profile_cache(&state, &db);
            let deleted = db.prune_old_telemetry(30);
            if deleted > 0 {
                tracing::info!(
                    "🧹 Очищено {} устаревших записей телеметрии (>30 дней)",
                    deleted
                );
            }
        }
    });
}

// ============================================================================
// ЭНДПОИНТЫ КАМЕР И ЛЕГКОЙ ДЕТЕКЦИИ ДВИЖЕНИЯ
// ============================================================================

async fn add_manual_camera(
    State(ctx): State<ServerContext>,
    Json(req): Json<AddCameraReq>,
) -> Json<Value> {
    let Ok(ip_addr) = req.ip.trim().parse::<IpAddr>() else {
        return Json(json!({ "ok": false, "error": "Некорректный IP-адрес камеры" }));
    };

    let id = format!("cam-{}", ip_addr);
    let vendor = match req.preset.as_str() {
        "icsee" => Vendor::CameraICSee,
        "v380" => Vendor::CameraV380,
        _ => Vendor::CameraOnvif,
    };

    let cfg = CameraConfig {
        preset: req.preset.clone(),
        username: req.username.trim().to_string(),
        password: req.password.trim().to_string(),
        ..Default::default()
    };

    let name = req
        .name
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| format!("Камера {}", ip_addr));

    ctx.state.hidden_ids.remove(&id);
    ctx.state.devices.insert(
        id.clone(),
        DiscoveredDevice {
            device_id: id.clone(),
            name: Some(name),
            category: Some("camera".to_string()),
            vendor,
            ip: Some(ip_addr),
            port: 554,
            version: encode_camera_version(&cfg),
            local_key: Some(cfg.password.clone()),
            online: true,
            last_seen: AppState::now(),
            status: Value::Null,
            metadata: json!({
                "preset": cfg.preset,
                "username": cfg.username,
                "rtsp_port": 554,
                "stream_quality": "sub",
                "detect_enabled": false,
                "sensitivity": 1.5
            }),
            dp_map: Default::default(),
            scale_map: Default::default(),
        },
    );

    persist_current_profile_cache(&ctx.state, &ctx.db);
    Json(json!({ "ok": true, "device_id": id }))
}

async fn save_camera_config(
    Path(id): Path<String>,
    State(ctx): State<ServerContext>,
    Json(req): Json<SaveCameraConfigReq>,
) -> Json<Value> {
    let cfg = CameraConfig {
        preset: req.preset,
        username: req.username,
        password: req.password,
        rtsp_port: if req.rtsp_port == 0 {
            554
        } else {
            req.rtsp_port
        },
        stream_quality: req.stream_quality,
        custom_url: req.custom_url,
        detect_enabled: req.detect_enabled,
        sensitivity: req.sensitivity.clamp(0.4, 25.0),
    };

    match cameras::update_camera_settings(&ctx.state, &id, req.name, cfg) {
        Ok(_) => {
            persist_current_profile_cache(&ctx.state, &ctx.db);
            Json(json!({ "ok": true }))
        }
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

async fn get_camera_snapshot(
    Path(id): Path<String>,
    State(ctx): State<ServerContext>,
) -> Json<Value> {
    match cameras::capture_and_analyze_camera(&ctx.state, &ctx.db, &id, false).await {
        Ok(val) => Json(val),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

async fn refresh_camera_snapshot(
    Path(id): Path<String>,
    State(ctx): State<ServerContext>,
) -> Json<Value> {
    match cameras::capture_and_analyze_camera(&ctx.state, &ctx.db, &id, true).await {
        Ok(val) => Json(val),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

// ============================================================================
// УПРАВЛЕНИЕ УСТРОЙСТВАМИ TUYA И EWELINK
// ============================================================================

pub async fn execute_device_command(
    state: &AppState,
    db: &TelemetryDb,
    id: &str,
    code: Option<String>,
    dp_id: Option<u32>,
    value: Value,
) -> Result<String> {
    let Some(dev) = state.devices.get(id).map(|d| d.value().clone()) else {
        return Err(anyhow!("Устройство не найдено"));
    };

    let code_str = code.unwrap_or_default();

    if dev.vendor == Vendor::EWeLink || dev.version.starts_with("eWeLink") {
        let turn_on = value.as_bool().unwrap_or_else(|| {
            let s = value.as_str().unwrap_or("").to_lowercase();
            s == "true" || s == "on" || s == "1"
        });
        let is_th = dev.category.as_deref() == Some("tdq")
            || dev.version.contains("TH")
            || dev.status.as_array().map(|a| a.len() > 1).unwrap_or(false);

        if let Some(ip) = dev.ip {
            let key = dev.local_key.as_deref().unwrap_or("");
            let _guard = LAN_LOCK.lock().await;
            if ewelink::control_ewelink_lan_http(ip, &dev.device_id, key, is_th, turn_on)
                .await
                .is_ok()
            {
                if let Some(mut entry) = state.devices.get_mut(id) {
                    if let Some(arr) = entry.status.as_array_mut() {
                        for item in arr.iter_mut() {
                            if item.get("code").and_then(|c| c.as_str()) == Some("switch_1") {
                                if let Some(obj) = item.as_object_mut() {
                                    obj.insert("value".to_string(), json!(turn_on));
                                }
                            }
                        }
                    }
                }
                record_all_devices_to_db(state, db);
                return Ok(format!("eWeLink LAN ({}:8081)", ip));
            }
        }

        let prof = state.current_profile();
        if let (Some(login), Some(pass)) = (
            db.get_setting(&format!("ewelink_login_{}", prof)),
            db.get_setting(&format!("ewelink_pass_{}", prof)),
        ) {
            let ep = db
                .get_setting(&format!("ewelink_ep_{}", prof))
                .unwrap_or_else(|| "eu".to_string());
            let client = ewelink::EWeLinkClient::new();
            client
                .send_cloud_command(&login, &pass, &ep, id, is_th, turn_on)
                .await?;

            if let Some(mut entry) = state.devices.get_mut(id) {
                if let Some(arr) = entry.status.as_array_mut() {
                    for item in arr.iter_mut() {
                        if item.get("code").and_then(|c| c.as_str()) == Some("switch_1") {
                            if let Some(obj) = item.as_object_mut() {
                                obj.insert("value".to_string(), json!(turn_on));
                            }
                        }
                    }
                }
            }
            record_all_devices_to_db(state, db);
            return Ok("eWeLink Cloud v2".to_string());
        }

        return Err(anyhow!(
            "Для управления этим реле eWeLink подключите аккаунт во вкладке «Сеть и Система»"
        ));
    }

    let resolved_dp_id = dp_id.filter(|&d| d > 0).or_else(|| {
        dev.dp_map.get(&code_str).copied().or_else(|| {
            if let Some(stripped) = code_str.strip_prefix("dp_") {
                stripped.parse::<u32>().ok()
            } else {
                match code_str.as_str() {
                    "switch" | "switch_1" => Some(1),
                    "mode" => Some(2),
                    "relay_status" => Some(14),
                    "temp_set" | "backlight_switch" => Some(16),
                    "upper_temp" => Some(19),
                    "child_lock" => Some(40),
                    "sensor_choose" => Some(43),
                    "frost" | "freeze_free" => Some(103),
                    "temp_differ_on" => Some(106),
                    _ => None,
                }
            }
        })
    });

    if let (Some(ip), Some(key), Some(dp_num)) = (dev.ip, dev.local_key.as_deref(), resolved_dp_id)
    {
        if key.len() == 16 {
            if let Ok(client) = TuyaClient::new(&dev.device_id, ip, dev.port, key, &dev.version) {
                let _guard = LAN_LOCK.lock().await;
                let dps_payload = json!({ dp_num.to_string(): value.clone() });

                match client.set_dps(dps_payload.clone()).await {
                    Ok(_) => {
                        state.record_lan_success(id);
                        state.apply_lan_dps(id, &json!({ "dps": dps_payload }));
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        if let Ok(fresh) = client.query_status().await {
                            state.apply_lan_dps(id, &fresh);
                        }
                        record_all_devices_to_db(state, db);
                        return Ok(format!("LAN v{} (DP {})", dev.version, dp_num));
                    }
                    Err(e) => {
                        tracing::warn!("⚠️ Ошибка LAN команды на {}: {}", ip, e);
                    }
                }
            }
        }
    }

    let prof = state.current_profile();
    if !code_str.is_empty() {
        if let Some((ep, aid, asec)) = resolve_cloud_credentials(db, &prof) {
            let client = TuyaOpenApiClient::new(&ep, &aid, &asec);
            if client
                .send_cloud_command(id, &code_str, value.clone())
                .await
                .is_ok()
            {
                if let Some(mut entry) = state.devices.get_mut(id) {
                    if let Some(arr) = entry.status.as_array_mut() {
                        for item in arr.iter_mut() {
                            if item.get("code").and_then(|c| c.as_str()) == Some(&code_str) {
                                if let Some(obj) = item.as_object_mut() {
                                    obj.insert("value".to_string(), value.clone());
                                }
                            }
                        }
                    }
                }
                record_all_devices_to_db(state, db);
                return Ok("Cloud API".to_string());
            }
        }
    }

    Err(anyhow!(
        "Команда не выполнена (проверьте подключение устройства и ключ Local Key)"
    ))
}

fn record_all_devices_to_db(state: &AppState, db: &TelemetryDb) {
    let prof = state.current_profile();
    for entry in state.devices.iter() {
        let d = entry.value();
        let Some(arr) = d.status.as_array() else {
            continue;
        };
        let cat = d.category.as_deref().unwrap_or("");

        for item in arr {
            let code = item.get("code").and_then(|c| c.as_str()).unwrap_or("");
            let dp_id = item.get("dp_id").and_then(|i| i.as_u64()).unwrap_or(0);
            let Some(val_num) = item.get("value").and_then(|v| v.as_f64()) else {
                continue;
            };

            if cat == "wk" {
                if code == "temp_floor" || code == "floor_temp" || dp_id == 101 {
                    db.record_metric(&prof, &d.device_id, "floor_temp", val_num / 10.0);
                } else if code == "temp_current" || code == "air_temp" || dp_id == 24 {
                    db.record_metric(&prof, &d.device_id, "air_temp", val_num / 10.0);
                }
            } else if cat == "kg" || cat == "cz" {
                if code == "cur_power" || dp_id == 23 {
                    db.record_metric(&prof, &d.device_id, "power_w", val_num / 10.0);
                } else if code == "cur_voltage" || dp_id == 22 {
                    db.record_metric(&prof, &d.device_id, "voltage_v", val_num / 10.0);
                }
            } else if code == "temp_current" || code == "va_temperature" || dp_id == 102 {
                let scaled = if val_num > 55.0 {
                    val_num / 10.0
                } else {
                    val_num
                };
                db.record_metric(&prof, &d.device_id, "temp", scaled);
            } else if code == "humidity_value" || code == "va_humidity" || dp_id == 103 {
                let scaled = if val_num > 100.0 {
                    val_num / 10.0
                } else {
                    val_num
                };
                db.record_metric(&prof, &d.device_id, "humidity", scaled);
            }
        }
    }
}

async fn get_profiles_info(State(ctx): State<ServerContext>) -> Json<Value> {
    let active = ctx.state.current_profile();
    let list = ctx.db.list_profiles();
    let diagnostics = build_profile_diagnostics(&ctx.state, &ctx.db, &active);
    let net = ctx.remote.net_status.read().unwrap().clone();
    Json(json!({
        "active": active,
        "profiles": list,
        "diagnostics": diagnostics,
        "network": net
    }))
}

async fn create_profile(
    State(ctx): State<ServerContext>,
    Json(req): Json<CreateProfileReq>,
) -> Json<Value> {
    let clean_id: String = req
        .id
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if clean_id.is_empty() || req.name.trim().is_empty() {
        return Json(
            json!({ "ok": false, "error": "Укажите латинский ID (например dacha) и название профиля" }),
        );
    }
    if let Err(e) = ctx.db.create_profile(&clean_id, req.name.trim()) {
        return Json(json!({ "ok": false, "error": e.to_string() }));
    }

    persist_current_profile_cache(&ctx.state, &ctx.db);
    load_profile_cache_into_state(&ctx.state, &ctx.db, &clean_id);
    persist_current_profile_cache(&ctx.state, &ctx.db);
    let diag = build_profile_diagnostics(&ctx.state, &ctx.db, &clean_id);

    Json(json!({ "ok": true, "active": clean_id, "diagnostics": diag }))
}

async fn rename_profile(
    Path(id): Path<String>,
    State(ctx): State<ServerContext>,
    Json(req): Json<RenameProfileReq>,
) -> Json<Value> {
    if req.name.trim().is_empty() {
        return Json(json!({ "ok": false, "error": "Название не может быть пустым" }));
    }
    match ctx.db.rename_profile(&id, req.name.trim()) {
        Ok(_) => Json(json!({ "ok": true })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

async fn delete_profile(Path(id): Path<String>, State(ctx): State<ServerContext>) -> Json<Value> {
    match ctx.db.delete_profile(&id) {
        Ok(next_profile) => {
            let _ = std::fs::remove_file(cache_file_for_profile(&id));
            load_profile_cache_into_state(&ctx.state, &ctx.db, &next_profile);
            Json(json!({ "ok": true, "active": next_profile }))
        }
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

async fn switch_profile(
    State(ctx): State<ServerContext>,
    Json(req): Json<SwitchProfileReq>,
) -> Json<Value> {
    persist_current_profile_cache(&ctx.state, &ctx.db);
    load_profile_cache_into_state(&ctx.state, &ctx.db, &req.profile_id);
    let diag = build_profile_diagnostics(&ctx.state, &ctx.db, &req.profile_id);

    Json(json!({
        "ok": true,
        "active": req.profile_id,
        "diagnostics": diag
    }))
}

async fn reset_database(
    State(ctx): State<ServerContext>,
    Json(req): Json<ResetRequest>,
) -> Json<Value> {
    let prof = ctx.state.current_profile();
    match req.scope.as_str() {
        "telemetry" => {
            let _ = ctx.db.clear_telemetry(&prof);
            tracing::info!("🧹 Очищена история графиков для профиля [{}]", prof);
        }
        "devices" => {
            let cache_file = cache_file_for_profile(&prof);
            let _ = std::fs::remove_file(&cache_file);
            if prof == "home" {
                let _ = std::fs::remove_file("devices_cache.json");
            }
            ctx.db.set_setting(&format!("cloud_id_{}", prof), "");
            ctx.db.set_setting(&format!("cloud_sec_{}", prof), "");
            ctx.db.set_setting(&format!("ewelink_login_{}", prof), "");
            ctx.db.set_setting(&format!("ewelink_pass_{}", prof), "");
            ctx.state.devices.clear();
            let _ = ctx.db.clear_telemetry(&prof);
            let _ = ctx.db.clear_automations(&prof);
            tracing::info!(
                "🧹 Полностью сброшены устройства, ключи и правила профиля [{}]",
                prof
            );
        }
        "all" => {
            let _ = ctx.db.factory_reset_all();
            for p in ctx.db.list_profiles() {
                let _ = std::fs::remove_file(cache_file_for_profile(&p.id));
            }
            let _ = std::fs::remove_file("devices_cache.json");
            ctx.state.devices.clear();
            tracing::info!("💥 Выполнен полный Factory Reset базы данных и всех кэшей");
        }
        _ => {}
    }
    Json(json!({ "ok": true }))
}

async fn list_automations(State(ctx): State<ServerContext>) -> Json<Value> {
    let prof = ctx.state.current_profile();
    let rules = ctx.db.list_automations(&prof);
    let logs = ctx
        .state
        .automation_logs
        .read()
        .map(|l| l.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    Json(json!({
        "rules": rules,
        "logs": logs
    }))
}

async fn save_automation(
    State(ctx): State<ServerContext>,
    Json(mut rule): Json<AutomationRule>,
) -> Json<Value> {
    rule.profile_id = ctx.state.current_profile();
    match ctx.db.save_automation(rule) {
        Ok(id) => Json(json!({ "ok": true, "id": id })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

async fn toggle_automation(
    Path(id): Path<i64>,
    State(ctx): State<ServerContext>,
    Json(req): Json<ToggleRuleReq>,
) -> Json<Value> {
    let _ = ctx.db.toggle_automation(id, req.enabled);
    Json(json!({ "ok": true }))
}

async fn delete_automation(Path(id): Path<i64>, State(ctx): State<ServerContext>) -> Json<Value> {
    let _ = ctx.db.delete_automation(id);
    Json(json!({ "ok": true }))
}

async fn get_device_history(
    Path(id): Path<String>,
    State(ctx): State<ServerContext>,
) -> Json<Value> {
    let prof = ctx.state.current_profile();
    let floor = ctx.db.get_recent_points(&prof, &id, "floor_temp", 48);
    let air = ctx.db.get_recent_points(&prof, &id, "air_temp", 48);
    let temp = ctx.db.get_recent_points(&prof, &id, "temp", 48);
    let power = ctx.db.get_recent_points(&prof, &id, "power_w", 48);
    let motion = ctx.db.get_recent_points(&prof, &id, "motion", 48);

    Json(json!({
        "floor_temp": floor,
        "air_temp": air,
        "temp": temp,
        "power_w": power,
        "motion": motion
    }))
}

async fn trigger_lan_scan(State(ctx): State<ServerContext>) -> Json<Value> {
    ctx.state.set_manual_scan_mode(true);
    let _ = discovery::run_subnet_scan_once(ctx.state.clone()).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    ctx.state.set_manual_scan_mode(false);

    // Если в текущем профиле уже заданы ключи Tuya OpenAPI и нашлись устройства без ключа — подтягиваем их имена
    let unnamed_tuya_seed = ctx
        .state
        .devices
        .iter()
        .find(|d| {
            d.vendor == Vendor::Tuya
                && d.ip.is_some()
                && d.local_key
                    .as_deref()
                    .map(|k| k.len() != 16)
                    .unwrap_or(true)
        })
        .map(|d| d.device_id.clone());

    if let Some(seed_id) = unnamed_tuya_seed {
        let prof = ctx.state.current_profile();
        if let Some((ep, aid, asec)) = resolve_cloud_credentials(&ctx.db, &prof) {
            let client = TuyaOpenApiClient::new(&ep, &aid, &asec);
            if let Ok(cloud_devs) = client.sync_all_devices(&seed_id).await {
                let local_ids: std::collections::HashSet<String> = ctx
                    .state
                    .devices
                    .iter()
                    .map(|d| d.device_id.clone())
                    .collect();
                let filtered: Vec<_> = cloud_devs
                    .into_iter()
                    .filter(|cd| local_ids.contains(&cd.id))
                    .collect();
                ctx.state.merge_from_cloud(filtered);
                record_all_devices_to_db(&ctx.state, &ctx.db);
            }
        }
    }

    let found_lan = ctx.state.devices.iter().filter(|d| d.ip.is_some()).count();

    persist_current_profile_cache(&ctx.state, &ctx.db);
    let diag = build_profile_diagnostics(&ctx.state, &ctx.db, &ctx.state.current_profile());
    Json(json!({
        "ok": true,
        "lan_count": found_lan,
        "diagnostics": diag
    }))
}

async fn delete_device(Path(id): Path<String>, State(ctx): State<ServerContext>) -> Json<Value> {
    ctx.state.hidden_ids.insert(id.clone());
    ctx.state.devices.remove(&id);
    persist_current_profile_cache(&ctx.state, &ctx.db);
    Json(json!({ "ok": true }))
}

async fn sync_openapi(
    State(ctx): State<ServerContext>,
    Json(req): Json<OpenApiSyncReq>,
) -> Json<Value> {
    let seed_id = ctx
        .state
        .devices
        .iter()
        .find(|d| d.vendor == Vendor::Tuya)
        .map(|d| d.device_id.clone());

    let Some(any_device_id) = seed_id else {
        return Json(json!({
            "ok": false,
            "error": "В текущем профиле еще не пойман ни один датчик Tuya. Сначала нажмите «Сканировать сеть» на вкладке Устройства."
        }));
    };

    let client = TuyaOpenApiClient::new(&req.region, &req.access_id, &req.access_secret);
    match client.sync_all_devices(&any_device_id).await {
        Ok(devices) => {
            let prof = ctx.state.current_profile();
            ctx.db
                .set_setting(&format!("cloud_ep_{}", prof), req.region.trim());
            ctx.db
                .set_setting(&format!("cloud_id_{}", prof), req.access_id.trim());
            ctx.db
                .set_setting(&format!("cloud_sec_{}", prof), req.access_secret.trim());

            ctx.state.merge_from_cloud(devices);
            let _ = discovery::run_subnet_scan_once(ctx.state.clone()).await;
            persist_current_profile_cache(&ctx.state, &ctx.db);
            record_all_devices_to_db(&ctx.state, &ctx.db);
            let count = ctx
                .state
                .devices
                .iter()
                .filter(|d| !format!("{:?}", d.vendor).starts_with("Camera"))
                .count();
            Json(json!({ "ok": true, "count": count }))
        }
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

async fn sync_ewelink(
    State(ctx): State<ServerContext>,
    Json(req): Json<EWeLinkSyncReq>,
) -> Json<Value> {
    let client = ewelink::EWeLinkClient::new();
    match client
        .sync_all_devices(&req.login, &req.password, &req.region)
        .await
    {
        Ok((devices, actual_region)) => {
            let prof = ctx.state.current_profile();
            ctx.db
                .set_setting(&format!("ewelink_ep_{}", prof), &actual_region);
            ctx.db
                .set_setting(&format!("ewelink_login_{}", prof), req.login.trim());
            ctx.db
                .set_setting(&format!("ewelink_pass_{}", prof), req.password.trim());

            let count = devices.len();
            ctx.state.merge_from_cloud(devices);
            persist_current_profile_cache(&ctx.state, &ctx.db);
            record_all_devices_to_db(&ctx.state, &ctx.db);
            Json(json!({ "ok": true, "count": count, "region": actual_region }))
        }
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

async fn set_device_key(
    Path(id): Path<String>,
    State(ctx): State<ServerContext>,
    Json(req): Json<SetKeyReq>,
) -> Json<Value> {
    let Some(mut dev) = ctx.state.devices.get_mut(&id) else {
        return Json(json!({ "ok": false, "error": "Устройство не найдено" }));
    };

    if !req.local_key.trim().is_empty() {
        dev.local_key = Some(req.local_key.trim().to_string());
    }
    if let Some(name) = &req.name {
        if !name.trim().is_empty() {
            dev.name = Some(name.trim().to_string());
        }
    }
    if let Some(cat) = &req.category {
        if !cat.trim().is_empty() {
            dev.category = Some(cat.trim().to_string());
        }
    } else if dev.category.is_none() {
        dev.category = Some("kg".to_string());
    }
    drop(dev);

    persist_current_profile_cache(&ctx.state, &ctx.db);
    Json(json!({ "ok": true }))
}

fn spawn_periodic_cloud_poller(state: AppState, db: TelemetryDb) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        loop {
            let prof = state.current_profile();

            if let Some((ep, aid, asec)) = resolve_cloud_credentials(&db, &prof) {
                let seed_id = state
                    .devices
                    .iter()
                    .find(|d| d.vendor == Vendor::Tuya)
                    .map(|d| d.device_id.clone());

                if let Some(any_id) = seed_id {
                    let client = TuyaOpenApiClient::new(&ep, &aid, &asec);
                    if let Ok(devs) = client.sync_all_devices(&any_id).await {
                        state.merge_from_cloud(devs);
                        record_all_devices_to_db(&state, &db);
                    }
                }
            }

            if let (Some(login), Some(pass)) = (
                db.get_setting(&format!("ewelink_login_{}", prof)),
                db.get_setting(&format!("ewelink_pass_{}", prof)),
            ) {
                if !login.is_empty() && !pass.is_empty() {
                    let ep = db
                        .get_setting(&format!("ewelink_ep_{}", prof))
                        .unwrap_or_else(|| "eu".to_string());
                    let ew_client = ewelink::EWeLinkClient::new();
                    if let Ok((devs, _)) = ew_client.sync_all_devices(&login, &pass, &ep).await {
                        state.merge_from_cloud(devs);
                        record_all_devices_to_db(&state, &db);
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
}

fn spawn_local_poller(state: AppState, db: TelemetryDb) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(6)).await;
            let targets: Vec<DiscoveredDevice> = state
                .devices
                .iter()
                .filter(|d| d.vendor == Vendor::Tuya && d.ip.is_some() && d.local_key.is_some())
                .map(|d| d.value().clone())
                .collect();

            for dev in targets {
                let (Some(ip), Some(key)) = (dev.ip, dev.local_key.as_deref()) else {
                    continue;
                };
                if key.len() != 16 {
                    continue;
                }
                if let Ok(client) = TuyaClient::new(&dev.device_id, ip, dev.port, key, &dev.version)
                {
                    let _guard = LAN_LOCK.lock().await;
                    match client.query_status().await {
                        Ok(dps_json) => {
                            state.record_lan_success(&dev.device_id);
                            state.apply_lan_dps(&dev.device_id, &dps_json);
                            record_all_devices_to_db(&state, &db);
                        }
                        Err(e) => {
                            tracing::debug!(
                                "⏳ LAN-опрос «{}» ({}, v{}) пропущен: {}",
                                dev.name.as_deref().unwrap_or(&dev.device_id),
                                ip,
                                dev.version,
                                e
                            );
                            state.record_lan_failure(&dev.device_id);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
    });
}

async fn list_devices(State(ctx): State<ServerContext>) -> Json<Vec<DiscoveredDevice>> {
    let now = AppState::now();
    let mut list: Vec<DiscoveredDevice> = ctx
        .state
        .devices
        .iter()
        .map(|e| {
            let mut d = e.value().clone();
            let age_sec = now.saturating_sub(d.last_seen);
            let mut meta_obj = d
                .metadata
                .as_object()
                .cloned()
                .unwrap_or_else(serde_json::Map::new);
            meta_obj.insert("sensor_age_sec".to_string(), json!(age_sec));
            d.metadata = Value::Object(meta_obj);
            d
        })
        .collect();

    list.sort_by(|a, b| a.name.cmp(&b.name));
    Json(list)
}

async fn get_device_status(
    Path(id): Path<String>,
    State(ctx): State<ServerContext>,
) -> Json<Value> {
    let Some(dev) = ctx.state.devices.get(&id).map(|d| d.value().clone()) else {
        return Json(json!({ "ok": false, "error": "Устройство не найдено" }));
    };

    let prof = ctx.state.current_profile();

    if dev.vendor == Vendor::EWeLink || dev.version.starts_with("eWeLink") {
        if let (Some(login), Some(pass)) = (
            ctx.db.get_setting(&format!("ewelink_login_{}", prof)),
            ctx.db.get_setting(&format!("ewelink_pass_{}", prof)),
        ) {
            let ep = ctx
                .db
                .get_setting(&format!("ewelink_ep_{}", prof))
                .unwrap_or_else(|| "eu".to_string());
            let ew_client = ewelink::EWeLinkClient::new();
            if let Ok((devs, _)) = ew_client.sync_all_devices(&login, &pass, &ep).await {
                ctx.state.merge_from_cloud(devs);
                record_all_devices_to_db(&ctx.state, &ctx.db);
                let st = ctx
                    .state
                    .devices
                    .get(&id)
                    .map(|d| d.status.clone())
                    .unwrap_or(Value::Null);
                return Json(json!({ "ok": true, "mode": "eWeLink Sync", "status": st }));
            }
        }
        return Json(json!({ "ok": true, "mode": "eWeLink Cache", "status": dev.status }));
    }

    if let (Some(ip), Some(key)) = (dev.ip, dev.local_key.as_deref()) {
        if key.len() == 16 {
            if let Ok(client) = TuyaClient::new(&dev.device_id, ip, dev.port, key, &dev.version) {
                let _guard = LAN_LOCK.lock().await;
                if let Ok(data) = client.query_status().await {
                    ctx.state.record_lan_success(&id);
                    if data.get("dps").is_some() {
                        ctx.state.apply_lan_dps(&id, &data);
                        record_all_devices_to_db(&ctx.state, &ctx.db);
                        return Json(json!({ "ok": true, "mode": "LAN Direct", "status": data }));
                    }
                }
            }
        }
    }

    if let Some((ep, aid, asec)) = resolve_cloud_credentials(&ctx.db, &prof) {
        let client = TuyaOpenApiClient::new(&ep, &aid, &asec);
        if let Ok(st) = client.fetch_device_status(&id).await {
            if let Some(mut entry) = ctx.state.devices.get_mut(&id) {
                entry.status = st.clone();
                entry.last_seen = AppState::now();
            }
            record_all_devices_to_db(&ctx.state, &ctx.db);
            return Json(json!({ "ok": true, "mode": "Shadow Sync", "status": st }));
        }
    }

    Json(json!({ "ok": true, "mode": "Cache", "status": dev.status }))
}

async fn control_device(
    Path(id): Path<String>,
    State(ctx): State<ServerContext>,
    Json(req): Json<ControlRequest>,
) -> Json<Value> {
    match execute_device_command(&ctx.state, &ctx.db, &id, req.code, req.dp_id, req.value).await {
        Ok(mode) => Json(json!({ "ok": true, "mode": mode })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}
