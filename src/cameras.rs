use crate::db::TelemetryDb;
use crate::ewelink::b64_encode;
use crate::state::{AppState, DiscoveredDevice, Vendor};
use anyhow::{Result, anyhow, bail};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::timeout;

static CAPTURE_SEM: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(2));

static CAMERA_RUNTIME: LazyLock<DashMap<String, CameraRuntimeState>> = LazyLock::new(DashMap::new);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraConfig {
    pub preset: String, // "icsee" | "v380" | "ipw_onvif" | "tapo_dahua" | "custom"
    pub username: String,
    pub password: String,
    pub rtsp_port: u16,
    pub stream_quality: String, // "sub" (640x360 H.264) | "main" (HD)
    pub custom_url: String,
    pub detect_enabled: bool,
    pub sensitivity: f64,
}

impl Default for CameraConfig {
    fn default() -> Self {
        Self {
            preset: "icsee".to_string(),
            username: "admin".to_string(),
            password: String::new(),
            rtsp_port: 554,
            stream_quality: "sub".to_string(),
            custom_url: String::new(),
            detect_enabled: false,
            sensitivity: 1.5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MotionBox {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub label: String,
}

#[derive(Debug, Clone, Default)]
pub struct CameraRuntimeState {
    pub last_jpeg_b64: Option<String>,
    pub last_capture_ts: u64,
    pub last_working_url: Option<String>,
    pub prev_luma_grid: Option<Vec<u8>>,
    pub motion_detected: bool,
    pub motion_score: f64,
    pub motion_box: Option<MotionBox>,
    pub last_motion_ts: u64,
    pub last_motion_time_str: Option<String>,
    pub last_motion_jpeg_b64: Option<String>,
    pub last_error: Option<String>,
}

pub fn read_arp_table() -> HashMap<IpAddr, String> {
    let mut map = HashMap::new();
    if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 && cols[2] != "0x0" && cols[3] != "00:00:00:00:00:00" {
                if let Ok(ip) = cols[0].parse::<IpAddr>() {
                    map.insert(ip, cols[3].to_lowercase());
                }
            }
        }
    }
    map
}

pub fn extract_camera_config(dev: &DiscoveredDevice) -> CameraConfig {
    let default_preset = match dev.vendor {
        Vendor::CameraICSee => "icsee",
        Vendor::CameraV380 => "v380",
        _ => "ipw_onvif",
    };

    let meta = &dev.metadata;
    let preset = meta
        .get("preset")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(default_preset)
        .to_string();

    let username = meta
        .get("username")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("admin")
        .to_string();

    let password = dev
        .local_key
        .clone()
        .or_else(|| {
            meta.get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    let rtsp_port = meta
        .get("rtsp_port")
        .and_then(|v| v.as_u64())
        .map(|p| p as u16)
        .unwrap_or(554);

    let stream_quality = meta
        .get("stream_quality")
        .and_then(|v| v.as_str())
        .unwrap_or("sub")
        .to_string();

    let custom_url = meta
        .get("custom_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let detect_enabled = meta
        .get("detect_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let sensitivity = meta
        .get("sensitivity")
        .and_then(|v| v.as_f64())
        .unwrap_or(1.5)
        .clamp(0.4, 25.0);

    CameraConfig {
        preset,
        username,
        password,
        rtsp_port,
        stream_quality,
        custom_url,
        detect_enabled,
        sensitivity,
    }
}

pub fn encode_camera_version(cfg: &CameraConfig) -> String {
    format!(
        "CAM|{}|{}|{}|{}|{}|{}|{}",
        cfg.preset,
        cfg.username,
        cfg.rtsp_port,
        cfg.stream_quality,
        if cfg.detect_enabled { "1" } else { "0" },
        cfg.sensitivity,
        cfg.custom_url
    )
}

pub fn decode_camera_version_to_meta(version_str: &str, password: &str) -> Option<Value> {
    let rest = version_str.strip_prefix("CAM|")?;
    let parts: Vec<&str> = rest.splitn(7, '|').collect();
    if parts.len() < 6 {
        return None;
    }
    Some(json!({
        "preset": parts[0],
        "username": parts[1],
        "password": password,
        "rtsp_port": parts[2].parse::<u16>().unwrap_or(554),
        "stream_quality": parts[3],
        "detect_enabled": parts[4] == "1",
        "sensitivity": parts[5].parse::<f64>().unwrap_or(1.5),
        "custom_url": parts.get(6).copied().unwrap_or(""),
    }))
}

pub fn update_camera_settings(
    state: &AppState,
    device_id: &str,
    name: Option<String>,
    cfg: CameraConfig,
) -> Result<()> {
    let Some(mut dev) = state.devices.get_mut(device_id) else {
        bail!("Камера не найдена");
    };

    if let Some(n) = name {
        if !n.trim().is_empty() {
            dev.name = Some(n.trim().to_string());
        }
    }

    dev.local_key = Some(cfg.password.clone());
    dev.category = Some("camera".to_string());
    dev.vendor = match cfg.preset.as_str() {
        "icsee" => Vendor::CameraICSee,
        "v380" => Vendor::CameraV380,
        _ => Vendor::CameraOnvif,
    };
    dev.version = encode_camera_version(&cfg);

    let mut meta_obj = dev
        .metadata
        .as_object()
        .cloned()
        .unwrap_or_else(serde_json::Map::new);
    meta_obj.insert("preset".to_string(), json!(cfg.preset));
    meta_obj.insert("username".to_string(), json!(cfg.username));
    meta_obj.insert("rtsp_port".to_string(), json!(cfg.rtsp_port));
    meta_obj.insert("stream_quality".to_string(), json!(cfg.stream_quality));
    meta_obj.insert("custom_url".to_string(), json!(cfg.custom_url));
    meta_obj.insert("detect_enabled".to_string(), json!(cfg.detect_enabled));
    meta_obj.insert("sensitivity".to_string(), json!(cfg.sensitivity));
    dev.metadata = Value::Object(meta_obj);

    if let Some(mut rt) = CAMERA_RUNTIME.get_mut(device_id) {
        rt.last_working_url = None;
    }

    Ok(())
}

/// Строит список кандидатов RTSP URL.
/// Для XM530 (icsee) автоматически пробует логин `admin` (даже если введена почта) и пустой пароль по умолчанию.
pub fn build_rtsp_candidates(ip: IpAddr, cfg: &CameraConfig) -> Vec<String> {
    if cfg.preset == "custom" && !cfg.custom_url.trim().is_empty() {
        return vec![cfg.custom_url.trim().to_string()];
    }

    let raw_user = cfg.username.trim();
    let pass = cfg.password.trim();
    let port = if cfg.rtsp_port == 0 {
        554
    } else {
        cfg.rtsp_port
    };
    let is_sub = cfg.stream_quality != "main";

    // Если пользователь ввел email в качестве логина камеры, первым приоритетом ставим "admin"
    let effective_user = if raw_user.is_empty() || raw_user.contains('@') {
        "admin"
    } else {
        raw_user
    };

    let enc_user = url_encode_component(effective_user);
    let enc_pass = url_encode_component(pass);

    let auth_prefix = if pass.is_empty() {
        format!("{}@", enc_user)
    } else {
        format!("{}:{}@", enc_user, enc_pass)
    };

    match cfg.preset.as_str() {
        // 1. Xiongmai XM530_RA50X20_8M (iCSee / XMEye):
        "icsee" => {
            let s1 = if is_sub { 1 } else { 0 };
            let s2 = if is_sub { 0 } else { 1 };
            let mut list = vec![
                format!(
                    "rtsp://{}:{}/user={}&password={}&channel=1&stream={}.sdp?",
                    ip, port, effective_user, enc_pass, s1
                ),
                format!(
                    "rtsp://{}:{}/user={}&password={}&channel=1&stream={}.sdp?",
                    ip, port, effective_user, enc_pass, s2
                ),
            ];
            // Многие камеры XM530 в iCSee имеют пустой локальный пароль для admin, даже если в облаке стоит пароль
            if !pass.is_empty() {
                list.push(format!(
                    "rtsp://{}:{}/user=admin&password=&channel=1&stream={}.sdp?",
                    ip, port, s1
                ));
                list.push(format!(
                    "rtsp://{}:{}/user=admin&password=&channel=1&stream={}.sdp?",
                    ip, port, s2
                ));
            }
            list.push(format!(
                "rtsp://{}{}:{}/live/ch00_{}",
                auth_prefix,
                ip,
                port,
                if is_sub { 1 } else { 0 }
            ));
            list
        }

        // 2. Macro-Video V380 / V380 Pro (HsAKPIQB):
        "v380" => {
            let ch = if is_sub { "ch00_1" } else { "ch00_0" };
            let alt = if is_sub { "ch00_0" } else { "ch00_1" };
            let mut list = vec![
                format!("rtsp://{}{}:{}/live/{}", auth_prefix, ip, port, ch),
                format!("rtsp://{}{}:{}/live/{}", auth_prefix, ip, port, alt),
            ];
            if !pass.is_empty() {
                list.push(format!("rtsp://admin@{}:{}/live/{}", ip, port, ch));
            }
            list
        }

        // 3. IPW-F4A2D1E1 («Деревня») / Uniview / HiLook / Hikvision / ONVIF:
        "ipw_onvif" => {
            let unv_s = if is_sub { 1 } else { 0 };
            let hik_ch = if is_sub { 102 } else { 101 };
            let tapo_s = if is_sub { "stream2" } else { "stream1" };
            vec![
                format!(
                    "rtsp://{}{}:{}/unicast/c1/s{}/live",
                    auth_prefix, ip, port, unv_s
                ),
                format!(
                    "rtsp://{}{}:{}/Streaming/Channels/{}",
                    auth_prefix, ip, port, hik_ch
                ),
                format!("rtsp://{}{}:{}/{}", auth_prefix, ip, port, tapo_s),
                format!("rtsp://{}{}:{}/live/ch1", auth_prefix, ip, port),
                format!(
                    "rtsp://{}{}:{}/cam/realmonitor?channel=1&subtype={}",
                    auth_prefix, ip, port, unv_s
                ),
            ]
        }

        _ => {
            let tapo_s = if is_sub { "stream2" } else { "stream1" };
            let sub_id = if is_sub { 1 } else { 0 };
            vec![
                format!("rtsp://{}{}:{}/{}", auth_prefix, ip, port, tapo_s),
                format!(
                    "rtsp://{}{}:{}/cam/realmonitor?channel=1&subtype={}",
                    auth_prefix, ip, port, sub_id
                ),
                format!(
                    "rtsp://{}{}:{}/unicast/c1/s{}/live",
                    auth_prefix, ip, port, sub_id
                ),
            ]
        }
    }
}

fn build_http_snapshot_candidates(ip: IpAddr, cfg: &CameraConfig) -> Vec<String> {
    let raw_user = cfg.username.trim();
    let user = if raw_user.is_empty() || raw_user.contains('@') {
        "admin"
    } else {
        raw_user
    };
    let pass = url_encode_component(cfg.password.trim());
    match cfg.preset.as_str() {
        "icsee" => vec![
            format!(
                "http://{}/webcapture.jpg?command=snap&channel=1&user={}&password={}",
                ip, user, pass
            ),
            format!(
                "http://{}/webcapture.jpg?command=snap&channel=1&user=admin&password=",
                ip
            ),
        ],
        "ipw_onvif" => vec![
            format!(
                "http://{}/LAPI/V1.0/Channels/1/Media/Video/Streams/1/Snapshot",
                ip
            ),
            format!("http://{}/ISAPI/Streaming/channels/102/picture", ip),
            format!("http://{}/onvif-http/snapshot?Profile_1", ip),
        ],
        _ => Vec::new(),
    }
}

pub async fn capture_and_analyze_camera(
    state: &AppState,
    db: &TelemetryDb,
    device_id: &str,
    force_fresh: bool,
) -> Result<Value> {
    let Some(dev) = state.devices.get(device_id).map(|d| d.value().clone()) else {
        bail!("Камера не найдена в текущем профиле");
    };

    let now = AppState::now();

    if !force_fresh {
        if let Some(rt) = CAMERA_RUNTIME.get(device_id) {
            if now.saturating_sub(rt.last_capture_ts) <= 1 && rt.last_jpeg_b64.is_some() {
                return Ok(build_camera_response_json(&dev, &rt));
            }
        }
    }

    let ip = dev
        .ip
        .ok_or_else(|| anyhow!("У камеры не определен локальный IP-адрес"))?;
    let cfg = extract_camera_config(&dev);

    let _permit = CAPTURE_SEM
        .acquire()
        .await
        .map_err(|_| anyhow!("Очередь видеозахвата занята"))?;

    let known_url = CAMERA_RUNTIME
        .get(device_id)
        .and_then(|r| r.last_working_url.clone());

    let grab_result = grab_jpeg_bytes(ip, &cfg, known_url.as_deref()).await;

    match grab_result {
        Ok((jpeg_bytes, working_url)) => {
            let b64_img = format!("data:image/jpeg;base64,{}", b64_encode(&jpeg_bytes));
            let luma_opt = extract_luma_grid_64x36(&jpeg_bytes).await.ok();

            let mut rt = CAMERA_RUNTIME.entry(device_id.to_string()).or_default();
            rt.last_jpeg_b64 = Some(b64_img.clone());
            rt.last_capture_ts = now;
            rt.last_working_url = Some(working_url.clone());
            rt.last_error = None;

            if let Some(curr_grid) = luma_opt {
                if let Some(prev_grid) = &rt.prev_luma_grid {
                    let (detected, score, bbox) =
                        run_two_stage_motion_detector(prev_grid, &curr_grid, cfg.sensitivity);

                    rt.motion_score = score;
                    rt.motion_detected = detected;
                    if detected {
                        let time_str = current_hms_string();
                        rt.motion_box = bbox;
                        rt.last_motion_ts = now;
                        rt.last_motion_time_str = Some(time_str);
                        rt.last_motion_jpeg_b64 = Some(b64_img);
                    } else if now.saturating_sub(rt.last_motion_ts) > 6 {
                        rt.motion_box = None;
                    }
                }
                rt.prev_luma_grid = Some(curr_grid);
            }

            let resp_json = build_camera_response_json(&dev, &rt);
            let motion_det = rt.motion_detected;
            let motion_sc = rt.motion_score;
            let motion_tm = rt
                .last_motion_time_str
                .clone()
                .unwrap_or_else(|| "—".to_string());
            let bbox_val = serde_json::to_value(&rt.motion_box).unwrap_or(Value::Null);
            drop(rt);

            if let Some(mut entry) = state.devices.get_mut(device_id) {
                entry.online = true;
                entry.last_seen = now;
                entry.status = json!([
                    { "code": "motion_detected", "dp_id": 201, "value": motion_det },
                    { "code": "motion_score", "dp_id": 202, "value": (motion_sc * 10.0).round() / 10.0 },
                    { "code": "last_motion_time", "dp_id": 203, "value": motion_tm }
                ]);

                let mut m = entry
                    .metadata
                    .as_object()
                    .cloned()
                    .unwrap_or_else(serde_json::Map::new);
                m.insert(
                    "active_stream_url".to_string(),
                    json!(mask_url_password(&working_url)),
                );
                m.insert("motion_detected".to_string(), json!(motion_det));
                m.insert("motion_score".to_string(), json!(motion_sc));
                m.insert("motion_box".to_string(), bbox_val);
                m.insert("last_error".to_string(), Value::Null);
                entry.metadata = Value::Object(m);
            }

            if motion_det {
                let prof = state.current_profile();
                db.record_metric(&prof, device_id, "motion", motion_sc);
            }

            Ok(resp_json)
        }
        Err(e) => {
            let err_msg = e.to_string();
            let mut rt = CAMERA_RUNTIME.entry(device_id.to_string()).or_default();
            rt.last_working_url = None;
            rt.last_error = Some(err_msg.clone());
            let resp_json = build_camera_response_json(&dev, &rt);
            drop(rt);

            if let Some(mut entry) = state.devices.get_mut(device_id) {
                let mut m = entry
                    .metadata
                    .as_object()
                    .cloned()
                    .unwrap_or_else(serde_json::Map::new);
                m.insert("last_error".to_string(), json!(err_msg));
                entry.metadata = Value::Object(m);
            }

            Ok(resp_json)
        }
    }
}

fn build_camera_response_json(dev: &DiscoveredDevice, rt: &CameraRuntimeState) -> Value {
    json!({
        "ok": rt.last_error.is_none() && rt.last_jpeg_b64.is_some(),
        "device_id": dev.device_id,
        "name": dev.name,
        "ip": dev.ip,
        "image_b64": rt.last_jpeg_b64,
        "capture_ts": rt.last_capture_ts,
        "motion_detected": rt.motion_detected,
        "motion_score": (rt.motion_score * 10.0).round() / 10.0,
        "motion_box": rt.motion_box,
        "last_motion_time": rt.last_motion_time_str,
        "last_motion_image_b64": rt.last_motion_jpeg_b64,
        "error": rt.last_error
    })
}

async fn grab_jpeg_bytes(
    ip: IpAddr,
    cfg: &CameraConfig,
    known_working_url: Option<&str>,
) -> Result<(Vec<u8>, String)> {
    if let Some(url) = known_working_url {
        if url.starts_with("http://") {
            if let Ok(bytes) = try_http_snapshot(url, &cfg.username, &cfg.password).await {
                return Ok((bytes, url.to_string()));
            }
        } else if let Ok(bytes) = try_ffmpeg_rtsp_snapshot(url).await {
            return Ok((bytes, url.to_string()));
        }
    }

    for http_url in build_http_snapshot_candidates(ip, cfg) {
        if let Ok(bytes) = try_http_snapshot(&http_url, &cfg.username, &cfg.password).await {
            return Ok((bytes, http_url));
        }
    }

    let candidates = build_rtsp_candidates(ip, cfg);
    let mut first_err: Option<String> = None;

    for rtsp_url in candidates {
        match try_ffmpeg_rtsp_snapshot(&rtsp_url).await {
            Ok(bytes) => {
                tracing::info!(
                    "📸 Успешный захват кадра по URL: {}",
                    mask_url_password(&rtsp_url)
                );
                return Ok((bytes, rtsp_url));
            }
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e.to_string());
                }
            }
        }
    }

    bail!(
        "{}",
        first_err.unwrap_or_else(|| "Не удалось подключиться к RTSP порту камеры".to_string())
    )
}

async fn try_http_snapshot(url: &str, user: &str, pass: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(1500))
        .build()?;

    let clean_user = if user.trim().is_empty() || user.contains('@') {
        "admin"
    } else {
        user.trim()
    };

    let req = client.get(url).basic_auth(clean_user, Some(pass.trim()));
    let resp = req.send().await?;
    if !resp.status().is_success() {
        bail!("HTTP {}", resp.status());
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > 256 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
        Ok(bytes.to_vec())
    } else {
        bail!("Ответ не является JPEG-кадром")
    }
}

/// Проверяет сырой ответ RTSP-сервера камеры перед запуском FFmpeg, чтобы точно видеть причину отказа в логе
async fn probe_rtsp_handshake(rtsp_url: &str) -> Result<()> {
    let without_scheme = rtsp_url.strip_prefix("rtsp://").unwrap_or(rtsp_url);
    let host_port_part = without_scheme.split('/').next().unwrap_or("");
    let clean_host_port = host_port_part.split('@').last().unwrap_or(host_port_part);

    let Ok(addr) = clean_host_port.parse::<std::net::SocketAddr>() else {
        return Ok(());
    };

    let Ok(Ok(mut stream)) = timeout(
        Duration::from_millis(1200),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    else {
        bail!("Порт RTSP ({}) не отвечает", addr);
    };

    let req = format!(
        "DESCRIBE {} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: SmartHub\r\nAccept: application/sdp\r\n\r\n",
        rtsp_url
    );
    let _ = stream.write_all(req.as_bytes()).await;

    let mut buf = [0u8; 1024];
    if let Ok(Ok(n)) = timeout(
        Duration::from_millis(1200),
        tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
    )
    .await
    {
        if n > 0 {
            let reply = String::from_utf8_lossy(&buf[..n]);
            let first_line = reply.lines().next().unwrap_or("");
            tracing::info!("📡 RTSP ответ от {}: {}", addr, first_line);

            if first_line.contains("401") {
                bail!("Камера вернула 401 Unauthorized (неверный пароль для admin)");
            } else if first_line.contains("404") || first_line.contains("454") {
                bail!(
                    "Камера вернула {} (неверный путь потока или пароль)",
                    first_line
                );
            }
        }
    }
    Ok(())
}

async fn try_ffmpeg_rtsp_snapshot(rtsp_url: &str) -> Result<Vec<u8>> {
    // Сначала проверяем ответ RTSP-сокета и выводим его в консоль
    probe_rtsp_handshake(rtsp_url).await?;

    let mut cmd = Command::new("ffmpeg");
    cmd.args([
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-analyzeduration",
        "4000000",
        "-probesize",
        "2000000",
        "-i",
        rtsp_url,
        "-frames:v",
        "1",
        "-vf",
        "scale=640:-2",
        "-q:v",
        "5",
        "-f",
        "image2pipe",
        "-vcodec",
        "mjpeg",
        "pipe:1",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);

    let out = timeout(Duration::from_millis(5500), cmd.output())
        .await
        .map_err(|_| anyhow!("Таймаут декодирования кадра RTSP"))??;

    if out.stdout.len() > 256 && out.stdout[0] == 0xFF && out.stdout[1] == 0xD8 {
        Ok(out.stdout)
    } else {
        let stderr_str = String::from_utf8_lossy(&out.stderr);
        tracing::warn!(
            "⚠️ Вывод FFmpeg для {}: {}",
            mask_url_password(rtsp_url),
            stderr_str.trim()
        );
        if stderr_str.contains("401 Unauthorized") || stderr_str.contains("authorization failed") {
            bail!("Ошибка 401: Неверный пароль камеры (логин admin, пароль от камеры в iCSee)");
        } else if stderr_str.contains("Connection refused") {
            bail!("Порт RTSP (554) закрыт на камере (включите RTSP/ONVIF в приложении)");
        } else if stderr_str.contains("Invalid data found") {
            bail!(
                "Камера отклонила пароль или поток (введите пароль камеры и нажмите «Сохранить»)"
            );
        }
        let short_err = stderr_str
            .lines()
            .next()
            .unwrap_or("Не удалось декодировать кадр");
        bail!("RTSP: {}", short_err)
    }
}

const GRID_W: usize = 64;
const GRID_H: usize = 36;
const GRID_SIZE: usize = GRID_W * GRID_H;

async fn extract_luma_grid_64x36(jpeg_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "mjpeg",
            "-i",
            "pipe:0",
            "-vf",
            "scale=64:36",
            "-pix_fmt",
            "gray",
            "-f",
            "rawvideo",
            "pipe:1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(jpeg_bytes).await;
        let _ = stdin.shutdown().await;
    }

    let out = timeout(Duration::from_millis(1200), child.wait_with_output()).await??;
    if out.stdout.len() >= GRID_SIZE {
        Ok(out.stdout[..GRID_SIZE].to_vec())
    } else {
        bail!("Не удалось получить матрицу яркости 64x36")
    }
}

fn run_two_stage_motion_detector(
    prev: &[u8],
    curr: &[u8],
    sensitivity_pct: f64,
) -> (bool, f64, Option<MotionBox>) {
    if prev.len() < GRID_SIZE || curr.len() < GRID_SIZE {
        return (false, 0.0, None);
    }

    let sum_prev: i32 = prev.iter().map(|&v| v as i32).sum();
    let sum_curr: i32 = curr.iter().map(|&v| v as i32).sum();
    let mean_shift = (sum_curr - sum_prev) / (GRID_SIZE as i32);

    let mut raw_active = [false; GRID_SIZE];
    let mut raw_count = 0usize;

    for i in 0..GRID_SIZE {
        let compensated_curr = (curr[i] as i32 - mean_shift).clamp(0, 255);
        let diff = (compensated_curr - prev[i] as i32).unsigned_abs();
        if diff >= 22 {
            raw_active[i] = true;
            raw_count += 1;
        }
    }

    if raw_count > (GRID_SIZE * 60 / 100) {
        return (false, 0.0, None);
    }

    let mut min_x = GRID_W;
    let mut min_y = GRID_H;
    let mut max_x = 0usize;
    let mut max_y = 0usize;
    let mut core_count = 0usize;

    for y in 1..(GRID_H - 1) {
        for x in 1..(GRID_W - 1) {
            let idx = y * GRID_W + x;
            if !raw_active[idx] {
                continue;
            }

            let mut neighbors = 0u8;
            for dy in -1i32..=1 {
                for dx in -1i32..=1 {
                    if dx == 0 && dy == 0 {
                        continue;
                    }
                    let n_idx = ((y as i32 + dy) as usize) * GRID_W + ((x as i32 + dx) as usize);
                    if raw_active[n_idx] {
                        neighbors += 1;
                    }
                }
            }

            if neighbors >= 2 {
                core_count += 1;
                if x < min_x {
                    min_x = x;
                }
                if x > max_x {
                    max_x = x;
                }
                if y < min_y {
                    min_y = y;
                }
                if y > max_y {
                    max_y = y;
                }
            }
        }
    }

    let score_pct = (core_count as f64 / GRID_SIZE as f64) * 100.0;
    if score_pct < sensitivity_pct || core_count < 4 || max_x < min_x || max_y < min_y {
        return (false, score_pct, None);
    }

    let box_w_cells = (max_x - min_x + 1).max(2);
    let box_h_cells = (max_y - min_y + 1).max(2);

    let x_pct = ((min_x * 100) / GRID_W) as u32;
    let y_pct = ((min_y * 100) / GRID_H) as u32;
    let w_pct = (((box_w_cells * 100) / GRID_W) as u32).clamp(6, 100 - x_pct);
    let h_pct = (((box_h_cells * 100) / GRID_H) as u32).clamp(8, 100 - y_pct);

    let label = if h_pct >= w_pct && score_pct >= 2.0 {
        format!("🚶 Силуэт / Объект ({:.1}%)", score_pct)
    } else {
        format!("🚨 Движение ({:.1}%)", score_pct)
    };

    (
        true,
        score_pct,
        Some(MotionBox {
            x: x_pct,
            y: y_pct,
            w: w_pct,
            h: h_pct,
            label,
        }),
    )
}

pub fn spawn_camera_worker(state: AppState, db: TelemetryDb) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            let active_cameras: Vec<String> = state
                .devices
                .iter()
                .filter(|d| {
                    format!("{:?}", d.vendor).starts_with("Camera")
                        && d.ip.is_some()
                        && d.metadata
                            .get("detect_enabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                })
                .map(|d| d.device_id.clone())
                .collect();

            for cam_id in active_cameras {
                let _ = capture_and_analyze_camera(&state, &db, &cam_id, true).await;
                tokio::time::sleep(Duration::from_millis(400)).await;
            }

            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

fn mask_url_password(url: &str) -> String {
    if let Some(idx) = url.find("password=") {
        let prefix = &url[..idx + 9];
        let rest = &url[idx + 9..];
        if let Some(amp) = rest.find('&') {
            return format!("{}***{}", prefix, &rest[amp..]);
        }
        return format!("{}***", prefix);
    }
    url.to_string()
}

fn url_encode_component(raw: &str) -> String {
    let mut out = String::new();
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn current_hms_string() -> String {
    if let Ok(out) = std::process::Command::new("date").arg("+%H:%M:%S").output() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }
    "сейчас".to_string()
}
