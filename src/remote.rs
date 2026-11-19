use crate::db::TelemetryDb;
use crate::state::AppState;
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::error::Error as StdError;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::time::timeout;
use uuid::Uuid;

fn default_vps_url() -> String {
    std::env::var("DEFAULT_VPS_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_default()
}

fn default_stun_server() -> String {
    std::env::var("DEFAULT_STUN_SERVER")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "stun.cloudflare.com:3478".to_string())
}

const STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.nextcloud.com:443",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfig {
    pub hub_id: String,
    pub vps_url: String,
    pub vps_secret: String,
    pub auth_password_hash: String,
    pub stun_server: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct WifiChannelInfo {
    pub ssid: String,
    pub band: String,
    pub channel: u32,
    pub freq_mhz: u32,
    pub signal_pct: u32,
    pub rssi_dbm: i32,
    pub overlapping_ap_count: usize,
    pub best_24_channel: u32,
    pub quality_grade: String, // "good", "warn", "bad"
    pub verdict: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AdaptiveNetworkStatus {
    pub local_endpoint: Option<String>,
    pub stun_public_endpoint: Option<String>,
    pub vps_relay_connected: bool,
    pub last_vps_sync_ts: u64,
    pub last_error: Option<String>,
    pub wifi: Option<WifiChannelInfo>,
}

#[derive(Clone)]
pub struct RemoteManager {
    pub config: Arc<RwLock<RemoteConfig>>,
    pub net_status: Arc<RwLock<AdaptiveNetworkStatus>>,
}

impl RemoteManager {
    pub fn new(db: &TelemetryDb) -> Self {
        let hub_id = db
            .get_setting("hub_id")
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| {
                let new_id = format!("hub-{}", &Uuid::new_v4().to_string()[..8]);
                db.set_setting("hub_id", &new_id);
                new_id
            });

        let vps_url = db
            .get_setting("vps_url")
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| {
                db.set_setting("vps_url", &default_vps_url());
                default_vps_url()
            });

        let vps_secret = db.get_setting("vps_secret").unwrap_or_default();
        let auth_password_hash = db.get_setting("auth_password_hash").unwrap_or_default();
        let stun_server = db
            .get_setting("stun_server")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| default_stun_server());

        let enabled = true;
        db.set_setting("remote_enabled", "true");

        Self {
            config: Arc::new(RwLock::new(RemoteConfig {
                hub_id,
                vps_url,
                vps_secret,
                auth_password_hash,
                stun_server,
                enabled,
            })),
            net_status: Arc::new(RwLock::new(AdaptiveNetworkStatus::default())),
        }
    }

    pub fn save_config(
        &self,
        db: &TelemetryDb,
        vps_url: String,
        vps_secret: String,
        new_password: Option<String>,
        stun_server: String,
        _enabled: bool,
    ) {
        if let Ok(mut cfg) = self.config.write() {
            let clean_url = vps_url.trim().trim_end_matches('/');
            cfg.vps_url = if clean_url.is_empty() {
                default_vps_url()
            } else {
                clean_url.to_string()
            };

            let clean_sec = vps_secret.trim();
            if clean_sec.eq_ignore_ascii_case("CLEAR") {
                cfg.vps_secret = String::new();
                db.set_setting("vps_secret", "");
            } else if !clean_sec.is_empty() {
                cfg.vps_secret = clean_sec.to_string();
                db.set_setting("vps_secret", &cfg.vps_secret);
            }

            if !stun_server.trim().is_empty() {
                cfg.stun_server = stun_server.trim().to_string();
            }
            cfg.enabled = true;

            if let Some(pwd) = new_password {
                let clean = pwd.trim();
                if clean.eq_ignore_ascii_case("CLEAR") {
                    cfg.auth_password_hash = String::new();
                    db.set_setting("auth_password_hash", "");
                } else if !clean.is_empty() {
                    cfg.auth_password_hash = hash_token(clean);
                    db.set_setting("auth_password_hash", &cfg.auth_password_hash);
                }
            }

            db.set_setting("vps_url", &cfg.vps_url);
            db.set_setting("stun_server", &cfg.stun_server);
            db.set_setting("remote_enabled", "true");
        }
    }

    pub fn verify_token_or_password(&self, token_or_pwd: &str) -> bool {
        let Ok(cfg) = self.config.read() else {
            return true;
        };
        if cfg.auth_password_hash.is_empty() {
            return true;
        }
        let cleaned = token_or_pwd.trim();
        cleaned == cfg.auth_password_hash || hash_token(cleaned) == cfg.auth_password_hash
    }
}

pub fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    let salt = std::env::var("AUTH_SALT").unwrap_or_else(|_| "smarthub-salt".to_string());
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn adaptive_cors_and_auth_middleware(
    axum::extract::State(remote): axum::extract::State<RemoteManager>,
    req: Request,
    next: Next,
) -> Response {
    if req.method() == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        append_adaptive_headers(resp.headers_mut());
        return resp;
    }

    let path = req.uri().path().to_string();
    let is_public_route = path == "/"
        || path == "/api/ping"
        || path == "/api/auth/login"
        || path.starts_with("/static");

    if !is_public_route {
        let requires_auth = remote
            .config
            .read()
            .map(|c| !c.auth_password_hash.is_empty())
            .unwrap_or(false);

        if requires_auth {
            let auth_header = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let bearer = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);

            if !remote.verify_token_or_password(bearer) {
                let body = serde_json::to_string(&json!({
                    "ok": false,
                    "auth_required": true,
                    "error": "Требуется авторизация (введите пароль)"
                }))
                .unwrap_or_default();

                let mut resp = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap();
                append_adaptive_headers(resp.headers_mut());
                return resp;
            }
        }
    }

    let mut resp = next.run(req).await;
    append_adaptive_headers(resp.headers_mut());
    resp
}

fn append_adaptive_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
    headers.insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static("Content-Type, Authorization, X-Hub-Token"),
    );
    headers.insert(
        "Access-Control-Allow-Private-Network",
        HeaderValue::from_static("true"),
    );
}

fn format_reqwest_error(err: &reqwest::Error) -> String {
    if err.is_timeout() {
        return "Таймаут ожидания ответа (порт 4000 закрыт файрволом)".to_string();
    }
    let mut cur: Option<&dyn StdError> = err.source();
    while let Some(src) = cur {
        let msg = src.to_string();
        if msg.contains("Connection refused") || msg.contains("os error 111") {
            return "Соединение отклонено (на VPS не запущен smart-hub-vps на порту 4000)"
                .to_string();
        }
        if src.source().is_none() {
            return msg;
        }
        cur = src.source();
    }
    err.to_string()
}

pub fn spawn_adaptive_network_worker(remote: RemoteManager, _state: AppState) {
    tokio::spawn(async move {
        let http_client = Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap_or_default();

        let p2p_socket = UdpSocket::bind("0.0.0.0:0").await.ok().map(Arc::new);
        let local_udp_port = p2p_socket
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(52321);

        if let Some(sock_cl) = p2p_socket.clone() {
            let rem_cl = remote.clone();
            let http_cl = http_client.clone();
            tokio::spawn(async move {
                run_p2p_udp_responder(sock_cl, rem_cl, http_cl).await;
            });
        }

        let mut last_stun_check: u64 = 0;
        let mut logged_connected = false;

        loop {
            let now = AppState::now();
            let (vps_url, vps_secret, hub_id) = {
                let cfg = remote.config.read().unwrap();
                (
                    cfg.vps_url.clone(),
                    cfg.vps_secret.clone(),
                    cfg.hub_id.clone(),
                )
            };

            let has_stun = remote
                .net_status
                .read()
                .map(|s| s.stun_public_endpoint.is_some())
                .unwrap_or(false);

            if !has_stun || now.saturating_sub(last_stun_check) >= 25 {
                last_stun_check = now;
                let local_ep = detect_local_ipv4().await.map(|ip| format!("{}:3000", ip));
                let wifi_info = analyze_wifi_channel().await;

                let mut stun_ep = None;
                if let Some(sock) = p2p_socket.as_ref() {
                    if let Some(vps_udp_addr) = parse_vps_udp_addr(&vps_url) {
                        let reg_msg = format!("SMARTHUB_HUB_REG:{}", hub_id);
                        let _ = sock.send_to(reg_msg.as_bytes(), vps_udp_addr).await;
                    }

                    for &srv in STUN_SERVERS {
                        if let Ok(addr) = query_stun_public_addr(sock, srv).await {
                            stun_ep = Some(addr.to_string());
                            break;
                        }
                    }
                }

                if stun_ep.is_none() {
                    if let Some(ext_ip) = fetch_external_ip_fallback(&http_client).await {
                        stun_ep = Some(format!("{}:{}", ext_ip, local_udp_port));
                    }
                }

                if let Ok(mut st) = remote.net_status.write() {
                    st.local_endpoint = local_ep;
                    st.wifi = wifi_info;
                    if stun_ep.is_some() {
                        st.stun_public_endpoint = stun_ep;
                    }
                }
            }

            if !vps_url.is_empty() {
                let (local_ep, stun_ep) = {
                    let st = remote.net_status.read().unwrap();
                    (st.local_endpoint.clone(), st.stun_public_endpoint.clone())
                };

                let heartbeat_url = format!("{}/api/relay/heartbeat", vps_url);
                let payload = json!({
                    "hub_id": hub_id,
                    "local_endpoint": local_ep,
                    "p2p_udp_endpoint": stun_ep,
                    "ts": now
                });

                match http_client
                    .post(&heartbeat_url)
                    .header("X-Relay-Secret", &vps_secret)
                    .json(&payload)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        if !logged_connected {
                            tracing::info!(
                                "🌐 Связь с VPS-координатором ({}) установлена!",
                                vps_url
                            );
                            logged_connected = true;
                        }
                        if let Ok(mut st) = remote.net_status.write() {
                            st.vps_relay_connected = true;
                            st.last_vps_sync_ts = AppState::now();
                            st.last_error = None;
                        }

                        if let Ok(body) = resp.json::<Value>().await {
                            if let (Some(peer_udp), Some(sock)) = (
                                body.get("punch_peer_udp").and_then(|v| v.as_str()),
                                p2p_socket.as_ref(),
                            ) {
                                if let Ok(peer_addr) = peer_udp.parse::<SocketAddr>() {
                                    let punch_pkt = json!({
                                        "type": "P2P_HELLO",
                                        "hub_id": hub_id
                                    })
                                    .to_string();
                                    for _ in 0..3 {
                                        let _ = sock.send_to(punch_pkt.as_bytes(), peer_addr).await;
                                        tokio::time::sleep(Duration::from_millis(30)).await;
                                    }
                                }
                            }

                            if let Some(pending_reqs) =
                                body.get("pending_requests").and_then(|v| v.as_array())
                            {
                                for req_item in pending_reqs {
                                    let req_id = req_item
                                        .get("req_id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let method = req_item
                                        .get("method")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("GET")
                                        .to_string();
                                    let path = req_item
                                        .get("path")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("/api/ping")
                                        .to_string();
                                    let auth = req_item
                                        .get("auth")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let req_body = req_item.get("body").cloned();

                                    if !req_id.is_empty() {
                                        let client_cl = http_client.clone();
                                        let vps_cl = vps_url.clone();
                                        let sec_cl = vps_secret.clone();
                                        tokio::spawn(async move {
                                            forward_relayed_request_to_local(
                                                &client_cl, &vps_cl, &sec_cl, &req_id, &method,
                                                &path, &auth, req_body,
                                            )
                                            .await;
                                        });
                                    }
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    Ok(resp) => {
                        logged_connected = false;
                        let code = resp.status().as_u16();
                        let msg = if code == 401 {
                            "HTTP 401: Не совпадает RELAY_SECRET на VPS и на Хабе".to_string()
                        } else {
                            format!("HTTP {}", code)
                        };
                        tracing::warn!("⚠️ Отказ VPS ({}): {}", vps_url, msg);
                        if let Ok(mut st) = remote.net_status.write() {
                            st.vps_relay_connected = false;
                            st.last_error = Some(msg);
                        }
                    }
                    Err(e) => {
                        logged_connected = false;
                        let detail = format_reqwest_error(&e);
                        tracing::warn!("⚠️ Нет связи с VPS ({}): {}", vps_url, detail);
                        if let Ok(mut st) = remote.net_status.write() {
                            st.vps_relay_connected = false;
                            st.last_error = Some(detail);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            } else {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    });
}

// ============================================================================
// АНАЛИЗАТОР КАНАЛА WI-FI И ПОМЕХ ДЛЯ ДАТЧИКОВ УМНОГО ДОМА (2.4 ГГц / 5 ГГц)
// ============================================================================

async fn analyze_wifi_channel() -> Option<WifiChannelInfo> {
    // 1. Опрашиваем NetworkManager (nmcli) без принудительного рескана (мгновенный ответ <15 мс)
    if let Ok(out) = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "IN-USE,CHAN,FREQ,SIGNAL,SSID",
            "dev",
            "wifi",
            "list",
            "--rescan",
            "no",
        ])
        .output()
        .await
    {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut active: Option<(u32, u32, u32, String)> = None;
            let mut neighbors_24: Vec<(u32, u32)> = Vec::new();

            for line in stdout.lines() {
                let parts: Vec<&str> = line.splitn(5, ':').collect();
                if parts.len() < 5 {
                    continue;
                }
                let is_active = parts[0].trim() == "*";
                let chan = parts[1].trim().parse::<u32>().unwrap_or(0);
                let freq = parts[2]
                    .split_whitespace()
                    .next()
                    .and_then(|f| f.parse::<u32>().ok())
                    .unwrap_or(0);
                let sig = parts[3].trim().parse::<u32>().unwrap_or(0);
                let ssid = parts[4].replace("\\:", ":");

                if chan == 0 {
                    continue;
                }
                if is_active {
                    active = Some((chan, freq, sig, ssid));
                } else if chan <= 14 {
                    neighbors_24.push((chan, sig));
                }
            }

            if let Some((chan, freq, sig, ssid)) = active {
                return Some(build_wifi_verdict(ssid, chan, freq, sig, &neighbors_24));
            }
        }
    }

    // 2. Резервный метод через `iw dev` + `/proc/net/wireless`
    let iw_out = Command::new("iw").args(["dev"]).output().await.ok()?;
    let iw_str = String::from_utf8_lossy(&iw_out.stdout);
    let mut ssid = String::new();
    let mut chan = 0u32;
    let mut freq = 0u32;

    for line in iw_str.lines() {
        let t = line.trim();
        if let Some(s) = t.strip_prefix("ssid ") {
            ssid = s.trim().to_string();
        } else if let Some(rest) = t.strip_prefix("channel ") {
            // Пример: "channel 6 (2437 MHz), width: 20 MHz..."
            let mut it = rest.split_whitespace();
            if let Some(c_str) = it.next() {
                chan = c_str.parse().unwrap_or(0);
            }
            if let Some(f_str) = it.next() {
                freq = f_str.trim_start_matches('(').parse().unwrap_or(0);
            }
        }
    }

    if chan == 0 {
        return None;
    }

    let mut rssi_dbm = -60i32;
    if let Ok(wireless) = std::fs::read_to_string("/proc/net/wireless") {
        for line in wireless.lines().skip(2) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 {
                if let Ok(lvl) = cols[3].trim_end_matches('.').parse::<i32>() {
                    rssi_dbm = lvl;
                }
            }
        }
    }
    let sig_pct = ((rssi_dbm + 100).clamp(0, 50) * 2) as u32;
    Some(build_wifi_verdict(ssid, chan, freq, sig_pct, &[]))
}

fn build_wifi_verdict(
    ssid: String,
    channel: u32,
    freq_mhz: u32,
    signal_pct: u32,
    neighbors_24: &[(u32, u32)],
) -> WifiChannelInfo {
    let rssi_dbm = (signal_pct as i32 / 2) - 100;
    let is_24 = channel <= 14 || (freq_mhz > 0 && freq_mhz < 3000);
    let band = if is_24 {
        "2.4 ГГц".to_string()
    } else {
        "5 ГГц".to_string()
    };

    // Считаем интерференцию на 3 главных непересекающихся каналах 2.4 ГГц (1, 6, 11)
    let mut best_24_channel = 6u32;
    let mut min_score = u32::MAX;
    for &candidate in &[1u32, 6, 11] {
        let mut score = 0u32;
        for &(n_ch, n_sig) in neighbors_24 {
            let dist = (n_ch as i32 - candidate as i32).unsigned_abs();
            if dist == 0 {
                score += n_sig;
            } else if dist <= 2 {
                score += (n_sig * 2) / 3;
            } else if dist <= 4 {
                score += n_sig / 3;
            }
        }
        if score < min_score {
            min_score = score;
            best_24_channel = candidate;
        }
    }

    let overlapping_ap_count = if is_24 {
        neighbors_24
            .iter()
            .filter(|&&(n_ch, _)| (n_ch as i32 - channel as i32).unsigned_abs() <= 2)
            .count()
    } else {
        0
    };

    let (quality_grade, verdict, details) = if is_24 {
        if channel >= 12 {
            (
                "bad".to_string(),
                format!("🔴 Канал {} нестабилен для датчиков", channel),
                format!(
                    "Модули Tuya/ESP8285 часто теряют связь на 12–13 каналах. Переключите роутер на канал {}",
                    best_24_channel
                ),
            )
        } else if channel != 1 && channel != 6 && channel != 11 {
            (
                "warn".to_string(),
                format!("⚠️ Канал {} (пересекающийся)", channel),
                format!(
                    "Собирает помехи соседних каналов (мешают сетей: {}). Лучше поставить чистый канал {}",
                    overlapping_ap_count, best_24_channel
                ),
            )
        } else if signal_pct < 45 {
            (
                "warn".to_string(),
                format!("⚠️ Канал {} • Слабый сигнал ({}%)", channel, signal_pct),
                format!(
                    "Уровень {} dBm • Соседних сетей на канале: {}",
                    rssi_dbm, overlapping_ap_count
                ),
            )
        } else if overlapping_ap_count >= 5 {
            (
                "warn".to_string(),
                format!(
                    "⚠️ Канал {} перегружен (соседей: {})",
                    channel, overlapping_ap_count
                ),
                format!(
                    "Сигнал {}% ({} dBm) • Самый свободный канал для роутера: {}",
                    signal_pct, rssi_dbm, best_24_channel
                ),
            )
        } else {
            (
                "good".to_string(),
                format!("🟢 Канал {} отличный (Сигнал {}%)", channel, signal_pct),
                format!(
                    "Непересекающийся канал 2.4 ГГц ({} dBm) • Соседних сетей: {}",
                    rssi_dbm, overlapping_ap_count
                ),
            )
        }
    } else {
        let grade = if signal_pct < 45 { "warn" } else { "good" };
        let icon = if signal_pct < 45 { "⚠️" } else { "🟢" };
        (
            grade.to_string(),
            format!("{} 5 ГГц Канал {} (Сигнал {}%)", icon, channel, signal_pct),
            format!(
                "Уровень {} dBm • Лучший канал 2.4 ГГц для умных реле: {}",
                rssi_dbm, best_24_channel
            ),
        )
    };

    WifiChannelInfo {
        ssid,
        band,
        channel,
        freq_mhz,
        signal_pct,
        rssi_dbm,
        overlapping_ap_count,
        best_24_channel,
        quality_grade,
        verdict,
        details,
    }
}

async fn run_p2p_udp_responder(sock: Arc<UdpSocket>, remote: RemoteManager, client: Client) {
    let mut buf = [0u8; 8192];
    loop {
        let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        if len < 4 || buf[0] == 0x00 || buf[0] == 0x01 {
            continue;
        }
        let text = String::from_utf8_lossy(&buf[..len]);
        if text.starts_with("P2P_PING") {
            let hub_id = remote
                .config
                .read()
                .map(|c| c.hub_id.clone())
                .unwrap_or_default();
            let pong = json!({ "ok": true, "type": "P2P_PONG", "hub_id": hub_id }).to_string();
            let _ = sock.send_to(pong.as_bytes(), peer).await;
            continue;
        }

        if let Some(json_str) = text.strip_prefix("P2P_REQ:") {
            if let Ok(req_val) = serde_json::from_str::<Value>(json_str) {
                let sock_cl = sock.clone();
                let client_cl = client.clone();
                tokio::spawn(async move {
                    let req_id = req_val.get("req_id").and_then(|v| v.as_str()).unwrap_or("");
                    let method = req_val
                        .get("method")
                        .and_then(|v| v.as_str())
                        .unwrap_or("GET");
                    let path = req_val
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("/api/ping");
                    let auth = req_val.get("auth").and_then(|v| v.as_str()).unwrap_or("");
                    let body = req_val.get("body").cloned();

                    let local_url = format!("http://127.0.0.1:3000{}", path);
                    let mut builder = match method {
                        "POST" => client_cl.post(&local_url),
                        "PUT" => client_cl.put(&local_url),
                        "DELETE" => client_cl.delete(&local_url),
                        _ => client_cl.get(&local_url),
                    };
                    if !auth.is_empty() {
                        builder = builder.header("Authorization", auth);
                    }
                    if let Some(b) = body {
                        builder = builder.json(&b);
                    }

                    let resp_val = match builder.send().await {
                        Ok(r) => r
                            .json::<Value>()
                            .await
                            .unwrap_or_else(|_| json!({ "ok": false })),
                        Err(e) => json!({ "ok": false, "error": e.to_string() }),
                    };

                    let reply = format!(
                        "P2P_RESP:{}",
                        json!({ "req_id": req_id, "response": resp_val })
                    );
                    let _ = sock_cl.send_to(reply.as_bytes(), peer).await;
                });
            }
        }
    }
}

fn parse_vps_udp_addr(vps_url: &str) -> Option<SocketAddr> {
    let stripped = vps_url
        .trim()
        .strip_prefix("http://")
        .or_else(|| vps_url.trim().strip_prefix("https://"))?;
    let host_port = stripped.split('/').next()?;
    host_port.parse::<SocketAddr>().ok()
}

async fn forward_relayed_request_to_local(
    client: &Client,
    vps_url: &str,
    vps_secret: &str,
    req_id: &str,
    method: &str,
    path: &str,
    auth: &str,
    body: Option<Value>,
) {
    let local_url = format!("http://127.0.0.1:3000{}", path);
    let mut builder = match method {
        "POST" => client.post(&local_url),
        "PUT" => client.put(&local_url),
        "DELETE" => client.delete(&local_url),
        _ => client.get(&local_url),
    };

    if !auth.is_empty() {
        builder = builder.header("Authorization", auth);
    }

    if let Some(b) = body {
        builder = builder.json(&b);
    }

    let (status_code, mut response_json) = match builder.send().await {
        Ok(r) => {
            let code = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            let val =
                serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!({ "_html": text }));
            (code, val)
        }
        Err(e) => (502, json!({ "ok": false, "error": e.to_string() })),
    };

    if status_code == 401 {
        if let Some(obj) = response_json.as_object_mut() {
            obj.insert("_http_status".to_string(), json!(401));
        }
    }

    let reply_url = format!("{}/api/relay/reply", vps_url);
    let _ = client
        .post(&reply_url)
        .header("X-Relay-Secret", vps_secret)
        .json(&json!({
            "req_id": req_id,
            "response": response_json
        }))
        .send()
        .await;
}

async fn query_stun_public_addr(socket: &UdpSocket, stun_host: &str) -> anyhow::Result<SocketAddr> {
    let target = timeout(
        Duration::from_millis(800),
        tokio::net::lookup_host(stun_host),
    )
    .await??
    .find(|a| a.is_ipv4())
    .ok_or_else(|| anyhow::anyhow!("IPv4 STUN not found"))?;

    let mut req = [0u8; 20];
    req[0] = 0x00;
    req[1] = 0x01;
    req[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    rand::thread_rng().fill_bytes(&mut req[8..20]);

    socket.send_to(&req, target).await?;

    let mut buf = [0u8; 512];
    let (len, _) = timeout(Duration::from_millis(900), socket.recv_from(&mut buf)).await??;
    if len < 20 || buf[0] != 0x01 || buf[1] != 0x01 {
        anyhow::bail!("Invalid STUN response");
    }

    let mut pos = 20;
    while pos + 4 <= len {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + attr_len > len {
            break;
        }

        if attr_type == 0x0020 && attr_len >= 8 && buf[pos + 1] == 0x01 {
            let port = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) ^ 0x2112;
            let ip = Ipv4Addr::new(
                buf[pos + 4] ^ 0x21,
                buf[pos + 5] ^ 0x12,
                buf[pos + 6] ^ 0xA4,
                buf[pos + 7] ^ 0x42,
            );
            return Ok(SocketAddr::new(IpAddr::V4(ip), port));
        } else if attr_type == 0x0001 && attr_len >= 8 && buf[pos + 1] == 0x01 {
            let port = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
            let ip = Ipv4Addr::new(buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]);
            return Ok(SocketAddr::new(IpAddr::V4(ip), port));
        }

        let padding = (4 - (attr_len % 4)) % 4;
        pos += attr_len + padding;
    }

    anyhow::bail!("No mapped address in STUN")
}

async fn fetch_external_ip_fallback(client: &Client) -> Option<String> {
    let resp = timeout(
        Duration::from_millis(1500),
        client.get("https://api.ipify.org").send(),
    )
    .await
    .ok()?
    .ok()?;
    let txt = resp.text().await.ok()?.trim().to_string();
    if txt.parse::<Ipv4Addr>().is_ok() {
        Some(txt)
    } else {
        None
    }
}

async fn detect_local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect("8.8.8.8:80").await.ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}
