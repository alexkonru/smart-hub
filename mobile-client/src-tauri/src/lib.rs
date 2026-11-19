use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{Manager, State};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;
use uuid::Uuid;

fn load_dotenv_for_client() {
    for path in [".env", "../../.env"] {
        if let Ok(content) = std::fs::read_to_string(path) {
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
            break;
        }
    }
}

fn resolve_default_vps_url() -> String {
    load_dotenv_for_client();
    std::env::var("DEFAULT_VPS_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| option_env!("DEFAULT_VPS_URL").map(|s| s.to_string()))
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteInfo {
    pub mode: String, // "LAN", "P2P", "VPS"
    pub target: String,
}

struct ClientState {
    vps_url: RwLock<String>,
    local_endpoint: RwLock<Option<String>>,
    hub_p2p_udp: RwLock<Option<SocketAddr>>,
    p2p_verified_at: RwLock<Option<Instant>>,
    active_route: RwLock<RouteInfo>,
    udp_sock: UdpSocket,
    http: Client,
}

#[derive(Deserialize)]
struct HubRequestArgs {
    method: String,
    path: String,
    auth: String,
    body: Option<Value>,
}

impl ClientState {
    async fn new() -> Self {
        let udp_sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("Failed to bind UDP socket");

        let http = Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_millis(1500))
            .timeout(Duration::from_secs(8))
            .build()
            .unwrap_or_default();

        let initial_vps = resolve_default_vps_url();

        Self {
            vps_url: RwLock::new(initial_vps),
            local_endpoint: RwLock::new(Some("127.0.0.1:3000".to_string())),
            hub_p2p_udp: RwLock::new(None),
            p2p_verified_at: RwLock::new(None),
            active_route: RwLock::new(RouteInfo {
                mode: "LAN".to_string(),
                target: "127.0.0.1:3000".to_string(),
            }),
            udp_sock,
            http,
        }
    }

    async fn refresh_endpoints_and_punch(&self) {
        let vps = self.vps_url.read().await.clone();

        if let Some(vps_udp_addr) = parse_host_port(&vps) {
            let _ = self
                .udp_sock
                .send_to(b"SMARTHUB_CLIENT_PUNCH", vps_udp_addr)
                .await;

            let mut buf = [0u8; 1024];
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(550), self.udp_sock.recv_from(&mut buf)).await
            {
                if let Ok(val) = serde_json::from_slice::<Value>(&buf[..len]) {
                    if let Some(loc) = val.get("local_endpoint").and_then(|v| v.as_str()) {
                        if !loc.is_empty() {
                            *self.local_endpoint.write().await = Some(loc.to_string());
                        }
                    }
                    if let Some(p2p_str) = val.get("hub_p2p_udp").and_then(|v| v.as_str()) {
                        if let Ok(addr) = p2p_str.parse::<SocketAddr>() {
                            *self.hub_p2p_udp.write().await = Some(addr);
                        }
                    }
                }
            }
        }

        let mut lan_candidates = Vec::new();
        if let Some(loc) = self.local_endpoint.read().await.clone() {
            lan_candidates.push(loc);
        }
        if !lan_candidates.iter().any(|c| c == "127.0.0.1:3000") {
            lan_candidates.push("127.0.0.1:3000".to_string());
        }

        for candidate in lan_candidates {
            let ping_url = format!("http://{}/api/ping", candidate);
            if let Ok(Ok(resp)) =
                timeout(Duration::from_millis(350), self.http.get(&ping_url).send()).await
            {
                if resp.status().is_success() {
                    *self.local_endpoint.write().await = Some(candidate.clone());
                    *self.p2p_verified_at.write().await = Some(Instant::now());
                    *self.active_route.write().await = RouteInfo {
                        mode: "LAN".to_string(),
                        target: candidate,
                    };
                    return;
                }
            }
        }

        if let Some(hub_udp) = *self.hub_p2p_udp.read().await {
            for _ in 0..3 {
                let _ = self.udp_sock.send_to(b"P2P_PING", hub_udp).await;
                let mut buf = [0u8; 1024];
                if let Ok(Ok((len, peer))) =
                    timeout(Duration::from_millis(300), self.udp_sock.recv_from(&mut buf)).await
                {
                    let msg = String::from_utf8_lossy(&buf[..len]);
                    if msg.contains("P2P_PONG") {
                        *self.hub_p2p_udp.write().await = Some(peer);
                        *self.p2p_verified_at.write().await = Some(Instant::now());
                        *self.active_route.write().await = RouteInfo {
                            mode: "P2P".to_string(),
                            target: peer.to_string(),
                        };
                        return;
                    }
                }
            }
        }

        *self.p2p_verified_at.write().await = Some(Instant::now());
        *self.active_route.write().await = RouteInfo {
            mode: "VPS".to_string(),
            target: vps,
        };
    }

    async fn try_p2p_udp_request(&self, args: &HubRequestArgs) -> Option<Value> {
        if args.path.contains("/snapshot") {
            return None;
        }

        let hub_udp = (*self.hub_p2p_udp.read().await)?;
        let req_id = Uuid::new_v4().to_string();

        let payload = format!(
            "P2P_REQ:{}",
            json!({
                "req_id": req_id,
                "method": args.method,
                "path": args.path,
                "auth": args.auth,
                "body": args.body
            })
        );

        let _ = self.udp_sock.send_to(payload.as_bytes(), hub_udp).await.ok()?;

        let mut buf = [0u8; 65507];
        let deadline = Instant::now() + Duration::from_millis(900);

        while Instant::now() < deadline {
            let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(450), self.udp_sock.recv_from(&mut buf)).await
            else {
                break;
            };
            let text = String::from_utf8_lossy(&buf[..len]);
            if let Some(json_str) = text.strip_prefix("P2P_RESP:") {
                if let Ok(val) = serde_json::from_str::<Value>(json_str) {
                    if val.get("req_id").and_then(|v| v.as_str()) == Some(&req_id) {
                        *self.p2p_verified_at.write().await = Some(Instant::now());
                        return val.get("response").cloned();
                    }
                }
            }
        }

        None
    }

    async fn execute_http(&self, base_url: &str, args: &HubRequestArgs) -> Result<Value, String> {
        if base_url.trim().is_empty() {
            return Err("Адрес VPS не задан".to_string());
        }
        let url = format!("{}{}", base_url.trim_end_matches('/'), args.path);
        let mut builder = match args.method.as_str() {
            "POST" => self.http.post(&url),
            "PUT" => self.http.put(&url),
            "DELETE" => self.http.delete(&url),
            _ => self.http.get(&url),
        };

        if !args.auth.is_empty() {
            builder = builder.header("Authorization", format!("Bearer {}", args.auth));
        }
        if let Some(b) = &args.body {
            builder = builder.json(b);
        }

        let resp = builder.send().await.map_err(|e| e.to_string())?;
        if resp.status().as_u16() == 401 {
            return Err("401".to_string());
        }
        resp.json::<Value>().await.map_err(|e| e.to_string())
    }
}

fn parse_host_port(url: &str) -> Option<SocketAddr> {
    let clean = url
        .trim()
        .strip_prefix("http://")
        .or_else(|| url.trim().strip_prefix("https://"))?;
    let host_port = clean.split('/').next()?;
    host_port.parse::<SocketAddr>().ok()
}

#[tauri::command]
async fn get_client_route(state: State<'_, Arc<ClientState>>) -> Result<RouteInfo, String> {
    Ok(state.active_route.read().await.clone())
}

#[tauri::command]
async fn hub_request(
    state: State<'_, Arc<ClientState>>,
    args: HubRequestArgs,
) -> Result<Value, String> {
    if args.path == "/api/remote/config" && args.method == "POST" {
        if let Some(new_vps) = args
            .body
            .as_ref()
            .and_then(|b| b.get("vps_url"))
            .and_then(|v| v.as_str())
        {
            if !new_vps.trim().is_empty() {
                *state.vps_url.write().await = new_vps.trim().to_string();
            }
        }
    }

    let needs_probe = {
        let verified = *state.p2p_verified_at.read().await;
        verified
            .map(|t| t.elapsed() > Duration::from_secs(20))
            .unwrap_or(true)
    };
    if needs_probe {
        state.refresh_endpoints_and_punch().await;
    }

    let current_mode = state.active_route.read().await.mode.clone();

    if current_mode == "LAN" {
        if let Some(loc) = state.local_endpoint.read().await.clone() {
            let base = format!("http://{}", loc);
            if let Ok(val) = state.execute_http(&base, &args).await {
                return Ok(val);
            }
        }
        state.refresh_endpoints_and_punch().await;
    }

    if state.active_route.read().await.mode == "P2P" {
        if let Some(val) = state.try_p2p_udp_request(&args).await {
            return Ok(val);
        }
    }

    let vps = state.vps_url.read().await.clone();
    let res = state.execute_http(&vps, &args).await?;

    if let Some(loc) = res
        .get("local_endpoint")
        .or_else(|| res.get("network").and_then(|n| n.get("local_endpoint")))
        .and_then(|v| v.as_str())
    {
        *state.local_endpoint.write().await = Some(loc.to_string());
    }

    Ok(res)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let client_state = tauri::async_runtime::block_on(ClientState::new());
            app.manage(Arc::new(client_state));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![hub_request, get_client_route])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}