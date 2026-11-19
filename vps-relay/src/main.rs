use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{any, post},
    Json, Router,
};
use dashmap::DashMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Notify};
use tokio::time::timeout;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct HubSession {
    hub_id: String,
    local_endpoint: Option<String>,
    p2p_udp_endpoint: Option<String>,
    punch_peer_udp: Option<String>,
    last_seen: u64,
}

#[derive(Debug, Clone, Serialize)]
struct PendingReq {
    req_id: String,
    method: String,
    path: String,
    auth: String,
    body: Option<Value>,
}

#[derive(Clone, Default)]
struct RelayState {
    hub: Arc<RwLock<HubSession>>,
    queue: Arc<RwLock<VecDeque<PendingReq>>>,
    waiters: Arc<DashMap<String, oneshot::Sender<Value>>>,
    notify_hub: Arc<Notify>,
    secret: String,
    http_client: Client,
}

#[derive(Deserialize)]
struct HeartbeatReq {
    hub_id: String,
    local_endpoint: Option<String>,
    p2p_udp_endpoint: Option<String>,
    ts: u64,
}

#[derive(Deserialize)]
struct ReplyReq {
    req_id: String,
    response: Value,
}

#[derive(Deserialize)]
struct PunchReq {
    client_udp_addr: String,
}

#[derive(Deserialize)]
struct CloudProxyReq {
    url: String,
    method: String,
    headers: HashMap<String, String>,
    body: Option<String>,
}

#[tokio::main]
async fn main() {
    let secret = std::env::var("RELAY_SECRET").unwrap_or_default();
    let port: u16 = std::env::var("PORT")
    .ok()
    .and_then(|p| p.parse().ok())
    .unwrap_or(4000);

    let http_client = Client::builder()
    .timeout(Duration::from_secs(12))
    .user_agent("eWeLink/4.30.0")
    .build()
    .unwrap_or_default();

    let state = RelayState {
        secret,
        http_client,
        ..Default::default()
    };

    // Запускаем UDP-координатор на том же порту (4000/udp) для STUN и прямого P2P-знакомства мобильного клиента и хаба
    let udp_state = state.clone();
    tokio::spawn(async move {
        let _ = run_udp_rendezvous_server(port, udp_state).await;
    });

    let app = Router::new()
    .route("/api/relay/heartbeat", post(hub_heartbeat))
    .route("/api/relay/reply", post(hub_reply))
    .route("/api/relay/punch", post(request_p2p_punch))
    .route("/api/relay/cloud_proxy", post(cloud_proxy_handler))
    .route("/", any(proxy_client_request))
    .route("/api/*path", any(proxy_client_request))
    .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("🌐 SmartHub VPS Coordinator (TCP+UDP) запущен на порту {}", port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// UDP-сервер знакомства (Rendezvous): сообщает клиенту и хабу их реальные внешние UDP IP:port для пробива CGNAT
async fn run_udp_rendezvous_server(port: u16, st: RelayState) -> std::io::Result<()> {
    let sock = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
    let mut buf = [0u8; 1024];

    loop {
        let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let msg = String::from_utf8_lossy(&buf[..len]);

        if msg.starts_with("SMARTHUB_HUB_REG:") {
            if let Ok(mut h) = st.hub.write() {
                h.p2p_udp_endpoint = Some(peer.to_string());
            }
            let reply = json!({ "ok": true, "your_udp": peer.to_string() }).to_string();
            let _ = sock.send_to(reply.as_bytes(), peer).await;
        } else if msg.starts_with("SMARTHUB_CLIENT_PUNCH") {
            let hub_info = {
                let mut h = st.hub.write().unwrap();
                h.punch_peer_udp = Some(peer.to_string());
                h.clone()
            };
            st.notify_hub.notify_waiters();
            let reply = json!({
                "ok": true,
                "client_udp": peer.to_string(),
                              "hub_id": hub_info.hub_id,
                              "local_endpoint": hub_info.local_endpoint,
                              "hub_p2p_udp": hub_info.p2p_udp_endpoint
            })
            .to_string();
            let _ = sock.send_to(reply.as_bytes(), peer).await;
        }
    }
}

async fn hub_heartbeat(
    State(st): State<RelayState>,
                       headers: HeaderMap,
                       Json(req): Json<HeartbeatReq>,
) -> Response {
    if !st.secret.is_empty() {
        let provided = headers
        .get("X-Relay-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
        if provided != st.secret {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    {
        let mut h = st.hub.write().unwrap();
        h.hub_id = req.hub_id;
        h.local_endpoint = req.local_endpoint;
        if req.p2p_udp_endpoint.is_some() {
            h.p2p_udp_endpoint = req.p2p_udp_endpoint;
        }
        h.last_seen = req.ts;
    }

    let has_queued = !st.queue.read().unwrap().is_empty();
    if !has_queued {
        let _ = timeout(Duration::from_secs(12), st.notify_hub.notified()).await;
    }

    let mut pending = Vec::new();
    {
        let mut q = st.queue.write().unwrap();
        while let Some(item) = q.pop_front() {
            pending.push(item);
        }
    }

    let punch_target = st.hub.write().unwrap().punch_peer_udp.take();

    Json(json!({
        "ok": true,
        "punch_peer_udp": punch_target,
        "pending_requests": pending
    }))
    .into_response()
}

async fn hub_reply(
    State(st): State<RelayState>,
                   headers: HeaderMap,
                   Json(req): Json<ReplyReq>,
) -> Response {
    if !st.secret.is_empty() {
        let provided = headers
        .get("X-Relay-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
        if provided != st.secret {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    if let Some((_, tx)) = st.waiters.remove(&req.req_id) {
        let _ = tx.send(req.response);
    }
    Json(json!({ "ok": true })).into_response()
}

async fn request_p2p_punch(
    State(st): State<RelayState>,
                           Json(req): Json<PunchReq>,
) -> Json<Value> {
    let hub_info = {
        let mut h = st.hub.write().unwrap();
        h.punch_peer_udp = Some(req.client_udp_addr);
        h.clone()
    };
    st.notify_hub.notify_waiters();

    Json(json!({
        "ok": true,
        "hub_id": hub_info.hub_id,
        "local_endpoint": hub_info.local_endpoint,
        "hub_p2p_udp": hub_info.p2p_udp_endpoint
    }))
}

/// Прокси для облачных запросов хаба (позволяет хабу обращаться к AWS coolkit.cc без VPN на ноутбуке)
async fn cloud_proxy_handler(
    State(st): State<RelayState>,
                             headers: HeaderMap,
                             Json(req): Json<CloudProxyReq>,
) -> Response {
    if !st.secret.is_empty() {
        let provided = headers
        .get("X-Relay-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
        if provided != st.secret {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    let mut builder = if req.method == "POST" {
        st.http_client.post(&req.url)
    } else {
        st.http_client.get(&req.url)
    };

    for (k, v) in req.headers {
        builder = builder.header(&k, &v);
    }
    if let Some(b) = req.body {
        builder = builder.body(b);
    }

    match builder.send().await {
        Ok(resp) => {
            let val = resp.json::<Value>().await.unwrap_or_else(|_| json!({}));
            Json(val).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": 502, "msg": e.to_string() })),
        )
        .into_response(),
    }
}

async fn proxy_client_request(
    State(st): State<RelayState>,
                              headers: HeaderMap,
                              method: Method,
                              uri: Uri,
                              body_bytes: Bytes,
) -> Response {
    let path_and_query = uri
    .path_and_query()
    .map(|pq| pq.as_str().to_string())
    .unwrap_or_else(|| uri.path().to_string());

    let auth = headers
    .get("Authorization")
    .and_then(|v| v.to_str().ok())
    .unwrap_or("")
    .to_string();

    let parsed_body = if body_bytes.is_empty() {
        None
    } else {
        serde_json::from_slice::<Value>(&body_bytes).ok()
    };

    let req_id = Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel();
    st.waiters.insert(req_id.clone(), tx);

    {
        let mut q = st.queue.write().unwrap();
        q.push_back(PendingReq {
            req_id: req_id.clone(),
                    method: method.as_str().to_string(),
                    path: path_and_query,
                    auth,
                    body: parsed_body,
        });
    }

    st.notify_hub.notify_waiters();

    match timeout(Duration::from_secs(8), rx).await {
        Ok(Ok(val)) => {
            if val.get("_http_status").and_then(|s| s.as_u64()) == Some(401) {
                return (StatusCode::UNAUTHORIZED, Json(val)).into_response();
            }
            if let Some(html_str) = val.get("_html").and_then(|h| h.as_str()) {
                return Html(html_str.to_string()).into_response();
            }
            Json(val).into_response()
        }
        _ => {
            st.waiters.remove(&req_id);
            (
                StatusCode::GATEWAY_TIMEOUT,
             Json(json!({
                 "ok": false,
                 "error": "Хаб сейчас не на связи с VPS"
             })),
            )
            .into_response()
        }
    }
}
