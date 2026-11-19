#![allow(dead_code)]

use crate::cameras::{encode_camera_version, read_arp_table, CameraConfig};
use crate::state::{AppState, DiscoveredDevice, Vendor};
use crate::tuya::TuyaClient;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;
use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Nonce, Tag};
use anyhow::{bail, Result};
use md5::{Digest, Md5};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

fn tuya_udp_key() -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(b"yGAdlopoPVldABfn");
    hasher.finalize().into()
}

pub fn spawn_discovery_workers(state: AppState) {
    let st1 = state.clone();
    tokio::spawn(async move {
        let _ = listen_tuya_udp(6666, false, st1).await;
    });

    let st2 = state.clone();
    tokio::spawn(async move {
        let _ = listen_tuya_udp(6667, true, st2).await;
    });

    let st3 = state.clone();
    tokio::spawn(async move {
        let _ = listen_tuya_udp_v35(7000, st3).await;
    });

    let st4 = state.clone();
    tokio::spawn(async move {
        let _ = listen_onvif_cameras(st4).await;
    });

    let st5 = state;
    tokio::spawn(async move {
        let _ = listen_ewelink_mdns(st5).await;
    });
}

async fn listen_tuya_udp(port: u16, encrypted: bool, state: AppState) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let sock = UdpSocket::bind(addr).await?;
    tracing::info!(
        "📡 Слушаем broadcast Tuya на UDP порту {} (encrypted={})",
        port,
        encrypted
    );

    let key = tuya_udp_key();
    let mut buf = [0u8; 2048];

    loop {
        let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        if len < 28 {
            continue;
        }
        let pkt = &buf[..len];
        let payload_end = len - 8;
        let raw_payload = &pkt[20..payload_end];

        let json_bytes = if encrypted {
            let Ok(dec) = aes_ecb_decrypt(&key, raw_payload) else {
                continue;
            };
            dec
        } else {
            raw_payload.to_vec()
        };

        if let Ok(val) = serde_json::from_slice::<Value>(&json_bytes) {
            register_tuya_broadcast(&state, &val, peer.ip());
        }
    }
}

async fn listen_tuya_udp_v35(port: u16, state: AppState) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let sock = UdpSocket::bind(addr).await?;
    tracing::info!("📡 Слушаем broadcast Tuya v3.5 на UDP порту {} (AES-GCM)", port);

    let key = tuya_udp_key();
    let mut buf = [0u8; 2048];

    loop {
        let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        if len < 48 {
            continue;
        }
        let pkt = &buf[..len];
        let prefix = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        if prefix != 0x00006699 {
            continue;
        }

        let aad = &pkt[4..18];
        let iv = &pkt[18..30];
        let tag_start = len - 20;
        if tag_start <= 30 {
            continue;
        }

        let mut data = pkt[30..tag_start].to_vec();
        let tag = Tag::from_slice(&pkt[tag_start..len - 4]);

        let Ok(cipher) = Aes128Gcm::new_from_slice(&key) else {
            continue;
        };
        if cipher
            .decrypt_in_place_detached(Nonce::from_slice(iv), aad, &mut data, tag)
            .is_ok()
        {
            let slice = if data.len() >= 4 && data[0..4] == [0, 0, 0, 0] {
                &data[4..]
            } else {
                &data[..]
            };
            if let Ok(val) = serde_json::from_slice::<Value>(slice) {
                register_tuya_broadcast(&state, &val, peer.ip());
            }
        }
    }
}

fn register_tuya_broadcast(state: &AppState, val: &Value, fallback_ip: IpAddr) {
    let Some(gw_id) = val.get("gwId").and_then(|v| v.as_str()) else {
        return;
    };
    let version = val
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("3.3")
        .to_string();
    let ip = val
        .get("ip")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<IpAddr>().ok())
        .unwrap_or(fallback_ip);

    state.upsert_from_lan(DiscoveredDevice {
        device_id: gw_id.to_string(),
        name: None,
        category: None,
        vendor: Vendor::Tuya,
        ip: Some(ip),
        port: 6668,
        version,
        local_key: None,
        online: true,
        last_seen: 0,
        status: Value::Null,
        metadata: val.clone(),
        dp_map: Default::default(),
        scale_map: Default::default(),
    });
}

async fn listen_onvif_cameras(state: AppState) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let _ = sock.set_broadcast(true);
    tracing::info!("📹 Запущен ONVIF WS-Discovery сканер камер (UDP 3702)");

    let probe_xml = r#"<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><w:MessageID>uuid:84ede3de-7dec-11d0-c360-f01234567890</w:MessageID><w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action a:mustUnderstand="true" xmlns:a="http://www.w3.org/2005/08/addressing">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>"#;
    let mcast = SocketAddr::from(([239, 255, 255, 250], 3702));

    let mut buf = [0u8; 4096];
    loop {
        let _ = sock.send_to(probe_xml.as_bytes(), mcast).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        while tokio::time::Instant::now() < deadline {
            match timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
                Ok(Ok((len, peer))) if len > 32 => {
                    let resp = String::from_utf8_lossy(&buf[..len]);
                    if resp.contains("NetworkVideoTransmitter") || resp.contains("onvif") {
                        register_discovered_camera(
                            &state,
                            peer.ip(),
                            Vendor::CameraOnvif,
                            "ipw_onvif",
                            "Камера (IP)",
                            None,
                        );
                    }
                }
                _ => break,
            }
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

async fn listen_ewelink_mdns(state: AppState) -> Result<()> {
    let sock = match UdpSocket::bind("0.0.0.0:5353").await {
        Ok(s) => s,
        Err(_) => UdpSocket::bind("0.0.0.0:0").await?,
    };

    let _ = sock.join_multicast_v4(Ipv4Addr::new(224, 0, 0, 251), Ipv4Addr::UNSPECIFIED);
    tracing::info!("📡 Слушаем mDNS для устройств eWeLink (_ewelink._tcp.local.)");

    let query_sock = UdpSocket::bind("0.0.0.0:0").await?;
    tokio::spawn(async move {
        let mdns_query: [u8; 37] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, b'_',
            b'e', b'w', b'e', b'l', b'i', b'n', b'k', 0x04, b'_', b't', b'c', b'p', 0x05, b'l',
            b'o', b'c', b'a', b'l', 0x00, 0x00, 0x0c, 0x00, 0x01,
        ];
        let mcast = SocketAddr::from(([224, 0, 0, 251], 5353));
        loop {
            let _ = query_sock.send_to(&mdns_query, mcast).await;
            tokio::time::sleep(Duration::from_secs(20)).await;
        }
    });

    let mut buf = [0u8; 2048];
    loop {
        let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        if len < 24 {
            continue;
        }
        let raw_str = String::from_utf8_lossy(&buf[..len]);
        if !raw_str.contains("eWeLink_") && !raw_str.contains("_ewelink") {
            continue;
        }

        let mut txt_map = std::collections::HashMap::new();
        let mut i = 12;
        while i < len {
            let slen = buf[i] as usize;
            i += 1;
            if slen > 0 && i + slen <= len {
                if let Ok(s) = std::str::from_utf8(&buf[i..i + slen]) {
                    if let Some((k, v)) = s.split_once('=') {
                        txt_map.insert(k.to_string(), v.to_string());
                    }
                }
            }
            i += slen;
        }

        let Some(dev_id) = txt_map.get("id").cloned() else {
            continue;
        };

        let mut data_b64 = String::new();
        for k in ["data1", "data2", "data3", "data4"] {
            if let Some(part) = txt_map.get(k) {
                data_b64.push_str(part);
            }
        }

        let mut parsed_status = Value::Null;
        if !data_b64.is_empty() {
            if txt_map.get("encrypt").map(|v| v == "true").unwrap_or(false) {
                if let (Some(iv), Some(existing)) =
                    (txt_map.get("iv"), state.devices.get(&dev_id))
                {
                    if let Some(key) = existing.local_key.as_deref() {
                        if let Ok(params) =
                            crate::ewelink::decrypt_ewelink_lan_data(key, iv, &data_b64)
                        {
                            parsed_status = crate::ewelink::ewelink_params_to_status_array(&params);
                        }
                    }
                }
            } else if let Ok(raw_bytes) = crate::ewelink::b64_decode(&data_b64) {
                if let Ok(params) = serde_json::from_slice::<Value>(&raw_bytes) {
                    parsed_status = crate::ewelink::ewelink_params_to_status_array(&params);
                }
            }
        }

        state.upsert_from_lan(DiscoveredDevice {
            device_id: dev_id,
            name: None,
            category: None,
            vendor: Vendor::EWeLink,
            ip: Some(peer.ip()),
            port: 8081,
            version: "eWeLink LAN".to_string(),
            local_key: None,
            online: true,
            last_seen: AppState::now(),
            status: parsed_status,
            metadata: json!(txt_map),
            dp_map: Default::default(),
            scale_map: Default::default(),
        });
    }
}

fn register_discovered_camera(
    state: &AppState,
    ip_addr: IpAddr,
    vendor: Vendor,
    preset: &str,
    label_prefix: &str,
    mac_opt: Option<&str>,
) {
    let id = format!("cam-{}", ip_addr);
    let cfg = CameraConfig {
        preset: preset.to_string(),
        ..Default::default()
    };
    let name_str = if let Some(mac) = mac_opt {
        format!("{} ({} • {})", label_prefix, ip_addr, mac.to_uppercase())
    } else {
        format!("{} ({})", label_prefix, ip_addr)
    };

    state.upsert_from_lan(DiscoveredDevice {
        device_id: id,
        name: Some(name_str),
        category: Some("camera".to_string()),
        vendor,
        ip: Some(ip_addr),
        port: 554,
        version: encode_camera_version(&cfg),
        local_key: Some(String::new()),
        online: true,
        last_seen: AppState::now(),
        status: Value::Null,
        metadata: json!({
            "preset": preset,
            "username": "admin",
            "rtsp_port": 554,
            "stream_quality": "sub",
            "detect_enabled": false,
            "sensitivity": 1.5,
            "mac": mac_opt.unwrap_or("")
        }),
        dp_map: Default::default(),
        scale_map: Default::default(),
    });
}

/// Двухфазное сканирование подсети, безопасное для Wi-Fi репитеров (полудуплекс):
/// 1) Плавное пробуждение ARP-таблицы без лавины SYN-пакетов.
/// 2) Точечное сканирование портов на живых узлах с низкой параллельностью (Semaphore = 8).
pub async fn run_subnet_scan_once(state: AppState) -> usize {
    let Some(local_ip) = get_local_ipv4().await else {
        return 0;
    };
    let octets = local_ip.octets();
    let prefix = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
    tracing::info!(
        "🔍 Сканирование подсети {}.0/24 (режим защиты от перегрузки Wi-Fi репитеров)...",
        prefix
    );

    // Фаза 1: Плавно будим подсеть (пауза 4 мс между пакетами, чтобы не забить буфер репитера)
    if let Ok(udp_sock) = UdpSocket::bind("0.0.0.0:0").await {
        for host in 1..=254 {
            let target = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], host)),
                34569,
            );
            let _ = udp_sock.send_to(b"PING", target).await;
            if host % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(12)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(350)).await;
    }

    let arp_snapshot = Arc::new(read_arp_table());

    // Формируем список кандидатов: сначала реально живые IP из ARP, а если ARP пуст — всю подсеть
    let target_hosts: Vec<Ipv4Addr> = if !arp_snapshot.is_empty() {
        tracing::info!(
            "📋 В ARP-таблице обнаружено {} живых узлов. Проверяем их открытые порты...",
            arp_snapshot.len()
        );
        arp_snapshot
            .keys()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) if *v4 != local_ip => Some(*v4),
                _ => None,
            })
            .collect()
    } else {
        (1..=254)
            .map(|h| Ipv4Addr::new(octets[0], octets[1], octets[2], h))
            .filter(|&ip| ip != local_ip)
            .collect()
    };

    // Ограничиваем параллельность до 8 потоков, чтобы репитер не терял TCP-пакеты
    let sem = Arc::new(Semaphore::new(8));
    let mut handles = Vec::new();

    for ip in target_hosts {
        let ip_addr = IpAddr::V4(ip);
        let state_cl = state.clone();
        let sem_cl = sem.clone();
        let arp_cl = arp_snapshot.clone();

        handles.push(tokio::spawn(async move {
            let Ok(_permit) = sem_cl.acquire().await else {
                return 0usize;
            };

            let mac_opt = arp_cl.get(&ip_addr).map(|s| s.as_str());

            // Проверяем все ключевые порты умного дома и камер с надежным таймаутом 900 мс
            let mut open_ports = Vec::new();
            for p in [
                80, 554, 5050, 6668, 8000, 8080, 8081, 8554, 8800, 8899, 34567, 37777,
            ] {
                if check_tcp_port(ip, p, 900).await {
                    open_ports.push(p);
                }
            }

            tracing::info!(
                "🌐 Узел в LAN: IP = {:<13} | MAC = {:<17} | Открытые порты: {:?}",
                ip.to_string(),
                mac_opt.unwrap_or("неизвестен").to_uppercase(),
                open_ports
            );

            let mut found = 0usize;

            // 1. Устройство Tuya (порт 6668)
            if open_ports.contains(&6668) {
                if probe_tuya_ip_with_known_keys(&state_cl, ip_addr).await {
                    found += 1;
                }
                return found;
            }

            // 2. Реле eWeLink (порт 8081)
            if open_ports.contains(&8081) {
                if probe_ewelink_ip(&state_cl, ip_addr).await {
                    found += 1;
                }
                return found;
            }

            // 3. Универсальное определение камер по открытым видео/управляющим портам:
            if open_ports.contains(&34567) {
                register_discovered_camera(
                    &state_cl,
                    ip_addr,
                    Vendor::CameraICSee,
                    "icsee",
                    "Камера (IP)",
                    mac_opt,
                );
                found += 1;
            } else if open_ports.contains(&8800) || open_ports.contains(&5050) {
                register_discovered_camera(
                    &state_cl,
                    ip_addr,
                    Vendor::CameraV380,
                    "v380",
                    "Камера (IP)",
                    mac_opt,
                );
                found += 1;
            } else if open_ports.contains(&554)
                || open_ports.contains(&8554)
                || open_ports.contains(&8899)
                || open_ports.contains(&8000)
                || open_ports.contains(&37777)
            {
                register_discovered_camera(
                    &state_cl,
                    ip_addr,
                    Vendor::CameraOnvif,
                    "ipw_onvif",
                    "Камера (IP)",
                    mac_opt,
                );
                found += 1;
            }

            found
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    state.devices.iter().filter(|d| d.ip.is_some()).count()
}

async fn probe_ewelink_ip(state: &AppState, ip: IpAddr) -> bool {
    tracing::info!("🔌 Найден открытый порт eWeLink 8081 на {}!", ip);

    let mut candidates: Vec<(String, String)> = state
        .devices
        .iter()
        .filter(|d| {
            d.vendor == Vendor::EWeLink
                && d.ip.is_none()
                && d.online
                && d.category.as_deref() == Some("kg")
        })
        .map(|d| (d.device_id.clone(), d.name.clone().unwrap_or_default()))
        .collect();

    if candidates.is_empty() {
        candidates = state
            .devices
            .iter()
            .filter(|d| d.vendor == Vendor::EWeLink && d.ip.is_none() && d.online)
            .map(|d| (d.device_id.clone(), d.name.clone().unwrap_or_default()))
            .collect();
    }

    if let Some((dev_id, name)) = candidates.first() {
        if let Some(mut dev) = state.devices.get_mut(dev_id) {
            dev.ip = Some(ip);
            dev.port = 8081;
            dev.version = "eWeLink LAN".to_string();
            tracing::info!(
                "🎯 Реле eWeLink «{}» ({}) привязано к LAN {}:8081",
                name,
                dev_id,
                ip
            );
            return true;
        }
    }
    false
}

async fn probe_tuya_ip_with_known_keys(state: &AppState, ip: IpAddr) -> bool {
    let mut candidates: Vec<(String, String, String)> = state
        .devices
        .iter()
        .filter(|d| d.vendor == Vendor::Tuya && (d.ip.is_none() || d.ip == Some(ip)))
        .filter_map(|d| {
            let key = d.local_key.as_ref()?.trim().to_string();
            if key.len() == 16 {
                Some((d.device_id.clone(), key, d.version.clone()))
            } else {
                None
            }
        })
        .collect();

    if candidates.is_empty() {
        candidates = state
            .devices
            .iter()
            .filter(|d| d.vendor == Vendor::Tuya)
            .filter_map(|d| {
                let key = d.local_key.as_ref()?.trim().to_string();
                if key.len() == 16 {
                    Some((d.device_id.clone(), key, d.version.clone()))
                } else {
                    None
                }
            })
            .collect();
    }

    if candidates.is_empty() {
        return false;
    }

    tracing::info!(
        "🔌 Найден порт Tuya 6668 на {}. Проверяем подходящий ключ...",
        ip
    );

    for (dev_id, key, known_ver) in &candidates {
        let versions = if known_ver == "3.5" {
            ["3.5", "3.4", "3.3"]
        } else {
            ["3.4", "3.5", "3.3"]
        };

        for ver in versions {
            if let Ok(client) = TuyaClient::new(dev_id, ip, 6668, key, ver) {
                if let Ok(dps_json) = client.query_status().await {
                    let is_valid = dps_json.get("dps").is_some()
                        || dps_json
                            .get("raw")
                            .and_then(|r| r.as_str())
                            .map(|s| s.is_empty())
                            .unwrap_or(false);

                    if is_valid {
                        if let Some(mut dev) = state.devices.get_mut(dev_id) {
                            dev.ip = Some(ip);
                            dev.port = 6668;
                            dev.version = ver.to_string();
                            dev.online = true;
                        }
                        if dps_json.get("dps").is_some() {
                            state.apply_lan_dps(dev_id, &dps_json);
                        }
                        return true;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    false
}

async fn check_tcp_port(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

async fn get_local_ipv4() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect("8.8.8.8:80").await.ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn aes_ecb_decrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        bail!("Invalid AES block length");
    }
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut buf = data.to_vec();
    for chunk in buf.chunks_mut(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    if let Some(&last) = buf.last() {
        let pad = last as usize;
        if pad > 0 && pad <= 16 && buf.len() >= pad {
            if buf[buf.len() - pad..].iter().all(|&b| b as usize == pad) {
                buf.truncate(buf.len() - pad);
            }
        }
    }
    Ok(buf)
}