use crate::cameras::decode_camera_version_to_meta;
use crate::cloud_sync::TuyaCloudDevice;
use dashmap::{DashMap, DashSet};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Vendor {
    Tuya,
    EWeLink,
    CameraICSee,
    CameraV380,
    CameraOnvif,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub device_id: String,
    pub name: Option<String>,
    pub category: Option<String>,
    pub vendor: Vendor,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub version: String,
    pub local_key: Option<String>,
    pub online: bool,
    pub last_seen: u64,
    pub status: Value,
    pub metadata: Value,
    #[serde(default)]
    pub dp_map: HashMap<String, u32>,
    #[serde(default)]
    pub scale_map: HashMap<String, u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationLogEntry {
    pub time_str: String,
    pub rule_name: String,
    pub message: String,
    pub mode: String,
}

#[derive(Clone, Default)]
pub struct AppState {
    pub active_profile: Arc<RwLock<String>>,
    pub devices: Arc<DashMap<String, DiscoveredDevice>>,
    pub hidden_ids: Arc<DashSet<String>>,
    pub automation_logs: Arc<RwLock<VecDeque<AutomationLogEntry>>>,
    pub lan_failures: Arc<DashMap<String, u8>>,
    pub last_heal_scan: Arc<AtomicU64>,
    pub allow_new_lan_devices: Arc<AtomicBool>,
}

impl AppState {
    fn populate_env_hidden_ids(hidden: &DashSet<String>) {
        if let Ok(raw) = std::env::var("HIDDEN_DEVICE_IDS") {
            for id in raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                hidden.insert(id.to_string());
            }
        }
    }

    pub fn new() -> Self {
        let hidden = DashSet::new();
        Self::populate_env_hidden_ids(&hidden);

        Self {
            active_profile: Arc::new(RwLock::new("home".to_string())),
            devices: Arc::new(DashMap::new()),
            hidden_ids: Arc::new(hidden),
            automation_logs: Arc::new(RwLock::new(VecDeque::with_capacity(40))),
            lan_failures: Arc::new(DashMap::new()),
            last_heal_scan: Arc::new(AtomicU64::new(0)),
            allow_new_lan_devices: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn set_manual_scan_mode(&self, enabled: bool) {
        self.allow_new_lan_devices.store(enabled, Ordering::Relaxed);
    }

    pub fn current_profile(&self) -> String {
        self.active_profile
            .read()
            .map(|p| p.clone())
            .unwrap_or_else(|_| "home".to_string())
    }

    pub fn set_profile(&self, new_profile: &str) {
        if let Ok(mut p) = self.active_profile.write() {
            *p = new_profile.to_string();
        }
        self.devices.clear();
        self.hidden_ids.clear();
        self.lan_failures.clear();
        Self::populate_env_hidden_ids(&self.hidden_ids);
    }

    pub fn push_auto_log(&self, entry: AutomationLogEntry) {
        if let Ok(mut logs) = self.automation_logs.write() {
            logs.push_front(entry);
            while logs.len() > 35 {
                logs.pop_back();
            }
        }
    }

    pub fn record_lan_success(&self, device_id: &str) {
        self.lan_failures.remove(device_id);
    }

    pub fn record_lan_failure(&self, device_id: &str) -> bool {
        let count = {
            let mut entry = self.lan_failures.entry(device_id.to_string()).or_insert(0);
            *entry = entry.saturating_add(1);
            *entry
        };

        if count >= 20 {
            self.lan_failures.remove(device_id);
            if let Some(mut dev) = self.devices.get_mut(device_id) {
                let old_ip = dev.ip.take();
                tracing::warn!(
                    "🔄 Устройство «{}» долго не отвечает по {:?}. Ожидаем новый адрес...",
                    dev.name.as_deref().unwrap_or(&dev.device_id),
                    old_ip
                );
                return true;
            }
        }
        false
    }

    #[allow(dead_code)]
    pub fn can_trigger_heal_scan(&self) -> bool {
        let now = Self::now();
        let last = self.last_heal_scan.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= 45 {
            self.last_heal_scan.store(now, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub fn upsert_from_lan(&self, mut incoming: DiscoveredDevice) {
        if self.hidden_ids.contains(&incoming.device_id) {
            return;
        }
        let now = Self::now();
        incoming.online = true;

        if let Some(mut existing) = self.devices.get_mut(&incoming.device_id) {
            let ip_changed = existing.ip != incoming.ip;
            existing.ip = incoming.ip;
            existing.port = incoming.port;
            // Не перезаписываем настроенную конфигурацию камеры `CAM|...` при повторном скане сети
            if !existing.version.starts_with("CAM|") {
                existing.version = incoming.version.clone();
            }
            existing.online = true;

            if !incoming.status.is_null() {
                existing.status = incoming.status;
                existing.last_seen = now;
            } else if existing.last_seen == 0 {
                existing.last_seen = now;
            }

            if ip_changed {
                tracing::info!(
                    "🎯 Устройство «{}» ({}) обнаружено в LAN на {:?}:{} ({})",
                    existing.name.as_deref().unwrap_or(&incoming.device_id),
                    incoming.device_id,
                    existing.ip,
                    existing.port,
                    existing.version
                );
            }
        } else if self.allow_new_lan_devices.load(Ordering::Relaxed) {
            incoming.last_seen = now;
            tracing::info!(
                "🎯 [Ручной поиск] Добавлено новое устройство [{:?}]: ID={} IP={:?}:{} ({})",
                incoming.vendor,
                incoming.device_id,
                incoming.ip,
                incoming.port,
                incoming.version
            );
            self.devices.insert(incoming.device_id.clone(), incoming);
        }
    }

    pub fn merge_from_cloud(&self, cloud_list: Vec<TuyaCloudDevice>) {
        let now = Self::now();
        for c_dev in cloud_list {
            if self.hidden_ids.contains(&c_dev.id) {
                self.devices.remove(&c_dev.id);
                continue;
            }

            let is_camera = c_dev.category == "camera" || c_dev.version.starts_with("CAM|");
            let is_ewelink = c_dev.version.starts_with("eWeLink");

            let cam_meta = if is_camera {
                decode_camera_version_to_meta(&c_dev.version, &c_dev.local_key)
            } else {
                None
            };

            let vendor = if is_camera {
                match cam_meta
                    .as_ref()
                    .and_then(|m| m.get("preset"))
                    .and_then(|p| p.as_str())
                {
                    Some("icsee") => Vendor::CameraICSee,
                    Some("v380") => Vendor::CameraV380,
                    _ => Vendor::CameraOnvif,
                }
            } else if is_ewelink {
                Vendor::EWeLink
            } else {
                Vendor::Tuya
            };

            let default_port = if is_camera {
                554
            } else if is_ewelink {
                8081
            } else {
                6668
            };

            let cloud_ts = if c_dev.last_data_ts > 0 {
                c_dev.last_data_ts
            } else {
                now
            };

            if let Some(mut existing) = self.devices.get_mut(&c_dev.id) {
                existing.vendor = vendor;
                existing.name = Some(c_dev.name.clone());
                existing.category = Some(c_dev.category.clone());
                if !c_dev.local_key.is_empty() {
                    existing.local_key = Some(c_dev.local_key);
                }
                if existing.ip.is_none() && c_dev.last_ip.is_some() {
                    existing.ip = c_dev.last_ip;
                }
                if !c_dev.version.is_empty()
                    && (existing.version == "3.3" || is_ewelink || is_camera)
                {
                    existing.version = c_dev.version;
                }
                if let Some(cm) = cam_meta {
                    existing.metadata = cm;
                }
                if !c_dev.dp_map.is_empty() {
                    existing.dp_map.extend(c_dev.dp_map);
                }
                if !c_dev.scale_map.is_empty() {
                    existing.scale_map.extend(c_dev.scale_map);
                }
                existing.online = c_dev.online || existing.ip.is_some();

                let last_lan_dps = existing
                    .metadata
                    .get("last_lan_dps_ts")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                if now.saturating_sub(last_lan_dps) > 12 || existing.status.is_null() {
                    if let Some(st) = c_dev.status {
                        if !st.is_null() {
                            existing.status = st;
                            existing.last_seen = if existing.ip.is_some() { now } else { cloud_ts };
                        }
                    }
                }
            } else {
                let ver = if c_dev.version.is_empty() {
                    "3.3".to_string()
                } else {
                    c_dev.version
                };
                let new_dev = DiscoveredDevice {
                    device_id: c_dev.id,
                    name: Some(c_dev.name),
                    category: Some(c_dev.category),
                    vendor,
                    ip: c_dev.last_ip,
                    port: default_port,
                    version: ver,
                    local_key: Some(c_dev.local_key),
                    online: c_dev.online || c_dev.last_ip.is_some(),
                    last_seen: cloud_ts,
                    status: c_dev.status.unwrap_or(Value::Null),
                    metadata: cam_meta.unwrap_or(Value::Null),
                    dp_map: c_dev.dp_map,
                    scale_map: c_dev.scale_map,
                };
                self.devices.insert(new_dev.device_id.clone(), new_dev);
            }
        }
    }

    pub fn export_devices_for_cache(&self) -> Vec<TuyaCloudDevice> {
        self.devices
            .iter()
            .map(|entry| {
                let d = entry.value();
                TuyaCloudDevice {
                    id: d.device_id.clone(),
                    name: d.name.clone().unwrap_or_else(|| d.device_id.clone()),
                    local_key: d.local_key.clone().unwrap_or_default(),
                    category: d.category.clone().unwrap_or_default(),
                    online: d.online,
                    status: Some(d.status.clone()),
                    dp_map: d.dp_map.clone(),
                    scale_map: d.scale_map.clone(),
                    last_data_ts: d.last_seen,
                    last_ip: d.ip,
                    version: d.version.clone(),
                }
            })
            .collect()
    }

    pub fn apply_lan_dps(&self, device_id: &str, lan_json: &Value) {
        let Some(dps_obj) = lan_json.get("dps").and_then(|d| d.as_object()) else {
            return;
        };
        if dps_obj.is_empty() {
            return;
        }
        let Some(mut dev) = self.devices.get_mut(device_id) else {
            return;
        };
        let now = Self::now();
        dev.last_seen = now;
        dev.online = true;

        let mut meta_obj = dev
            .metadata
            .as_object()
            .cloned()
            .unwrap_or_else(serde_json::Map::new);
        meta_obj.insert("last_lan_dps_ts".to_string(), json!(now));
        dev.metadata = Value::Object(meta_obj);

        let cat = dev.category.clone().unwrap_or_default();

        let mut id_to_code: HashMap<u32, String> = HashMap::new();
        for (code, &num) in &dev.dp_map {
            if !code.starts_with("dp_") {
                id_to_code.insert(num, code.clone());
            }
        }
        if let Some(arr) = dev.status.as_array() {
            for item in arr {
                if let (Some(c), Some(d)) = (
                    item.get("code").and_then(|v| v.as_str()),
                    item.get("dp_id").and_then(|v| v.as_u64()),
                ) {
                    if !c.starts_with("dp_") && d > 0 {
                        id_to_code.insert(d as u32, c.to_string());
                    }
                }
            }
        }

        let mut current_map: HashMap<u32, Value> = HashMap::new();
        if let Some(arr) = dev.status.as_array() {
            for item in arr {
                if let Some(dp_id) = item.get("dp_id").and_then(|d| d.as_u64()) {
                    if dp_id > 0 {
                        if let Some(v) = item.get("value") {
                            current_map.insert(dp_id as u32, v.clone());
                        }
                    }
                }
            }
        }

        for (k, v) in dps_obj {
            if let Ok(dp_num) = k.parse::<u32>() {
                current_map.insert(dp_num, v.clone());
            }
        }

        let mut sorted_dps: Vec<u32> = current_map.keys().copied().collect();
        let priority = |dp: u32| -> u32 {
            match dp {
                1 => 1,
                101 => 2,
                16 => 3,
                24 => 4,
                2 => 5,
                36 => 6,
                14 => 7,
                15 => 8,
                7 => 9,
                43 => 10,
                40 => 11,
                103 => 12,
                19 => 13,
                _ => 100 + dp,
            }
        };
        sorted_dps.sort_by_key(|&dp| priority(dp));

        let mut new_status = Vec::new();
        for dp_num in sorted_dps {
            let val = current_map.get(&dp_num).cloned().unwrap_or(Value::Null);
            let code = id_to_code
                .remove(&dp_num)
                .unwrap_or_else(|| map_dp_to_code(dp_num, &cat));
            dev.dp_map.insert(code.clone(), dp_num);
            new_status.push(json!({
                "code": code,
                "dp_id": dp_num,
                "value": val
            }));
        }

        dev.status = Value::Array(new_status);
    }
}

fn map_dp_to_code(dp: u32, category: &str) -> String {
    if category == "wk" {
        match dp {
            1 => "switch".to_string(),
            2 => "mode".to_string(),
            16 => "temp_set".to_string(),
            19 => "upper_temp".to_string(),
            24 => "air_temp".to_string(),
            26 => "lower_temp".to_string(),
            27 => "temp_correction".to_string(),
            36 => "work_state".to_string(),
            40 => "child_lock".to_string(),
            43 => "sensor_choose".to_string(),
            45 => "fault".to_string(),
            52 => "backlight".to_string(),
            101 => "floor_temp".to_string(),
            103 => "frost".to_string(),
            104 => "schedule_type".to_string(),
            106 => "temp_differ_on".to_string(),
            other => format!("dp_{}", other),
        }
    } else {
        match dp {
            1 => "switch_1".to_string(),
            2 => "switch_2".to_string(),
            7 => "countdown_1".to_string(),
            14 => "relay_status".to_string(),
            15 => "light_mode".to_string(),
            16 => "switch_backlight".to_string(),
            47 => "switch_type".to_string(),
            other => format!("dp_{}", other),
        }
    }
}
