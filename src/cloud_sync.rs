use anyhow::{Result, anyhow, bail};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuyaCloudDevice {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub local_key: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub status: Option<Value>,
    #[serde(default)]
    pub dp_map: HashMap<String, u32>,
    #[serde(default)]
    pub scale_map: HashMap<String, u32>,
    #[serde(default)]
    pub last_data_ts: u64,
    /// Последний успешный локальный IP устройства в Wi-Fi сети
    #[serde(default)]
    pub last_ip: Option<std::net::IpAddr>,
    /// Определенная версия локального протокола ("3.3", "3.4", "3.5")
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedAuthSession {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub access_id: String,
    #[serde(default)]
    pub access_secret: String,
    #[serde(default)]
    pub devices: Vec<TuyaCloudDevice>,
    #[serde(default)]
    pub hidden_ids: Vec<String>,
}

fn default_mode() -> String {
    "openapi".to_string()
}

pub struct TuyaOpenApiClient {
    client: Client,
    base_url: String,
    access_id: String,
    access_secret: String,
}

impl TuyaOpenApiClient {
    pub fn new(region: &str, access_id: &str, access_secret: &str) -> Self {
        let base_url = match region {
            "cn" => "https://openapi.tuyacn.com",
            "us" => "https://openapi.tuyaus.com",
            "we" => "https://openapi-weaz.tuyaeu.com",
            _ => "https://openapi.tuyaeu.com",
        };

        Self {
            client: Client::new(),
            base_url: base_url.trim().to_string(),
            access_id: access_id.trim().to_string(),
            access_secret: access_secret.trim().to_string(),
        }
    }

    async fn get_token(&self) -> Result<String> {
        let path = "/v1.0/token?grant_type=1";
        let resp = self.signed_request("GET", path, None, None).await?;

        let success = resp
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !success {
            bail!("Ошибка токена Tuya OpenAPI: {}", resp);
        }

        resp.get("result")
            .and_then(|r| r.get("access_token"))
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Не найден access_token: {}", resp))
    }

    pub async fn sync_all_devices(&self, seed_device_id: &str) -> Result<Vec<TuyaCloudDevice>> {
        let token = self.get_token().await?;

        let dev_path = format!("/v1.0/devices/{}", seed_device_id);
        let dev_info = self
            .signed_request("GET", &dev_path, Some(&token), None)
            .await?;

        let uid = dev_info
            .get("result")
            .and_then(|r| r.get("uid"))
            .and_then(|u| u.as_str())
            .ok_or_else(|| anyhow!("Не удалось получить UID: {}", dev_info))?;

        let list_path = format!("/v1.0/users/{}/devices", uid);
        let list_resp = self
            .signed_request("GET", &list_path, Some(&token), None)
            .await?;

        let Some(arr) = list_resp.get("result").and_then(|r| r.as_array()) else {
            bail!("Ошибка списка устройств: {}", list_resp);
        };

        let mut devices = Vec::new();
        for item in arr {
            let id = item
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Устройство")
                .to_string();
            let local_key = item
                .get("local_key")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let category = item
                .get("category")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let online = item
                .get("online")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mut status = item.get("status").cloned();

            let mut dp_map = HashMap::new();
            let mut scale_map = HashMap::new();
            let mut latest_ts_sec: u64 = item
                .get("update_time")
                .and_then(|t| t.as_u64())
                .unwrap_or(0);

            let shadow_path = format!("/v2.0/cloud/thing/{}/shadow/properties", id);
            if let Ok(shadow_resp) = self
                .signed_request("GET", &shadow_path, Some(&token), None)
                .await
            {
                if let Some(props) = shadow_resp
                    .get("result")
                    .and_then(|r| r.get("properties"))
                    .and_then(|p| p.as_array())
                {
                    let mut fresh_status = Vec::new();
                    for p in props {
                        let code = p.get("code").and_then(|c| c.as_str()).unwrap_or_default();
                        let dp_id = p.get("dp_id").and_then(|d| d.as_u64()).unwrap_or(0) as u32;
                        let val = p.get("value").cloned().unwrap_or(Value::Null);
                        // Поле time в shadow/properties содержит миллисекунды реального отчета датчика
                        if let Some(t_ms) = p.get("time").and_then(|t| t.as_u64()) {
                            let t_sec = if t_ms > 10_000_000_000 {
                                t_ms / 1000
                            } else {
                                t_ms
                            };
                            if t_sec > latest_ts_sec {
                                latest_ts_sec = t_sec;
                            }
                        }

                        if !code.is_empty() && dp_id > 0 {
                            dp_map.insert(code.to_string(), dp_id);
                        }
                        if !code.is_empty() {
                            fresh_status.push(json!({
                                "code": code,
                                "dp_id": dp_id,
                                "value": val
                            }));
                        }
                    }
                    if !fresh_status.is_empty() {
                        status = Some(Value::Array(fresh_status));
                    }
                }
            }

            let spec_path = format!("/v1.0/devices/{}/specifications", id);
            if let Ok(spec_resp) = self
                .signed_request("GET", &spec_path, Some(&token), None)
                .await
            {
                if let Some(res) = spec_resp.get("result") {
                    for section in ["status", "functions"] {
                        if let Some(spec_arr) = res.get(section).and_then(|s| s.as_array()) {
                            for sp in spec_arr {
                                let code =
                                    sp.get("code").and_then(|c| c.as_str()).unwrap_or_default();
                                if let Some(values_str) = sp.get("values").and_then(|v| v.as_str())
                                {
                                    if let Ok(v_json) = serde_json::from_str::<Value>(values_str) {
                                        if let Some(scale) =
                                            v_json.get("scale").and_then(|sc| sc.as_u64())
                                        {
                                            scale_map.insert(code.to_string(), scale as u32);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            devices.push(TuyaCloudDevice {
                id,
                name,
                local_key,
                category,
                online,
                status,
                dp_map,
                scale_map,
                last_data_ts: latest_ts_sec,
                last_ip: None,
                version: String::new(),
            });
        }

        Ok(devices)
    }

    pub async fn fetch_device_status(&self, device_id: &str) -> Result<Value> {
        let token = self.get_token().await?;

        let shadow_path = format!("/v2.0/cloud/thing/{}/shadow/properties", device_id);
        if let Ok(shadow_resp) = self
            .signed_request("GET", &shadow_path, Some(&token), None)
            .await
        {
            if let Some(props) = shadow_resp
                .get("result")
                .and_then(|r| r.get("properties"))
                .and_then(|p| p.as_array())
            {
                let list: Vec<Value> = props
                    .iter()
                    .map(|p| {
                        json!({
                            "code": p.get("code").and_then(|c| c.as_str()).unwrap_or_default(),
                            "dp_id": p.get("dp_id").and_then(|d| d.as_u64()).unwrap_or(0),
                            "value": p.get("value").cloned().unwrap_or(Value::Null)
                        })
                    })
                    .collect();
                if !list.is_empty() {
                    return Ok(Value::Array(list));
                }
            }
        }

        let path = format!("/v1.0/devices/{}/status", device_id);
        let resp = self
            .signed_request("GET", &path, Some(&token), None)
            .await?;
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    pub async fn send_cloud_command(
        &self,
        device_id: &str,
        code: &str,
        value: Value,
    ) -> Result<Value> {
        let token = self.get_token().await?;

        let path_v1 = format!("/v1.0/devices/{}/commands", device_id);
        let body_v1 = json!({
            "commands": [{ "code": code, "value": value }]
        });
        let resp_v1 = self
            .signed_request("POST", &path_v1, Some(&token), Some(&body_v1))
            .await?;

        if resp_v1
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Ok(resp_v1);
        }

        let props_str = json!({ code: value }).to_string();
        let path_v2 = format!("/v2.0/cloud/thing/{}/shadow/properties/issue", device_id);
        let body_v2 = json!({ "properties": props_str });
        let resp_v2 = self
            .signed_request("POST", &path_v2, Some(&token), Some(&body_v2))
            .await?;

        if resp_v2
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Ok(resp_v2);
        }

        bail!("Облако отклонило команду: {}", resp_v1)
    }

    async fn signed_request(
        &self,
        method: &str,
        path_and_query: &str,
        access_token: Option<&str>,
        body_json: Option<&Value>,
    ) -> Result<Value> {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .to_string();

        let body_str = body_json.map(|b| b.to_string()).unwrap_or_default();
        let body_hash = hex::encode(Sha256::digest(body_str.as_bytes()));

        let string_to_sign = format!("{}\n{}\n\n{}", method, body_hash, path_and_query);
        let token_str = access_token.unwrap_or("");
        let payload = format!("{}{}{}{}", self.access_id, token_str, t, string_to_sign);

        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.access_secret.as_bytes())?;
        mac.update(payload.as_bytes());
        let sign = hex::encode(mac.finalize().into_bytes()).to_uppercase();

        let url = format!("{}{}", self.base_url, path_and_query);
        let mut req = match method {
            "POST" => self.client.post(&url),
            _ => self.client.get(&url),
        };

        req = req
            .header("client_id", &self.access_id)
            .header("sign", sign)
            .header("t", t)
            .header("sign_method", "HMAC-SHA256");

        if let Some(tok) = access_token {
            req = req.header("access_token", tok);
        }

        if method == "POST" {
            req = req
                .header("Content-Type", "application/json")
                .body(body_str);
        }

        let resp = req.send().await?.json::<Value>().await?;
        Ok(resp)
    }
}
