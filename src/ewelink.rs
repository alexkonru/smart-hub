use crate::cloud_sync::TuyaCloudDevice;
use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use anyhow::{Result, anyhow, bail};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand::RngCore;
use reqwest::{Client, RequestBuilder};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

fn ewelink_app_id() -> String {
    std::env::var("EWELINK_APP_ID").unwrap_or_default()
}

fn ewelink_app_secret() -> String {
    std::env::var("EWELINK_APP_SECRET").unwrap_or_default()
}

fn format_net_error(err: &reqwest::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut cur: Option<&dyn StdError> = err.source();
    while let Some(src) = cur {
        parts.push(src.to_string());
        cur = src.source();
    }
    parts.join(" -> ")
}

pub struct EWeLinkClient {
    direct_http: Client,
    proxy_http: Client,
}

impl EWeLinkClient {
    pub fn new() -> Self {
        let direct_http = Client::builder()
            .no_proxy()
            .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .connect_timeout(Duration::from_secs(6))
            .timeout(Duration::from_secs(12))
            .user_agent("eWeLink/4.30.0")
            .build()
            .unwrap_or_default();

        let proxy_http = Client::builder()
            .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .connect_timeout(Duration::from_secs(6))
            .timeout(Duration::from_secs(12))
            .user_agent("eWeLink/4.30.0")
            .build()
            .unwrap_or_default();

        Self {
            direct_http,
            proxy_http,
        }
    }

    fn nonce() -> String {
        let mut bytes = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    async fn send_with_fallback<F>(&self, build_fn: F) -> Result<Value>
    where
        F: Fn(&Client) -> RequestBuilder,
    {
        match build_fn(&self.direct_http).send().await {
            Ok(resp) => Ok(resp.json::<Value>().await?),
            Err(direct_err) => match build_fn(&self.proxy_http).send().await {
                Ok(resp) => Ok(resp.json::<Value>().await?),
                Err(_) => bail!("Ошибка сети: {}", format_net_error(&direct_err)),
            },
        }
    }

    pub async fn login(
        &self,
        username: &str,
        password: &str,
        initial_region: &str,
    ) -> Result<(String, String)> {
        let mut region = if initial_region.trim().is_empty() {
            "eu".to_string()
        } else {
            initial_region.trim().to_lowercase()
        };

        for _ in 0..2 {
            let host = if region == "cn" {
                "https://cn-apia.coolkit.cn".to_string()
            } else {
                format!("https://{}-apia.coolkit.cc", region)
            };

            let clean_user = username.trim();
            let mut body_map = serde_json::Map::new();
            body_map.insert("password".to_string(), json!(password));
            body_map.insert("countryCode".to_string(), json!("+7"));
            if clean_user.contains('@') {
                body_map.insert("email".to_string(), json!(clean_user));
            } else {
                let phone = if clean_user.starts_with('+') {
                    clean_user.to_string()
                } else if clean_user.starts_with('8') && clean_user.len() == 11 {
                    format!("+7{}", &clean_user[1..])
                } else {
                    format!("+{}", clean_user)
                };
                body_map.insert("phoneNumber".to_string(), json!(phone));
            }

            let body_str = serde_json::to_string(&Value::Object(body_map))?;
            let mut mac = <HmacSha256 as Mac>::new_from_slice(ewelink_app_secret().as_bytes())?;
            mac.update(body_str.as_bytes());
            let sign = b64_encode(&mac.finalize().into_bytes());

            let url = format!("{}/v2/user/login", host);
            let nonce = Self::nonce();
            let auth_hdr = format!("Sign {}", sign);

            let resp = self
                .send_with_fallback(|client| {
                    client
                        .post(&url)
                        .header("X-CK-Appid", &ewelink_app_id())
                        .header("X-CK-Nonce", &nonce)
                        .header("Authorization", &auth_hdr)
                        .header("Content-Type", "application/json")
                        .body(body_str.clone())
                })
                .await?;

            let err = resp.get("error").and_then(|e| e.as_i64()).unwrap_or(-1);
            if err == 0 {
                let token = resp
                    .get("data")
                    .and_then(|d| d.get("at"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Токен 'at' не найден в ответе eWeLink"))?;
                return Ok((token.to_string(), region));
            } else if err == 10004 {
                if let Some(new_reg) = resp
                    .get("data")
                    .and_then(|d| d.get("region"))
                    .and_then(|r| r.as_str())
                {
                    region = new_reg.to_string();
                    continue;
                }
            }

            let msg = resp
                .get("msg")
                .and_then(|m| m.as_str())
                .unwrap_or("Неверный логин или пароль");
            bail!("eWeLink ({}): {}", err, msg);
        }

        bail!("Не удалось определить регион аккаунта eWeLink")
    }

    pub async fn sync_all_devices(
        &self,
        username: &str,
        password: &str,
        region: &str,
    ) -> Result<(Vec<TuyaCloudDevice>, String)> {
        let (token, actual_region) = self.login(username, password, region).await?;
        let host = if actual_region == "cn" {
            "https://cn-apia.coolkit.cn".to_string()
        } else {
            format!("https://{}-apia.coolkit.cc", actual_region)
        };

        let url = format!("{}/v2/device/thing?num=0", host);
        let nonce = Self::nonce();
        let bearer = format!("Bearer {}", token);

        let resp = self
            .send_with_fallback(|client| {
                client
                    .get(&url)
                    .header("X-CK-Appid", &ewelink_app_id())
                    .header("X-CK-Nonce", &nonce)
                    .header("Authorization", &bearer)
            })
            .await?;

        let err = resp.get("error").and_then(|e| e.as_i64()).unwrap_or(-1);
        if err != 0 {
            bail!("Ошибка загрузки списка eWeLink: {}", resp);
        }

        let empty_vec = Vec::new();
        let thing_list = resp
            .get("data")
            .and_then(|d| d.get("thingList"))
            .and_then(|l| l.as_array())
            .unwrap_or(&empty_vec);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut result = Vec::new();
        for thing in thing_list {
            let Some(item) = thing.get("itemData") else {
                continue;
            };
            let Some(dev_id) = item.get("deviceid").and_then(|v| v.as_str()) else {
                continue;
            };
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(dev_id)
                .to_string();
            let devicekey = item
                .get("devicekey")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let online = item
                .get("online")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let uiid = item
                .get("extra")
                .and_then(|e| e.get("uiid"))
                .and_then(|u| u.as_u64())
                .unwrap_or(1);
            let model = item
                .get("productModel")
                .or_else(|| item.get("extra").and_then(|e| e.get("model")))
                .and_then(|m| m.as_str())
                .unwrap_or("");

            let empty_params = json!({});
            let params = item.get("params").unwrap_or(&empty_params);

            let has_temp = params
                .get("currentTemperature")
                .and_then(|v| v.as_str())
                .map(|s| s != "unavailable")
                .unwrap_or(false)
                || uiid == 15
                || uiid == 181
                || model.contains("TH");

            let category = if has_temp {
                "tdq".to_string()
            } else {
                "kg".to_string()
            };

            let status = ewelink_params_to_status_array(params);

            result.push(TuyaCloudDevice {
                id: dev_id.to_string(),
                name,
                local_key: devicekey,
                category,
                online,
                status: Some(status),
                dp_map: HashMap::new(),
                scale_map: HashMap::new(),
                last_data_ts: now,
                last_ip: None,
                version: "eWeLink".to_string(),
            });
        }

        Ok((result, actual_region))
    }

    pub async fn send_cloud_command(
        &self,
        username: &str,
        password: &str,
        region: &str,
        device_id: &str,
        is_th_thermostat: bool,
        turn_on: bool,
    ) -> Result<()> {
        let (token, actual_region) = self.login(username, password, region).await?;
        let host = if actual_region == "cn" {
            "https://cn-apia.coolkit.cn".to_string()
        } else {
            format!("https://{}-apia.coolkit.cc", actual_region)
        };

        let state_str = if turn_on { "on" } else { "off" };
        let params = if is_th_thermostat {
            json!({
                "switch": state_str,
                "mainSwitch": state_str,
                "deviceType": "normal"
            })
        } else {
            json!({
                "switch": state_str
            })
        };

        let url = format!("{}/v2/device/thing/status", host);
        let body = json!({
            "type": 1,
            "id": device_id,
            "params": params
        });
        let nonce = Self::nonce();
        let bearer = format!("Bearer {}", token);

        let resp = self
            .send_with_fallback(|client| {
                client
                    .post(&url)
                    .header("X-CK-Appid", &ewelink_app_id())
                    .header("X-CK-Nonce", &nonce)
                    .header("Authorization", &bearer)
                    .json(&body)
            })
            .await?;

        let err = resp.get("error").and_then(|e| e.as_i64()).unwrap_or(-1);
        if err == 0 {
            Ok(())
        } else {
            let fallback_body = json!({
                "type": 1,
                "id": device_id,
                "params": {
                    "switches": [{ "switch": state_str, "outlet": 0 }]
                }
            });
            let nonce2 = Self::nonce();
            let resp2 = self
                .send_with_fallback(|client| {
                    client
                        .post(&url)
                        .header("X-CK-Appid", &ewelink_app_id())
                        .header("X-CK-Nonce", &nonce2)
                        .header("Authorization", &bearer)
                        .json(&fallback_body)
                })
                .await?;

            if resp2.get("error").and_then(|e| e.as_i64()) == Some(0) {
                Ok(())
            } else {
                bail!("Отказ eWeLink Cloud ({}): {}", err, resp)
            }
        }
    }
}

pub fn derive_ewelink_aes_key(devicekey: &str) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(devicekey.trim().as_bytes());
    hasher.finalize().into()
}

pub fn decrypt_ewelink_lan_data(devicekey: &str, iv_b64: &str, data_b64: &str) -> Result<Value> {
    let key = derive_ewelink_aes_key(devicekey);
    let iv_vec = b64_decode(iv_b64)?;
    if iv_vec.len() != 16 {
        bail!("Некорректная длина IV eWeLink: {}", iv_vec.len());
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&iv_vec);

    let cipher_bytes = b64_decode(data_b64)?;
    let plain_bytes = aes_128_cbc_decrypt(&key, &iv, &cipher_bytes)?;
    let val = serde_json::from_slice::<Value>(&plain_bytes)?;
    Ok(val)
}

pub async fn control_ewelink_lan_http(
    ip: IpAddr,
    device_id: &str,
    devicekey: &str,
    is_th_thermostat: bool,
    turn_on: bool,
) -> Result<()> {
    let state_str = if turn_on { "on" } else { "off" };
    let inner_data = if is_th_thermostat {
        json!({
            "switch": state_str,
            "mainSwitch": state_str,
            "deviceType": "normal"
        })
    } else {
        json!({
            "switch": state_str
        })
    };

    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string();

    let payload = if !devicekey.trim().is_empty() {
        let key = derive_ewelink_aes_key(devicekey);
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        let plain = inner_data.to_string();
        let enc = aes_128_cbc_encrypt(&key, &iv, plain.as_bytes());
        json!({
            "sequence": seq,
            "deviceid": device_id,
            "selfApikey": "123",
            "iv": b64_encode(&iv),
            "encrypt": true,
            "data": b64_encode(&enc)
        })
    } else {
        json!({
            "sequence": seq,
            "deviceid": device_id,
            "selfApikey": "123",
            "encrypt": false,
            "data": inner_data
        })
    };

    let body_bytes = serde_json::to_vec(&payload)?;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(1200))
        .build()?;

    let url = format!("http://{}:8081/zeroconf/switch", ip);
    let resp: Value = client
        .post(&url)
        .header("Connection", "close")
        .header("Content-Type", "application/json")
        .body(body_bytes)
        .send()
        .await?
        .json()
        .await?;

    if resp.get("error").and_then(|e| e.as_i64()) == Some(0) {
        Ok(())
    } else {
        bail!("Отказ LAN :8081: {}", resp)
    }
}

pub fn ewelink_params_to_status_array(params: &Value) -> Value {
    let mut list = Vec::new();

    let sw_opt = params
        .get("switch")
        .and_then(|v| v.as_str())
        .or_else(|| {
            params
                .get("switches")
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|o| o.get("switch"))
                .and_then(|v| v.as_str())
        })
        .or_else(|| params.get("mainSwitch").and_then(|v| v.as_str()));

    if let Some(sw) = sw_opt {
        list.push(json!({
            "code": "switch_1",
            "dp_id": 1,
            "value": sw == "on"
        }));
    }

    let temp_opt = params
        .get("currentTemperature")
        .or_else(|| params.get("temperature"))
        .and_then(|v| {
            if let Some(s) = v.as_str() {
                if s != "unavailable" {
                    s.parse::<f64>().ok()
                } else {
                    None
                }
            } else {
                v.as_f64()
            }
        });

    if let Some(t) = temp_opt {
        list.push(json!({
            "code": "temp_current",
            "dp_id": 102,
            "value": t
        }));
    }

    let hum_opt = params
        .get("currentHumidity")
        .or_else(|| params.get("humidity"))
        .and_then(|v| {
            if let Some(s) = v.as_str() {
                if s != "unavailable" {
                    s.parse::<f64>().ok()
                } else {
                    None
                }
            } else {
                v.as_f64()
            }
        });

    if let Some(h) = hum_opt {
        list.push(json!({
            "code": "humidity_value",
            "dp_id": 103,
            "value": h
        }));
    }

    if let Some(pwr) = params.get("power").and_then(|v| {
        v.as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .or_else(|| v.as_f64())
    }) {
        list.push(json!({
            "code": "cur_power",
            "dp_id": 23,
            "value": (pwr * 10.0).round()
        }));
    }

    Value::Array(list)
}

fn aes_128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let pad_len = 16 - (data.len() % 16);
    let mut buf = Vec::with_capacity(data.len() + pad_len);
    buf.extend_from_slice(data);
    buf.resize(data.len() + pad_len, pad_len as u8);

    let mut prev = *iv;
    for chunk in buf.chunks_mut(16) {
        for i in 0..16 {
            chunk[i] ^= prev[i];
        }
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        prev.copy_from_slice(chunk);
    }
    buf
}

fn aes_128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        bail!("Некорректная длина блока AES-CBC: {}", data.len());
    }
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;

    for chunk in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        let mut plain_chunk = [0u8; 16];
        for i in 0..16 {
            plain_chunk[i] = block[i] ^ prev[i];
        }
        out.extend_from_slice(&plain_chunk);
        prev.copy_from_slice(chunk);
    }

    if let Some(&last) = out.last() {
        let pad = last as usize;
        if pad > 0 && pad <= 16 && out.len() >= pad {
            if out[out.len() - pad..].iter().all(|&b| b as usize == pad) {
                out.truncate(out.len() - pad);
            }
        }
    }
    Ok(out)
}

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64_CHARS[((n >> 18) & 63) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_CHARS[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn b64_decode(input: &str) -> Result<Vec<u8>> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace() && b != b'=')
        .collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let mut vals = [0u32; 4];
        for (i, &c) in chunk.iter().enumerate() {
            vals[i] = match c {
                b'A'..=b'Z' => (c - b'A') as u32,
                b'a'..=b'z' => (c - b'a' + 26) as u32,
                b'0'..=b'9' => (c - b'0' + 52) as u32,
                b'+' | b'-' => 62,
                b'/' | b'_' => 63,
                _ => bail!("Invalid base64 char"),
            };
        }
        let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push(((n >> 16) & 0xFF) as u8);
        if chunk.len() > 2 {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if chunk.len() > 3 {
            out.push((n & 0xFF) as u8);
        }
    }
    Ok(out)
}
