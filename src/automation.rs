use crate::db::TelemetryDb;
use crate::execute_device_command;
use crate::state::{AppState, AutomationLogEntry, DiscoveredDevice};
use chrono::Local;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

const TTL_LAN_SECS: u64 = 180;
const TTL_BATTERY_SECS: u64 = 7200;

pub fn spawn_automation_worker(state: AppState, db: TelemetryDb) {
    tokio::spawn(async move {
        let mut cooldowns: HashMap<i64, u64> = HashMap::new();
        let mut last_schedule_minute: HashMap<i64, String> = HashMap::new();

        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            let profile_id = state.current_profile();
            let rules = db.list_automations(&profile_id);
            let now_ts = AppState::now();
            let now_hhmm = Local::now().format("%H:%M").to_string();

            for rule in rules {
                if !rule.enabled {
                    continue;
                }

                if let Some(&last_ts) = cooldowns.get(&rule.id) {
                    if now_ts.saturating_sub(last_ts) < 55 {
                        continue;
                    }
                }

                let should_fire = if rule.rule_type == "schedule" {
                    if rule.schedule_time.trim() == now_hhmm {
                        let already_fired = last_schedule_minute
                            .get(&rule.id)
                            .map(|m| m == &now_hhmm)
                            .unwrap_or(false);
                        if !already_fired {
                            last_schedule_minute.insert(rule.id, now_hhmm.clone());
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    let Some(trigger_dev) = state
                        .devices
                        .get(&rule.trigger_device_id)
                        .map(|d| d.value().clone())
                    else {
                        continue;
                    };

                    let max_ttl = if trigger_dev.ip.is_some() {
                        TTL_LAN_SECS
                    } else {
                        TTL_BATTERY_SECS
                    };
                    let sensor_age = now_ts.saturating_sub(trigger_dev.last_seen);
                    if !trigger_dev.online || sensor_age > max_ttl {
                        continue;
                    }

                    let Some(current_val) =
                        extract_human_metric(&trigger_dev, &rule.trigger_metric)
                    else {
                        continue;
                    };

                    match rule.operator.as_str() {
                        "lt" => current_val < rule.threshold,
                        "lte" => current_val <= rule.threshold,
                        "gt" => current_val > rule.threshold,
                        "gte" => current_val >= rule.threshold,
                        "eq" => (current_val - rule.threshold).abs() < 0.1,
                        _ => false,
                    }
                };

                if !should_fire {
                    continue;
                }

                let Some(target_dev) = state
                    .devices
                    .get(&rule.action_device_id)
                    .map(|d| d.value().clone())
                else {
                    continue;
                };

                let raw_target_val =
                    to_raw_tuya_value(&target_dev, &rule.action_code, &rule.action_value);

                if is_already_in_state(&target_dev, &rule.action_code, &raw_target_val) {
                    continue;
                }

                match execute_device_command(
                    &state,
                    &db,
                    &rule.action_device_id,
                    Some(rule.action_code.clone()),
                    None,
                    raw_target_val,
                )
                .await
                {
                    Ok(mode) => {
                        cooldowns.insert(rule.id, now_ts);
                        let time_str = Local::now().format("%H:%M:%S").to_string();
                        let target_name = target_dev
                            .name
                            .clone()
                            .unwrap_or_else(|| target_dev.device_id.clone());

                        let action_desc = format_action_human(&rule.action_code, &rule.action_value);

                        state.push_auto_log(AutomationLogEntry {
                            time_str,
                            rule_name: rule.name.clone(),
                            message: format!("{} → {}", target_name, action_desc),
                            mode,
                        });
                    }
                    Err(e) => {
                        tracing::warn!("⚠️ Ошибка выполнения правила «{}»: {}", rule.name, e);
                    }
                }
            }
        }
    });
}

fn extract_human_metric(dev: &DiscoveredDevice, metric: &str) -> Option<f64> {
    // 1. Быстрая проверка метрик движения для камер из metadata
    if metric == "motion_score" {
        if let Some(sc) = dev.metadata.get("motion_score").and_then(|v| v.as_f64()) {
            return Some(sc);
        }
    } else if metric == "motion_detected" {
        if let Some(det) = dev.metadata.get("motion_detected").and_then(|v| v.as_bool()) {
            return Some(if det { 1.0 } else { 0.0 });
        }
    }

    // 2. Поиск в массиве регистров status
    let arr = dev.status.as_array()?;
    let cat = dev.category.as_deref().unwrap_or("");

    for item in arr {
        let code = item.get("code").and_then(|c| c.as_str()).unwrap_or("");
        let dp_id = item.get("dp_id").and_then(|d| d.as_u64()).unwrap_or(0);

        let matched = match metric {
            "floor_temp" => code == "floor_temp" || code == "temp_floor" || dp_id == 101,
            "air_temp" => {
                (cat == "wk") && (code == "air_temp" || code == "temp_current" || dp_id == 24)
            }
            "temp_current" => {
                code == "temp_current"
                    || code == "va_temperature"
                    || dp_id == 102
                    || (cat == "wk" && dp_id == 24)
            }
            "humidity_value" => code == "humidity_value" || code == "va_humidity" || dp_id == 103,
            "cur_power" => code == "cur_power" || dp_id == 23,
            "motion_score" => code == "motion_score" || dp_id == 202,
            other => code == other,
        };

        if matched {
            if let Some(b) = item.get("value").and_then(|v| v.as_bool()) {
                return Some(if b { 1.0 } else { 0.0 });
            }
            let raw = item.get("value")?.as_f64()?;
            if metric.contains("temp") || metric == "cur_power" {
                return Some(if raw > 50.0 || cat == "wk" || metric == "cur_power" {
                    raw / 10.0
                } else {
                    raw
                });
            }
            if metric == "humidity_value" && raw > 100.0 {
                return Some(raw / 10.0);
            }
            return Some(raw);
        }
    }
    None
}

pub fn to_raw_tuya_value(dev: &DiscoveredDevice, code: &str, human_val: &Value) -> Value {
    if code == "temp_set" || code == "upper_temp" || code == "temp_differ_on" {
        if let Some(num) = human_val.as_f64() {
            let is_thermostat = dev.category.as_deref() == Some("wk");
            let raw = if num <= 50.0 && is_thermostat {
                (num * 10.0).round() as i64
            } else {
                num.round() as i64
            };
            return json!(raw);
        }
    }
    human_val.clone()
}

fn is_already_in_state(dev: &DiscoveredDevice, code: &str, target_raw_val: &Value) -> bool {
    let Some(arr) = dev.status.as_array() else {
        return false;
    };

    for item in arr {
        let item_code = item.get("code").and_then(|c| c.as_str()).unwrap_or("");
        let dp_id = item.get("dp_id").and_then(|d| d.as_u64()).unwrap_or(0);

        let is_target_prop = item_code == code
            || (code == "switch" && dp_id == 1)
            || (code == "switch_1" && dp_id == 1)
            || (code == "temp_set" && dp_id == 16)
            || (code == "upper_temp" && dp_id == 19)
            || (code == "temp_differ_on" && dp_id == 106);

        if is_target_prop {
            if let Some(curr_val) = item.get("value") {
                return curr_val == target_raw_val;
            }
        }
    }
    false
}

fn format_action_human(code: &str, val: &Value) -> String {
    match (code, val.as_bool()) {
        ("switch" | "switch_1", Some(true)) => "Включено".to_string(),
        ("switch" | "switch_1", Some(false)) => "Выключено".to_string(),
        _ => {
            if code == "temp_set" {
                format!("Уставка {} °C", val)
            } else {
                format!("{} = {}", code, val)
            }
        }
    }
}