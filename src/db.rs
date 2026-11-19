use anyhow::Result;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct HistoryPoint {
    pub ts: u64,
    pub val: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeProfile {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationRule {
    pub id: i64,
    pub profile_id: String,
    pub name: String,
    pub enabled: bool,
    pub rule_type: String,
    pub trigger_device_id: String,
    pub trigger_metric: String,
    pub operator: String,
    pub threshold: f64,
    pub schedule_time: String,
    pub action_device_id: String,
    pub action_code: String,
    pub action_value: Value,
    #[serde(default)]
    pub last_triggered: u64,
}

#[derive(Clone)]
pub struct TelemetryDb {
    conn: Arc<Mutex<Connection>>,
    last_written: Arc<Mutex<HashMap<String, (u64, f64)>>>,
}

impl TelemetryDb {
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;

             CREATE TABLE IF NOT EXISTS settings (
                 key TEXT PRIMARY KEY,
                 val TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS profiles (
                 id TEXT PRIMARY KEY,
                 name TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS telemetry (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 profile_id TEXT NOT NULL DEFAULT 'home',
                 device_id TEXT NOT NULL,
                 metric TEXT NOT NULL,
                 ts INTEGER NOT NULL,
                 val REAL NOT NULL
             );

             CREATE TABLE IF NOT EXISTS automations (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 profile_id TEXT NOT NULL,
                 rule_json TEXT NOT NULL
             );",
        )?;

        let _ = conn.execute(
            "ALTER TABLE telemetry ADD COLUMN profile_id TEXT NOT NULL DEFAULT 'home'",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_prof_dev_metric ON telemetry(profile_id, device_id, metric, ts)",
            [],
        );

        // Создаем базовый профиль ТОЛЬКО если таблица профилей абсолютно пуста (первый запуск)
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM profiles", [], |r| r.get(0))
            .unwrap_or(0);
        if count == 0 {
            conn.execute(
                "INSERT INTO profiles (id, name) VALUES ('home', 'Основной дом')",
                [],
            )?;
        }

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            last_written: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    // ========================================================================
    // УПРАВЛЕНИЕ ПРОФИЛЯМИ (CRUD: СОЗДАНИЕ, ПЕРЕИМЕНОВАНИЕ, УДАЛЕНИЕ, ВЫБОР)
    // ========================================================================

    pub fn get_saved_active_profile(&self) -> String {
        let Ok(conn) = self.conn.lock() else {
            return "home".to_string();
        };
        if let Ok(prof) = conn.query_row(
            "SELECT val FROM settings WHERE key = 'active_profile'",
            [],
            |r| r.get::<_, String>(0),
        ) {
            // Проверяем, что такой профиль реально существует
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM profiles WHERE id = ?1",
                    params![prof],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if exists > 0 {
                return prof;
            }
        }
        // Иначе берем первый существующий профиль из таблицы
        conn.query_row(
            "SELECT id FROM profiles ORDER BY rowid ASC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| "home".to_string())
    }

    pub fn save_active_profile(&self, profile_id: &str) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO settings (key, val) VALUES ('active_profile', ?1)",
                params![profile_id],
            );
        }
    }

    pub fn list_profiles(&self) -> Vec<HomeProfile> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare("SELECT id, name FROM profiles ORDER BY rowid ASC") else {
            return Vec::new();
        };
        stmt.query_map([], |row| {
            Ok(HomeProfile {
                id: row.get(0)?,
                name: row.get(1)?,
            })
        })
        .map(|iter| iter.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    pub fn create_profile(&self, id: &str, name: &str) -> Result<()> {
        let Ok(conn) = self.conn.lock() else {
            anyhow::bail!("DB lock error");
        };
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM profiles WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists > 0 {
            anyhow::bail!("Профиль с ID «{}» уже существует", id);
        }
        conn.execute(
            "INSERT INTO profiles (id, name) VALUES (?1, ?2)",
            params![id, name],
        )?;
        Ok(())
    }

    pub fn rename_profile(&self, id: &str, new_name: &str) -> Result<()> {
        let Ok(conn) = self.conn.lock() else {
            anyhow::bail!("DB lock error");
        };
        let updated = conn.execute(
            "UPDATE profiles SET name = ?1 WHERE id = ?2",
            params![new_name, id],
        )?;
        if updated == 0 {
            anyhow::bail!("Профиль не найден");
        }
        Ok(())
    }

    pub fn delete_profile(&self, id: &str) -> Result<String> {
        let Ok(conn) = self.conn.lock() else {
            anyhow::bail!("DB lock error");
        };
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM profiles", [], |r| r.get(0))
            .unwrap_or(1);
        if count <= 1 {
            anyhow::bail!(
                "Нельзя удалить единственный оставшийся профиль. Сначала создайте другой профиль или используйте кнопку сброса."
            );
        }

        conn.execute("DELETE FROM profiles WHERE id = ?1", params![id])?;
        conn.execute("DELETE FROM telemetry WHERE profile_id = ?1", params![id])?;
        conn.execute("DELETE FROM automations WHERE profile_id = ?1", params![id])?;

        let next_profile: String = conn.query_row(
            "SELECT id FROM profiles ORDER BY rowid ASC LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        let _ = conn.execute(
            "INSERT OR REPLACE INTO settings (key, val) VALUES ('active_profile', ?1)",
            params![next_profile],
        );
        Ok(next_profile)
    }

    // ========================================================================
    // ТЕЛЕМЕТРИЯ И ГРАФИКИ
    // ========================================================================

    pub fn record_metric(&self, profile_id: &str, device_id: &str, metric: &str, val: f64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let key = format!("{}:{}:{}", profile_id, device_id, metric);
        {
            let mut cache = self.last_written.lock().unwrap();
            if let Some(&(last_ts, last_val)) = cache.get(&key) {
                if now.saturating_sub(last_ts) < 300 && (val - last_val).abs() < 0.2 {
                    return;
                }
            }
            cache.insert(key, (now, val));
        }

        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT INTO telemetry (profile_id, device_id, metric, ts, val) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![profile_id, device_id, metric, now as i64, val],
            );
        }
    }

    pub fn get_recent_points(
        &self,
        profile_id: &str,
        device_id: &str,
        metric: &str,
        limit: usize,
    ) -> Vec<HistoryPoint> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT ts, val FROM (
                SELECT ts, val FROM telemetry
                WHERE profile_id = ?1 AND device_id = ?2 AND metric = ?3
                ORDER BY ts DESC LIMIT ?4
             ) ORDER BY ts ASC",
        ) else {
            return Vec::new();
        };

        let rows = stmt.query_map(
            params![profile_id, device_id, metric, limit as i64],
            |row| {
                Ok(HistoryPoint {
                    ts: row.get::<_, i64>(0)? as u64,
                    val: row.get::<_, f64>(1)?,
                })
            },
        );

        match rows {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    // ========================================================================
    // АВТОМАТИЗАЦИИ
    // ========================================================================

    pub fn list_automations(&self, profile_id: &str) -> Vec<AutomationRule> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn
            .prepare("SELECT id, rule_json FROM automations WHERE profile_id = ?1 ORDER BY id ASC")
        else {
            return Vec::new();
        };

        stmt.query_map(params![profile_id], |row| {
            let id: i64 = row.get(0)?;
            let json_str: String = row.get(1)?;
            Ok((id, json_str))
        })
        .map(|iter| {
            iter.filter_map(|r| r.ok())
                .filter_map(|(id, s)| {
                    serde_json::from_str::<AutomationRule>(&s)
                        .ok()
                        .map(|mut rule| {
                            rule.id = id;
                            rule
                        })
                })
                .collect()
        })
        .unwrap_or_default()
    }

    pub fn save_automation(&self, mut rule: AutomationRule) -> Result<i64> {
        let Ok(conn) = self.conn.lock() else {
            anyhow::bail!("DB lock error");
        };
        if rule.id > 0 {
            let json_str = serde_json::to_string(&rule)?;
            conn.execute(
                "UPDATE automations SET rule_json = ?1 WHERE id = ?2",
                params![json_str, rule.id],
            )?;
            Ok(rule.id)
        } else {
            let json_str = serde_json::to_string(&rule)?;
            conn.execute(
                "INSERT INTO automations (profile_id, rule_json) VALUES (?1, ?2)",
                params![rule.profile_id, json_str],
            )?;
            let new_id = conn.last_insert_rowid();
            rule.id = new_id;
            let updated_json = serde_json::to_string(&rule)?;
            conn.execute(
                "UPDATE automations SET rule_json = ?1 WHERE id = ?2",
                params![updated_json, new_id],
            )?;
            Ok(new_id)
        }
    }

    pub fn toggle_automation(&self, id: i64, enabled: bool) -> Result<()> {
        let Ok(conn) = self.conn.lock() else {
            anyhow::bail!("DB lock error");
        };
        let json_str: String = conn.query_row(
            "SELECT rule_json FROM automations WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;
        if let Ok(mut rule) = serde_json::from_str::<AutomationRule>(&json_str) {
            rule.id = id;
            rule.enabled = enabled;
            let updated = serde_json::to_string(&rule)?;
            conn.execute(
                "UPDATE automations SET rule_json = ?1 WHERE id = ?2",
                params![updated, id],
            )?;
        }
        Ok(())
    }

    pub fn delete_automation(&self, id: i64) -> Result<()> {
        if let Ok(conn) = self.conn.lock() {
            conn.execute("DELETE FROM automations WHERE id = ?1", params![id])?;
        }
        Ok(())
    }

    // ========================================================================
    // СБРОС БД
    // ========================================================================

    pub fn clear_telemetry(&self, profile_id: &str) -> Result<()> {
        if let Ok(mut cache) = self.last_written.lock() {
            cache.clear();
        }
        if let Ok(conn) = self.conn.lock() {
            conn.execute(
                "DELETE FROM telemetry WHERE profile_id = ?1",
                params![profile_id],
            )?;
            let _ = conn.execute_batch("VACUUM;");
        }
        Ok(())
    }

    pub fn clear_automations(&self, profile_id: &str) -> Result<()> {
        if let Ok(conn) = self.conn.lock() {
            conn.execute(
                "DELETE FROM automations WHERE profile_id = ?1",
                params![profile_id],
            )?;
        }
        Ok(())
    }

    pub fn factory_reset_all(&self) -> Result<()> {
        if let Ok(mut cache) = self.last_written.lock() {
            cache.clear();
        }
        if let Ok(conn) = self.conn.lock() {
            conn.execute_batch(
                "DELETE FROM telemetry;
                 DELETE FROM automations;
                 VACUUM;",
            )?;
        }
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        conn.query_row(
            "SELECT val FROM settings WHERE key = ?1",
            params![key],
            |r| r.get(0),
        )
        .ok()
    }

    pub fn set_setting(&self, key: &str, val: &str) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO settings (key, val) VALUES (?1, ?2)",
                params![key, val],
            );
        }
    }

    /// Удаляет старые точки графиков старше retention_days дней, чтобы база никогда не переполняла диск
    pub fn prune_old_telemetry(&self, retention_days: u64) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(retention_days * 86400);

        if let Ok(conn) = self.conn.lock() {
            let deleted = conn
                .execute(
                    "DELETE FROM telemetry WHERE ts < ?1",
                    params![cutoff as i64],
                )
                .unwrap_or(0);
            let _ = conn.execute_batch("PRAGMA optimize;");
            return deleted;
        }
        0
    }
}
