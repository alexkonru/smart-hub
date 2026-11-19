#![allow(dead_code)]

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use anyhow::{Result, anyhow, bail};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{Value, json};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use aes_gcm::{Aes128Gcm, Nonce, Tag, aead::AeadInPlace as GcmKeyInit};

type HmacSha256 = Hmac<Sha256>;

const PREFIX_55AA: u32 = 0x000055AA;
const SUFFIX_AA55: u32 = 0x0000AA55;
const PREFIX_6699: u32 = 0x00006699;
const SUFFIX_9966: u32 = 0x00009966;

const CMD_SESS_KEY_NEG_START: u32 = 3;
const CMD_SESS_KEY_NEG_RESP: u32 = 4;
const CMD_SESS_KEY_NEG_FINISH: u32 = 5;
const CMD_CONTROL: u32 = 7;
const CMD_STATUS: u32 = 8;
const CMD_DP_QUERY: u32 = 10;
const CMD_CONTROL_NEW: u32 = 13;
const CMD_DP_QUERY_NEW: u32 = 16;
const CMD_UPDATEDPS: u32 = 18;

pub struct TuyaClient {
    device_id: String,
    addr: SocketAddr,
    local_key: [u8; 16],
    version: String,
}

impl TuyaClient {
    pub fn new(
        device_id: &str,
        ip: IpAddr,
        port: u16,
        local_key: &str,
        version: &str,
    ) -> Result<Self> {
        let key_bytes = local_key.trim().as_bytes();
        if key_bytes.len() != 16 {
            bail!("Local Key должен содержать ровно 16 символов");
        }
        let mut key = [0u8; 16];
        key.copy_from_slice(key_bytes);

        Ok(Self {
            device_id: device_id.to_string(),
            addr: SocketAddr::new(ip, port),
            local_key: key,
            version: version.to_string(),
        })
    }

    pub async fn query_status(&self) -> Result<Value> {
        match self.version.as_str() {
            "3.5" => self.query_v35().await,
            "3.4" => self.query_v34().await,
            _ => self.query_v33().await,
        }
    }

    pub async fn set_dps(&self, dps: Value) -> Result<Value> {
        match self.version.as_str() {
            "3.5" => self.control_v35(dps).await,
            "3.4" => self.control_v34(dps).await,
            _ => self.control_v33(dps).await,
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    // ========================================================================
    // ПРОТОКОЛ v3.3 (AES-128-ECB + CRC32)
    // ========================================================================

    async fn query_v33(&self) -> Result<Value> {
        let mut stream =
            timeout(Duration::from_millis(1800), TcpStream::connect(self.addr)).await??;
        let payload = json!({
            "gwId": self.device_id,
            "devId": self.device_id,
            "uid": self.device_id,
            "t": Self::now_secs().to_string()
        })
        .to_string();

        let enc = aes_ecb_encrypt_pkcs7(&self.local_key, payload.as_bytes());
        let pkt = encode_55aa_crc32(1, CMD_DP_QUERY, &enc);
        stream.write_all(&pkt).await?;

        let (_, raw_body) = read_55aa_crc32(&mut stream).await?;
        let dec = aes_ecb_decrypt_pkcs7(&self.local_key, &raw_body)?;
        let val = parse_tuya_payload(&dec);
        if val.get("dps").is_some() {
            tracing::info!("📥 LAN v3.3 ответ от {}: {}", self.addr.ip(), val);
        }
        Ok(val)
    }

    async fn control_v33(&self, dps: Value) -> Result<Value> {
        let mut stream =
            timeout(Duration::from_millis(1800), TcpStream::connect(self.addr)).await??;
        let payload = json!({
            "devId": self.device_id,
            "uid": self.device_id,
            "t": Self::now_secs().to_string(),
            "dps": dps
        })
        .to_string();

        let mut plain = Vec::with_capacity(15 + payload.len());
        plain.extend_from_slice(b"3.3");
        plain.extend_from_slice(&[0u8; 12]);
        plain.extend_from_slice(payload.as_bytes());

        let enc = aes_ecb_encrypt_pkcs7(&self.local_key, &plain);
        let pkt = encode_55aa_crc32(1, CMD_CONTROL, &enc);
        stream.write_all(&pkt).await?;

        let _ = timeout(Duration::from_millis(800), read_55aa_crc32(&mut stream)).await;
        Ok(json!({ "ok": true }))
    }

    // ========================================================================
    // ПРОТОКОЛ v3.4 (3-Way Session Key Handshake + AES-ECB + HMAC-SHA256)
    // ========================================================================

    async fn negotiate_v34(&self, stream: &mut TcpStream) -> Result<[u8; 16]> {
        let _ = stream.set_nodelay(true);

        let mut local_nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut local_nonce);
        for b in &mut local_nonce {
            *b = b'0' + (*b % 10);
        }

        let enc_start = aes_ecb_encrypt_pkcs7(&self.local_key, &local_nonce);
        let pkt1 = encode_55aa_hmac(1, CMD_SESS_KEY_NEG_START, &enc_start, &self.local_key);
        stream.write_all(&pkt1).await?;
        stream.flush().await?;

        let (cmd, enc_resp) = timeout(
            Duration::from_millis(1500),
            read_55aa_hmac(stream, &self.local_key),
        )
        .await??;
        if cmd != CMD_SESS_KEY_NEG_RESP {
            bail!("Ожидался CMD_SESS_KEY_NEG_RESP (4), получен {}", cmd);
        }

        let dec_resp = aes_ecb_decrypt_pkcs7(&self.local_key, &enc_resp)?;
        if dec_resp.len() < 48 {
            bail!("Короткий ответ рукопожатия v3.4: {} байт", dec_resp.len());
        }

        let remote_nonce = &dec_resp[0..16];
        let mut finish_mac = <HmacSha256 as Mac>::new_from_slice(&self.local_key)?;
        finish_mac.update(remote_nonce);
        let rkey_hmac = finish_mac.finalize().into_bytes();

        let enc_finish = aes_ecb_encrypt_pkcs7(&self.local_key, &rkey_hmac);
        let pkt3 = encode_55aa_hmac(2, CMD_SESS_KEY_NEG_FINISH, &enc_finish, &self.local_key);
        stream.write_all(&pkt3).await?;
        stream.flush().await?;

        let mut xor_block = [0u8; 16];
        for i in 0..16 {
            xor_block[i] = local_nonce[i] ^ remote_nonce[i];
        }
        let cipher = Aes128::new(GenericArray::from_slice(&self.local_key));
        let mut block = GenericArray::clone_from_slice(&xor_block);
        cipher.encrypt_block(&mut block);

        let mut session_key = [0u8; 16];
        session_key.copy_from_slice(&block);

        // Пауза 60 мс, чтобы пакет завершения рукопожатия ушел отдельно и чип переключил ключ шифрования
        tokio::time::sleep(Duration::from_millis(60)).await;
        Ok(session_key)
    }

    async fn query_v34(&self) -> Result<Value> {
        let mut stream =
            timeout(Duration::from_millis(2000), TcpStream::connect(self.addr)).await??;
        let sess_key = self.negotiate_v34(&mut stream).await?;

        // Отправляем одиночный запрос состояния DP_QUERY_NEW (0x10)
        let enc_q = aes_ecb_encrypt_pkcs7(&sess_key, b"{}");
        let pkt_q = encode_55aa_hmac(3, CMD_DP_QUERY_NEW, &enc_q, &sess_key);
        stream.write_all(&pkt_q).await?;
        stream.flush().await?;

        let mut last_val = json!({ "raw": "" });
        for _ in 0..2 {
            match timeout(
                Duration::from_millis(800),
                read_55aa_hmac(&mut stream, &sess_key),
            )
            .await
            {
                Ok(Ok((_cmd, enc_body))) => {
                    if !enc_body.is_empty() {
                        if let Ok(dec) = aes_ecb_decrypt_pkcs7(&sess_key, &enc_body) {
                            let val = parse_tuya_payload(&dec);
                            if val.get("dps").is_some() {
                                tracing::info!("📥 LAN v3.4 ответ от {}: {}", self.addr.ip(), val);
                                return Ok(val);
                            }
                            last_val = val;
                        }
                    }
                }
                _ => break,
            }
        }

        // Если на 0x10 пришел пустой ACK — запрашиваем принудительную выгрузку регистров UPDATEDPS (0x12)
        let update_req = json!({ "dpId": [1, 2, 16, 24, 36, 40, 43, 101, 103] }).to_string();
        let enc_upd = aes_ecb_encrypt_pkcs7(&sess_key, update_req.as_bytes());
        let pkt_upd = encode_55aa_hmac(4, CMD_UPDATEDPS, &enc_upd, &sess_key);
        if stream.write_all(&pkt_upd).await.is_ok() {
            let _ = stream.flush().await;
            for _ in 0..2 {
                match timeout(
                    Duration::from_millis(700),
                    read_55aa_hmac(&mut stream, &sess_key),
                )
                .await
                {
                    Ok(Ok((_cmd, enc_body))) => {
                        if !enc_body.is_empty() {
                            if let Ok(dec) = aes_ecb_decrypt_pkcs7(&sess_key, &enc_body) {
                                let val = parse_tuya_payload(&dec);
                                if val.get("dps").is_some() {
                                    tracing::info!(
                                        "📥 LAN v3.4 ответ от {}: {}",
                                        self.addr.ip(),
                                        val
                                    );
                                    return Ok(val);
                                }
                                last_val = val;
                            }
                        }
                    }
                    _ => break,
                }
            }
        }

        Ok(last_val)
    }

    async fn control_v34(&self, dps: Value) -> Result<Value> {
        let mut stream =
            timeout(Duration::from_millis(2000), TcpStream::connect(self.addr)).await??;
        let sess_key = self.negotiate_v34(&mut stream).await?;

        let body_json = json!({
            "protocol": 5,
            "t": Self::now_secs(),
            "data": { "dps": dps }
        })
        .to_string();

        let mut plain = Vec::with_capacity(15 + body_json.len());
        plain.extend_from_slice(b"3.4");
        plain.extend_from_slice(&[0u8; 12]);
        plain.extend_from_slice(body_json.as_bytes());

        let enc = aes_ecb_encrypt_pkcs7(&sess_key, &plain);
        let pkt = encode_55aa_hmac(3, CMD_CONTROL_NEW, &enc, &sess_key);
        stream.write_all(&pkt).await?;

        let _ = timeout(
            Duration::from_millis(800),
            read_55aa_hmac(&mut stream, &sess_key),
        )
        .await;
        Ok(json!({ "ok": true }))
    }

    // ========================================================================
    // ПРОТОКОЛ v3.5 (6699 Framing + AES-128-GCM Session Key)
    // ========================================================================

    async fn negotiate_v35(&self, stream: &mut TcpStream) -> Result<[u8; 16]> {
        let mut local_nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut local_nonce);
        for b in &mut local_nonce {
            *b = b'0' + (*b % 10);
        }

        let pkt1 = encode_6699_gcm(1, CMD_SESS_KEY_NEG_START, &local_nonce, &self.local_key)?;
        stream.write_all(&pkt1).await?;

        let (cmd, dec_resp) = read_6699_gcm(stream, &self.local_key).await?;
        if cmd != CMD_SESS_KEY_NEG_RESP {
            bail!("Ожидался CMD_SESS_KEY_NEG_RESP (4) в v3.5, получен {}", cmd);
        }
        let payload = strip_retcode(&dec_resp);
        if payload.len() < 48 {
            bail!("Короткий ответ рукопожатия v3.5: {} байт", payload.len());
        }

        let remote_nonce = &payload[0..16];
        let mut finish_mac = <HmacSha256 as Mac>::new_from_slice(&self.local_key)?;
        finish_mac.update(remote_nonce);
        let rkey_hmac = finish_mac.finalize().into_bytes();

        let pkt3 = encode_6699_gcm(2, CMD_SESS_KEY_NEG_FINISH, &rkey_hmac, &self.local_key)?;
        stream.write_all(&pkt3).await?;

        let mut xor_block = [0u8; 16];
        for i in 0..16 {
            xor_block[i] = local_nonce[i] ^ remote_nonce[i];
        }
        let iv = &local_nonce[0..12];
        let cipher =
            Aes128Gcm::new_from_slice(&self.local_key).map_err(|_| anyhow!("GCM init error"))?;
        let mut buf = xor_block.to_vec();
        let _ = cipher
            .encrypt_in_place_detached(Nonce::from_slice(iv), b"", &mut buf)
            .map_err(|_| anyhow!("GCM session key derive error"))?;

        let mut session_key = [0u8; 16];
        session_key.copy_from_slice(&buf[0..16]);
        Ok(session_key)
    }

    async fn query_v35(&self) -> Result<Value> {
        let mut stream =
            timeout(Duration::from_millis(2000), TcpStream::connect(self.addr)).await??;
        let sess_key = self.negotiate_v35(&mut stream).await?;

        let pkt = encode_6699_gcm(3, CMD_DP_QUERY_NEW, b"{}", &sess_key)?;
        stream.write_all(&pkt).await?;

        for _ in 0..2 {
            let (_cmd, dec) = timeout(
                Duration::from_millis(1200),
                read_6699_gcm(&mut stream, &sess_key),
            )
            .await??;
            let body = strip_retcode(&dec);
            if !body.is_empty() {
                let val = parse_tuya_payload(body);
                if val.get("dps").is_some() {
                    tracing::info!("📥 LAN v3.5 ответ от {}: {}", self.addr.ip(), val);
                    return Ok(val);
                }
            }
        }
        Ok(json!({ "raw": "" }))
    }

    async fn control_v35(&self, dps: Value) -> Result<Value> {
        let mut stream =
            timeout(Duration::from_millis(2000), TcpStream::connect(self.addr)).await??;
        let sess_key = self.negotiate_v35(&mut stream).await?;

        let body_json = json!({
            "protocol": 5,
            "t": Self::now_secs(),
            "data": { "dps": dps }
        })
        .to_string();

        let mut plain = Vec::with_capacity(15 + body_json.len());
        plain.extend_from_slice(b"3.5");
        plain.extend_from_slice(&[0u8; 12]);
        plain.extend_from_slice(body_json.as_bytes());

        let pkt = encode_6699_gcm(3, CMD_CONTROL_NEW, &plain, &sess_key)?;
        stream.write_all(&pkt).await?;

        let _ = timeout(
            Duration::from_millis(800),
            read_6699_gcm(&mut stream, &sess_key),
        )
        .await;
        Ok(json!({ "ok": true }))
    }
}

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ПАКЕТОВ И ШИФРОВАНИЯ
// ============================================================================

fn strip_retcode(data: &[u8]) -> &[u8] {
    if data.len() >= 4 && data[0..4] == [0, 0, 0, 0] {
        &data[4..]
    } else {
        data
    }
}

/// Извлекает JSON из ответа Tuya (пропуская заголовок "3.3"/"3.4"/"3.5" + 12 нулей) и разворачивает data.dps -> dps
fn parse_tuya_payload(raw: &[u8]) -> Value {
    let mut slice = raw;
    if slice.len() >= 15
        && (slice.starts_with(b"3.3") || slice.starts_with(b"3.4") || slice.starts_with(b"3.5"))
    {
        slice = &slice[15..];
    }
    if let Some(pos) = slice.iter().position(|&b| b == b'{') {
        slice = &slice[pos..];
    }
    if let Ok(mut parsed) = serde_json::from_slice::<Value>(slice) {
        if parsed.get("dps").is_none() {
            if let Some(inner_dps) = parsed.get("data").and_then(|d| d.get("dps")).cloned() {
                if let Some(obj) = parsed.as_object_mut() {
                    obj.insert("dps".to_string(), inner_dps);
                }
            }
        }
        return parsed;
    }
    json!({
        "raw": String::from_utf8_lossy(raw).trim_matches('\0').to_string()
    })
}

fn aes_ecb_encrypt_pkcs7(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let pad_len = 16 - (data.len() % 16);
    let mut buf = Vec::with_capacity(data.len() + pad_len);
    buf.extend_from_slice(data);
    buf.resize(data.len() + pad_len, pad_len as u8);

    for chunk in buf.chunks_mut(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    buf
}

fn aes_ecb_decrypt_pkcs7(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        bail!("Некорректная длина AES-блока: {}", data.len());
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

fn encode_55aa_crc32(seq: u32, cmd: u32, payload: &[u8]) -> Vec<u8> {
    let len = (payload.len() + 8) as u32;
    let mut pkt = Vec::with_capacity(16 + payload.len() + 8);
    pkt.extend_from_slice(&PREFIX_55AA.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&cmd.to_be_bytes());
    pkt.extend_from_slice(&len.to_be_bytes());
    pkt.extend_from_slice(payload);

    let crc = crc32fast::hash(&pkt);
    pkt.extend_from_slice(&crc.to_be_bytes());
    pkt.extend_from_slice(&SUFFIX_AA55.to_be_bytes());
    pkt
}

async fn read_55aa_crc32(stream: &mut TcpStream) -> Result<(u32, Vec<u8>)> {
    let mut hdr = [0u8; 16];
    timeout(Duration::from_millis(1500), stream.read_exact(&mut hdr)).await??;
    let prefix = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if prefix != PREFIX_55AA {
        bail!("Неверный префикс v3.3: {:08x}", prefix);
    }
    let cmd = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let total_len = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as usize;
    if total_len < 8 || total_len > 16384 {
        bail!("Некорректная длина пакета v3.3: {}", total_len);
    }
    let mut rest = vec![0u8; total_len];
    timeout(Duration::from_millis(1500), stream.read_exact(&mut rest)).await??;
    let body_end = total_len - 8;
    let body = strip_retcode(&rest[..body_end]).to_vec();
    Ok((cmd, body))
}

fn encode_55aa_hmac(seq: u32, cmd: u32, payload: &[u8], hmac_key: &[u8; 16]) -> Vec<u8> {
    let len = (payload.len() + 36) as u32;
    let mut pkt = Vec::with_capacity(16 + payload.len() + 36);
    pkt.extend_from_slice(&PREFIX_55AA.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&cmd.to_be_bytes());
    pkt.extend_from_slice(&len.to_be_bytes());
    pkt.extend_from_slice(payload);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key).unwrap();
    mac.update(&pkt);
    let sig = mac.finalize().into_bytes();

    pkt.extend_from_slice(&sig);
    pkt.extend_from_slice(&SUFFIX_AA55.to_be_bytes());
    pkt
}

async fn read_55aa_hmac(stream: &mut TcpStream, hmac_key: &[u8; 16]) -> Result<(u32, Vec<u8>)> {
    let mut hdr = [0u8; 16];
    stream.read_exact(&mut hdr).await?;
    let prefix = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if prefix != PREFIX_55AA {
        bail!("Неверный префикс v3.4: {:08x}", prefix);
    }
    let cmd = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let total_len = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as usize;
    if total_len < 36 || total_len > 16384 {
        bail!("Некорректная длина пакета v3.4: {}", total_len);
    }
    let mut rest = vec![0u8; total_len];
    stream.read_exact(&mut rest).await?;

    let payload_end = total_len - 36;
    let expected_hmac = &rest[payload_end..total_len - 4];

    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)?;
    mac.update(&hdr);
    mac.update(&rest[..payload_end]);
    mac.verify_slice(expected_hmac)
        .map_err(|_| anyhow!("Ошибка проверки HMAC v3.4 (неверный Local Key)"))?;

    let body = strip_retcode(&rest[..payload_end]).to_vec();
    Ok((cmd, body))
}

fn encode_6699_gcm(seq: u32, cmd: u32, payload: &[u8], key: &[u8; 16]) -> Result<Vec<u8>> {
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);

    let len = (12 + payload.len() + 16) as u32;
    let mut aad = [0u8; 14];
    aad[2..6].copy_from_slice(&seq.to_be_bytes());
    aad[6..10].copy_from_slice(&cmd.to_be_bytes());
    aad[10..14].copy_from_slice(&len.to_be_bytes());

    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| anyhow!("GCM error"))?;
    let mut enc = payload.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&iv), &aad, &mut enc)
        .map_err(|_| anyhow!("GCM encrypt error"))?;

    let mut pkt = Vec::with_capacity(4 + 14 + 12 + enc.len() + 16 + 4);
    pkt.extend_from_slice(&PREFIX_6699.to_be_bytes());
    pkt.extend_from_slice(&aad);
    pkt.extend_from_slice(&iv);
    pkt.extend_from_slice(&enc);
    pkt.extend_from_slice(&tag);
    pkt.extend_from_slice(&SUFFIX_9966.to_be_bytes());
    Ok(pkt)
}

async fn read_6699_gcm(stream: &mut TcpStream, key: &[u8; 16]) -> Result<(u32, Vec<u8>)> {
    let mut hdr = [0u8; 18];
    stream.read_exact(&mut hdr).await?;
    let prefix = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if prefix != PREFIX_6699 {
        bail!("Неверный префикс v3.5: {:08x}", prefix);
    }
    let aad = &hdr[4..18];
    let cmd = u32::from_be_bytes([aad[6], aad[7], aad[8], aad[9]]);
    let len = u32::from_be_bytes([aad[10], aad[11], aad[12], aad[13]]) as usize;
    if len < 28 || len > 16384 {
        bail!("Некорректная длина пакета v3.5: {}", len);
    }

    let mut rest = vec![0u8; len + 4];
    stream.read_exact(&mut rest).await?;

    let iv = &rest[0..12];
    let enc_end = len - 16;
    let mut data = rest[12..enc_end].to_vec();
    let tag = Tag::from_slice(&rest[enc_end..len]);

    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| anyhow!("GCM error"))?;
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(iv), aad, &mut data, tag)
        .map_err(|_| anyhow!("Ошибка расшифровки GCM v3.5 (неверный Local Key)"))?;

    Ok((cmd, data))
}
