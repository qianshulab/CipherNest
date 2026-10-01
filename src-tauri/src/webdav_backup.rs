//! Independent, versioned WebDAV backup storage. This module never updates a
//! mutable remote head and does not participate in multi-device synchronization.

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
    time::Duration,
};

use atomicwrites::{AtomicFile, OverwriteBehavior};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use quick_xml::{events::Event, name::ResolveResult, NsReader};
use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    tls::Version as TlsVersion,
    Method, StatusCode, Url,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::MAX_VAULT_BYTES,
    error::{VaultError, VaultResult},
    sync::validate_webdav_endpoint,
};

const CONFIG_FORMAT: &str = "CipherNest-WebDAV-Backup-Config";
const CONFIG_VERSION: u8 = 1;
const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_PROPFIND_BYTES: usize = 4 * 1024 * 1024;
const BACKUP_PREFIX: &str = "cnbackup_v1_";

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackupConfig {
    pub endpoint: String,
    pub username: String,
    pub app_password: String,
    pub automatic: bool,
    pub last_upload_at: Option<u64>,
    pub last_uploaded_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_uploaded_sha256: Option<String>,
    pub warning: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptedConfig {
    format: String,
    version: u8,
    vault_id: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WebDavBackupItem {
    pub file_name: String,
    pub file_size: u64,
    pub generation: u64,
    pub updated_at: u64,
    pub vault_id_short: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebDavBackupStatus {
    pub configured: bool,
    pub endpoint: Option<String>,
    pub username: Option<String>,
    pub automatic: bool,
    pub pending: bool,
    pub last_upload_at: Option<u64>,
    pub last_uploaded_generation: Option<u64>,
    pub warning: Option<String>,
}

impl WebDavBackupStatus {
    pub fn absent() -> Self {
        Self {
            configured: false,
            endpoint: None,
            username: None,
            automatic: false,
            pending: false,
            last_upload_at: None,
            last_uploaded_generation: None,
            warning: None,
        }
    }

    pub fn from_config(config: &BackupConfig) -> Self {
        Self {
            configured: true,
            endpoint: Some(config.endpoint.clone()),
            username: Some(config.username.clone()),
            automatic: config.automatic,
            pending: false,
            last_upload_at: config.last_upload_at,
            last_uploaded_generation: config.last_uploaded_generation,
            warning: config.warning.clone(),
        }
    }
}

pub struct WebDavBackupClient {
    client: reqwest::Client,
    endpoint: Url,
    username: String,
    app_password: Zeroizing<String>,
}

impl WebDavBackupClient {
    pub fn new(endpoint: &str, username: String, app_password: String) -> VaultResult<Self> {
        let app_password = Zeroizing::new(app_password);
        let endpoint = validate_webdav_endpoint(endpoint)
            .map_err(|_| backup_error("请输入以 / 结尾的有效 HTTPS WebDAV 文件夹地址。"))?;
        validate_credentials(&username, &app_password)?;
        let builder = reqwest::Client::builder()
            .https_only(true)
            .min_tls_version(TlsVersion::TLS_1_2)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .user_agent("CipherNest-WebDAV-Backup/1");
        // Schannel uses the Windows certificate chain engine, including
        // system trust and intermediate-certificate discovery.
        #[cfg(target_os = "windows")]
        let builder = builder.use_native_tls();
        let client = builder
            .build()
            .map_err(|_| backup_error("无法初始化 HTTPS 客户端。"))?;
        Ok(Self {
            client,
            endpoint,
            username,
            app_password,
        })
    }

    fn request(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        self.client
            .request(method, url)
            .basic_auth(&self.username, Some(self.app_password.as_str()))
    }

    fn object_url(&self, file_name: &str) -> VaultResult<Url> {
        if !valid_backup_name(file_name) && !valid_probe_name(file_name) {
            return Err(backup_error("远端备份文件名无效。"));
        }
        self.endpoint
            .join(file_name)
            .map_err(|_| backup_error("远端备份文件名无效。"))
    }

    pub async fn test_read_write_delete(&self) -> VaultResult<()> {
        self.ensure_collection().await?;
        let file_name = format!("cnbackup-test-{}.tmp", Uuid::new_v4());
        let url = self.object_url(&file_name)?;
        let payload = Uuid::new_v4().as_bytes().to_vec();
        let put = self
            .request(Method::PUT, url.clone())
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(payload.clone())
            .send()
            .await;
        let put = match put {
            Ok(response) => response,
            Err(error) => {
                let original = network_error(error);
                if self.delete_probe(url).await.is_err() {
                    return Err(backup_error(&format!(
                        "{original} 临时测试文件的清理状态未确认，请检查远端目录。"
                    )));
                }
                return Err(original);
            }
        };
        if !put.status().is_success() {
            let original = status_error("写入测试文件", put.status());
            if self.delete_probe(url).await.is_err() {
                return Err(backup_error(&format!(
                    "{original} 临时测试文件的清理状态未确认，请检查远端目录。"
                )));
            }
            return Err(original);
        }
        let checked = self.download_url(url.clone()).await;
        self.delete_probe(url).await?;
        let returned = checked?;
        if returned != payload {
            return Err(backup_error("测试文件回读内容与写入内容不一致。"));
        }
        Ok(())
    }

    async fn delete_probe(&self, url: Url) -> VaultResult<()> {
        let deleted = self
            .request(Method::DELETE, url.clone())
            .send()
            .await
            .map_err(network_error)?;
        if !deleted.status().is_success() && deleted.status() != StatusCode::NOT_FOUND {
            return Err(backup_error(
                "测试文件已写入，但无法清理；请检查 WebDAV 删除权限。",
            ));
        }
        let remaining = self
            .request(Method::GET, url)
            .send()
            .await
            .map_err(network_error)?;
        if remaining.status() != StatusCode::NOT_FOUND {
            return Err(backup_error(
                "测试文件删除后未返回 HTTP 404，无法确认 WebDAV 清理成功。",
            ));
        }
        Ok(())
    }

    async fn ensure_collection(&self) -> VaultResult<()> {
        let propfind =
            Method::from_bytes(b"PROPFIND").map_err(|_| backup_error("无法生成 WebDAV 请求。"))?;
        let response = self
            .request(propfind, self.endpoint.clone())
            .header("Depth", "0")
            .header(CONTENT_TYPE, "application/xml; charset=utf-8")
            .header(ACCEPT, "application/xml, text/xml")
            .body("<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:resourcetype/></d:prop></d:propfind>")
            .send()
            .await
            .map_err(network_error)?;
        if response.status() != StatusCode::MULTI_STATUS {
            return Err(status_error("检查 WebDAV 文件夹", response.status()));
        }
        let body = read_limited(response, MAX_PROPFIND_BYTES).await?;
        if !propfind_reports_collection(&body, &self.endpoint)? {
            return Err(backup_error("所填地址不是现有 WebDAV 文件夹。"));
        }
        Ok(())
    }

    pub async fn upload(
        &self,
        bytes: &[u8],
        vault_id: &str,
        generation: u64,
        updated_at: u64,
    ) -> VaultResult<WebDavBackupItem> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_VAULT_BYTES {
            return Err(VaultError::InvalidVault);
        }
        let name = new_backup_name(vault_id, generation, updated_at)?;
        let url = self.object_url(&name)?;
        let result = self
            .request(Method::PUT, url.clone())
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(network_error)?;
        if !result.status().is_success() {
            return Err(status_error("上传备份", result.status()));
        }
        let returned = self.download_url(url).await?;
        if Sha256::digest(&returned).as_slice() != Sha256::digest(bytes).as_slice() {
            return Err(backup_error(
                "备份已上传，但回读校验失败；请勿将其视为可用备份。",
            ));
        }
        parse_backup_name(&name, bytes.len() as u64)
            .ok_or_else(|| backup_error("生成的备份文件名无效。"))
    }

    pub async fn list(&self) -> VaultResult<Vec<WebDavBackupItem>> {
        let propfind =
            Method::from_bytes(b"PROPFIND").map_err(|_| backup_error("无法生成 WebDAV 请求。"))?;
        let response = self
            .request(propfind, self.endpoint.clone())
            .header("Depth", "1")
            .header(CONTENT_TYPE, "application/xml; charset=utf-8")
            .header(ACCEPT, "application/xml, text/xml")
            .body("<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:getcontentlength/></d:prop></d:propfind>")
            .send()
            .await
            .map_err(network_error)?;
        if response.status() != StatusCode::MULTI_STATUS {
            return Err(status_error("列出 WebDAV 备份", response.status()));
        }
        let body = read_limited(response, MAX_PROPFIND_BYTES).await?;
        parse_listing(&body, &self.endpoint)
    }

    pub async fn download(&self, file_name: &str) -> VaultResult<Vec<u8>> {
        if !valid_backup_name(file_name) {
            return Err(backup_error("远端备份文件名无效。"));
        }
        self.download_url(self.object_url(file_name)?).await
    }

    async fn download_url(&self, url: Url) -> VaultResult<Vec<u8>> {
        let response = self
            .request(Method::GET, url)
            .send()
            .await
            .map_err(network_error)?;
        if !response.status().is_success() {
            return Err(status_error("下载备份", response.status()));
        }
        read_limited(response, MAX_VAULT_BYTES as usize).await
    }
}

fn propfind_reports_collection(body: &[u8], endpoint: &Url) -> VaultResult<bool> {
    #[derive(Clone, Copy)]
    enum Capture {
        Href,
        Status,
    }
    let mut reader = NsReader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut in_response = false;
    let mut in_propstat = false;
    let mut in_resource_type = false;
    let mut capture = None;
    let mut href = String::new();
    let mut status = String::new();
    let mut collection_in_propstat = false;
    let mut response_is_collection = false;
    let mut exact_collection_found = false;
    loop {
        let (namespace, event) = reader
            .read_resolved_event_into(&mut buffer)
            .map_err(|_| backup_error("WebDAV 文件夹响应 XML 无效。"))?;
        if matches!(namespace, ResolveResult::Unknown(_)) {
            return Err(backup_error("WebDAV 文件夹响应 XML 无效。"));
        }
        let is_dav =
            matches!(namespace, ResolveResult::Bound(ref value) if value.as_ref() == b"DAV:");
        match event {
            Event::Start(element) if is_dav => match element.local_name().as_ref() {
                b"response" => {
                    if in_response {
                        return Err(backup_error("WebDAV 文件夹响应 XML 无效。"));
                    }
                    in_response = true;
                    href.clear();
                    response_is_collection = false;
                }
                b"propstat" if in_response => {
                    in_propstat = true;
                    status.clear();
                    collection_in_propstat = false;
                }
                b"href" if in_response && !in_propstat => {
                    href.clear();
                    capture = Some(Capture::Href);
                }
                b"status" if in_propstat => {
                    status.clear();
                    capture = Some(Capture::Status);
                }
                b"resourcetype" if in_propstat => in_resource_type = true,
                b"collection" if in_propstat && in_resource_type => collection_in_propstat = true,
                _ => {}
            },
            Event::Empty(element) if is_dav => {
                if element.local_name().as_ref() == b"collection" && in_propstat && in_resource_type
                {
                    collection_in_propstat = true;
                }
            }
            Event::Text(text) => {
                if let Some(field) = capture {
                    let value = text
                        .xml10_content()
                        .map_err(|_| backup_error("WebDAV 文件夹响应 XML 无效。"))?;
                    match field {
                        Capture::Href => {
                            if href.len().saturating_add(value.len()) > 4096 {
                                return Err(backup_error("WebDAV 文件夹响应字段过长。"));
                            }
                            href.push_str(&value);
                        }
                        Capture::Status => {
                            if status.len().saturating_add(value.len()) > 4096 {
                                return Err(backup_error("WebDAV 文件夹响应字段过长。"));
                            }
                            status.push_str(&value);
                        }
                    }
                }
            }
            Event::End(element) if is_dav => match element.local_name().as_ref() {
                b"href" | b"status" => capture = None,
                b"resourcetype" => in_resource_type = false,
                b"propstat" => {
                    if collection_in_propstat
                        && status.split_ascii_whitespace().nth(1) == Some("200")
                    {
                        response_is_collection = true;
                    }
                    in_propstat = false;
                    capture = None;
                }
                b"response" => {
                    if response_is_collection {
                        if let Ok(url) = endpoint.join(&href) {
                            exact_collection_found |= url == *endpoint;
                        }
                    }
                    in_response = false;
                }
                _ => {}
            },
            Event::DocType(_) | Event::GeneralRef(_) => {
                return Err(backup_error("WebDAV 文件夹响应 XML 无效。"));
            }
            Event::Eof => {
                if in_response || in_propstat || in_resource_type || capture.is_some() {
                    return Err(backup_error("WebDAV 文件夹响应 XML 无效。"));
                }
                return Ok(exact_collection_found);
            }
            _ => {}
        }
        buffer.clear();
    }
}

fn validate_credentials(username: &str, password: &str) -> VaultResult<()> {
    if username.is_empty()
        || username.len() > 512
        || password.is_empty()
        || password.len() > 4096
        || username.chars().any(char::is_control)
        || password.chars().any(char::is_control)
    {
        return Err(backup_error("WebDAV 用户名或密码无效。"));
    }
    Ok(())
}

pub fn new_backup_name(vault_id: &str, generation: u64, updated_at: u64) -> VaultResult<String> {
    let id = Uuid::parse_str(vault_id).map_err(|_| VaultError::InvalidVault)?;
    if id.to_string() != vault_id || generation == 0 || updated_at == 0 {
        return Err(VaultError::InvalidVault);
    }
    Ok(format!(
        "{BACKUP_PREFIX}{vault_id}_{generation}_{updated_at}_{}.cnvault",
        Uuid::new_v4()
    ))
}

fn valid_probe_name(name: &str) -> bool {
    name.strip_prefix("cnbackup-test-")
        .and_then(|tail| tail.strip_suffix(".tmp"))
        .is_some_and(|id| Uuid::parse_str(id).is_ok())
}

pub fn valid_backup_name(name: &str) -> bool {
    parse_backup_name(name, 0).is_some()
}

fn parse_backup_name(name: &str, file_size: u64) -> Option<WebDavBackupItem> {
    let stem = name.strip_prefix(BACKUP_PREFIX)?.strip_suffix(".cnvault")?;
    let mut parts = stem.split('_');
    let vault_id = parts.next()?;
    let generation: u64 = parts.next()?.parse().ok()?;
    let updated_at: u64 = parts.next()?.parse().ok()?;
    let random_id = parts.next()?;
    if parts.next().is_some()
        || Uuid::parse_str(vault_id).ok()?.to_string() != vault_id
        || Uuid::parse_str(random_id).ok()?.to_string() != random_id
        || generation == 0
        || updated_at == 0
    {
        return None;
    }
    Some(WebDavBackupItem {
        file_name: name.to_owned(),
        file_size,
        generation,
        updated_at,
        vault_id_short: vault_id[..8].to_owned(),
    })
}

fn parse_listing(body: &[u8], endpoint: &Url) -> VaultResult<Vec<WebDavBackupItem>> {
    #[derive(Clone, Copy)]
    enum Capture {
        Href,
        Length,
        Status,
    }
    let mut reader = NsReader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut in_response = false;
    let mut in_propstat = false;
    let mut capture = None;
    let mut href = String::new();
    let mut length = String::new();
    let mut status = String::new();
    let mut successful_prop = false;
    let mut listing = Vec::new();
    loop {
        let (namespace, event) = reader
            .read_resolved_event_into(&mut buffer)
            .map_err(|_| backup_error("WebDAV 列表 XML 无效。"))?;
        if matches!(namespace, ResolveResult::Unknown(_)) {
            return Err(backup_error("WebDAV 列表 XML 无效。"));
        }
        let is_dav =
            matches!(namespace, ResolveResult::Bound(ref value) if value.as_ref() == b"DAV:");
        match event {
            Event::Start(element) if is_dav => match element.local_name().as_ref() {
                b"response" => {
                    if in_response {
                        return Err(backup_error("WebDAV 列表 XML 无效。"));
                    }
                    in_response = true;
                    href.clear();
                    length.clear();
                    successful_prop = false;
                }
                b"propstat" if in_response => {
                    in_propstat = true;
                    status.clear();
                }
                b"href" if in_response && !in_propstat => capture = Some(Capture::Href),
                b"getcontentlength" if in_propstat => capture = Some(Capture::Length),
                b"status" if in_propstat => capture = Some(Capture::Status),
                _ => {}
            },
            Event::Text(text) => {
                if let Some(field) = capture {
                    let value = text
                        .xml10_content()
                        .map_err(|_| backup_error("WebDAV 列表 XML 无效。"))?;
                    match field {
                        Capture::Href => {
                            if href.len().saturating_add(value.len()) > 4096 {
                                return Err(backup_error("WebDAV 列表字段过长。"));
                            }
                            href.push_str(&value);
                        }
                        Capture::Length => {
                            if length.len().saturating_add(value.len()) > 4096 {
                                return Err(backup_error("WebDAV 列表字段过长。"));
                            }
                            length.push_str(&value);
                        }
                        Capture::Status => {
                            if status.len().saturating_add(value.len()) > 4096 {
                                return Err(backup_error("WebDAV 列表字段过长。"));
                            }
                            status.push_str(&value);
                        }
                    }
                }
            }
            Event::End(element) if is_dav => match element.local_name().as_ref() {
                b"href" | b"getcontentlength" | b"status" => capture = None,
                b"propstat" => {
                    successful_prop |= status.split_ascii_whitespace().nth(1) == Some("200");
                    in_propstat = false;
                    capture = None;
                }
                b"response" => {
                    if successful_prop {
                        if let Some(item) = item_from_href(&href, &length, endpoint) {
                            listing.push(item);
                        }
                    }
                    in_response = false;
                    capture = None;
                }
                _ => {}
            },
            Event::DocType(_) | Event::GeneralRef(_) => {
                return Err(backup_error("WebDAV 列表 XML 无效。"));
            }
            Event::Eof => {
                if in_response || in_propstat || capture.is_some() {
                    return Err(backup_error("WebDAV 列表 XML 无效。"));
                }
                break;
            }
            _ => {}
        }
        buffer.clear();
    }
    listing.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| b.file_name.cmp(&a.file_name))
    });
    Ok(listing)
}

fn item_from_href(href: &str, length: &str, endpoint: &Url) -> Option<WebDavBackupItem> {
    if href.is_empty() || href.trim() != href || href.chars().any(char::is_control) {
        return None;
    }
    let url = endpoint.join(href).ok()?;
    if url.scheme() != endpoint.scheme()
        || url.host_str() != endpoint.host_str()
        || url.port_or_known_default() != endpoint.port_or_known_default()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let name = url.path().strip_prefix(endpoint.path())?;
    if name.contains('/') || name.contains('%') {
        return None;
    }
    parse_backup_name(name, length.parse().unwrap_or(0))
}

async fn read_limited(mut response: reqwest::Response, limit: usize) -> VaultResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(backup_error("WebDAV 响应超过大小限制。"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(network_error)? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(backup_error("WebDAV 响应超过大小限制。"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn backup_error(message: &str) -> VaultError {
    VaultError::WebDavBackup(message.to_owned())
}

fn network_error(error: reqwest::Error) -> VaultError {
    let chain = format!("{error:?}").to_ascii_lowercase();
    if chain.contains("certificate") || chain.contains("unknownissuer") {
        backup_error("HTTPS 证书链验证失败；请在 WebDAV 服务端配置完整的证书链。")
    } else if error.is_timeout() {
        backup_error("连接超时；请检查 WebDAV 地址和网络。")
    } else {
        backup_error("无法连接 WebDAV 服务器；请检查地址、网络与 HTTPS 配置。")
    }
}

fn status_error(action: &str, status: StatusCode) -> VaultError {
    let explanation = match status.as_u16() {
        401 | 403 => "账号、密码或 WebDAV 权限不足",
        404 => "WebDAV 文件夹或文件不存在",
        405 => "服务器不支持所需的 WebDAV 操作",
        409 => "目标文件夹不存在",
        413 | 507 => "服务器空间或上传大小限制不足",
        _ => "服务器拒绝请求",
    };
    backup_error(&format!(
        "{action}失败（HTTP {}）：{explanation}。",
        status.as_u16()
    ))
}

pub fn write_config(
    path: &Path,
    vault_id: &str,
    root_key: &[u8; 32],
    config: &BackupConfig,
) -> VaultResult<()> {
    validate_webdav_endpoint(&config.endpoint).map_err(|_| backup_error("WebDAV 地址无效。"))?;
    validate_credentials(&config.username, &config.app_password)?;
    let plaintext =
        Zeroizing::new(serde_json::to_vec(config).map_err(|_| backup_error("无法保存备份配置。"))?);
    if plaintext.len() > MAX_CONFIG_BYTES as usize {
        return Err(backup_error("备份配置过大。"));
    }
    let key = config_key(vault_id, root_key)?;
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| backup_error("无法生成备份配置随机数。"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| backup_error("无法加密备份配置。"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: config_aad(vault_id).as_bytes(),
            },
        )
        .map_err(|_| backup_error("无法加密备份配置。"))?;
    let envelope = EncryptedConfig {
        format: CONFIG_FORMAT.into(),
        version: CONFIG_VERSION,
        vault_id: vault_id.into(),
        nonce: STANDARD_NO_PAD.encode(nonce),
        ciphertext: STANDARD_NO_PAD.encode(ciphertext),
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| backup_error("无法保存备份配置。"))?;
    if bytes.len() > MAX_CONFIG_BYTES as usize {
        return Err(backup_error("备份配置过大。"));
    }
    write_private_atomic(path, &bytes)
}

pub fn read_config(path: &Path, vault_id: &str, root_key: &[u8; 32]) -> VaultResult<BackupConfig> {
    let file = File::open(path).map_err(|_| backup_error("备份配置不可读取。"))?;
    let metadata = file
        .metadata()
        .map_err(|_| backup_error("备份配置不可读取。"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
        return Err(backup_error("备份配置无效。"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| backup_error("备份配置不可读取。"))?;
    if bytes.len() > MAX_CONFIG_BYTES as usize {
        return Err(backup_error("备份配置过大。"));
    }
    let envelope: EncryptedConfig =
        serde_json::from_slice(&bytes).map_err(|_| backup_error("备份配置无效。"))?;
    if envelope.format != CONFIG_FORMAT
        || envelope.version != CONFIG_VERSION
        || envelope.vault_id != vault_id
    {
        return Err(backup_error("备份配置与当前保险库不匹配。"));
    }
    let nonce = STANDARD_NO_PAD
        .decode(envelope.nonce)
        .map_err(|_| backup_error("备份配置无效。"))?;
    if nonce.len() != 24 {
        return Err(backup_error("备份配置无效。"));
    }
    let ciphertext = STANDARD_NO_PAD
        .decode(envelope.ciphertext)
        .map_err(|_| backup_error("备份配置无效。"))?;
    let key = config_key(vault_id, root_key)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| backup_error("无法读取备份配置。"))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: config_aad(vault_id).as_bytes(),
                },
            )
            .map_err(|_| backup_error("备份配置与当前保险库不匹配。"))?,
    );
    let config: BackupConfig =
        serde_json::from_slice(&plaintext).map_err(|_| backup_error("备份配置无效。"))?;
    validate_webdav_endpoint(&config.endpoint).map_err(|_| backup_error("备份配置无效。"))?;
    validate_credentials(&config.username, &config.app_password)?;
    Ok(config)
}

pub fn remove_config(path: &Path) -> VaultResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(backup_error("无法清理旧的备份配置。")),
    }
}

fn config_key(vault_id: &str, root_key: &[u8; 32]) -> VaultResult<Zeroizing<[u8; 32]>> {
    let id = Uuid::parse_str(vault_id).map_err(|_| VaultError::InvalidVault)?;
    if id.to_string() != vault_id {
        return Err(VaultError::InvalidVault);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), root_key);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(b"CipherNest WebDAV backup config v1", key.as_mut())
        .map_err(|_| backup_error("无法派生备份配置密钥。"))?;
    Ok(key)
}

fn config_aad(vault_id: &str) -> String {
    format!("{CONFIG_FORMAT}:v{CONFIG_VERSION}:{vault_id}")
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> VaultResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| backup_error("备份配置路径无效。"))?;
    fs::create_dir_all(parent).map_err(|_| backup_error("无法保存备份配置。"))?;
    let atomic = AtomicFile::new(path, OverwriteBehavior::AllowOverwrite);
    atomic
        .write(|file| -> io::Result<()> {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            file.write_all(bytes)?;
            file.sync_all()
        })
        .map_err(|_| backup_error("无法保存备份配置。"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> BackupConfig {
        BackupConfig {
            endpoint: "https://dav.example.test/backups/".into(),
            username: "alice".into(),
            app_password: "secret password".into(),
            automatic: true,
            last_upload_at: Some(123),
            last_uploaded_generation: Some(4),
            last_uploaded_sha256: None,
            warning: None,
        }
    }

    #[test]
    fn config_is_encrypted_and_bound_to_vault_and_root_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.cnvault.webdav-backup");
        let id = Uuid::new_v4().to_string();
        let config = sample_config();
        write_config(&path, &id, &[7; 32], &config).unwrap();
        let raw = fs::read(&path).unwrap();
        assert!(!raw
            .windows(config.app_password.len())
            .any(|slice| slice == config.app_password.as_bytes()));
        assert_eq!(read_config(&path, &id, &[7; 32]).unwrap().username, "alice");
        assert!(read_config(&path, &id, &[8; 32]).is_err());
        assert!(read_config(&path, &Uuid::new_v4().to_string(), &[7; 32]).is_err());
    }

    #[test]
    fn legacy_config_without_confirmed_digest_remains_readable() {
        let config = sample_config();
        let legacy = serde_json::to_value(&config).unwrap();
        assert!(legacy.get("lastUploadedSha256").is_none());
        let restored: BackupConfig = serde_json::from_value(legacy).unwrap();
        assert_eq!(restored.last_uploaded_generation, Some(4));
        assert!(restored.last_uploaded_sha256.is_none());
    }

    #[test]
    fn names_are_unique_and_reject_path_traversal() {
        let id = Uuid::new_v4().to_string();
        let one = new_backup_name(&id, 9, 1234).unwrap();
        let two = new_backup_name(&id, 9, 1234).unwrap();
        assert_ne!(one, two);
        assert_eq!(parse_backup_name(&one, 88).unwrap().file_size, 88);
        assert!(!valid_backup_name("../vault.cnvault"));
        assert!(!valid_backup_name("cnbackup_v1_bad.cnvault"));
    }

    #[test]
    fn listing_ignores_foreign_paths_and_parses_own_backups() {
        let id = Uuid::new_v4().to_string();
        let name = new_backup_name(&id, 2, 456).unwrap();
        let body = format!("<d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>/backups/{name}</d:href><d:propstat><d:prop><d:getcontentlength>123</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/outside/{name}</d:href><d:propstat><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>");
        let url = Url::parse("https://dav.example.test/backups/").unwrap();
        let items = parse_listing(body.as_bytes(), &url).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_name, name);
        assert_eq!(items[0].file_size, 123);
    }

    #[test]
    fn collection_probe_requires_exact_dav_collection_property() {
        let endpoint = Url::parse("https://dav.example.test/backups/").unwrap();
        let valid = b"<d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>/backups/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>";
        assert!(propfind_reports_collection(valid, &endpoint).unwrap());
        let wrong_path = b"<d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>/elsewhere/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>";
        assert!(!propfind_reports_collection(wrong_path, &endpoint).unwrap());
        let failed_property = b"<d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>/backups/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat></d:response></d:multistatus>";
        assert!(!propfind_reports_collection(failed_property, &endpoint).unwrap());
    }

    #[tokio::test]
    #[ignore = "requires an explicitly selected disposable WebDAV test directory"]
    async fn live_webdav_backup_client_round_trip_probe() {
        let endpoint = std::env::var("CIPHERNEST_WEBDAV_TEST_URL").expect("test URL");
        let username = std::env::var("CIPHERNEST_WEBDAV_TEST_USER").expect("test user");
        let password = std::env::var("CIPHERNEST_WEBDAV_TEST_PASSWORD").expect("test password");
        let client = WebDavBackupClient::new(&endpoint, username, password).unwrap();
        client.test_read_write_delete().await.unwrap();
    }
}
