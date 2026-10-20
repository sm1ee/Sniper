//! Bounded, passive provider readers and static document discovery.
//!
//! Provider URLs are constructed here, never taken from returned API links. The
//! caller supplies a dedicated client with redirects disabled and no target
//! credentials or cookies. Returned URLs are evidence, not permission to fetch.
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
    time::Duration,
};

use regex::Regex;
use reqwest::{
    header::{HeaderValue, RETRY_AFTER},
    Client, RequestBuilder,
};
use serde_json::Value;
use url::Url;

pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_STATIC_ITEMS: usize = 10_000;
const MAX_WARNINGS: usize = 32;
const MAX_URL_BYTES: usize = 16_384;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Clone, Debug)]
pub struct Discovery {
    pub url: String,
    pub method: String,
    pub kind: String,
    pub location: String,
    pub timestamp: Option<String>,
    pub status: Option<u16>,
}

#[derive(Default, Debug)]
pub struct SourceReport {
    pub requests: usize,
    pub truncated: bool,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

impl SourceReport {
    fn warn(&mut self, warning: impl Into<String>) {
        let warning = warning.into();
        if self.warnings.len() < MAX_WARNINGS && !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }

    fn fail(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
        self.truncated = true;
    }
}

#[derive(Debug)]
enum FetchError {
    Cancelled,
    Http(u16),
    TooLarge,
    Transport,
    InvalidText,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Cancelled"),
            Self::Http(status) => write!(f, "Provider returned HTTP {status}"),
            Self::TooLarge => f.write_str("Provider response exceeded the 2 MiB limit"),
            Self::Transport => f.write_str("Provider request failed or timed out"),
            Self::InvalidText => f.write_str("Provider returned invalid UTF-8"),
        }
    }
}

async fn cancelled(cancel: &AtomicBool) {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn pause(duration: Duration, cancel: &AtomicBool) -> Result<(), FetchError> {
    if cancel.load(Ordering::Relaxed) {
        return Err(FetchError::Cancelled);
    }
    tokio::select! {
        _ = cancelled(cancel) => Err(FetchError::Cancelled),
        _ = tokio::time::sleep(duration) => Ok(()),
    }
}

/// Retries reads only. Scan submissions deliberately do not retry: a lost
/// response must not cause a second active scan or a second paid API operation.
async fn fetch_text(
    request: RequestBuilder,
    cancel: &AtomicBool,
    report: &mut SourceReport,
    retry_rate_limit: bool,
) -> Result<String, FetchError> {
    for attempt in 0..=2u32 {
        if cancel.load(Ordering::Relaxed) {
            return Err(FetchError::Cancelled);
        }
        let current = request.try_clone().ok_or(FetchError::Transport)?;
        report.requests += 1;
        let mut response = tokio::select! {
            _ = cancelled(cancel) => return Err(FetchError::Cancelled),
            result = current.timeout(REQUEST_TIMEOUT).send() => result.map_err(|_| FetchError::Transport)?,
        };
        let status = response.status();
        if status.as_u16() == 429 && retry_rate_limit && attempt < 2 {
            let retry_after = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(1 << attempt)
                .clamp(1, 10);
            report.warn("Provider rate-limited a request; retried with bounded backoff");
            drop(response);
            pause(Duration::from_secs(retry_after), cancel).await?;
            continue;
        }
        if !status.is_success() {
            return Err(FetchError::Http(status.as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
        {
            return Err(FetchError::TooLarge);
        }
        let mut bytes = Vec::new();
        // chunk() is used rather than text()/json() so chunked responses cannot
        // allocate an unbounded body before the size check is performed.
        loop {
            let chunk = tokio::select! {
                _ = cancelled(cancel) => return Err(FetchError::Cancelled),
                result = response.chunk() => result.map_err(|_| FetchError::Transport)?,
            };
            let Some(chunk) = chunk else {
                break;
            };
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(FetchError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        return String::from_utf8(bytes).map_err(|_| FetchError::InvalidText);
    }
    Err(FetchError::Http(429))
}

fn api_key() -> Result<Option<HeaderValue>, String> {
    match std::env::var("URLSCAN_API_KEY") {
        Ok(value) if !value.trim().is_empty() => {
            let mut value = HeaderValue::from_str(value.trim())
                .map_err(|_| "URLSCAN_API_KEY is not a valid HTTP header".to_string())?;
            value.set_sensitive(true);
            Ok(Some(value))
        }
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err("URLSCAN_API_KEY is not valid UTF-8".into()),
    }
}

fn authenticated(request: RequestBuilder, key: &Option<HeaderValue>) -> RequestBuilder {
    match key {
        Some(key) => request.header("api-key", key.clone()),
        None => request,
    }
}

fn provider_host(target: &Url) -> Result<&str, String> {
    target
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "Target has no hostname".to_string())
}

fn urlscan_search_url(host: &str, _subdomains: bool, size: usize, after: Option<&str>) -> Url {
    // Use the broad search fields, then apply the shared scope matcher before
    // candidates consume the result quota.
    let field = "domain";
    let task_field = "task.domain";
    // URL host strings cannot contain quotation marks, but escaping also makes
    // this helper safe to reuse with fixture input and IP literals.
    let host = host.replace('\\', "\\\\").replace('"', "\\\"");
    let query = format!("({field}:\"{host}\" OR {task_field}:\"{host}\")");
    let mut url = Url::parse("https://urlscan.io/api/v1/search/").expect("constant URL");
    url.query_pairs_mut()
        .append_pair("q", &query)
        .append_pair("size", &size.to_string());
    if let Some(after) = after {
        url.query_pairs_mut().append_pair("search_after", after);
    }
    url
}

fn result_url(uuid: &str) -> Option<Url> {
    let id = uuid::Uuid::parse_str(uuid).ok()?;
    Some(Url::parse(&format!("https://urlscan.io/api/v1/result/{id}/")).expect("UUID URL"))
}

fn sort_cursor(value: &Value) -> Option<String> {
    let values = value.as_array()?;
    if values.is_empty() || values.len() > 8 {
        return None;
    }
    let mut parts = Vec::new();
    for value in values {
        let part = match value {
            Value::String(value)
                if !value.is_empty()
                    && value.len() <= 1024
                    && !value.contains([',', '\r', '\n']) =>
            {
                value.clone()
            }
            Value::Number(value) => value.to_string(),
            _ => return None,
        };
        parts.push(part);
    }
    Some(parts.join(","))
}

fn status(value: Option<&Value>) -> Option<u16> {
    let value = value?;
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .or_else(|| value.as_str()?.parse().ok())
        .filter(|v| (100..=599).contains(v))
}

fn text_at<'a>(value: &'a Value, paths: &[&str]) -> Option<&'a str> {
    paths
        .iter()
        .find_map(|path| value.pointer(path).and_then(Value::as_str))
}

fn method(value: Option<&str>) -> String {
    let value = value.unwrap_or("GET");
    if !value.is_empty()
        && value.len() <= 32
        && value.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-')
    {
        value.to_ascii_uppercase()
    } else {
        "GET".into()
    }
}

fn push_discovery(
    out: &mut Vec<Discovery>,
    seen: &mut HashSet<(String, String, String)>,
    item: Discovery,
    max: usize,
) -> bool {
    if item.url.is_empty() {
        return true;
    }
    if item.url.len() > MAX_URL_BYTES {
        return false;
    }
    let key = (item.url.clone(), item.method.clone(), item.location.clone());
    if seen.contains(&key) {
        // Search summaries often lack status codes that the full scan supplies.
        if item.status.is_some() || item.timestamp.is_some() {
            if let Some(existing) = out.iter_mut().find(|d| {
                d.url == item.url && d.method == item.method && d.location == item.location
            }) {
                if existing.status.is_none() {
                    existing.status = item.status;
                }
                if existing.timestamp.is_none() {
                    existing.timestamp = item.timestamp;
                }
            }
        }
        return true;
    }
    if out.len() >= max {
        return false;
    }
    seen.insert(key);
    out.push(item);
    true
}

/// Extract only explicit URL-bearing fields, never arbitrary strings such as
/// cookies, request bodies, response contents, API links, or scanner metadata.
fn urlscan_discoveries_filtered(
    document: &Value,
    location: &str,
    max: usize,
    in_scope: impl Fn(&str) -> bool,
) -> (Vec<Discovery>, bool) {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let timestamp = document
        .pointer("/task/time")
        .and_then(Value::as_str)
        .filter(|s| s.len() <= 128)
        .map(str::to_string);
    let mut complete = true;
    let mut add = |url: &str, verb: Option<&str>, code: Option<u16>| {
        if !in_scope(url) {
            return;
        }
        complete &= push_discovery(
            &mut out,
            &mut seen,
            Discovery {
                url: url.to_string(),
                method: method(verb),
                kind: "history".into(),
                location: location.into(),
                timestamp: timestamp.clone(),
                status: code,
            },
            max,
        );
    };
    if let Some(url) = text_at(document, &["/task/url"]) {
        add(url, None, None);
    }
    if let Some(url) = text_at(document, &["/page/url"]) {
        add(url, None, status(document.pointer("/page/status")));
    }
    // Prefer the detailed observations before derivative lists so methods and
    // status codes survive when the bounded output fills up.
    if let Some(requests) = document.pointer("/data/requests").and_then(Value::as_array) {
        for request in requests {
            let verb = text_at(
                request,
                &["/request/request/method", "/request/method", "/method"],
            );
            let code = status(
                request
                    .pointer("/response/response/status")
                    .or_else(|| request.pointer("/response/status")),
            );
            for path in [
                "/request/request/url",
                "/request/url",
                "/response/response/url",
                "/response/url",
            ] {
                if let Some(url) = text_at(request, &[path]) {
                    add(url, verb, code);
                }
            }
        }
    }
    if let Some(urls) = document.pointer("/lists/urls").and_then(Value::as_array) {
        for url in urls.iter().filter_map(Value::as_str) {
            add(url, None, None);
        }
    }
    for (path, fields) in [
        ("/data/links", &["/href", "/url"][..]),
        (
            "/data/redirects",
            &[
                "/url",
                "/from",
                "/to",
                "/from/url",
                "/to/url",
                "/response/url",
                "/request/url",
                "/redirectResponse/url",
                "/request/request/url",
                "/response/response/url",
            ][..],
        ),
        (
            "/data/websockets",
            &["/url", "/request/url", "/request/request/url"][..],
        ),
    ] {
        if let Some(entries) = document.pointer(path).and_then(Value::as_array) {
            for entry in entries {
                if let Some(url) = entry.as_str() {
                    add(url, None, None);
                }
                for field in fields {
                    if let Some(url) = text_at(entry, &[*field]) {
                        add(url, None, None);
                    }
                }
            }
        }
    }
    (out, !complete)
}

pub async fn urlscan(
    client: &Client,
    target: &Url,
    include_subdomains: bool,
    max_pages: usize,
    max_results: usize,
    cancel: &AtomicBool,
) -> (Vec<Discovery>, SourceReport) {
    let mut out = Vec::new();
    let mut report = SourceReport::default();
    let host = match provider_host(target) {
        Ok(host) => host,
        Err(e) => {
            report.fail(e);
            return (out, report);
        }
    };
    let key = match api_key() {
        Ok(key) => key,
        Err(e) => {
            report.fail(e);
            return (out, report);
        }
    };
    if max_pages == 0 || max_results == 0 {
        report.truncated = true;
        return (out, report);
    }
    let size = max_results.min(100);
    let mut after: Option<String> = None;
    let mut cursors = HashSet::new();
    let mut scan_ids = HashSet::new();
    let mut seen = HashSet::new();
    let mut scanned = 0usize;
    for page_index in 0..max_pages {
        let url = urlscan_search_url(host, include_subdomains, size, after.as_deref());
        let text = match fetch_text(
            authenticated(client.get(url), &key),
            cancel,
            &mut report,
            true,
        )
        .await
        {
            Ok(text) => text,
            Err(e) => {
                report.fail(e.to_string());
                break;
            }
        };
        let data: Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(_) => {
                report.fail("urlscan returned malformed JSON");
                break;
            }
        };
        if let Some(days) = data.get("search_date_limit_days").and_then(Value::as_u64) {
            report.warn(format!(
                "urlscan search history is limited to the past {days} days for this account"
            ));
            report.truncated = true;
        }
        let Some(results) = data.get("results").and_then(Value::as_array) else {
            report.fail("urlscan response is missing its results array");
            break;
        };
        if results.is_empty() {
            break;
        }
        scanned += results.len();
        let total = data.get("total").and_then(Value::as_u64);
        let more = data
            .get("has_more")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || total.is_some_and(|n| n > scanned as u64)
            || (total.is_none() && results.len() >= size);
        for result in results {
            if cancel.load(Ordering::Relaxed) {
                report.fail("Cancelled");
                break;
            }
            let uuid = text_at(result, &["/task/uuid", "/_id"]);
            let full_url = uuid.and_then(result_url);
            let location = full_url
                .as_ref()
                .map(Url::as_str)
                .unwrap_or("https://urlscan.io/api/v1/search/");
            let (summary, clipped) =
                urlscan_discoveries_filtered(result, location, max_results, |url| {
                    crate::recon::discovery_in_scope(target, include_subdomains, url)
                });
            report.truncated |= clipped;
            for item in summary {
                if !push_discovery(&mut out, &mut seen, item, max_results) {
                    report.truncated = true;
                }
            }
            if out.len() >= max_results {
                report.truncated = true;
                break;
            }
            let Some(full_url) = full_url else {
                report.warn(
                    "A urlscan result had no valid scan UUID; its detail document was skipped",
                );
                report.truncated = true;
                continue;
            };
            if !scan_ids.insert(full_url.to_string()) {
                continue;
            }
            let text = match fetch_text(
                authenticated(client.get(full_url.clone()), &key),
                cancel,
                &mut report,
                true,
            )
            .await
            {
                Ok(text) => text,
                Err(e @ (FetchError::Cancelled | FetchError::Http(429))) => {
                    report.fail(e.to_string());
                    break;
                }
                Err(e) => {
                    report.warn(format!(
                        "Some urlscan detail documents could not be read: {e}"
                    ));
                    report.truncated = true;
                    continue;
                }
            };
            let document: Value = match serde_json::from_str(&text) {
                Ok(value) => value,
                Err(_) => {
                    report.warn("Some urlscan detail documents contained malformed JSON");
                    report.truncated = true;
                    continue;
                }
            };
            let (found, clipped) =
                urlscan_discoveries_filtered(&document, full_url.as_str(), max_results, |url| {
                    crate::recon::discovery_in_scope(target, include_subdomains, url)
                });
            report.truncated |= clipped;
            for item in found {
                if !push_discovery(&mut out, &mut seen, item, max_results) {
                    report.truncated = true;
                }
            }
            if out.len() >= max_results {
                report.truncated = true;
                break;
            }
        }
        if report.error.is_some() || out.len() >= max_results || !more {
            break;
        }
        if page_index + 1 == max_pages {
            report.truncated = true;
            report.warn("urlscan search page limit reached");
            break;
        }
        let next = results
            .last()
            .and_then(|r| r.get("sort"))
            .and_then(sort_cursor);
        let Some(next) = next else {
            report.truncated = true;
            report.warn("urlscan reported more results without a usable search cursor");
            break;
        };
        if !cursors.insert(next.clone()) {
            report.truncated = true;
            report.warn("urlscan repeated a search cursor; pagination stopped");
            break;
        }
        after = Some(next);
    }
    (out, report)
}

fn wayback_url(host: &str, subdomains: bool, limit: usize, resume: Option<&str>) -> Url {
    let mut url = Url::parse("https://web.archive.org/cdx/search/cdx").expect("constant URL");
    url.query_pairs_mut()
        .append_pair("url", host)
        .append_pair("matchType", if subdomains { "domain" } else { "host" })
        .append_pair("output", "json")
        .append_pair("fl", "urlkey,timestamp,original,mimetype,statuscode,digest")
        .append_pair("showResumeKey", "true")
        .append_pair("limit", &limit.to_string());
    if let Some(resume) = resume {
        // CDX returns an application/x-www-form-urlencoded cursor. Decode it
        // once before query_pairs_mut encodes it; otherwise % and + double-encode.
        let encoded = format!("key={resume}");
        let decoded = url::form_urlencoded::parse(encoded.as_bytes())
            .next()
            .map(|(_, value)| value.into_owned())
            .unwrap_or_else(|| resume.to_string());
        url.query_pairs_mut().append_pair("resumeKey", &decoded);
    }
    url
}

/// CDX emits an empty separator row and a single-cell cursor row. Some
/// deployments append the cursor after the JSON document instead; accept both.
fn parse_cdx_filtered(
    text: &str,
    max: usize,
    in_scope: impl Fn(&str) -> bool,
) -> Result<(Vec<Discovery>, Option<String>, bool), String> {
    let mut stream = serde_json::Deserializer::from_str(text).into_iter::<Value>();
    let value = stream
        .next()
        .ok_or("Wayback returned an empty response")?
        .map_err(|_| "Wayback returned malformed JSON")?;
    let offset = stream.byte_offset();
    let rows = value
        .as_array()
        .ok_or("Wayback response is not a CDX array")?;
    if rows.is_empty() {
        return Ok((Vec::new(), None, false));
    }
    let header = rows[0]
        .as_array()
        .ok_or("Wayback response is missing a CDX header")?;
    let index = |name: &str| header.iter().position(|v| v.as_str() == Some(name));
    let original = index("original").ok_or("Wayback CDX header has no original URL column")?;
    let timestamp = index("timestamp");
    let statuscode = index("statuscode");
    let mut out = Vec::new();
    let mut resume = None;
    let mut clipped = false;
    let mut malformed = false;
    for row in &rows[1..] {
        let Some(row) = row.as_array() else {
            malformed = true;
            continue;
        };
        if row.is_empty() {
            continue;
        }
        if row.len() == 1 {
            if let Some(cursor) = row[0]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= MAX_URL_BYTES)
            {
                resume = Some(cursor.to_string());
            }
            continue;
        }
        let Some(url) = row.get(original).and_then(Value::as_str) else {
            malformed = true;
            continue;
        };
        if !in_scope(url) {
            continue;
        }
        if out.len() >= max {
            clipped = true;
            continue;
        }
        if url.len() > MAX_URL_BYTES {
            clipped = true;
            continue;
        }
        let time = timestamp
            .and_then(|i| row.get(i))
            .and_then(Value::as_str)
            .filter(|s| *s != "-" && s.len() <= 128);
        out.push(Discovery {
            url: url.into(),
            method: "GET".into(),
            kind: "history".into(),
            location: "https://web.archive.org/cdx/search/cdx".into(),
            timestamp: time.map(str::to_string),
            status: status(statuscode.and_then(|i| row.get(i))),
        });
    }
    let tail = text[offset..].trim();
    if !tail.is_empty() {
        let cursor = match serde_json::from_str::<Value>(tail) {
            Ok(Value::String(cursor)) => Some(cursor),
            Ok(Value::Array(values)) if values.len() == 1 => values[0].as_str().map(str::to_string),
            Ok(_) => None,
            Err(_) if !tail.contains(['\r', '\n']) => Some(tail.into()),
            Err(_) => None,
        };
        if let Some(cursor) = cursor.filter(|s| !s.is_empty() && s.len() <= MAX_URL_BYTES) {
            resume = Some(cursor);
        } else {
            malformed = true;
        }
    }
    Ok((out, resume, clipped || malformed))
}

pub async fn wayback(
    client: &Client,
    target: &Url,
    include_subdomains: bool,
    max_pages: usize,
    max_results: usize,
    cancel: &AtomicBool,
) -> (Vec<Discovery>, SourceReport) {
    let mut out = Vec::new();
    let mut report = SourceReport::default();
    let host = match provider_host(target) {
        Ok(host) => host,
        Err(e) => {
            report.fail(e);
            return (out, report);
        }
    };
    if max_pages == 0 || max_results == 0 {
        report.truncated = true;
        return (out, report);
    }
    let mut resume: Option<String> = None;
    let mut cursors = HashSet::new();
    for page in 0..max_pages {
        let limit = max_results.saturating_sub(out.len()).min(1000);
        let url = wayback_url(host, include_subdomains, limit, resume.as_deref());
        // Deliberately never attach urlscan's key to Archive.org requests.
        let text = match fetch_text(client.get(url), cancel, &mut report, true).await {
            Ok(text) => text,
            Err(e) => {
                report.fail(e.to_string());
                break;
            }
        };
        let (found, cursor, clipped) = match parse_cdx_filtered(&text, limit, |url| {
            crate::recon::discovery_in_scope(target, include_subdomains, url)
        }) {
            Ok(parsed) => parsed,
            Err(e) => {
                report.fail(e);
                break;
            }
        };
        out.extend(found);
        report.truncated |= clipped;
        if clipped {
            report.warn("Some CDX rows were malformed or exceeded the result limit");
        }
        let Some(cursor) = cursor else {
            break;
        };
        if out.len() >= max_results || page + 1 == max_pages {
            report.truncated = true;
            report.warn("Wayback result or page limit reached");
            break;
        }
        if !cursors.insert(cursor.clone()) {
            report.truncated = true;
            report.warn("Wayback repeated a resume cursor; pagination stopped");
            break;
        }
        resume = Some(cursor);
    }
    (out, report)
}

/// This separately authorized operation causes urlscan to visit the target.
/// Never invoke it as a fallback for an empty or failed historical search.
pub async fn submit_urlscan(
    client: &Client,
    target: &Url,
    include_subdomains: bool,
    visibility: &str,
    max_results: usize,
    cancel: &AtomicBool,
    on_submitted: impl Fn(&str) + Send + Sync,
) -> (Vec<Discovery>, SourceReport) {
    let mut report = SourceReport::default();
    if max_results == 0 {
        report.fail("A positive result limit is required to submit a scan");
        return (Vec::new(), report);
    }
    if !matches!(visibility, "private" | "unlisted" | "public") {
        report.fail("urlscan visibility must be private, unlisted, or public");
        return (Vec::new(), report);
    }
    if !matches!(target.scheme(), "http" | "https")
        || !target.username().is_empty()
        || target.password().is_some()
    {
        report.fail("urlscan submission requires an HTTP(S) target without credentials");
        return (Vec::new(), report);
    }
    let key = match api_key() {
        Ok(Some(key)) => Some(key),
        Ok(None) => {
            report.fail("URLSCAN_API_KEY is required to submit a scan");
            return (Vec::new(), report);
        }
        Err(e) => {
            report.fail(e);
            return (Vec::new(), report);
        }
    };
    let request = authenticated(
        client
            .post("https://urlscan.io/api/v1/scan/")
            .json(&serde_json::json!({
                "url": target.as_str(), "visibility": visibility,
            })),
        &key,
    );
    let body = match fetch_text(request, cancel, &mut report, false).await {
        Ok(body) => body,
        Err(e) => {
            report.fail(format!(
                "Scan submission did not return a usable confirmation: {e}. It was not retried"
            ));
            return (Vec::new(), report);
        }
    };
    let data: Value = match serde_json::from_str(&body) {
        Ok(data) => data,
        Err(_) => {
            report.fail("Scan submission returned malformed JSON; it was not retried");
            return (Vec::new(), report);
        }
    };
    let Some(url) = data
        .get("uuid")
        .and_then(Value::as_str)
        .and_then(result_url)
    else {
        report.fail("Scan submission returned no valid UUID; it was not retried");
        return (Vec::new(), report);
    };
    on_submitted(url.as_str());
    report.warn(format!("An active urlscan scan was submitted with {visibility} visibility: {url}. Stopping this job cannot cancel the remote scan"));
    // Poll within a fixed observation window; each individual request is also
    // bounded. Returning the UUID URL lets the user revisit a delayed result.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if let Err(e) = pause(Duration::from_secs(15).min(remaining), cancel).await {
            report.fail(e.to_string());
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            report.fail(format!("urlscan result is not ready yet: {url}"));
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let fetched = tokio::time::timeout(
            remaining,
            fetch_text(
                authenticated(client.get(url.clone()), &key),
                cancel,
                &mut report,
                true,
            ),
        )
        .await;
        match fetched {
            Ok(Ok(body)) => {
                let value: Value = match serde_json::from_str(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        report.fail("urlscan result contained malformed JSON");
                        break;
                    }
                };
                let (mut found, clipped) =
                    urlscan_discoveries_filtered(&value, url.as_str(), max_results, |found| {
                        crate::recon::discovery_in_scope(target, include_subdomains, found)
                    });
                for item in &mut found {
                    item.kind = "observed".into();
                }
                report.truncated |= clipped;
                return (found, report);
            }
            Ok(Err(FetchError::Http(404))) => continue,
            Ok(Err(e)) => {
                report.fail(format!(
                    "Could not retrieve submitted scan result: {e}; result: {url}"
                ));
                break;
            }
            Err(_) => {
                report.fail(format!("urlscan result is not ready yet: {url}"));
                break;
            }
        }
    }
    (Vec::new(), report)
}

fn entity_decode(value: &str) -> String {
    // A deliberately small HTML/XML entity decoder. Unknown entities remain
    // literal; they never manufacture a tag or cause active content execution.
    static ENTITIES: OnceLock<Regex> = OnceLock::new();
    ENTITIES
        .get_or_init(|| {
            Regex::new(r"&(#x[0-9a-fA-F]+|#X[0-9a-fA-F]+|#[0-9]+|amp|quot|apos|lt|gt);")
                .expect("entity pattern")
        })
        .replace_all(value, |captures: &regex::Captures<'_>| {
            let entity = &captures[1];
            let decoded = match entity {
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "lt" => Some('<'),
                "gt" => Some('>'),
                _ => entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .or_else(|| entity.strip_prefix('#').and_then(|s| s.parse().ok()))
                    .and_then(char::from_u32),
            };
            decoded
                .map(|c| c.to_string())
                .unwrap_or_else(|| captures[0].to_string())
        })
        .into_owned()
}

fn resolve(base: &Url, literal: &str) -> Option<String> {
    let literal = literal.trim();
    if literal.is_empty()
        || literal.starts_with('#')
        || literal.len() > MAX_URL_BYTES
        || literal.chars().any(char::is_control)
    {
        return None;
    }
    // Absolute observations retain spelling, encoding and duplicate query
    // parameters. URL parsing is used for eligibility, not as storage format.
    if let Ok(url) = Url::parse(literal) {
        return matches!(url.scheme(), "http" | "https" | "ws" | "wss")
            .then(|| literal.to_string());
    }
    let url = base.join(literal).ok()?;
    matches!(url.scheme(), "http" | "https" | "ws" | "wss").then(|| url.to_string())
}

#[derive(Debug)]
struct Tag {
    name: String,
    closing: bool,
    attrs: HashMap<String, String>,
    body: Option<(usize, usize)>,
}

fn attributes(source: &str) -> HashMap<String, String> {
    static ATTR: OnceLock<Regex> = OnceLock::new();
    let regex = ATTR.get_or_init(|| {
        Regex::new(r#"(?s)([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?"#)
            .expect("attribute pattern")
    });
    let mut attrs = HashMap::new();
    for capture in regex.captures_iter(source).take(128) {
        let name = capture[1].to_ascii_lowercase();
        let value = capture
            .get(2)
            .or_else(|| capture.get(3))
            .or_else(|| capture.get(4))
            .map_or("", |v| v.as_str());
        // Browser HTML semantics use the first duplicate attribute.
        attrs.entry(name).or_insert_with(|| entity_decode(value));
    }
    attrs
}

/// A bounded literal tokenizer, not a browser DOM parser. It skips comments
/// and raw-text elements so fake tags inside scripts cannot become crawl links.
fn html_tags(body: &str) -> (Vec<Tag>, bool) {
    let bytes = body.as_bytes();
    let lower_body = body.to_ascii_lowercase();
    let mut tags = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() && tags.len() < MAX_STATIC_ITEMS {
        let Some(relative) = body[cursor..].find('<') else {
            break;
        };
        let start = cursor + relative;
        if body[start..].starts_with("<!--") {
            match body[start + 4..].find("-->") {
                Some(end) => cursor = start + 4 + end + 3,
                None => break,
            }
            continue;
        }
        let mut index = start + 1;
        let closing = bytes.get(index) == Some(&b'/');
        if closing {
            index += 1;
        }
        let name_start = index;
        while bytes
            .get(index)
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(*b, b'-' | b':'))
        {
            index += 1;
        }
        if index == name_start || !bytes[name_start].is_ascii_alphabetic() {
            cursor = start + 1;
            continue;
        }
        let name = body[name_start..index].to_ascii_lowercase();
        let attr_start = index;
        let mut quote = None;
        while index < bytes.len() {
            let byte = bytes[index];
            if let Some(q) = quote {
                if byte == q {
                    quote = None;
                }
            } else if matches!(byte, b'\'' | b'"') {
                quote = Some(byte);
            } else if byte == b'>' {
                break;
            }
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        cursor = index + 1;
        let mut tag = Tag {
            name,
            closing,
            attrs: attributes(&body[attr_start..index]),
            body: None,
        };
        if !closing && matches!(tag.name.as_str(), "script" | "style" | "textarea" | "title") {
            let end_prefix = format!("</{}", tag.name);
            // ASCII case conversion preserves byte offsets, including UTF-8.
            let lower = &lower_body[cursor..];
            let mut search_at = 0;
            let mut end = None;
            while let Some(offset) = lower[search_at..].find(&end_prefix) {
                let candidate = search_at + offset;
                let after = candidate + end_prefix.len();
                if lower
                    .as_bytes()
                    .get(after)
                    .is_some_and(|b| b.is_ascii_whitespace() || matches!(*b, b'>' | b'/'))
                {
                    end = Some(candidate);
                    break;
                }
                search_at = after;
            }
            let raw_end = end.map_or(bytes.len(), |offset| cursor + offset);
            tag.body = Some((cursor, raw_end));
            cursor = raw_end;
        }
        tags.push(tag);
    }
    // Do not scan past the token budget to prove that the remaining text is
    // harmless. Retain the bounded prefix and conservatively report partial.
    let truncated = tags.len() == MAX_STATIC_ITEMS && cursor < bytes.len();
    (tags, truncated)
}

fn static_discovery(url: String, method: String, kind: &str, label: &str, base: &Url) -> Discovery {
    Discovery {
        url,
        method,
        kind: kind.into(),
        location: format!("{label}: {base}"),
        timestamp: None,
        status: None,
    }
}

fn js_candidates(
    base: &Url,
    body: &str,
    out: &mut Vec<Discovery>,
    seen: &mut HashSet<(String, String, String)>,
) -> bool {
    // String-literal heuristics only. No interpolation, JS evaluation, guessed
    // variable contents, or inferred response/HTTP-method claims.
    static LITERALS: OnceLock<Regex> = OnceLock::new();
    let regex = LITERALS.get_or_init(|| {
        Regex::new(r#"(?s)"((?:\\.|[^"\\])+)"|'((?:\\.|[^'\\])+)'|`((?:\\.|[^`\\])+)`"#)
            .expect("JS literal pattern")
    });
    for (index, capture) in regex
        .captures_iter(body)
        .take(MAX_STATIC_ITEMS + 1)
        .enumerate()
    {
        if index == MAX_STATIC_ITEMS {
            return true;
        }
        let literal = capture
            .get(1)
            .or_else(|| capture.get(2))
            .or_else(|| capture.get(3))
            .unwrap()
            .as_str();
        if literal.len() > 8192 {
            continue;
        }
        let literal = literal
            .replace("\\/", "/")
            .replace("\\u002f", "/")
            .replace("\\u002F", "/");
        if literal.contains("${")
            || literal.contains('\\')
            || literal.chars().any(char::is_whitespace)
        {
            continue;
        }
        if !(literal.starts_with('/')
            || literal.starts_with("./")
            || literal.starts_with("../")
            || literal.starts_with("http://")
            || literal.starts_with("https://")
            || literal.starts_with("ws://")
            || literal.starts_with("wss://"))
        {
            continue;
        }
        if let Some(url) = resolve(base, &literal) {
            if !push_discovery(
                out,
                seen,
                static_discovery(url, "GET".into(), "candidate", "javascript", base),
                MAX_STATIC_ITEMS,
            ) {
                return true;
            }
        }
    }
    false
}

/// Keep crawler dispatch and extraction in agreement, including extensionless
/// ECMAScript responses. A declared non-script MIME type overrides the suffix.
pub fn is_javascript_document(base: &Url, content_type: &str) -> bool {
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    content_type.contains("javascript")
        || content_type.contains("ecmascript")
        || (content_type.is_empty() && base.path().ends_with(".js"))
}

/// Extracts static evidence without executing scripts or submitting forms.
/// Relative literals in external JavaScript are resolved against the script
/// URL as a heuristic; the location label keeps them distinct from observations.
/// The boolean reports when a byte, token, or discovery budget left a partial result.
pub fn extract_document(base: &Url, content_type: &str, body: &str) -> (Vec<Discovery>, bool) {
    let mut end = body.len().min(MAX_RESPONSE_BYTES);
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = end < body.len();
    let body = &body[..end];
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    if is_javascript_document(base, &content_type) {
        truncated |= js_candidates(base, body, &mut out, &mut seen);
        return (out, truncated);
    }
    if base.path().ends_with("/robots.txt") {
        for (index, line) in body.lines().take(MAX_STATIC_ITEMS + 1).enumerate() {
            if index == MAX_STATIC_ITEMS {
                truncated = true;
                break;
            }
            let line = line.split('#').next().unwrap_or("").trim();
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let label = match key.trim().to_ascii_lowercase().as_str() {
                "sitemap" => "sitemap",
                "allow" | "disallow" => "robots",
                _ => continue,
            };
            let value = value.trim();
            if value.contains(['*', '$']) {
                continue;
            }
            if let Some(url) = resolve(base, value) {
                let kind = if label == "sitemap" {
                    "observed"
                } else {
                    "candidate"
                };
                if !push_discovery(
                    &mut out,
                    &mut seen,
                    static_discovery(url, "GET".into(), kind, label, base),
                    MAX_STATIC_ITEMS,
                ) {
                    truncated = true;
                    break;
                }
            }
        }
        return (out, truncated);
    }
    if content_type.contains("xml") || base.path().ends_with(".xml") {
        static LOC: OnceLock<Regex> = OnceLock::new();
        let regex = LOC.get_or_init(|| {
            Regex::new(r"(?is)<(?:[a-z0-9_-]+:)?loc\b[^>]*>(.*?)</(?:[a-z0-9_-]+:)?loc\s*>")
                .expect("sitemap loc pattern")
        });
        for (index, capture) in regex
            .captures_iter(body)
            .take(MAX_STATIC_ITEMS + 1)
            .enumerate()
        {
            if index == MAX_STATIC_ITEMS {
                truncated = true;
                break;
            }
            let literal = capture[1].trim();
            let literal = literal
                .strip_prefix("<![CDATA[")
                .and_then(|s| s.strip_suffix("]]>"))
                .unwrap_or(literal);
            if let Some(url) = resolve(base, &entity_decode(literal)) {
                if !push_discovery(
                    &mut out,
                    &mut seen,
                    static_discovery(url, "GET".into(), "observed", "sitemap", base),
                    MAX_STATIC_ITEMS,
                ) {
                    truncated = true;
                    break;
                }
            }
        }
        if content_type != "application/xhtml+xml" {
            return (out, truncated);
        }
    }
    if !matches!(
        content_type.as_str(),
        "text/html" | "application/xhtml+xml" | ""
    ) {
        return (out, truncated);
    }
    let (tags, clipped) = html_tags(body);
    truncated |= clipped;
    let document_base = tags
        .iter()
        .filter(|tag| !tag.closing && tag.name == "base")
        .find_map(|tag| tag.attrs.get("href"))
        .and_then(|href| resolve(base, href))
        .and_then(|href| Url::parse(&href).ok())
        .unwrap_or_else(|| base.clone());
    let mut current_form: Option<(String, String, Vec<String>)> = None;
    let flush_form = |form: (String, String, Vec<String>),
                      out: &mut Vec<Discovery>,
                      seen: &mut HashSet<(String, String, String)>| {
        let (mut url, verb, names) = form;
        if verb == "GET" && !names.is_empty() {
            if let Ok(mut parsed) = Url::parse(&url) {
                for name in &names {
                    parsed.query_pairs_mut().append_pair(name, "");
                }
                url = parsed.to_string();
            }
        }
        let mut item = static_discovery(url, verb, "candidate", "form", base);
        if !names.is_empty() {
            item.location
                .push_str(&format!(" (field names: {})", names.join(", ")));
        }
        push_discovery(out, seen, item, MAX_STATIC_ITEMS)
    };
    for tag in tags {
        if out.len() >= MAX_STATIC_ITEMS {
            truncated = true;
            break;
        }
        if tag.closing {
            if tag.name == "form" {
                if let Some(form) = current_form.take() {
                    truncated |= !flush_form(form, &mut out, &mut seen);
                }
            }
            continue;
        }
        if tag.name == "base" {
            continue;
        }
        if tag.name == "form" {
            if let Some(form) = current_form.take() {
                truncated |= !flush_form(form, &mut out, &mut seen);
            }
            let action = match tag
                .attrs
                .get("action")
                .filter(|action| !action.trim().is_empty())
            {
                Some(literal) => match resolve(&document_base, literal) {
                    Some(url) => url,
                    None => continue,
                },
                None => base.to_string(),
            };
            let verb = match tag.attrs.get("method").map(|s| s.to_ascii_lowercase()) {
                Some(value) if value == "post" => "POST",
                Some(value) if value == "dialog" => continue,
                _ => "GET",
            };
            current_form = Some((action, verb.into(), Vec::new()));
        }
        if matches!(
            tag.name.as_str(),
            "input" | "select" | "textarea" | "button"
        ) && !tag.attrs.contains_key("disabled")
        {
            if let (Some((_, _, names)), Some(name)) = (&mut current_form, tag.attrs.get("name")) {
                if !name.is_empty()
                    && name.len() <= 256
                    && names.len() < 128
                    && !names.contains(name)
                {
                    names.push(name.clone());
                }
            }
        }
        for attr in ["href", "src", "poster", "data"] {
            // object[data] contains a resource URL; arbitrary data attributes do not.
            if attr == "data" && tag.name != "object" {
                continue;
            }
            if let Some(literal) = tag.attrs.get(attr) {
                if let Some(url) = resolve(&document_base, literal) {
                    let label = if tag.name == "script" {
                        "script"
                    } else if attr == "href" {
                        "link"
                    } else {
                        "resource"
                    };
                    truncated |= !push_discovery(
                        &mut out,
                        &mut seen,
                        static_discovery(url, "GET".into(), "observed", label, base),
                        MAX_STATIC_ITEMS,
                    );
                }
            }
        }
        if let Some(action) = tag
            .attrs
            .get("formaction")
            .and_then(|s| resolve(&document_base, s))
        {
            let verb = tag
                .attrs
                .get("formmethod")
                .map(String::as_str)
                .or_else(|| current_form.as_ref().map(|(_, m, _)| m.as_str()));
            truncated |= !push_discovery(
                &mut out,
                &mut seen,
                static_discovery(action, method(verb), "candidate", "form", base),
                MAX_STATIC_ITEMS,
            );
        }
        if tag.name == "script" {
            if let Some((start, end)) = tag.body {
                truncated |= js_candidates(&document_base, &body[start..end], &mut out, &mut seen);
            }
        }
    }
    if let Some(form) = current_form.take() {
        truncated |= !flush_form(form, &mut out, &mut seen);
    }
    (out, truncated)
}

/// Candidates from forms, JavaScript, and robots rules remain passive evidence.
pub fn is_followable(discovery: &Discovery) -> bool {
    discovery.kind == "observed"
        && discovery.method == "GET"
        && ["link:", "resource:", "script:", "sitemap:"]
            .iter()
            .any(|prefix| discovery.location.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn urlscan_discoveries(document: &Value, location: &str, max: usize) -> (Vec<Discovery>, bool) {
        urlscan_discoveries_filtered(document, location, max, |_| true)
    }
    fn parse_cdx(text: &str, max: usize) -> Result<(Vec<Discovery>, Option<String>, bool), String> {
        parse_cdx_filtered(text, max, |_| true)
    }
    fn base() -> Url {
        Url::parse("https://example.com/folder/page.html").unwrap()
    }

    #[test]
    fn urlscan_extracts_complete_result_url_fields_and_metadata() {
        let document = json!({
            "task": {"url":"https://example.com/start", "time":"2026-10-01T12:00:00Z"},
            "page": {"url":"https://example.com/final", "status":"200"},
            "lists": {"urls":["https://example.com/static.js", "https://example.com/api?a=1&a=2"]},
            "api":"https://example.com/not-a-result-api",
            "data": {
                "requests": [{"request":{"request":{"url":"https://example.com/api?a=1&a=2", "method":"POST"}},
                    "response":{"response":{"url":"https://example.com/api?a=1&a=2", "status":403}}}],
                "links": [{"href":"https://example.com/link"}],
                "redirects": [{"from":"https://example.com/old", "to":"https://example.com/new"}],
                "websockets": [{"url":"wss://example.com/events?token=fixture"}],
                "cookies": [{"value":"https://example.com/not-a-url-field"}]
            }
        });
        let (found, clipped) = urlscan_discoveries(&document, "fixture", 100);
        assert!(!clipped);
        for url in [
            "https://example.com/start",
            "https://example.com/final",
            "https://example.com/static.js",
            "https://example.com/link",
            "https://example.com/old",
            "https://example.com/new",
            "wss://example.com/events?token=fixture",
        ] {
            assert!(found.iter().any(|d| d.url == url), "missing {url}");
        }
        let post = found.iter().find(|d| d.method == "POST").unwrap();
        assert_eq!(post.url, "https://example.com/api?a=1&a=2");
        assert_eq!(post.status, Some(403));
        assert_eq!(post.timestamp.as_deref(), Some("2026-10-01T12:00:00Z"));
        assert!(found.iter().all(|d| d.kind == "history"));
        assert!(!found.iter().any(|d| d.url.contains("not-a-")));
    }

    #[test]
    fn urlscan_does_not_infer_http_method_from_submission_method() {
        let (found, _) = urlscan_discoveries(
            &json!({"task":{"url":"https://example.com/", "method":"manual"}}),
            "fixture",
            10,
        );
        assert_eq!(found[0].method, "GET");
    }

    #[test]
    fn urlscan_result_urls_ignore_untrusted_api_urls() {
        assert_eq!(
            result_url("123e4567-e89b-12d3-a456-426614174000")
                .unwrap()
                .as_str(),
            "https://urlscan.io/api/v1/result/123e4567-e89b-12d3-a456-426614174000/"
        );
        for invalid in [
            "../../example.com",
            "https://example.com/api/",
            "123e4567-e89b-12d3-a456-426614174000/other",
            "",
        ] {
            assert!(result_url(invalid).is_none());
        }
    }

    #[test]
    fn urlscan_query_and_cursor_are_data_not_url_paths() {
        let url = urlscan_search_url("example.com", true, 100, Some("123,uuid"));
        let args: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            args["q"],
            "(domain:\"example.com\" OR task.domain:\"example.com\")"
        );
        assert_eq!(args["search_after"], "123,uuid");
        assert_eq!(url.host_str(), Some("urlscan.io"));
        let exact = urlscan_search_url("example.com", false, 100, None);
        assert_eq!(
            exact.query_pairs().find(|(key, _)| key == "q").unwrap().1,
            args["q"]
        );
        assert_eq!(
            sort_cursor(&json!([123, "uuid"])).as_deref(),
            Some("123,uuid")
        );
        assert!(sort_cursor(&json!(["bad,cursor"])).is_none());
        assert!(sort_cursor(&json!([{}])).is_none());
    }

    #[test]
    fn urlscan_result_budget_is_visible() {
        let (found, clipped) = urlscan_discoveries(
            &json!({"lists":{"urls":["https://example.com/1", "https://example.com/2"]}}),
            "fixture",
            1,
        );
        assert_eq!(found.len(), 1);
        assert!(clipped);
    }

    #[test]
    fn duplicate_summary_is_enriched_by_detailed_status() {
        let mut found = Vec::new();
        let mut seen = HashSet::new();
        let mut item = static_discovery(
            "https://example.com/".into(),
            "GET".into(),
            "history",
            "scan",
            &base(),
        );
        push_discovery(&mut found, &mut seen, item.clone(), 1);
        item.status = Some(404);
        assert!(push_discovery(&mut found, &mut seen, item, 1));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].status, Some(404));
    }

    #[test]
    fn cdx_reads_reordered_columns_and_encoded_resume_key() {
        let fixture = r#"[["statuscode","original","timestamp","mimetype","urlkey","digest"],
          ["404","https://example.com/a%2Fb?q=1&q=2","20200101000000","application/json","com,example)/a","ABC"],
          ["500","http://example.com:80/private","20210101000000","text/plain","com,example)/private","DEF"],
          [], ["com%2Cexample%29%2Fprivate+20210101000000%21"]]"#;
        let (found, resume, clipped) = parse_cdx(fixture, 100).unwrap();
        assert!(!clipped);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].url, "https://example.com/a%2Fb?q=1&q=2");
        assert_eq!(found[0].status, Some(404));
        assert_eq!(found[1].status, Some(500));
        assert_eq!(found[1].timestamp.as_deref(), Some("20210101000000"));
        let request = wayback_url("example.com", true, 100, resume.as_deref());
        let args: HashMap<_, _> = request.query_pairs().into_owned().collect();
        assert_eq!(args["resumeKey"], "com,example)/private 20210101000000!");
        assert_eq!(args["matchType"], "domain");
        assert!(!args.contains_key("filter"));
        assert!(!args.contains_key("collapse"));
    }

    #[test]
    fn cdx_accepts_trailing_cursor_and_reports_partial_rows() {
        let fixture = "[[\"original\",\"timestamp\",\"statuscode\"],[\"https://example.com/\",\"20200101000000\",\"-\"],{},[]]\n\ncom%2Cexample%29%2F+20200101000000%21";
        let (found, resume, clipped) = parse_cdx(fixture, 10).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].status, None);
        assert!(resume.is_some());
        assert!(clipped);
        assert!(parse_cdx("not json", 10).is_err());
        assert!(parse_cdx("[[\"timestamp\"],[\"20200101000000\"]]", 10).is_err());
    }

    #[test]
    fn cdx_retains_capture_history_and_obeys_cap() {
        let fixture = r#"[["original","timestamp"],["https://example.com/","20200101000000"],["https://example.com/","20210101000000"]]"#;
        assert_eq!(parse_cdx(fixture, 10).unwrap().0.len(), 2);
        let (found, _, clipped) = parse_cdx(fixture, 1).unwrap();
        assert_eq!(found.len(), 1);
        assert!(clipped);
        assert!(parse_cdx("[]", 10).unwrap().0.is_empty());
    }

    #[test]
    fn html_resolves_base_attributes_and_entities_without_running_content() {
        let (found, _) = extract_document(
            &base(),
            "text/html; charset=utf-8",
            r##"
          <base href="/assets/"><a href='view?x=1&amp;x=2'>view</a>
          <img src=image.png><script src="/bundle.js"></script>
          <!-- <a href="/comment-decoy"> -->
          <script>const template = '<a href="/fake-link">'; fetch('/api/data');</script>
          <style>.foo{content:'<a href="/style-decoy">'}</style>
          <a href="javascript:alert(1)">invalid</a><a href="#only-fragment">fragment</a>
        "##,
        );
        let link = found
            .iter()
            .find(|d| d.url == "https://example.com/assets/view?x=1&x=2")
            .unwrap();
        assert!(is_followable(link));
        assert!(found
            .iter()
            .any(|d| d.url == "https://example.com/assets/image.png"));
        assert!(found
            .iter()
            .any(|d| d.location.starts_with("script:") && d.url.ends_with("bundle.js")));
        let candidate = found
            .iter()
            .find(|d| d.url == "https://example.com/api/data")
            .unwrap();
        assert_eq!(candidate.kind, "candidate");
        assert!(!is_followable(candidate));
        assert!(!found
            .iter()
            .any(|d| d.url.contains("comment-decoy") || d.url.contains("style-decoy")));
        assert!(!found
            .iter()
            .any(|d| d.url.contains("fake-link") && is_followable(d)));
    }

    #[test]
    fn html_forms_preserve_method_and_names_never_values_or_execution() {
        let (found, _) = extract_document(
            &base(),
            "text/html",
            r#"
          <form action="/search?lang=en" method="GET"><input name="q" value="secret"><input name="q"><input name="ignored" disabled></form>
          <form action="/login" method="post"><input name="username" value="private"><input name="password" value="secret"></form>
        "#,
        );
        let get = found.iter().find(|d| d.url.contains("/search")).unwrap();
        assert_eq!(get.url, "https://example.com/search?lang=en&q=");
        assert_eq!(get.kind, "candidate");
        assert!(!is_followable(get));
        let post = found.iter().find(|d| d.method == "POST").unwrap();
        assert_eq!(post.url, "https://example.com/login");
        assert!(post.location.contains("username, password"));
        assert!(!found.iter().any(|d| d.url.contains("secret")
            || d.location.contains("secret")
            || d.location.contains("private")));
    }

    #[test]
    fn quoted_greater_than_and_raw_text_do_not_break_html_tokenization() {
        let (found, _) = extract_document(&base(), "text/html", "<a title='x > y' href='/good'>link</a><textarea name='text'><a href='/bad'></textarea><a href='/after'>ok</a>");
        assert!(found.iter().any(|d| d.url.ends_with("/good")));
        assert!(found.iter().any(|d| d.url.ends_with("/after")));
        assert!(!found.iter().any(|d| d.url.ends_with("/bad")));
    }

    #[test]
    fn javascript_literals_are_candidates_and_interpolations_are_skipped() {
        let (found, _) = extract_document(
            &Url::parse("https://example.com/assets/app.js").unwrap(),
            "application/javascript",
            r#"
          fetch("/api/v1?x=1&x=2"); let relative = '../status';
          const socket = "wss:\/\/example.com\/events";
          fetch(`/api/${id}`); const text = "ordinary text"; const query = '/bad path';
        "#,
        );
        assert_eq!(found.len(), 3);
        assert!(found
            .iter()
            .all(|d| d.kind == "candidate" && !is_followable(d)));
        assert!(found.iter().any(|d| d.url == "https://example.com/status"));
        assert!(found.iter().any(|d| d.url == "wss://example.com/events"));
    }

    #[test]
    fn javascript_dispatch_uses_the_same_media_type_and_suffix_rules_as_extraction() {
        for media_type in [
            "application/javascript",
            "text/javascript",
            "application/ecmascript",
            "text/ecmascript",
            "APPLICATION/ECMASCRIPT; charset=UTF-8",
            " application/x-javascript ; charset=utf-8",
        ] {
            let url = Url::parse("https://example.com/extensionless").unwrap();
            assert!(is_javascript_document(&url, media_type), "{media_type}");
            let (found, clipped) = extract_document(&url, media_type, "fetch('/candidate')");
            assert_eq!(found.len(), 1, "{media_type}");
            assert_eq!(found[0].kind, "candidate");
            assert!(!clipped);
        }
        for (path, media_type, expected) in [
            ("/bundle.js?version=1", "", true),
            ("/bundle.JS", "", false),
            ("/bundle.js", "text/plain; charset=javascript", false),
            ("/bundle.js", "application/octet-stream", false),
            ("/extensionless", "", false),
        ] {
            let url = Url::parse(&format!("https://example.com{path}")).unwrap();
            assert_eq!(
                is_javascript_document(&url, media_type),
                expected,
                "{path} {media_type}"
            );
            assert_eq!(
                extract_document(&url, media_type, "fetch('/candidate')")
                    .0
                    .len(),
                usize::from(expected)
            );
        }
    }

    #[test]
    fn html_token_limit_reports_unscanned_suffix_but_preserves_the_boundary_prefix() {
        let prefix = "<span></span>".repeat(MAX_STATIC_ITEMS / 2);
        let (found, clipped) = extract_document(&base(), "text/html", &prefix);
        assert!(found.is_empty());
        assert!(!clipped);
        let (_, clipped) = extract_document(
            &base(),
            "text/html",
            &format!("{prefix}<a href='/late'>late</a>"),
        );
        assert!(clipped);
        // At the budget boundary, suffix bytes are deliberately not scanned,
        // including whitespace or a comment which may conceal more markup.
        assert!(extract_document(&base(), "text/html", &format!("{prefix}\n")).1);
        let before = format!(
            "{}<a href='/retained'>link</a>",
            "<span></span>".repeat(MAX_STATIC_ITEMS / 2 - 1)
        );
        let (found, clipped) = extract_document(&base(), "text/html", &before);
        assert!(!clipped);
        assert_eq!(found.len(), 1);
        assert!(found[0].url.ends_with("/retained"));
    }

    #[test]
    fn static_item_limits_report_clipping_even_when_the_prefix_has_no_urls() {
        for (path, media_type, empty_item, final_item) in [
            (
                "/bundle.js",
                "application/javascript",
                "'not-a-url';",
                "'/late'",
            ),
            ("/robots.txt", "text/plain", "# ignored\n", "Allow: /late\n"),
            (
                "/sitemap.xml",
                "application/xml",
                "<loc>#fragment</loc>",
                "<loc>/late</loc>",
            ),
        ] {
            let url = Url::parse(&format!("https://example.com{path}")).unwrap();
            let body = empty_item.repeat(MAX_STATIC_ITEMS);
            let (found, clipped) = extract_document(&url, media_type, &body);
            assert!(found.is_empty(), "{path}");
            assert!(!clipped, "{path}");
            let (found, clipped) =
                extract_document(&url, media_type, &format!("{body}{final_item}"));
            assert!(found.is_empty(), "{path}");
            assert!(clipped, "{path}");
        }
        let inline = format!(
            "<script>{}'/late'</script>",
            "'not-a-url';".repeat(MAX_STATIC_ITEMS)
        );
        assert!(extract_document(&base(), "text/html", &inline).1);
    }

    #[test]
    fn discovery_output_limit_reports_partial_and_never_expands_the_result_cap() {
        let body = (0..MAX_STATIC_ITEMS / 3 + 1)
            .map(|index| {
                format!("<object data='/data/{index}' src='/src/{index}' href='/link/{index}'>")
            })
            .collect::<String>();
        let (found, clipped) = extract_document(&base(), "text/html", &body);
        assert!(clipped);
        assert_eq!(found.len(), MAX_STATIC_ITEMS);
    }

    #[test]
    fn document_byte_limit_is_reported_and_preserves_utf8_boundaries() {
        let body = " ".repeat(MAX_RESPONSE_BYTES);
        assert!(!extract_document(&base(), "text/html", &body).1);
        let body = format!(
            "{}é<a href='/late'>late</a>",
            " ".repeat(MAX_RESPONSE_BYTES - 1)
        );
        let (found, clipped) = extract_document(&base(), "text/html", &body);
        assert!(found.is_empty());
        assert!(clipped);
    }

    #[test]
    fn robots_and_sitemaps_are_static_evidence() {
        let (robots, _) = extract_document(&Url::parse("https://example.com/robots.txt").unwrap(), "text/plain", "User-agent: *\nDisallow: /private\nAllow: /public\nDisallow: /*?token=\nSitemap: https://example.com/sitemap.xml\n");
        assert_eq!(robots.len(), 3);
        assert!(!is_followable(
            robots.iter().find(|d| d.url.ends_with("/private")).unwrap()
        ));
        assert!(is_followable(
            robots.iter().find(|d| d.url.ends_with(".xml")).unwrap()
        ));
        let (sitemap, _) = extract_document(&base(), "application/xml", "<urlset><url><loc>https://example.com/p?a=1&amp;b=2</loc></url><url><loc><![CDATA[https://example.com/cdata]]></loc></url></urlset>");
        assert_eq!(sitemap.len(), 2);
        assert!(sitemap.iter().all(is_followable));
        assert_eq!(sitemap[0].url, "https://example.com/p?a=1&b=2");
    }

    #[test]
    fn unsupported_media_and_long_multibyte_body_are_bounded() {
        assert!(
            extract_document(&base(), "image/svg+xml", "<a href='/not-a-page'>")
                .0
                .is_empty()
        );
        let body = format!(
            "{}<a href='/past-limit'>",
            "😀".repeat(MAX_RESPONSE_BYTES / 4 + 1)
        );
        assert!(extract_document(&base(), "text/html", &body).0.is_empty());
    }

    #[test]
    fn warnings_and_error_preserve_partial_report() {
        let mut report = SourceReport::default();
        for i in 0..100 {
            report.warn(format!("warning {i}"));
        }
        assert_eq!(report.warnings.len(), MAX_WARNINGS);
        report.fail("fixture failure");
        assert!(report.truncated);
        assert_eq!(report.error.as_deref(), Some("fixture failure"));
    }

    #[tokio::test]
    async fn cancelled_reads_do_not_send_any_requests() {
        let cancel = AtomicBool::new(true);
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let mut report = SourceReport::default();
        let result = fetch_text(
            client.get("https://example.com/never-contacted"),
            &cancel,
            &mut report,
            true,
        )
        .await;
        assert!(matches!(result, Err(FetchError::Cancelled)));
        assert_eq!(report.requests, 0);
        let (_, report) = urlscan(&client, &base(), false, 2, 100, &cancel).await;
        assert_eq!(report.requests, 0);
        let (_, report) = wayback(&client, &base(), false, 2, 100, &cancel).await;
        assert_eq!(report.requests, 0);
    }

    #[tokio::test]
    async fn invalid_submission_options_are_rejected_before_network() {
        let client = Client::new();
        let cancel = AtomicBool::new(false);
        let (_, report) =
            submit_urlscan(&client, &base(), false, "invalid", 100, &cancel, |_| {}).await;
        assert_eq!(report.requests, 0);
        assert!(report.error.is_some());
        let target = Url::parse("https://fixture:secret@example.com/").unwrap();
        let (_, report) =
            submit_urlscan(&client, &target, false, "private", 100, &cancel, |_| {}).await;
        assert_eq!(report.requests, 0);
    }
    #[test]
    fn off_scope_provider_entries_do_not_consume_result_limit() {
        let document = json!({"lists":{"urls":[
            "https://static.example.com/first", "https://example.com/wanted"
        ]}});
        let (found, clipped) = urlscan_discoveries_filtered(&document, "fixture", 1, |url| {
            url.starts_with("https://example.com/")
        });
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].url, "https://example.com/wanted");
        assert!(!clipped);
        let fixture = r#"[["original","statuscode"],["https://static.example.com/first","200"],["https://example.com/wanted","200"]]"#;
        let (found, _, clipped) =
            parse_cdx_filtered(fixture, 1, |url| url.starts_with("https://example.com/")).unwrap();
        assert_eq!(found[0].url, "https://example.com/wanted");
        assert!(!clipped);
    }

    #[tokio::test]
    async fn response_body_limits_apply_before_unbounded_buffering() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        for chunked in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let fixture = tokio::spawn(async move {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                let _ = connection.read(&mut request).await;
                if chunked {
                    let _ = connection.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await;
                    let header = format!("{:x}\r\n", MAX_RESPONSE_BYTES + 1);
                    let _ = connection.write_all(header.as_bytes()).await;
                    let _ = connection
                        .write_all(&vec![b'x'; MAX_RESPONSE_BYTES + 1])
                        .await;
                    let _ = connection.write_all(b"\r\n0\r\n\r\n").await;
                } else {
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        MAX_RESPONSE_BYTES + 1
                    );
                    let _ = connection.write_all(headers.as_bytes()).await;
                }
            });
            let client = Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .unwrap();
            let mut report = SourceReport::default();
            let cancel = AtomicBool::new(false);
            let result = fetch_text(
                client.get(format!("http://{address}/fixture")),
                &cancel,
                &mut report,
                true,
            )
            .await;
            assert!(matches!(result, Err(FetchError::TooLarge)));
            assert_eq!(report.requests, 1);
            fixture.await.unwrap();
        }
    }

    #[tokio::test]
    async fn provider_redirects_are_not_followed_and_post_is_not_retried() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        for (status, retry_reads) in [(302, true), (429, false)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let fixture = tokio::spawn(async move {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                let _ = connection.read(&mut request).await;
                let response = format!("HTTP/1.1 {status} Fixture\r\nLocation: http://{address}/must-not-follow\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                connection.write_all(response.as_bytes()).await.unwrap();
            });
            let client = Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .unwrap();
            let mut report = SourceReport::default();
            let cancel = AtomicBool::new(false);
            let request = if retry_reads {
                client.get(format!("http://{address}/fixture"))
            } else {
                client
                    .post(format!("http://{address}/fixture"))
                    .json(&json!({"fixture":true}))
            };
            let result = fetch_text(request, &cancel, &mut report, retry_reads).await;
            assert!(matches!(result, Err(FetchError::Http(code)) if code == status));
            assert_eq!(report.requests, 1);
            fixture.await.unwrap();
        }
    }

    #[tokio::test]
    async fn rate_limit_wait_can_be_cancelled_without_another_request() {
        use std::sync::Arc;
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        let fixture = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = connection.read(&mut request).await;
            connection.write_all(b"HTTP/1.1 429 Fixture\r\nRetry-After: 10\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            signal.store(true, Ordering::Relaxed);
        });
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();
        let mut report = SourceReport::default();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            fetch_text(
                client.get(format!("http://{address}/fixture")),
                &cancel,
                &mut report,
                true,
            ),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(FetchError::Cancelled)));
        assert_eq!(report.requests, 1);
        assert!(!report.warnings.is_empty());
        fixture.await.unwrap();
    }
}
