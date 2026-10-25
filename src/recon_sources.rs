//! Passive provider readers and static document discovery.
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
        if !self.warnings.contains(&warning) {
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
    Transport,
    InvalidText,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Cancelled"),
            Self::Http(status) => write!(f, "Provider returned HTTP {status}"),
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
    fetch_text_with_progress(request, cancel, report, retry_rate_limit, |_| {}).await
}

async fn fetch_text_with_progress(
    request: RequestBuilder,
    cancel: &AtomicBool,
    report: &mut SourceReport,
    retry_rate_limit: bool,
    on_progress: impl Fn(&SourceReport),
) -> Result<String, FetchError> {
    for attempt in 0..=2u32 {
        if cancel.load(Ordering::Relaxed) {
            return Err(FetchError::Cancelled);
        }
        let current = request.try_clone().ok_or(FetchError::Transport)?;
        report.requests += 1;
        on_progress(report);
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
            on_progress(report);
            drop(response);
            pause(Duration::from_secs(retry_after), cancel).await?;
            continue;
        }
        if !status.is_success() {
            return Err(FetchError::Http(status.as_u16()));
        }
        let mut bytes = Vec::new();
        // Keep cancellation responsive while reading the complete response,
        // including bodies streamed without a Content-Length header.
        loop {
            let chunk = tokio::select! {
                _ = cancelled(cancel) => return Err(FetchError::Cancelled),
                result = response.chunk() => result.map_err(|_| FetchError::Transport)?,
            };
            let Some(chunk) = chunk else {
                break;
            };
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
    if values.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for value in values {
        let part = match value {
            Value::String(value) if !value.is_empty() && !value.contains([',', '\r', '\n']) => {
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
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-') {
        value.to_ascii_uppercase()
    } else {
        "GET".into()
    }
}

fn html_form_method(value: Option<&str>) -> &'static str {
    // HTML submission methods are enumerated, unlike observed HTTP methods.
    match value {
        Some(value) if value.eq_ignore_ascii_case("post") => "POST",
        Some(value) if value.eq_ignore_ascii_case("dialog") => "DIALOG",
        _ => "GET",
    }
}

fn is_cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|flag| flag.load(Ordering::Relaxed))
}

/// A zero budget means collect until the source is exhausted or cancelled.
fn limit_reached(limit: usize, count: usize) -> bool {
    limit != 0 && count >= limit
}

fn batch_size(limit: usize, count: usize, provider_batch: usize) -> usize {
    if limit == 0 {
        provider_batch
    } else {
        limit.saturating_sub(count).min(provider_batch)
    }
}

fn urlscan_has_more(data: &Value, page_results: usize, scanned: usize, size: usize) -> bool {
    if page_results == 0 {
        return false;
    }
    // An explicit provider exhaustion signal takes precedence over page size.
    data.get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            data.get("total")
                .and_then(Value::as_u64)
                .map_or(page_results >= size, |total| total > scanned as u64)
        })
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
    if limit_reached(max, out.len()) {
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
    cancel: Option<&AtomicBool>,
) -> (Vec<Discovery>, bool) {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let timestamp = document
        .pointer("/task/time")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut complete = true;
    let mut add = |url: &str, verb: Option<&str>, code: Option<u16>| {
        if is_cancelled(cancel) {
            complete = false;
            return;
        }
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
    // status codes survive when an explicit result budget fills up.
    if let Some(requests) = document.pointer("/data/requests").and_then(Value::as_array) {
        for request in requests {
            if is_cancelled(cancel) {
                drop(add);
                return (out, true);
            }
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
            if is_cancelled(cancel) {
                drop(add);
                return (out, true);
            }
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
                if is_cancelled(cancel) {
                    drop(add);
                    return (out, true);
                }
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
    on_progress: impl Fn(&[Discovery], &SourceReport) + Send + Sync,
) -> (Vec<Discovery>, SourceReport) {
    let key = match api_key() {
        Ok(key) => key,
        Err(e) => {
            let mut report = SourceReport::default();
            report.fail(e);
            return (Vec::new(), report);
        }
    };
    read_urlscan(
        client,
        target,
        include_subdomains,
        max_pages,
        max_results,
        cancel,
        on_progress,
        &key,
        urlscan_search_url,
        result_url,
    )
    .await
}

async fn read_urlscan(
    client: &Client,
    target: &Url,
    include_subdomains: bool,
    max_pages: usize,
    max_results: usize,
    cancel: &AtomicBool,
    on_progress: impl Fn(&[Discovery], &SourceReport) + Send + Sync,
    key: &Option<HeaderValue>,
    search_url: impl Fn(&str, bool, usize, Option<&str>) -> Url,
    scan_url: impl Fn(&str) -> Option<Url>,
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
    let size = batch_size(max_results, 0, 100);
    let mut after: Option<String> = None;
    let mut cursors = HashSet::new();
    let mut scan_ids = HashSet::new();
    let mut seen = HashSet::new();
    let mut scanned = 0usize;
    let mut page_index = 0usize;
    loop {
        page_index += 1;
        let url = search_url(host, include_subdomains, size, after.as_deref());
        let text = match fetch_text_with_progress(
            authenticated(client.get(url), key),
            cancel,
            &mut report,
            true,
            |report| on_progress(&[], report),
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
        let more = urlscan_has_more(&data, results.len(), scanned, size);
        if more && limit_reached(max_pages, page_index) {
            report.truncated = true;
            report.warn("urlscan search page limit reached");
        }
        let mut checkpoint = Vec::new();
        let mut detail_urls = Vec::new();
        for result in results {
            if cancel.load(Ordering::Relaxed) {
                report.fail("Cancelled");
                break;
            }
            let uuid = text_at(result, &["/task/uuid", "/_id"]);
            let full_url = uuid.and_then(&scan_url);
            let location = full_url
                .as_ref()
                .map(Url::as_str)
                .unwrap_or("https://urlscan.io/api/v1/search/");
            let (summary, clipped) = urlscan_discoveries_filtered(
                result,
                location,
                max_results,
                |url| crate::recon::discovery_in_scope(target, include_subdomains, url),
                Some(cancel),
            );
            report.truncated |= clipped;
            if cancel.load(Ordering::Relaxed) {
                report.fail("Cancelled");
                break;
            }
            for item in summary {
                if cancel.load(Ordering::Relaxed) {
                    report.fail("Cancelled");
                    break;
                }
                if !push_discovery(&mut out, &mut seen, item.clone(), max_results) {
                    report.truncated = true;
                } else {
                    checkpoint.push(item);
                }
            }
            let Some(full_url) = full_url else {
                report.warn(
                    "A urlscan result had no valid scan UUID; its detail document was skipped",
                );
                report.truncated = true;
                continue;
            };
            if scan_ids.insert(full_url.to_string()) {
                detail_urls.push(full_url);
            }
        }
        if limit_reached(max_results, out.len()) {
            report.truncated = true;
        }
        // The entire search page has arrived. Retain its summaries before any
        // detail request can stall; explicit budgets give this page priority.
        on_progress(&checkpoint, &report);
        if report.error.is_some() || limit_reached(max_results, out.len()) {
            break;
        }
        for full_url in detail_urls {
            let text = match fetch_text_with_progress(
                authenticated(client.get(full_url.clone()), key),
                cancel,
                &mut report,
                true,
                |report| on_progress(&[], report),
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
            let (found, clipped) = urlscan_discoveries_filtered(
                &document,
                full_url.as_str(),
                max_results,
                |url| crate::recon::discovery_in_scope(target, include_subdomains, url),
                Some(cancel),
            );
            report.truncated |= clipped;
            if cancel.load(Ordering::Relaxed) {
                report.fail("Cancelled");
                break;
            }
            let mut checkpoint = Vec::new();
            for item in found {
                if cancel.load(Ordering::Relaxed) {
                    report.fail("Cancelled");
                    break;
                }
                if !push_discovery(&mut out, &mut seen, item.clone(), max_results) {
                    report.truncated = true;
                } else {
                    checkpoint.push(item);
                }
            }
            if limit_reached(max_results, out.len()) {
                report.truncated = true;
            }
            on_progress(&checkpoint, &report);
            if limit_reached(max_results, out.len()) {
                break;
            }
        }
        if report.error.is_some() || limit_reached(max_results, out.len()) || !more {
            break;
        }
        if limit_reached(max_pages, page_index) {
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
    cancel: Option<&AtomicBool>,
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
        if is_cancelled(cancel) {
            return Ok((out, resume, true));
        }
        let Some(row) = row.as_array() else {
            malformed = true;
            continue;
        };
        if row.is_empty() {
            continue;
        }
        if row.len() == 1 {
            if let Some(cursor) = row[0].as_str().filter(|s| !s.is_empty()) {
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
        if limit_reached(max, out.len()) {
            clipped = true;
            continue;
        }
        let time = timestamp
            .and_then(|i| row.get(i))
            .and_then(Value::as_str)
            .filter(|s| *s != "-");
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
        if let Some(cursor) = cursor.filter(|s| !s.is_empty()) {
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
    on_progress: impl Fn(&[Discovery], &SourceReport) + Send + Sync,
) -> (Vec<Discovery>, SourceReport) {
    read_wayback(
        client,
        target,
        include_subdomains,
        max_pages,
        max_results,
        cancel,
        on_progress,
        wayback_url,
    )
    .await
}

async fn read_wayback(
    client: &Client,
    target: &Url,
    include_subdomains: bool,
    max_pages: usize,
    max_results: usize,
    cancel: &AtomicBool,
    on_progress: impl Fn(&[Discovery], &SourceReport) + Send + Sync,
    page_url: impl Fn(&str, bool, usize, Option<&str>) -> Url,
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
    let mut resume: Option<String> = None;
    let mut cursors = HashSet::new();
    let mut page = 0usize;
    loop {
        page += 1;
        let limit = batch_size(max_results, out.len(), 1000);
        let url = page_url(host, include_subdomains, limit, resume.as_deref());
        // Deliberately never attach urlscan's key to Archive.org requests.
        let text =
            match fetch_text_with_progress(client.get(url), cancel, &mut report, true, |report| {
                on_progress(&[], report)
            })
            .await
            {
                Ok(text) => text,
                Err(e) => {
                    report.fail(e.to_string());
                    break;
                }
            };
        let remaining = max_results.saturating_sub(out.len());
        let (found, cursor, clipped) = match parse_cdx_filtered(
            &text,
            remaining,
            |url| crate::recon::discovery_in_scope(target, include_subdomains, url),
            Some(cancel),
        ) {
            Ok(parsed) => parsed,
            Err(e) => {
                report.fail(e);
                break;
            }
        };
        let previous = out.len();
        out.extend(found);
        report.truncated |= clipped;
        if clipped {
            report.warn("Some CDX rows were malformed or exceeded the result limit");
        }
        if cursor.is_some()
            && (limit_reached(max_results, out.len()) || limit_reached(max_pages, page))
        {
            report.truncated = true;
            report.warn("Wayback result or page limit reached");
        }
        on_progress(&out[previous..], &report);
        if cancel.load(Ordering::Relaxed) {
            report.fail("Cancelled");
            break;
        }
        let Some(cursor) = cursor else {
            break;
        };
        if limit_reached(max_results, out.len()) || limit_reached(max_pages, page) {
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
                let (mut found, clipped) = urlscan_discoveries_filtered(
                    &value,
                    url.as_str(),
                    max_results,
                    |found| crate::recon::discovery_in_scope(target, include_subdomains, found),
                    Some(cancel),
                );
                let mut converted = 0;
                for item in &mut found {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    item.kind = "observed".into();
                    converted += 1;
                }
                found.truncate(converted);
                if cancel.load(Ordering::Relaxed) {
                    report.fail("Cancelled");
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
    if literal.is_empty() || literal.starts_with('#') || literal.chars().any(char::is_control) {
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

fn attributes(source: &str, cancel: Option<&AtomicBool>) -> HashMap<String, String> {
    static ATTR: OnceLock<Regex> = OnceLock::new();
    let regex = ATTR.get_or_init(|| {
        Regex::new(r#"(?s)([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?"#)
            .expect("attribute pattern")
    });
    let mut attrs = HashMap::new();
    for capture in regex.captures_iter(source) {
        if is_cancelled(cancel) {
            break;
        }
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

/// A literal tokenizer, not a browser DOM parser. It skips comments
/// and raw-text elements so fake tags inside scripts cannot become crawl links.
fn html_tags(body: &str, cancel: Option<&AtomicBool>) -> Vec<Tag> {
    let bytes = body.as_bytes();
    let lower_body = body.to_ascii_lowercase();
    let mut tags = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if is_cancelled(cancel) {
            break;
        }
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
            if is_cancelled(cancel) {
                return tags;
            }
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
            attrs: attributes(&body[attr_start..index], cancel),
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
    tags
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
    cancel: Option<&AtomicBool>,
) -> bool {
    // String-literal heuristics only. No interpolation, JS evaluation, guessed
    // variable contents, or inferred response/HTTP-method claims.
    static LITERALS: OnceLock<Regex> = OnceLock::new();
    let regex = LITERALS.get_or_init(|| {
        Regex::new(r#"(?s)"((?:\\.|[^"\\])+)"|'((?:\\.|[^'\\])+)'|`((?:\\.|[^`\\])+)`"#)
            .expect("JS literal pattern")
    });
    for capture in regex.captures_iter(body) {
        if is_cancelled(cancel) {
            return true;
        }
        let literal = capture
            .get(1)
            .or_else(|| capture.get(2))
            .or_else(|| capture.get(3))
            .unwrap()
            .as_str();
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
                0,
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
/// Static extraction has no implicit byte, token, URL, or discovery budget;
/// the boolean reports incomplete extraction (for example, cancellation).
pub fn extract_document(base: &Url, content_type: &str, body: &str) -> (Vec<Discovery>, bool) {
    extract_document_inner(base, content_type, body, None)
}

/// The cancellation-aware crawler path preserves evidence collected before stop.
pub fn extract_document_cancellable(
    base: &Url,
    content_type: &str,
    body: &str,
    cancel: &AtomicBool,
) -> (Vec<Discovery>, bool) {
    extract_document_inner(base, content_type, body, Some(cancel))
}

fn extract_document_inner(
    base: &Url,
    content_type: &str,
    body: &str,
    cancel: Option<&AtomicBool>,
) -> (Vec<Discovery>, bool) {
    if is_cancelled(cancel) {
        return (Vec::new(), true);
    }
    let mut truncated = false;
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    if is_javascript_document(base, &content_type) {
        truncated |= js_candidates(base, body, &mut out, &mut seen, cancel);
        return (out, truncated);
    }
    if base.path().ends_with("/robots.txt") {
        for line in body.lines() {
            if is_cancelled(cancel) {
                return (out, true);
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
                    0,
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
        for capture in regex.captures_iter(body) {
            if is_cancelled(cancel) {
                return (out, true);
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
                    0,
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
    let tags = html_tags(body, cancel);
    let document_base = tags
        .iter()
        .filter(|tag| !tag.closing && tag.name == "base")
        .find_map(|tag| tag.attrs.get("href"))
        .and_then(|href| resolve(base, href))
        .and_then(|href| Url::parse(&href).ok())
        .unwrap_or_else(|| base.clone());
    let mut current_form: Option<(Option<String>, String, Vec<String>)> = None;
    let flush_form = |form: (Option<String>, String, Vec<String>),
                      out: &mut Vec<Discovery>,
                      seen: &mut HashSet<(String, String, String)>| {
        let (url, verb, names) = form;
        if verb == "DIALOG" {
            return true;
        }
        let Some(mut url) = url else {
            return true;
        };
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
        push_discovery(out, seen, item, 0)
    };
    for tag in tags {
        if is_cancelled(cancel) {
            return (out, true);
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
                Some(literal) => resolve(&document_base, literal),
                None => Some(base.to_string()),
            };
            // A submit button can replace an unsupported parent action while
            // still inheriting the form's submission method.
            let verb = html_form_method(tag.attrs.get("method").map(String::as_str));
            current_form = Some((action, verb.into(), Vec::new()));
        }
        if matches!(
            tag.name.as_str(),
            "input" | "select" | "textarea" | "button"
        ) && !tag.attrs.contains_key("disabled")
        {
            if let (Some((_, _, names)), Some(name)) = (&mut current_form, tag.attrs.get("name")) {
                if !name.is_empty() && !names.contains(name) {
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
                        0,
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
            let verb = html_form_method(verb);
            if verb != "DIALOG" {
                truncated |= !push_discovery(
                    &mut out,
                    &mut seen,
                    static_discovery(action, verb.into(), "candidate", "form", base),
                    0,
                );
            }
        }
        if tag.name == "script" {
            if let Some((start, end)) = tag.body {
                truncated |= js_candidates(
                    &document_base,
                    &body[start..end],
                    &mut out,
                    &mut seen,
                    cancel,
                );
            }
        }
    }
    if is_cancelled(cancel) {
        return (out, true);
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
        urlscan_discoveries_filtered(document, location, max, |_| true, None)
    }
    fn parse_cdx(text: &str, max: usize) -> Result<(Vec<Discovery>, Option<String>, bool), String> {
        parse_cdx_filtered(text, max, |_| true, None)
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
    fn zero_budgets_are_unbounded_and_positive_budgets_are_explicit() {
        assert!(!limit_reached(0, usize::MAX));
        assert!(!limit_reached(3, 2));
        assert!(limit_reached(3, 3));
        assert!(limit_reached(3, 4));
        assert_eq!(batch_size(0, 50_000, 100), 100);
        assert_eq!(batch_size(0, 50_000, 1000), 1000);
        assert_eq!(batch_size(3, 2, 100), 1);
        let urls = (0..10_001)
            .map(|index| format!("https://example.com/{index}"))
            .collect::<Vec<_>>();
        let document = json!({"lists": {"urls": urls}});
        let (found, clipped) = urlscan_discoveries(&document, "fixture", 0);
        assert_eq!(found.len(), 10_001);
        assert!(!clipped);
        let (found, clipped) = urlscan_discoveries(&document, "fixture", 3);
        assert_eq!(found.len(), 3);
        assert!(clipped);
    }

    #[test]
    fn urlscan_pagination_obeys_exhaustion_signals_and_preserves_long_cursors() {
        assert!(!urlscan_has_more(
            &json!({"has_more": false}),
            100,
            100,
            100
        ));
        assert!(!urlscan_has_more(&json!({"has_more": true}), 0, 100, 100));
        assert!(urlscan_has_more(&json!({"has_more": true}), 1, 1, 100));
        assert!(urlscan_has_more(&json!({"total": 101}), 100, 100, 100));
        assert!(!urlscan_has_more(&json!({"total": 100}), 100, 100, 100));
        assert!(urlscan_has_more(&json!({}), 100, 100, 100));
        assert!(!urlscan_has_more(&json!({}), 99, 99, 100));
        let parts = vec!["x".repeat(2048); 10];
        assert_eq!(sort_cursor(&json!(parts)).unwrap(), parts.join(","));
        assert!(sort_cursor(&json!(["bad\ncursor"])).is_none());
        let cursor = "c".repeat(20_000);
        let fixture = json!([["original", "timestamp"], [], [cursor]]).to_string();
        assert_eq!(
            parse_cdx(&fixture, 0).unwrap().1.as_deref(),
            Some(cursor.as_str())
        );
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
    fn html_scans_all_tokens_and_attributes_without_implicit_caps() {
        let attributes = (0..300)
            .map(|index| format!(" data-fixture-{index}='ignored'"))
            .collect::<String>();
        let body = format!(
            "{}<a{attributes} href='/late'>late</a>",
            "<span></span>".repeat(10_001)
        );
        let (found, clipped) = extract_document(&base(), "text/html", &body);
        assert!(!clipped);
        assert_eq!(found.len(), 1);
        assert!(found[0].url.ends_with("/late"));
    }

    #[test]
    fn static_extraction_scans_past_large_non_url_prefixes() {
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
            let body = format!("{}{final_item}", empty_item.repeat(10_001));
            let (found, clipped) = extract_document(&url, media_type, &body);
            assert_eq!(found.len(), 1, "{path}");
            assert!(found[0].url.ends_with("/late"), "{path}");
            assert!(!clipped, "{path}");
        }
        let inline = format!("<script>{}'/late'</script>", "'not-a-url';".repeat(10_001));
        let (found, clipped) = extract_document(&base(), "text/html", &inline);
        assert_eq!(found.len(), 1);
        assert!(!clipped);
    }

    #[test]
    fn static_documents_preserve_more_than_ten_thousand_discoveries() {
        let count = 10_001;
        for (path, media_type, body) in [
            (
                "/index.html",
                "text/html",
                (0..count)
                    .map(|index| format!("<a href='/page/{index}'>"))
                    .collect::<String>(),
            ),
            (
                "/bundle.js",
                "application/javascript",
                (0..count)
                    .map(|index| format!("'/api/{index}';"))
                    .collect::<String>(),
            ),
            (
                "/robots.txt",
                "text/plain",
                (0..count)
                    .map(|index| format!("Allow: /page/{index}\n"))
                    .collect::<String>(),
            ),
            (
                "/sitemap.xml",
                "application/xml",
                (0..count)
                    .map(|index| format!("<loc>/page/{index}</loc>"))
                    .collect::<String>(),
            ),
        ] {
            let url = Url::parse(&format!("https://example.com{path}")).unwrap();
            let (found, clipped) = extract_document(&url, media_type, &body);
            assert!(!clipped, "{path}");
            assert_eq!(found.len(), count, "{path}");
            assert!(found.last().unwrap().url.ends_with("/10000"), "{path}");
        }
    }

    #[test]
    fn large_documents_preserve_the_suffix_and_multibyte_text() {
        for padding in [" ".repeat(2 * 1024 * 1024 - 1) + "é", "😀".repeat(600_000)] {
            let body = format!("{padding}<a href='/late'>late</a>");
            let (found, clipped) = extract_document(&base(), "text/html", &body);
            assert_eq!(found.len(), 1);
            assert!(found[0].url.ends_with("/late"));
            assert!(!clipped);
        }
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
    fn unsupported_media_is_not_treated_as_html() {
        assert!(
            extract_document(&base(), "image/svg+xml", "<a href='/not-a-page'>")
                .0
                .is_empty()
        );
    }

    #[test]
    fn long_urls_literals_methods_and_metadata_are_preserved() {
        let long_url = format!("https://example.com/{}", "a".repeat(20_000));
        let time = "t".repeat(300);
        let verb = "CUSTOM".repeat(10);
        let document = json!({
            "task": {"time": time},
            "data": {"requests": [{"request": {"url": long_url, "method": verb}}]}
        });
        let (found, clipped) = urlscan_discoveries(&document, "fixture", 0);
        assert!(!clipped);
        assert_eq!(found[0].url, long_url);
        assert_eq!(found[0].method, verb);
        assert_eq!(found[0].timestamp.as_deref(), Some(time.as_str()));
        let cdx = json!([["original", "timestamp"], [long_url, time]]).to_string();
        let (found, _, clipped) = parse_cdx(&cdx, 0).unwrap();
        assert!(!clipped);
        assert_eq!(found[0].url, long_url);
        assert_eq!(found[0].timestamp.as_deref(), Some(time.as_str()));
        for (media_type, body) in [
            ("text/html", format!("<a href='{long_url}'>")),
            ("application/javascript", format!("fetch('{long_url}')")),
            ("application/xml", format!("<loc>{long_url}</loc>")),
        ] {
            let (found, clipped) = extract_document(&base(), media_type, &body);
            assert!(!clipped, "{media_type}");
            assert_eq!(found[0].url, long_url, "{media_type}");
        }
    }

    #[test]
    fn forms_preserve_all_field_names_without_collecting_values() {
        let long_name = "n".repeat(300);
        let fields = (0..300)
            .map(|index| format!("<input name='field{index}' value='private-value'>"))
            .collect::<String>();
        let body = format!("<form action='/search'>{fields}<input name='{long_name}'></form>");
        let (found, clipped) = extract_document(&base(), "text/html", &body);
        assert!(!clipped);
        assert_eq!(found.len(), 1);
        let url = Url::parse(&found[0].url).unwrap();
        assert_eq!(url.query_pairs().count(), 301);
        assert!(found[0].location.contains("field299"));
        assert!(found[0].location.contains(&long_name));
        assert!(!found[0].location.contains("private-value"));
        assert!(!found[0].url.contains("private-value"));
    }

    #[test]
    fn html_formmethod_dialog_does_not_invent_network_candidates() {
        // https://html.spec.whatwg.org/dev/form-control-infrastructure.html#form-submission-attributes
        let body = r#"
            <form method="post" action="/save">
                <button formaction="/close" formmethod="DiAlOg">Close</button>
            </form>
            <form method="dialog" action="/dialog">
                <button formaction="/inherited-dialog">Close</button>
                <button formaction="/explicit-post" formmethod="POST">Save</button>
            </form>
        "#;
        let (found, clipped) = extract_document(&base(), "text/html", body);
        assert!(!clipped);
        let mut methods = found
            .iter()
            .map(|item| {
                (
                    Url::parse(&item.url).unwrap().path().to_string(),
                    item.method.as_str(),
                )
            })
            .collect::<Vec<_>>();
        methods.sort();
        assert_eq!(
            methods,
            vec![("/explicit-post".into(), "POST"), ("/save".into(), "POST")]
        );
        assert!(found
            .iter()
            .all(|item| item.kind == "candidate" && !is_followable(item)));
    }

    #[test]
    fn html_formmethod_invalid_defaults_and_inheritance_are_html_specific() {
        let body = r#"
            <form method="pOsT" action="/save">
                <button formaction="/inherited">Save</button>
                <button formaction="/invalid" formmethod="DELETE">Delete</button>
                <button formaction="/empty" formmethod="">Empty</button>
                <button formaction="/spaced" formmethod=" post ">Spaced</button>
                <button formaction="/get" formmethod="gEt">Get</button>
            </form>
            <form method="DELETE" action="/invalid-form"></form>
        "#;
        let (found, clipped) = extract_document(&base(), "text/html", body);
        assert!(!clipped);
        let mut methods = found
            .iter()
            .map(|item| {
                (
                    Url::parse(&item.url).unwrap().path().to_string(),
                    item.method.as_str(),
                )
            })
            .collect::<Vec<_>>();
        methods.sort();
        assert_eq!(
            methods,
            vec![
                ("/empty".into(), "GET"),
                ("/get".into(), "GET"),
                ("/inherited".into(), "POST"),
                ("/invalid".into(), "GET"),
                ("/invalid-form".into(), "GET"),
                ("/save".into(), "POST"),
                ("/spaced".into(), "GET")
            ]
        );
        assert!(found
            .iter()
            .all(|item| item.kind == "candidate" && !is_followable(item)));
        // Observed provider traffic is not restricted to HTML submission methods.
        assert_eq!(method(Some("DELETE")), "DELETE");
    }

    #[test]
    fn html_formmethod_inheritance_survives_an_unsupported_parent_action() {
        let body = r#"
            <form method="dialog" action="javascript:void(0)">
                <button formaction="/dialog-close">Close</button>
                <button formaction="/explicit-post" formmethod="POST">Post</button>
            </form>
            <form method="post" action="javascript:void(0)">
                <button formaction="/post-override">Post</button>
            </form>
        "#;
        let (found, clipped) = extract_document(&base(), "text/html", body);
        assert!(!clipped);
        let mut methods = found
            .iter()
            .map(|item| {
                (
                    Url::parse(&item.url).unwrap().path().to_string(),
                    item.method.as_str(),
                )
            })
            .collect::<Vec<_>>();
        methods.sort();
        assert_eq!(
            methods,
            vec![
                ("/explicit-post".into(), "POST"),
                ("/post-override".into(), "POST")
            ]
        );
        assert!(found
            .iter()
            .all(|item| item.kind == "candidate" && !is_followable(item)));
    }

    #[test]
    fn warnings_and_error_preserve_partial_report() {
        let mut report = SourceReport::default();
        for i in 0..100 {
            report.warn(format!("warning {i}"));
        }
        report.warn("warning 0");
        assert_eq!(report.warnings.len(), 100);
        report.fail("fixture failure");
        assert!(report.truncated);
        assert_eq!(report.error.as_deref(), Some("fixture failure"));
    }

    #[test]
    fn cancelled_static_extraction_does_not_process_the_document() {
        let cancel = AtomicBool::new(true);
        for (path, media_type, body) in [
            ("/index.html", "text/html", "<a href='/link'>"),
            ("/bundle.js", "application/javascript", "fetch('/api')"),
            ("/robots.txt", "text/plain", "Allow: /path"),
            ("/sitemap.xml", "application/xml", "<loc>/path</loc>"),
        ] {
            let url = Url::parse(&format!("https://example.com{path}")).unwrap();
            let (found, clipped) = extract_document_cancellable(&url, media_type, body, &cancel);
            assert!(found.is_empty(), "{path}");
            assert!(clipped, "{path}");
        }
        cancel.store(false, Ordering::Relaxed);
        let (found, clipped) =
            extract_document_cancellable(&base(), "text/html", "<a href='/link'>", &cancel);
        assert_eq!(found.len(), 1);
        assert!(!clipped);
    }

    #[test]
    fn provider_extraction_preserves_the_prefix_when_cancelled_mid_document() {
        use std::cell::Cell;
        let cancel = AtomicBool::new(false);
        let calls = Cell::new(0usize);
        let urls = (0..100)
            .map(|index| format!("https://example.com/{index}"))
            .collect::<Vec<_>>();
        let document = json!({"lists": {"urls": urls}});
        let (found, clipped) = urlscan_discoveries_filtered(
            &document,
            "fixture",
            0,
            |_| {
                calls.set(calls.get() + 1);
                if calls.get() == 5 {
                    cancel.store(true, Ordering::Relaxed);
                }
                true
            },
            Some(&cancel),
        );
        assert_eq!(found.len(), 5);
        assert!(clipped);
        cancel.store(false, Ordering::Relaxed);
        calls.set(0);
        let body = cdx_page(
            &(0..100).map(|index| index.to_string()).collect::<Vec<_>>(),
            None,
        );
        let (found, _, clipped) = parse_cdx_filtered(
            &body,
            0,
            |_| {
                calls.set(calls.get() + 1);
                if calls.get() == 5 {
                    cancel.store(true, Ordering::Relaxed);
                }
                true
            },
            Some(&cancel),
        )
        .unwrap();
        assert_eq!(found.len(), 5);
        assert!(clipped);
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
        let (_, report) = urlscan(&client, &base(), false, 0, 0, &cancel, |_, _| {}).await;
        assert_eq!(report.requests, 0);
        let (_, report) = wayback(&client, &base(), false, 0, 0, &cancel, |_, _| {}).await;
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
        let (found, clipped) = urlscan_discoveries_filtered(
            &document,
            "fixture",
            1,
            |url| url.starts_with("https://example.com/"),
            None,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].url, "https://example.com/wanted");
        assert!(!clipped);
        let fixture = r#"[["original","statuscode"],["https://static.example.com/first","200"],["https://example.com/wanted","200"]]"#;
        let (found, _, clipped) = parse_cdx_filtered(
            fixture,
            1,
            |url| url.starts_with("https://example.com/"),
            None,
        )
        .unwrap();
        assert_eq!(found[0].url, "https://example.com/wanted");
        assert!(!clipped);
    }

    async fn wayback_fixture(
        bodies: Vec<String>,
        max_pages: usize,
        max_results: usize,
    ) -> (Vec<Discovery>, SourceReport, Vec<String>) {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let mut requests = Vec::new();
            for body in bodies {
                let (mut connection, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut request = [0u8; 4096];
                let len = connection.read(&mut request).await.unwrap();
                requests.push(String::from_utf8(request[..len].to_vec()).unwrap());
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                connection.write_all(headers.as_bytes()).await.unwrap();
                connection.write_all(body.as_bytes()).await.unwrap();
            }
            requests
        });
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();
        let cancel = AtomicBool::new(false);
        let (found, report) = read_wayback(
            &client,
            &base(),
            false,
            max_pages,
            max_results,
            &cancel,
            |_, _| {},
            |host, subdomains, limit, resume| {
                let production = wayback_url(host, subdomains, limit, resume);
                let mut local = Url::parse(&format!("http://{address}/fixture")).unwrap();
                local.set_query(production.query());
                local
            },
        )
        .await;
        (found, report, fixture.await.unwrap())
    }

    fn cdx_page(paths: &[String], cursor: Option<&str>) -> String {
        let mut rows = vec![json!(["original", "timestamp"])];
        rows.extend(
            paths
                .iter()
                .map(|path| json!([format!("https://example.com/{path}"), "20200101000000"])),
        );
        if let Some(cursor) = cursor {
            rows.push(json!([]));
            rows.push(json!([cursor]));
        }
        serde_json::to_string(&rows).unwrap()
    }

    #[tokio::test]
    async fn completed_provider_batches_are_checkpointed_before_a_stalled_next_request() {
        use std::sync::{Arc, Mutex};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
            sync::oneshot,
        };
        for source in ["wayback", "urlscan"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (waiting, next_request) = oneshot::channel();
            let fixture = tokio::spawn(async move {
                let bodies = if source == "wayback" {
                    vec![
                        cdx_page(&["one".into()], Some("next")),
                        cdx_page(&["two".into()], Some("last")),
                    ]
                } else {
                    vec![
                        json!({"results":[{"_id":"11111111-1111-4111-8111-111111111111", "page":{"url":"https://example.com/one"}, "sort":[1]}], "has_more":true}).to_string(),
                        json!({"page":{"url":"https://example.com/one","status":204},"lists":{"urls":["https://example.com/two"]}}).to_string(),
                    ]
                };
                for body in bodies {
                    let (mut connection, _) = listener.accept().await.unwrap();
                    let mut request = [0u8; 4096];
                    connection.read(&mut request).await.unwrap();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    connection.write_all(response.as_bytes()).await.unwrap();
                }
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                connection.read(&mut request).await.unwrap();
                waiting.send(()).unwrap();
                // Aborting local work must close this request, not discard the
                // two complete documents that were already delivered.
                let _ = tokio::time::timeout(Duration::from_secs(5), connection.read(&mut request))
                    .await
                    .unwrap();
            });
            let checkpoints = Arc::new(Mutex::new(Vec::new()));
            let retained = checkpoints.clone();
            let reader = tokio::spawn(async move {
                let client = Client::builder().no_proxy().build().unwrap();
                let cancel = AtomicBool::new(false);
                let progress = move |batch: &[Discovery], report: &SourceReport| {
                    if batch.is_empty() {
                        return;
                    }
                    retained.lock().unwrap().push((
                        batch
                            .iter()
                            .map(|item| (item.url.clone(), item.status))
                            .collect::<Vec<_>>(),
                        report.requests,
                    ));
                };
                if source == "wayback" {
                    read_wayback(
                        &client,
                        &base(),
                        false,
                        0,
                        0,
                        &cancel,
                        progress,
                        |_, _, _, _| Url::parse(&format!("http://{address}/page")).unwrap(),
                    )
                    .await
                } else {
                    read_urlscan(
                        &client,
                        &base(),
                        false,
                        0,
                        0,
                        &cancel,
                        progress,
                        &None,
                        |_, _, _, _| Url::parse(&format!("http://{address}/search")).unwrap(),
                        |_| Some(Url::parse(&format!("http://{address}/result")).unwrap()),
                    )
                    .await
                }
            });
            tokio::time::timeout(Duration::from_secs(5), next_request)
                .await
                .unwrap()
                .unwrap();
            assert!(!reader.is_finished());
            let mut second = vec![("https://example.com/two".to_string(), None)];
            if source == "urlscan" {
                second.insert(0, ("https://example.com/one".to_string(), Some(204)));
            }
            assert_eq!(
                *checkpoints.lock().unwrap(),
                vec![
                    (vec![("https://example.com/one".to_string(), None)], 1),
                    (second, 2),
                ],
                "{source} must publish each completed batch before awaiting another request"
            );
            reader.abort();
            assert!(reader.await.unwrap_err().is_cancelled());
            assert_eq!(checkpoints.lock().unwrap().len(), 2);
            fixture.await.unwrap();
        }
    }

    #[tokio::test]
    async fn urlscan_checkpoints_all_search_summaries_limits_and_warnings_before_details() {
        use std::sync::{Arc, Mutex};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
            sync::oneshot,
        };
        for budget in [0, 2] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (waiting, detail_started) = oneshot::channel();
            let fixture = tokio::spawn(async move {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                connection.read(&mut request).await.unwrap();
                let body = json!({"search_date_limit_days":30,"has_more":false,"results":[
                    {"_id":"11111111-1111-4111-8111-111111111111","page":{"url":"https://outside.example.com/not-in-scope"}},
                    {"_id":"22222222-2222-4222-8222-222222222222","page":{"url":"https://example.com/one"}},
                    {"_id":"33333333-3333-4333-8333-333333333333","page":{"url":"https://example.com/two"}}
                ]}).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                connection.write_all(response.as_bytes()).await.unwrap();
                drop(connection);
                let (mut connection, _) = listener.accept().await.unwrap();
                connection.read(&mut request).await.unwrap();
                waiting.send(()).unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(5), connection.read(&mut request))
                    .await
                    .unwrap();
            });
            let retained = Arc::new(Mutex::new((
                Vec::<String>::new(),
                0,
                false,
                Vec::<String>::new(),
            )));
            let saved = retained.clone();
            let reader = tokio::spawn(async move {
                let client = Client::builder().no_proxy().build().unwrap();
                read_urlscan(
                    &client,
                    &base(),
                    false,
                    0,
                    budget,
                    &AtomicBool::new(false),
                    |batch, report| {
                        let mut saved = saved.lock().unwrap();
                        saved.0.extend(batch.iter().map(|item| item.url.clone()));
                        saved.1 = report.requests;
                        saved.2 |= report.truncated;
                        for warning in &report.warnings {
                            if !saved.3.contains(warning) {
                                saved.3.push(warning.clone());
                            }
                        }
                    },
                    &None,
                    |_, _, _, _| Url::parse(&format!("http://{address}/search")).unwrap(),
                    |uuid| Some(Url::parse(&format!("http://{address}/result/{uuid}")).unwrap()),
                )
                .await
            });
            if budget == 0 {
                tokio::time::timeout(Duration::from_secs(5), detail_started)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(!reader.is_finished());
                reader.abort();
                assert!(reader.await.unwrap_err().is_cancelled());
                fixture.await.unwrap();
            } else {
                let (found, report) = tokio::time::timeout(Duration::from_secs(5), reader)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(found.len(), 2);
                assert_eq!(report.requests, 1, "completed-page summaries consume the explicit budget before any detail request");
                fixture.abort();
                let _ = fixture.await;
            }
            let saved = retained.lock().unwrap();
            assert_eq!(
                saved.0,
                vec!["https://example.com/one", "https://example.com/two"]
            );
            assert_eq!(saved.1, if budget == 0 { 2 } else { 1 });
            assert!(saved.2);
            assert_eq!(
                saved.3,
                vec!["urlscan search history is limited to the past 30 days for this account"]
            );
        }
    }

    #[tokio::test]
    async fn urlscan_search_page_exhaustion_is_partial_while_its_detail_is_pending() {
        use std::sync::{Arc, Mutex};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
            sync::oneshot,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (waiting, detail_started) = oneshot::channel();
        let fixture = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            connection.read(&mut request).await.unwrap();
            let body = json!({"has_more":true,"results":[{
                "_id":"11111111-1111-4111-8111-111111111111",
                "page":{"url":"https://example.com/one"},"sort":[1]
            }]})
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            connection.write_all(response.as_bytes()).await.unwrap();
            drop(connection);
            let (mut connection, _) = listener.accept().await.unwrap();
            connection.read(&mut request).await.unwrap();
            waiting.send(()).unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), connection.read(&mut request))
                .await
                .unwrap();
        });
        let report = Arc::new(Mutex::new((0, false, Vec::new())));
        let saved_report = report.clone();
        let reader = tokio::spawn(async move {
            let client = Client::builder().no_proxy().build().unwrap();
            read_urlscan(
                &client,
                &base(),
                false,
                1,
                0,
                &AtomicBool::new(false),
                |_, report| {
                    *saved_report.lock().unwrap() =
                        (report.requests, report.truncated, report.warnings.clone());
                },
                &None,
                |_, _, _, _| Url::parse(&format!("http://{address}/search")).unwrap(),
                |_| Some(Url::parse(&format!("http://{address}/detail")).unwrap()),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), detail_started)
            .await
            .unwrap()
            .unwrap();
        reader.abort();
        assert!(reader.await.unwrap_err().is_cancelled());
        fixture.await.unwrap();
        assert_eq!(
            *report.lock().unwrap(),
            (
                2,
                true,
                vec!["urlscan search page limit reached".to_string()]
            )
        );
    }

    #[tokio::test]
    async fn wayback_zero_budgets_follow_all_pages_until_cursor_exhaustion() {
        let bodies = (0..26)
            .map(|page| {
                let paths = if page == 0 {
                    (0..1001).map(|index| format!("first/{index}")).collect()
                } else {
                    vec![format!("page/{page}")]
                };
                cdx_page(
                    &paths,
                    (page < 25).then(|| format!("cursor-{page}")).as_deref(),
                )
            })
            .collect();
        let (found, report, requests) = wayback_fixture(bodies, 0, 0).await;
        assert_eq!(found.len(), 1026);
        assert_eq!(report.requests, 26);
        assert!(!report.truncated);
        assert!(report.error.is_none());
        assert!(requests
            .iter()
            .all(|request| request.contains("limit=1000")));
        assert!(!requests[0].contains("resumeKey="));
        assert!(requests[25].contains("resumeKey=cursor-24"));
    }

    #[tokio::test]
    async fn wayback_explicit_page_and_result_budgets_still_stop_collection() {
        let pages = vec![
            cdx_page(&["one".into()], Some("a")),
            cdx_page(&["two".into()], Some("b")),
        ];
        let (found, report, _) = wayback_fixture(pages, 2, 0).await;
        assert_eq!(found.len(), 2);
        assert_eq!(report.requests, 2);
        assert!(report.truncated);
        assert!(report.error.is_none());
        let pages = vec![
            cdx_page(&["one".into(), "two".into()], Some("a")),
            cdx_page(&["three".into(), "four".into()], Some("b")),
        ];
        let (found, report, requests) = wayback_fixture(pages, 0, 3).await;
        assert_eq!(found.len(), 3);
        assert_eq!(report.requests, 2);
        assert!(report.truncated);
        assert!(report.error.is_none());
        assert!(requests[0].contains("limit=3"));
        assert!(requests[1].contains("limit=1"));
    }

    #[tokio::test]
    async fn wayback_cursor_cycles_stop_without_discarding_collected_evidence() {
        let pages = vec![
            cdx_page(&["one".into()], Some("a")),
            cdx_page(&["two".into()], Some("b")),
            cdx_page(&["three".into()], Some("a")),
        ];
        let (found, report, _) = wayback_fixture(pages, 0, 0).await;
        assert_eq!(found.len(), 3);
        assert_eq!(report.requests, 3);
        assert!(report.truncated);
        assert!(report.error.is_none());
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("repeated a resume cursor")));
    }

    #[tokio::test]
    async fn large_response_bodies_are_read_completely_with_or_without_content_length() {
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
                    let header = format!("{:x}\r\n", 2 * 1024 * 1024 + 1);
                    let _ = connection.write_all(header.as_bytes()).await;
                    let _ = connection.write_all(&vec![b'x'; 2 * 1024 * 1024 + 1]).await;
                    let _ = connection.write_all(b"\r\n0\r\n\r\n").await;
                } else {
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        2 * 1024 * 1024 + 1
                    );
                    let _ = connection.write_all(headers.as_bytes()).await;
                    let _ = connection.write_all(&vec![b'x'; 2 * 1024 * 1024 + 1]).await;
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
            assert_eq!(result.unwrap(), "x".repeat(2 * 1024 * 1024 + 1));
            assert_eq!(report.requests, 1);
            fixture.await.unwrap();
        }
    }

    #[tokio::test]
    async fn streamed_response_reads_remain_cancellable() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
            sync::oneshot,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (started, ready) = oneshot::channel();
        let fixture = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = connection.read(&mut request).await.unwrap();
            connection.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n").await.unwrap();
            started.send(()).unwrap();
            // Leave the body open until cancellation closes the client socket.
            let mut byte = [0u8; 1];
            let _ = tokio::time::timeout(Duration::from_secs(5), connection.read(&mut byte))
                .await
                .unwrap();
        });
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();
        let cancel = AtomicBool::new(false);
        let mut report = SourceReport::default();
        let fetched = fetch_text(
            client.get(format!("http://{address}/fixture")),
            &cancel,
            &mut report,
            true,
        );
        let stop = async {
            ready.await.unwrap();
            cancel.store(true, Ordering::Relaxed);
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(fetched, stop)
        })
        .await
        .unwrap();
        assert!(matches!(result, Err(FetchError::Cancelled)));
        assert_eq!(report.requests, 1);
        fixture.await.unwrap();
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
