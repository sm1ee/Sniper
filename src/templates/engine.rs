//! Judging an HTTP response with a template's matchers and extractors, the
//! way Nuclei's operators do: extractors first, so a named value (a version)
//! is there for the matchers; then each matcher, negated if asked; then the
//! template's matchers-condition.

use std::{borrow::Cow, collections::HashMap, sync::Arc};

use aho_corasick::{AhoCorasick, MatchKind};
use regex::{Regex, RegexSet};
use serde_json::{Map, Value};

use super::dsl::{self, Allow, CompileError, Expr, Interp, Val, Vars};
use super::model::{Classification, ParsedTemplate, PassiveKind, TemplateInfo};
use crate::model::{BodyEncoding, MessageRecord, TransactionRecord};

/// The most body a passive template reads. Beyond it a body counts as
/// truncated, and templates whose result missing bytes could flip skip it.
pub const MAX_PASSIVE_BODY_BYTES: usize = 2 * 1024 * 1024;

/// The most body an active template reads: what Nuclei reads by default.
/// One response is judged by one template, so no prefilter needs bounding.
pub const MAX_ACTIVE_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    Body,
    Header,
    All,
    Request,
    /// A response variable: a header (`server`, `content_type`) or a value
    /// like `status_code`.
    Var(String),
}

#[derive(Clone, Debug)]
enum MatcherKind {
    Words(Vec<Interp>),
    HexWords(Vec<Vec<u8>>),
    Regex(Vec<Arc<Regex>>),
    Status(Vec<u16>),
    Size(Vec<usize>),
    Binary(Vec<Vec<u8>>),
    Dsl(Vec<DslItem>),
}

#[derive(Clone, Debug)]
enum DslItem {
    Static(Expr),
    /// An expression with markers inside, filled before it is read.
    Rendered(Interp, Allow),
}

#[derive(Clone, Debug)]
struct Matcher {
    name: Option<String>,
    part: Part,
    negative: bool,
    internal: bool,
    and: bool,
    case_insensitive: bool,
    kind: MatcherKind,
}

#[derive(Clone, Debug)]
enum ExtractorKind {
    Regex {
        patterns: Vec<Arc<Regex>>,
        group: usize,
    },
    Kval(Vec<String>),
    Dsl(Vec<Expr>),
    Json(Vec<super::jq::Query>),
}

#[derive(Clone, Debug)]
struct Extractor {
    name: Option<String>,
    part: Part,
    internal: bool,
    kind: ExtractorKind,
}

#[derive(Clone, Debug)]
pub(super) struct Operators {
    and: bool,
    matchers: Vec<Matcher>,
    extractors: Vec<Extractor>,
}

impl Operators {
    /// Neither matchers nor extractors: answers are never judged.
    pub(super) fn is_empty(&self) -> bool {
        self.matchers.is_empty() && self.extractors.is_empty()
    }
}

/// A template compiled for judging responses.
#[derive(Clone, Debug)]
pub struct CompiledTemplate {
    pub info: TemplateInfo,
    pub passive: Option<PassiveKind>,
    pub(super) operators: Operators,
    /// Whether bytes missing from a truncated body could turn a non-match
    /// into a match: a negated body matcher, a size, an expression reading
    /// the body.
    pub(super) body_sensitive: bool,
}

/// One result of a template on one response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateMatch {
    /// The named matcher that matched, when the template reports by name.
    pub matcher: Option<String>,
    pub extracted: Vec<String>,
    /// The words or patterns that matched, for evidence.
    pub snippets: Vec<String>,
}

pub(super) fn reason(code: impl Into<String>) -> CompileError {
    CompileError(code.into())
}

/// Compiles a template's single request block for passive use. The
/// classification must already allow it.
pub fn compile_passive(
    template: &ParsedTemplate,
    classification: &Classification,
) -> Result<CompiledTemplate, CompileError> {
    let Some(kind) = classification.passive else {
        return Err(reason("passive:shape"));
    };
    if let Some(first) = classification.passive_reasons.first() {
        return Err(reason(first.clone()));
    }
    let block = template
        .root
        .get("http")
        .or_else(|| template.root.get("requests"))
        .and_then(Value::as_array)
        .and_then(|blocks| blocks.first())
        .and_then(Value::as_object)
        .ok_or_else(|| reason("http:empty"))?;
    let operators = compile_operators(block, Allow::default(), false)?;
    if operators.is_empty() {
        return Err(reason("operators:empty"));
    }
    let body_sensitive = body_sensitive(&operators);
    Ok(CompiledTemplate {
        info: template.info.clone(),
        passive: Some(kind),
        operators,
        body_sensitive,
    })
}

pub(super) fn compile_operators(
    block: &Map<String, Value>,
    allow: Allow,
    request_part: bool,
) -> Result<Operators, CompileError> {
    let and = condition(block.get("matchers-condition"))?;
    let mut matchers = Vec::new();
    for value in block
        .get("matchers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let map = value
            .as_object()
            .ok_or_else(|| reason("matcher:not_a_mapping"))?;
        matchers.push(compile_matcher(map, allow, request_part)?);
    }
    let mut extractors = Vec::new();
    for value in block
        .get("extractors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let map = value
            .as_object()
            .ok_or_else(|| reason("extractor:not_a_mapping"))?;
        extractors.push(compile_extractor(map, allow, request_part)?);
    }
    Ok(Operators {
        and,
        matchers,
        extractors,
    })
}

fn condition(value: Option<&Value>) -> Result<bool, CompileError> {
    match value.map(text_of).as_deref() {
        None | Some("or") | Some("") => Ok(false),
        Some("and") => Ok(true),
        Some(_) => Err(reason("condition")),
    }
}

pub(super) fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        _ => String::new(),
    }
}

pub(super) fn flag(map: &Map<String, Value>, key: &str) -> Result<bool, CompileError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(reason(format!("field:{key}"))),
    }
}

/// A list of strings; a lone scalar counts as a list of one.
pub(super) fn strings(map: &Map<String, Value>, key: &str) -> Result<Vec<String>, CompileError> {
    let items = match map.get(key) {
        Some(Value::Array(items)) => items.iter().map(text_of).collect(),
        Some(scalar @ (Value::String(_) | Value::Number(_))) => vec![text_of(scalar)],
        _ => return Err(reason(format!("field:{key}"))),
    };
    Ok(items)
}

fn integers<T: TryFrom<u64>>(map: &Map<String, Value>, key: &str) -> Result<Vec<T>, CompileError> {
    strings(map, key)?
        .iter()
        .map(|item| {
            item.trim()
                .parse::<u64>()
                .ok()
                .and_then(|number| T::try_from(number).ok())
                .ok_or_else(|| reason(format!("field:{key}")))
        })
        .collect()
}

fn part(value: Option<&Value>, request_part: bool) -> Result<Part, CompileError> {
    let name = value.map(text_of).unwrap_or_default();
    match name.as_str() {
        "" | "body" => Ok(Part::Body),
        "header" | "all_headers" => Ok(Part::Header),
        "all" | "response" | "raw" => Ok(Part::All),
        "request" if request_part => Ok(Part::Request),
        "request" => Err(reason("part:request")),
        other
            if !other.is_empty()
                && other
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') =>
        {
            Ok(Part::Var(other.to_string()))
        }
        _ => Err(reason("part:unknown")),
    }
}

fn hex_bytes(text: &str) -> Result<Vec<u8>, CompileError> {
    dsl::hex_decode(text.trim()).ok_or_else(|| reason("hex"))
}

fn compile_dsl(text: &str, allow: Allow) -> Result<DslItem, CompileError> {
    if text.contains("{{") {
        // Check both the markers and the expression around them now, so a
        // template that cannot run is known before it is enabled.
        let interp = Interp::compile(text, allow)?;
        Expr::compile(&dsl::without_markers(text), allow)?;
        Ok(DslItem::Rendered(interp, allow))
    } else {
        Ok(DslItem::Static(Expr::compile(text, allow)?))
    }
}

fn compile_matcher(
    map: &Map<String, Value>,
    allow: Allow,
    request_part: bool,
) -> Result<Matcher, CompileError> {
    let kind_name = map.get("type").map(text_of).unwrap_or_default();
    let case_insensitive = flag(map, "case-insensitive")?;
    let hex = match map.get("encoding").map(text_of).as_deref() {
        None | Some("") => false,
        Some("hex") => true,
        Some(_) => return Err(reason("matcher:encoding")),
    };
    let kind = match kind_name.as_str() {
        "word" if hex => MatcherKind::HexWords(
            strings(map, "words")?
                .iter()
                .map(|word| hex_bytes(word))
                .collect::<Result<_, _>>()?,
        ),
        "word" => MatcherKind::Words(
            strings(map, "words")?
                .iter()
                .map(|word| Interp::compile(word, allow))
                .collect::<Result<_, _>>()?,
        ),
        "regex" => MatcherKind::Regex(
            strings(map, "regex")?
                .iter()
                .map(|pattern| {
                    if pattern.contains("{{") {
                        return Err(reason("regex:marker"));
                    }
                    dsl::go_regex(pattern).map(Arc::new)
                })
                .collect::<Result<_, _>>()?,
        ),
        "status" => MatcherKind::Status(integers(map, "status")?),
        "size" => MatcherKind::Size(integers(map, "size")?),
        "binary" => MatcherKind::Binary(
            strings(map, "binary")?
                .iter()
                .map(|pattern| hex_bytes(pattern))
                .collect::<Result<_, _>>()?,
        ),
        "dsl" => MatcherKind::Dsl(
            strings(map, "dsl")?
                .iter()
                .map(|expression| compile_dsl(expression, allow))
                .collect::<Result<_, _>>()?,
        ),
        other => return Err(reason(format!("matcher:{other}"))),
    };
    Ok(Matcher {
        name: map
            .get("name")
            .map(text_of)
            .filter(|name| !name.trim().is_empty()),
        part: part(map.get("part"), request_part)?,
        negative: flag(map, "negative")?,
        internal: flag(map, "internal")?,
        and: condition(map.get("condition"))?,
        case_insensitive,
        kind,
    })
}

fn compile_extractor(
    map: &Map<String, Value>,
    allow: Allow,
    request_part: bool,
) -> Result<Extractor, CompileError> {
    // Nuclei documents no meaning for it on extractors; guessing one could
    // change what a template reports.
    if flag(map, "case-insensitive")? {
        return Err(reason("extractor:case-insensitive"));
    }
    let kind = match map.get("type").map(text_of).as_deref() {
        Some("regex") => ExtractorKind::Regex {
            patterns: strings(map, "regex")?
                .iter()
                .map(|pattern| dsl::go_regex(pattern).map(Arc::new))
                .collect::<Result<_, _>>()?,
            group: match map.get("group") {
                None => 0,
                Some(value) => text_of(value).parse().map_err(|_| reason("field:group"))?,
            },
        },
        Some("kval") => ExtractorKind::Kval(
            strings(map, "kval")?
                .into_iter()
                .map(|key| key.to_ascii_lowercase().replace('-', "_"))
                .collect(),
        ),
        Some("dsl") => ExtractorKind::Dsl(
            strings(map, "dsl")?
                .iter()
                .map(|expression| Expr::compile(expression, allow))
                .collect::<Result<_, _>>()?,
        ),
        Some("json") => ExtractorKind::Json(
            strings(map, "json")?
                .iter()
                .map(|query| super::jq::Query::compile(query))
                .collect::<Result<_, _>>()?,
        ),
        Some(other) => return Err(reason(format!("extractor:{other}"))),
        None => return Err(reason("extractor:no_type")),
    };
    Ok(Extractor {
        name: map
            .get("name")
            .map(text_of)
            .filter(|name| !name.trim().is_empty()),
        part: part(map.get("part"), request_part)?,
        internal: flag(map, "internal")?,
        kind,
    })
}

pub(super) fn body_sensitive(operators: &Operators) -> bool {
    let reads_body = |part: &Part| matches!(part, Part::Body | Part::All);
    operators.matchers.iter().any(|matcher| {
        (matcher.negative && reads_body(&matcher.part))
            || (matches!(matcher.kind, MatcherKind::Size(_)) && reads_body(&matcher.part))
            || match &matcher.kind {
                MatcherKind::Dsl(items) => items.iter().any(|item| match item {
                    DslItem::Static(expr) => expr
                        .variables()
                        .into_iter()
                        .any(|name| matches!(name, "body" | "response" | "raw" | "content_length")),
                    DslItem::Rendered(..) => true,
                }),
                _ => false,
            }
    })
}

// ---- Responses ----

/// Values a template's markers and expressions can read about where a
/// request went: `{{BaseURL}}` and the rest.
#[derive(Clone, Debug, Default)]
pub struct UrlVars {
    pub base_url: String,
    pub root_url: String,
    pub hostname: String,
    pub host: String,
    pub port: String,
    pub path: String,
    pub file: String,
    pub scheme: String,
}

impl UrlVars {
    /// The URL a captured request went to. None when it is not an HTTP(S)
    /// request Sniper can name.
    pub fn of_record(record: &TransactionRecord) -> Option<Self> {
        let (base, _) = crate::service_map::request_target(record)?;
        Self::of_url(&base, &record.path)
    }

    /// The values for `path_and_query` on `base`'s origin, as Nuclei names
    /// them: `Hostname` carries a port only when the URL spells one out, and
    /// `Host` is the bare name.
    pub fn of_url(base: &url::Url, path_and_query: &str) -> Option<Self> {
        let scheme = base.scheme().to_string();
        let name = base.host_str()?;
        let port = base.port_or_known_default()?.to_string();
        let hostname = match base.port() {
            Some(port) => format!("{name}:{port}"),
            None => name.to_string(),
        };
        let root_url = format!("{scheme}://{hostname}");
        let path_and_query = path_and_query.split('#').next().unwrap_or("");
        let path = path_and_query.split('?').next().unwrap_or("");
        let directory = path.rsplit_once('/').map_or("", |(dir, _)| dir);
        let file = path.rsplit('/').next().unwrap_or("");
        Some(Self {
            base_url: format!("{root_url}{path_and_query}"),
            root_url,
            hostname,
            host: name
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            port,
            path: directory.to_string(),
            file: file.to_string(),
            scheme,
        })
    }

    pub(super) fn get(&self, name: &str) -> Option<&str> {
        Some(match name {
            "BaseURL" => &self.base_url,
            "RootURL" => &self.root_url,
            "Hostname" => &self.hostname,
            "Host" => &self.host,
            "Port" => &self.port,
            "Path" => &self.path,
            "File" => &self.file,
            "Scheme" => &self.scheme,
            _ => return None,
        })
    }
}

/// An out-of-band callback a request caused, as Nuclei hands it to
/// matchers: `interactsh_protocol`, `interactsh_request`, `interactsh_ip`.
#[derive(Clone, Debug, Default)]
pub struct Interaction {
    protocol: String,
    request: String,
    ip: String,
}

impl Interaction {
    pub fn new(protocol: &str, request: &str, ip: &str) -> Self {
        // Nuclei lowers a DNS question, whose case a resolver may change.
        let request = if protocol.eq_ignore_ascii_case("dns") {
            request.to_lowercase()
        } else {
            request.to_string()
        };
        Self {
            protocol: protocol.to_string(),
            request,
            ip: ip.to_string(),
        }
    }
}

/// A response as Nuclei presents it to matchers: Go-canonical header names,
/// the status line first, the decoded body.
pub struct ResponseView {
    status: u16,
    header_text: String,
    body: Vec<u8>,
    body_text: String,
    all_text: String,
    /// Lower snake header names (`content_type`) with values joined by a
    /// space, as Nuclei names them in expressions.
    header_vars: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    content_length: f64,
    duration: f64,
    truncated: bool,
    request_text: Option<String>,
    /// Values the request was built with: an active template's variables and
    /// random strings, so a matcher can look for what was sent.
    request_vars: HashMap<String, String>,
    url: UrlVars,
    /// This answer's request in a scan's run, from 1, and what the run's
    /// earlier requests were answered, for names such as `body_1`.
    number: usize,
    history: Vec<Option<Arc<ResponseView>>>,
    interaction: Option<Interaction>,
}

impl ResponseView {
    /// The response a record holds. Matchers judge what the server sent:
    /// when a Match & Replace rule rewrote the response, that is the
    /// original, or a stripped security header would read as missing.
    pub fn from_record(
        record: &TransactionRecord,
        url: UrlVars,
        body_limit: usize,
    ) -> Option<Self> {
        let response = record
            .original_response
            .as_ref()
            .or(record.response.as_ref())?;
        let status = record.status?;
        Some(Self::from_message(
            status,
            record.response_http_version.as_deref(),
            response,
            record.duration_ms,
            url,
            body_limit,
        ))
    }

    fn from_message(
        status: u16,
        version: Option<&str>,
        message: &MessageRecord,
        duration_ms: u64,
        url: UrlVars,
        body_limit: usize,
    ) -> Self {
        let mut body = match message.body_encoding {
            BodyEncoding::Utf8 => message.body_preview.as_bytes().to_vec(),
            BodyEncoding::Base64 => {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                STANDARD.decode(&message.body_preview).unwrap_or_default()
            }
        };
        let mut truncated = message.preview_truncated;
        if body.len() > body_limit {
            body.truncate(body_limit);
            truncated = true;
        }
        let body_text = String::from_utf8_lossy(&body).into_owned();
        let reason = http::StatusCode::from_u16(status)
            .ok()
            .and_then(|code| code.canonical_reason())
            .unwrap_or("");
        let version = match version {
            Some(version) if version.starts_with("HTTP/") => version,
            _ => "HTTP/1.1",
        };
        let mut header_text = format!("{version} {status} {reason}")
            .trim_end()
            .to_string();
        let mut header_vars: Vec<(String, String)> = Vec::new();
        let mut cookies = Vec::new();
        for header in &message.headers {
            header_text.push_str("\r\n");
            header_text.push_str(&canonical_header_name(&header.name));
            header_text.push_str(": ");
            header_text.push_str(&header.value);
            let key = header.name.to_ascii_lowercase().replace('-', "_");
            match header_vars.iter_mut().find(|(name, _)| *name == key) {
                Some((_, value)) => {
                    value.push(' ');
                    value.push_str(&header.value);
                }
                None => header_vars.push((key.clone(), header.value.clone())),
            }
            if key == "set_cookie" {
                if let Some((name, value)) = header
                    .value
                    .split(';')
                    .next()
                    .and_then(|pair| pair.split_once('='))
                {
                    // Named like kval keys, which cannot contain a dash.
                    let name = name.trim().to_ascii_lowercase().replace('-', "_");
                    cookies.push((name, value.trim().to_string()));
                }
            }
        }
        header_text.push_str("\r\n");
        let all_text = format!("{header_text}\r\n{body_text}");
        let content_length = header_vars
            .iter()
            .find(|(name, _)| name == "content_length")
            .and_then(|(_, value)| value.trim().parse::<f64>().ok())
            .unwrap_or(body.len() as f64);
        Self {
            status,
            header_text,
            body,
            body_text,
            all_text,
            header_vars,
            cookies,
            content_length,
            duration: duration_ms as f64 / 1000.0,
            truncated,
            request_text: None,
            request_vars: HashMap::new(),
            url,
            number: 1,
            history: Vec::new(),
            interaction: None,
        }
    }

    /// The answer with the callback its request caused, which matchers read
    /// as the `interactsh_*` parts.
    pub fn with_interaction(mut self, interaction: Interaction) -> Self {
        self.interaction = Some(interaction);
        self
    }

    /// The request this response answers, for an active template's matchers.
    pub(super) fn with_request(mut self, text: String, values: HashMap<String, String>) -> Self {
        self.request_text = Some(text);
        self.request_vars = values;
        self
    }

    /// Places this answer in a scan's run: `number` is its request, from 1,
    /// and `history` holds the answers to the requests before it, `None`
    /// where a request got none.
    pub(super) fn with_history(
        mut self,
        number: usize,
        history: Vec<Option<Arc<ResponseView>>>,
    ) -> Self {
        self.number = number;
        self.history = history;
        self
    }

    fn part_text(&self, part: &Part) -> Option<Cow<'_, str>> {
        Some(match part {
            Part::Body => Cow::Borrowed(self.body_text.as_str()),
            Part::Header => Cow::Borrowed(self.header_text.as_str()),
            Part::All => Cow::Borrowed(self.all_text.as_str()),
            Part::Request => Cow::Borrowed(self.request_text.as_deref()?),
            Part::Var(name) => self.var(name)?.text().into_owned().into(),
        })
    }

    fn part_bytes(&self, part: &Part) -> Option<Cow<'_, [u8]>> {
        match part {
            Part::Body => Some(Cow::Borrowed(&self.body)),
            other => self
                .part_text(other)
                .map(|text| Cow::Owned(text.into_owned().into_bytes())),
        }
    }

    fn var(&self, name: &str) -> Option<Val<'_>> {
        fn text(value: &str) -> Option<Val<'_>> {
            Some(Val::Str(Cow::Borrowed(value)))
        }
        match name {
            "status_code" => Some(Val::Num(self.status as f64)),
            "content_length" => Some(Val::Num(self.content_length)),
            "duration" => Some(Val::Num(self.duration)),
            "body" => text(&self.body_text),
            "header" | "all_headers" => text(&self.header_text),
            "response" | "raw" | "all" => text(&self.all_text),
            "request" => text(self.request_text.as_deref()?),
            "interactsh_protocol" => text(&self.interaction.as_ref()?.protocol),
            "interactsh_request" => text(&self.interaction.as_ref()?.request),
            "interactsh_ip" => text(&self.interaction.as_ref()?.ip),
            // Sniper does not keep what the OAST server answered.
            "interactsh_response" => {
                self.interaction.as_ref()?;
                text("")
            }
            _ => {
                if let Some(value) = self.url.get(name) {
                    return text(value);
                }
                if let Some(value) = self.request_vars.get(name) {
                    return text(value);
                }
                if let Some((_, value)) = self.header_vars.iter().find(|(key, _)| key == name) {
                    return text(value);
                }
                // `body_2`: what the run's second request was answered.
                let (base, number) = name.rsplit_once('_')?;
                if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let number: usize = number.parse().ok()?;
                if number == self.number {
                    self.var(base)
                } else {
                    self.history
                        .get(number.checked_sub(1)?)?
                        .as_ref()?
                        .var(base)
                }
            }
        }
    }
}

/// Go's `http.CanonicalHeaderKey`: each dash-separated word capitalised.
fn canonical_header_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for c in name.chars() {
        if upper {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c.to_ascii_lowercase());
        }
        upper = c == '-';
    }
    out
}

/// What expressions see while one template judges one response: the
/// response, plus values its extractors have named.
struct Scope<'r> {
    view: &'r ResponseView,
    dynamic: &'r HashMap<String, String>,
}

impl Vars for Scope<'_> {
    fn get(&self, name: &str) -> Option<Val<'_>> {
        if let Some(value) = self.dynamic.get(name) {
            return Some(Val::Str(Cow::Borrowed(value.as_str())));
        }
        self.view.var(name)
    }

    fn bytes(&self, name: &str) -> Option<Cow<'_, [u8]>> {
        (name == "body" && !self.dynamic.contains_key(name))
            .then(|| Cow::Borrowed(self.view.body.as_slice()))
    }
}

impl CompiledTemplate {
    /// The template's results on one response. Empty when it does not match,
    /// or when a truncated body could have changed the answer.
    pub fn evaluate(&self, view: &ResponseView) -> Vec<TemplateMatch> {
        self.evaluate_carrying(view).0
    }

    /// The results, and the first value of each named internal extractor,
    /// which Nuclei hands to the run's later requests. An extractor that
    /// reads one request's answer (`part: body_2`) hands on only from it.
    pub fn evaluate_carrying(
        &self,
        view: &ResponseView,
    ) -> (Vec<TemplateMatch>, Vec<(String, String)>) {
        if view.truncated && self.body_sensitive {
            return (Vec::new(), Vec::new());
        }
        let operators = &self.operators;
        let mut dynamic: HashMap<String, String> = HashMap::new();
        let mut carried = Vec::new();
        let mut extracted = Vec::new();
        for extractor in &operators.extractors {
            let values = run_extractor(extractor, view, &dynamic);
            if let (Some(name), Some(first)) = (&extractor.name, values.first()) {
                dynamic.insert(name.clone(), first.clone());
                if extractor.internal && reads_request(&extractor.part, view.number) {
                    carried.push((name.clone(), first.clone()));
                }
            }
            if !extractor.internal {
                for value in values {
                    if !extracted.contains(&value) {
                        extracted.push(value);
                    }
                }
            }
        }
        (self.match_view(view, &dynamic, extracted), carried)
    }

    /// The matchers' verdict on one answer, given what the extractors found.
    fn match_view(
        &self,
        view: &ResponseView,
        dynamic: &HashMap<String, String>,
        extracted: Vec<String>,
    ) -> Vec<TemplateMatch> {
        let operators = &self.operators;
        if operators.matchers.is_empty() {
            return if extracted.is_empty() {
                Vec::new()
            } else {
                vec![TemplateMatch {
                    matcher: None,
                    extracted,
                    snippets: Vec::new(),
                }]
            };
        }
        let scope = Scope { view, dynamic };
        let outcomes: Vec<(bool, Vec<String>)> = operators
            .matchers
            .iter()
            .map(|matcher| {
                let (matched, snippets) = run_matcher(matcher, &scope);
                if matcher.negative {
                    (!matched, Vec::new())
                } else {
                    (matched, snippets)
                }
            })
            .collect();
        if operators.and {
            if !outcomes.iter().all(|(matched, _)| *matched) {
                return Vec::new();
            }
            return vec![TemplateMatch {
                matcher: None,
                extracted,
                snippets: outcomes
                    .into_iter()
                    .flat_map(|(_, snippets)| snippets)
                    .collect(),
            }];
        }
        // Or: each named matcher that matched is its own result, as Nuclei
        // reports `template:matcher`; anything else that matched is one more.
        let mut results = Vec::new();
        let mut unnamed: Option<TemplateMatch> = None;
        for (matcher, (matched, snippets)) in operators.matchers.iter().zip(outcomes) {
            if !matched {
                continue;
            }
            match (&matcher.name, matcher.internal) {
                (Some(name), false) => results.push(TemplateMatch {
                    matcher: Some(name.clone()),
                    extracted: extracted.clone(),
                    snippets,
                }),
                _ => unnamed
                    .get_or_insert_with(|| TemplateMatch {
                        matcher: None,
                        extracted: extracted.clone(),
                        snippets: Vec::new(),
                    })
                    .snippets
                    .extend(snippets),
            }
        }
        if results.is_empty() {
            results.extend(unnamed);
        }
        results
    }
}

/// Whether an extractor reads this request's answer: one naming a request
/// (`body_2`) reads only that one's, as Nuclei decides it.
fn reads_request(part: &Part, number: usize) -> bool {
    let Part::Var(name) = part else {
        return true;
    };
    match name.rsplit_once('_') {
        Some((_, suffix)) => suffix
            .parse::<usize>()
            .map_or(true, |index| index == number),
        None => true,
    }
}

fn run_matcher(matcher: &Matcher, scope: &Scope<'_>) -> (bool, Vec<String>) {
    let view = scope.view;
    let combine = |hits: Vec<Option<String>>| -> (bool, Vec<String>) {
        let matched = if matcher.and {
            !hits.is_empty() && hits.iter().all(Option::is_some)
        } else {
            hits.iter().any(Option::is_some)
        };
        (matched, hits.into_iter().flatten().collect())
    };
    match &matcher.kind {
        MatcherKind::Status(codes) => (codes.contains(&view.status), Vec::new()),
        MatcherKind::Size(sizes) => {
            let length = view
                .part_bytes(&matcher.part)
                .map_or(0, |bytes| bytes.len());
            (sizes.contains(&length), Vec::new())
        }
        MatcherKind::Words(words) => {
            let Some(corpus) = view.part_text(&matcher.part) else {
                return (false, Vec::new());
            };
            let corpus = if matcher.case_insensitive {
                Cow::Owned(corpus.to_lowercase())
            } else {
                corpus
            };
            combine(
                words
                    .iter()
                    .map(|word| {
                        let word = word.render(scope).ok()?;
                        let needle = if matcher.case_insensitive {
                            word.to_lowercase()
                        } else {
                            word.clone()
                        };
                        corpus.contains(needle.as_str()).then_some(word)
                    })
                    .collect(),
            )
        }
        MatcherKind::HexWords(words) | MatcherKind::Binary(words) => {
            let Some(corpus) = view.part_bytes(&matcher.part) else {
                return (false, Vec::new());
            };
            combine(
                words
                    .iter()
                    .map(|needle| {
                        contains_bytes(&corpus, needle)
                            .then(|| String::from_utf8_lossy(needle).into_owned())
                    })
                    .collect(),
            )
        }
        MatcherKind::Regex(patterns) => {
            let Some(corpus) = view.part_text(&matcher.part) else {
                return (false, Vec::new());
            };
            combine(
                patterns
                    .iter()
                    .map(|pattern| {
                        pattern
                            .find(&corpus)
                            .map(|found| found.as_str().to_string())
                    })
                    .collect(),
            )
        }
        MatcherKind::Dsl(items) => {
            let hits: Vec<bool> = items
                .iter()
                .map(|item| {
                    let value = match item {
                        DslItem::Static(expr) => expr.eval(scope).ok(),
                        DslItem::Rendered(interp, allow) => interp
                            .render(scope)
                            .ok()
                            .and_then(|filled| Expr::compile(&filled, *allow).ok())
                            .and_then(|expr| {
                                expr.eval(scope)
                                    .ok()
                                    .map(|v| matches!(v, Val::Bool(true)))
                                    .map(Val::Bool)
                            }),
                    };
                    matches!(value, Some(Val::Bool(true)))
                })
                .collect();
            let matched = if matcher.and {
                !hits.is_empty() && hits.iter().all(|hit| *hit)
            } else {
                hits.iter().any(|hit| *hit)
            };
            // An expression has no text of its own to show as evidence.
            (matched, Vec::new())
        }
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// The most values one extractor reports.
const MAX_EXTRACTED: usize = 20;

fn run_extractor(
    extractor: &Extractor,
    view: &ResponseView,
    dynamic: &HashMap<String, String>,
) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    let mut push = |value: String| {
        if values.len() < MAX_EXTRACTED && !value.is_empty() && !values.contains(&value) {
            values.push(value);
        }
    };
    match &extractor.kind {
        ExtractorKind::Regex { patterns, group } => {
            let Some(corpus) = view.part_text(&extractor.part) else {
                return Vec::new();
            };
            for pattern in patterns {
                for captures in pattern.captures_iter(&corpus) {
                    if let Some(value) = captures.get(*group) {
                        push(value.as_str().to_string());
                    }
                }
            }
        }
        ExtractorKind::Kval(keys) => {
            for key in keys {
                if let Some((_, value)) = view.header_vars.iter().find(|(name, _)| name == key) {
                    push(value.clone());
                } else if let Some((_, value)) = view.cookies.iter().find(|(name, _)| name == key) {
                    push(value.clone());
                }
            }
        }
        ExtractorKind::Dsl(expressions) => {
            let scope = Scope { view, dynamic };
            for expression in expressions {
                if let Ok(value) = expression.eval(&scope) {
                    push(value.text().into_owned());
                }
            }
        }
        ExtractorKind::Json(queries) => {
            let document = view
                .part_text(&extractor.part)
                .and_then(|corpus| serde_json::from_str::<serde_json::Value>(&corpus).ok());
            for query in queries {
                for value in document.iter().flat_map(|document| query.extract(document)) {
                    push(value);
                }
            }
        }
    }
    values
}

// ---- Passive sets ----

/// What must be in a response for a template to have any chance of
/// matching: one of these literals. None when that cannot be said, and the
/// template is always evaluated.
enum Need {
    Word {
        text: String,
        ascii_case_insensitive: bool,
    },
    Pattern {
        part: Part,
        source: String,
    },
}

fn matcher_needs(matcher: &Matcher) -> Option<Vec<Need>> {
    if matcher.negative {
        return None;
    }
    if !matches!(matcher.part, Part::Body | Part::Header | Part::All) {
        return None;
    }
    match &matcher.kind {
        MatcherKind::Words(words) => {
            let literals: Vec<&str> = words
                .iter()
                .map(|word| word.literal())
                .collect::<Option<_>>()?;
            // Nuclei folds case with Unicode rules; an ASCII-insensitive
            // search only covers ASCII words.
            if matcher.case_insensitive && literals.iter().any(|word| !word.is_ascii()) {
                return None;
            }
            let chosen: Vec<&str> = if matcher.and {
                vec![literals.iter().copied().max_by_key(|word| word.len())?]
            } else {
                literals
            };
            if chosen.iter().any(|word| word.is_empty()) {
                return None;
            }
            Some(
                chosen
                    .into_iter()
                    .map(|word| Need::Word {
                        text: if matcher.case_insensitive {
                            word.to_ascii_lowercase()
                        } else {
                            word.to_string()
                        },
                        ascii_case_insensitive: matcher.case_insensitive,
                    })
                    .collect(),
            )
        }
        MatcherKind::Regex(patterns) => {
            let chosen: Vec<&Arc<Regex>> = if matcher.and {
                vec![patterns.first()?]
            } else {
                patterns.iter().collect()
            };
            Some(
                chosen
                    .into_iter()
                    .map(|pattern| Need::Pattern {
                        part: matcher.part.clone(),
                        source: pattern.as_str().to_string(),
                    })
                    .collect(),
            )
        }
        _ => None,
    }
}

fn template_needs(template: &CompiledTemplate) -> Option<Vec<Need>> {
    let operators = &template.operators;
    if operators.matchers.is_empty() {
        return None;
    }
    if operators.and {
        // Any one matcher with a literal need is a need of the template.
        operators
            .matchers
            .iter()
            .filter_map(matcher_needs)
            .min_by_key(Vec::len)
    } else {
        let mut all = Vec::new();
        for matcher in &operators.matchers {
            all.extend(matcher_needs(matcher)?);
        }
        Some(all)
    }
}

/// The enabled passive templates, with a prefilter that picks the few that
/// could match a response in one pass over it.
pub struct PassiveSet {
    templates: Vec<Arc<CompiledTemplate>>,
    always: Vec<usize>,
    words: Option<(AhoCorasick, Vec<usize>)>,
    words_folded: Option<(AhoCorasick, Vec<usize>)>,
    patterns: Vec<(Part, RegexSet, Vec<usize>)>,
}

impl PassiveSet {
    pub fn new(templates: Vec<Arc<CompiledTemplate>>) -> Self {
        let mut always = Vec::new();
        let mut words: (Vec<String>, Vec<usize>) = (Vec::new(), Vec::new());
        let mut folded: (Vec<String>, Vec<usize>) = (Vec::new(), Vec::new());
        let mut patterns: Vec<(Part, Vec<String>, Vec<usize>)> = Vec::new();
        for (index, template) in templates.iter().enumerate() {
            let Some(needs) = template_needs(template) else {
                always.push(index);
                continue;
            };
            for need in needs {
                match need {
                    Need::Word {
                        text,
                        ascii_case_insensitive: false,
                    } => {
                        words.0.push(text);
                        words.1.push(index);
                    }
                    Need::Word { text, .. } => {
                        folded.0.push(text);
                        folded.1.push(index);
                    }
                    Need::Pattern { part, source } => {
                        match patterns.iter_mut().find(|(p, ..)| *p == part) {
                            Some((_, sources, owners)) => {
                                sources.push(source);
                                owners.push(index);
                            }
                            None => patterns.push((part, vec![source], vec![index])),
                        }
                    }
                }
            }
        }
        let automaton = |(texts, owners): (Vec<String>, Vec<usize>), fold: bool| {
            if texts.is_empty() {
                return None;
            }
            AhoCorasick::builder()
                .ascii_case_insensitive(fold)
                .match_kind(MatchKind::Standard)
                .build(&texts)
                .ok()
                .map(|automaton| (automaton, owners))
        };
        let mut built_patterns = Vec::new();
        for (part, sources, owners) in patterns {
            match RegexSet::new(&sources) {
                Ok(set) => built_patterns.push((part, set, owners)),
                // A set too large to build: its templates are evaluated on
                // every response instead.
                Err(_) => always.extend(owners),
            }
        }
        always.sort_unstable();
        always.dedup();
        Self {
            templates,
            always,
            words: automaton(words, false),
            words_folded: automaton(folded, true),
            patterns: built_patterns,
        }
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    /// The templates the prefilter cannot narrow, evaluated on every response.
    pub fn always_evaluated(&self) -> usize {
        self.always.len()
    }

    fn candidates(&self, view: &ResponseView) -> Vec<usize> {
        let mut selected = vec![false; self.templates.len()];
        for &index in &self.always {
            selected[index] = true;
        }
        for (automaton, owners) in self.words.iter().chain(self.words_folded.iter()) {
            for found in automaton.find_overlapping_iter(view.all_text.as_str()) {
                selected[owners[found.pattern().as_usize()]] = true;
            }
        }
        for (part, set, owners) in &self.patterns {
            if let Some(text) = view.part_text(part) {
                for pattern in set.matches(&text).iter() {
                    selected[owners[pattern]] = true;
                }
            }
        }
        selected
            .into_iter()
            .enumerate()
            .filter_map(|(index, keep)| keep.then_some(index))
            .collect()
    }

    pub fn scan(&self, view: &ResponseView) -> Vec<(Arc<CompiledTemplate>, TemplateMatch)> {
        let mut results = Vec::new();
        for index in self.candidates(view) {
            let template = &self.templates[index];
            for result in template.evaluate(view) {
                results.push((Arc::clone(template), result));
            }
        }
        results
    }

    #[cfg(test)]
    fn scan_without_prefilter(&self, view: &ResponseView) -> Vec<(String, TemplateMatch)> {
        self.templates
            .iter()
            .flat_map(|template| {
                template
                    .evaluate(view)
                    .into_iter()
                    .map(|result| (template.info.id.clone(), result))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::HeaderRecord;
    use crate::templates::model::{classify, parse};

    fn compiled(yaml: &str) -> CompiledTemplate {
        let parsed = parse(yaml).unwrap();
        let classification = classify(&parsed);
        compile_passive(&parsed, &classification).unwrap()
    }

    fn view(status: u16, headers: &[(&str, &str)], body: &str) -> ResponseView {
        let message = MessageRecord {
            headers: headers
                .iter()
                .map(|(name, value)| HeaderRecord {
                    name: name.to_string(),
                    value: value.to_string(),
                })
                .collect(),
            body_preview: body.to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: body.len(),
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let url = UrlVars {
            base_url: "https://example.com/app".into(),
            root_url: "https://example.com".into(),
            hostname: "example.com:443".into(),
            host: "example.com".into(),
            port: "443".into(),
            path: "".into(),
            file: "app".into(),
            scheme: "https".into(),
        };
        ResponseView::from_message(status, None, &message, 120, url, MAX_PASSIVE_BODY_BYTES)
    }

    #[test]
    fn json_extractors_read_the_body_with_jq() {
        let template = compiled(
            "id: example-json\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    extractors:\n      - type: json\n        json:\n          - '.version'\n          - '.plugins[] | select(.active) | .name'\n",
        );
        let found = template.evaluate(&view(
            200,
            &[("Content-Type", "application/json")],
            r#"{"version":"1.2.3","plugins":[{"name":"a","active":true},{"name":"b","active":false}]}"#,
        ));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].extracted, ["1.2.3", "a"]);
        // A body that is not JSON gives nothing.
        assert!(template.evaluate(&view(200, &[], "<html>")).is_empty());
    }

    #[test]
    fn a_favicon_hash_is_taken_over_the_bytes_the_server_sent() {
        let template = compiled(
            "id: example-favicon\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - type: dsl\n        dsl: ['mmh3(base64_py(body)) == \"-96116520\"']\n",
        );
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let icon = [0x00, 0xff, 0x10, 0x89, 0x50];
        let message = MessageRecord {
            headers: Vec::new(),
            body_preview: STANDARD.encode(icon),
            body_encoding: BodyEncoding::Base64,
            body_size: icon.len(),
            decoded_body_size: None,
            preview_truncated: false,
            content_type: Some("image/x-icon".into()),
            content_decoded: false,
        };
        let answer = ResponseView::from_message(
            200,
            None,
            &message,
            1,
            UrlVars::default(),
            MAX_PASSIVE_BODY_BYTES,
        );
        assert_eq!(template.evaluate(&answer).len(), 1);
    }

    #[test]
    fn a_callback_is_read_as_the_interactsh_parts() {
        let parsed = parse(
            "id: example-oast\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}/?u={{interactsh-url}}']\n    matchers-condition: and\n    matchers:\n      - type: word\n        part: interactsh_protocol\n        words: [dns]\n      - type: word\n        part: interactsh_request\n        words: ['example.com']\n      - type: status\n        status: [200]\n",
        )
        .unwrap();
        let template =
            crate::templates::active::compile_active(&parsed, &classify(&parsed), &HashMap::new())
                .unwrap()
                .blocks
                .remove(0)
                .template;
        let answer = || view(200, &[], "ok");
        assert!(template.evaluate(&answer()).is_empty(), "no callback yet");
        // Nuclei reads a DNS question in lower case.
        let callback = Interaction::new("dns", "EXAMPLE.COM. IN A", "192.0.2.1");
        assert_eq!(
            template
                .evaluate(&answer().with_interaction(callback))
                .len(),
            1
        );
    }

    #[test]
    fn and_needs_every_matcher_and_reports_once() {
        let template = compiled(
            "id: example-git\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers-condition: and\n    matchers:\n      - type: word\n        words: ['[core]', '[credentials]']\n      - type: dsl\n        dsl:\n          - \"!contains(tolower(body), '<html')\"\n      - type: status\n        status: [200]\n    extractors:\n      - type: regex\n        group: 1\n        regex: ['url = (\\S+)']\n",
        );
        let hit = template.evaluate(&view(
            200,
            &[],
            "[core]\n\turl = https://example.com/repo.git\n",
        ));
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].extracted, ["https://example.com/repo.git"]);
        assert_eq!(hit[0].snippets, ["[core]"]);
        assert!(template.evaluate(&view(404, &[], "[core]")).is_empty());
        assert!(template
            .evaluate(&view(200, &[], "<HTML>[core]"))
            .is_empty());
    }

    #[test]
    fn named_or_matchers_report_each_name() {
        let template = compiled(
            "id: example-waf\ninfo: {}\nhttp:\n  - global-matchers: true\n    matchers:\n      - type: regex\n        name: alpha\n        regex: ['(?i)alphawaf']\n        part: response\n      - type: word\n        name: beta\n        part: header\n        words: ['X-Beta']\n      - type: word\n        name: hidden\n        internal: true\n        words: ['zzz']\n",
        );
        let results = template.evaluate(&view(200, &[("x-beta", "1")], "AlphaWAF blocked"));
        let names: Vec<_> = results.iter().map(|r| r.matcher.clone()).collect();
        assert_eq!(names, [Some("alpha".to_string()), Some("beta".to_string())]);
        let internal_only = template.evaluate(&view(200, &[], "zzz"));
        assert_eq!(internal_only.len(), 1);
        assert_eq!(internal_only[0].matcher, None);
    }

    #[test]
    fn a_run_reads_earlier_answers_and_hands_on_internal_values() {
        let parsed = parse(
            "id: example-steps\ninfo: {}\nhttp:\n  - raw:\n      - |\n        GET /a HTTP/1.1\n      - |\n        GET /b?t={{token}} HTTP/1.1\n    extractors:\n      - type: regex\n        name: token\n        internal: true\n        group: 1\n        regex: ['token=(\\w+)']\n      - type: regex\n        name: shown\n        group: 1\n        regex: ['shown=(\\w+)']\n      - type: regex\n        name: second\n        internal: true\n        part: body_2\n        group: 1\n        regex: ['next=(\\w+)']\n    matchers:\n      - type: dsl\n        dsl:\n          - 'status_code_1 == 200 && contains(body_2, \"welcome\")'\n",
        )
        .unwrap();
        let template =
            crate::templates::active::compile_active(&parsed, &classify(&parsed), &HashMap::new())
                .unwrap()
                .blocks
                .remove(0)
                .template;
        let first =
            Arc::new(view(200, &[], "token=abc shown=x next=one").with_history(1, Vec::new()));
        let (results, carried) = template.evaluate_carrying(&first);
        // The first answer alone: body_2 is not there yet.
        assert!(results.is_empty());
        // Only named internal extractors hand values on, and one reading
        // body_2 only from the second request.
        assert_eq!(carried, [("token".to_string(), "abc".to_string())]);
        let second = view(200, &[], "welcome next=two").with_history(2, vec![Some(first)]);
        let (results, carried) = template.evaluate_carrying(&second);
        assert_eq!(results.len(), 1);
        assert_eq!(carried, [("second".to_string(), "two".to_string())]);
        assert_eq!(
            second.var("body_1").unwrap().text(),
            "token=abc shown=x next=one"
        );
        assert_eq!(second.var("status_code_2").unwrap(), Val::Num(200.0));
        // A request the run has not made reads as missing.
        assert!(second.var("body_3").is_none());
    }

    #[test]
    fn named_extractors_feed_matchers() {
        let template = compiled(
            "id: example-eol\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    extractors:\n      - type: regex\n        name: version\n        group: 1\n        internal: true\n        regex: ['Server: Example/([\\d.]+)']\n        part: header\n    matchers:\n      - type: dsl\n        dsl:\n          - 'compare_versions(version, \"< 2.0\")'\n",
        );
        assert_eq!(
            template
                .evaluate(&view(200, &[("server", "Example/1.9.3")], ""))
                .len(),
            1
        );
        assert!(template
            .evaluate(&view(200, &[("server", "Example/2.1")], ""))
            .is_empty());
        // No version at all: the expression errors, which is not a match.
        assert!(template.evaluate(&view(200, &[], "")).is_empty());
    }

    #[test]
    fn header_variables_and_kval_follow_nuclei_names() {
        let template = compiled(
            "id: example-kval\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - type: word\n        part: x_powered_by\n        words: ['PHP']\n    extractors:\n      - type: kval\n        kval: [x_powered_by, session-id]\n",
        );
        let results = template.evaluate(&view(
            200,
            &[
                ("X-Powered-By", "PHP/8.1"),
                ("set-cookie", "session-id=abc; Path=/"),
            ],
            "",
        ));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].extracted, ["PHP/8.1", "abc"]);
        let header = view(
            200,
            &[("content-type", "text/html"), ("x-a", "1"), ("X-A", "2")],
            "",
        );
        assert_eq!(
            header.header_text,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-A: 1\r\nX-A: 2\r\n"
        );
        assert_eq!(header.var("x_a"), Some(Val::Str(Cow::Borrowed("1 2"))));
    }

    #[test]
    fn negation_case_folding_and_binary() {
        let template = compiled(
            "id: example-misc\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers-condition: and\n    matchers:\n      - type: word\n        case-insensitive: true\n        words: ['WELCOME']\n      - type: word\n        negative: true\n        words: ['denied']\n      - type: binary\n        binary: ['3c6831']\n",
        );
        assert_eq!(
            template.evaluate(&view(200, &[], "<h1>welcome</h1>")).len(),
            1
        );
        assert!(template
            .evaluate(&view(200, &[], "<h1>welcome</h1> denied"))
            .is_empty());
    }

    #[test]
    fn a_truncated_body_skips_templates_it_could_fool() {
        let template = compiled(
            "id: example-neg\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - type: word\n        negative: true\n        words: ['footer']\n",
        );
        let mut truncated = view(200, &[], "header only");
        assert_eq!(template.evaluate(&truncated).len(), 1);
        truncated.truncated = true;
        assert!(template.evaluate(&truncated).is_empty());
    }

    #[test]
    fn markers_read_the_requests_url() {
        let template = compiled(
            "id: example-host\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - type: word\n        words: ['{{Host}}/login']\n",
        );
        assert_eq!(
            template
                .evaluate(&view(200, &[], "go to example.com/login"))
                .len(),
            1
        );
    }

    #[test]
    fn prefiltered_scans_equal_full_evaluation() {
        let sources = [
            "id: t-and\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers-condition: and\n    matchers:\n      - type: word\n        words: ['alpha', 'beta']\n        condition: and\n      - type: status\n        status: [200]\n",
            "id: t-or\ninfo: {}\nhttp:\n  - global-matchers: true\n    matchers:\n      - type: word\n        case-insensitive: true\n        words: ['GAMMA']\n      - type: regex\n        part: header\n        regex: ['^HTTP/1.1 50[0-9]']\n",
            "id: t-neg\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - type: word\n        negative: true\n        words: ['delta']\n",
            "id: t-dsl\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - type: dsl\n        dsl: ['len(body) == 5']\n",
            "id: t-regex\ninfo: {}\nhttp:\n  - global-matchers: true\n    matchers:\n      - type: regex\n        regex: ['\\Aalpha', 'eps[a-z]lon']\n",
        ];
        let set = PassiveSet::new(
            sources
                .iter()
                .map(|source| Arc::new(compiled(source)))
                .collect(),
        );
        assert!(set.always_evaluated() >= 2);
        let words = [
            "alpha", "beta", "gamma", "GaMmA", "delta", "epsilon", "x", " ",
        ];
        let mut checked = 0;
        for seed in 0u64..400 {
            let mut state = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let body: String = (0..(next() % 6))
                .map(|_| words[(next() % words.len() as u64) as usize])
                .collect::<Vec<_>>()
                .join(" ");
            let status = [200, 404, 503][(next() % 3) as usize];
            let response = view(
                status,
                &[("server", words[(next() % words.len() as u64) as usize])],
                &body,
            );
            let prefiltered: Vec<(String, TemplateMatch)> = set
                .scan(&response)
                .into_iter()
                .map(|(template, result)| (template.info.id.clone(), result))
                .collect();
            let mut full = set.scan_without_prefilter(&response);
            let mut prefiltered = prefiltered;
            full.sort_by(|a, b| a.0.cmp(&b.0));
            prefiltered.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(prefiltered, full, "body {body:?} status {status}");
            checked += full.len();
        }
        assert!(
            checked > 100,
            "the generated responses should match often: {checked}"
        );
    }
}
