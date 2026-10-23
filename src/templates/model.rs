//! Reading a Nuclei template and deciding what Sniper can do with it.
//!
//! A template is untrusted YAML from a public repository. It is parsed with
//! budget limits into a generic value, its metadata is read leniently, and
//! everything that would change what is sent or how a response is judged is
//! checked against an allow-list. Anything not on it makes the template
//! unsupported with a stated reason: running part of a template would report
//! results its author never wrote.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::dsl;

/// Larger files are skipped at import. The largest community template is a
/// fraction of this; the cap bounds what one file can make the parser do.
pub const MAX_TEMPLATE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub code: &'static str,
    pub detail: String,
}

impl ParseError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// The `info` block, read leniently: it is shown, never executed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TemplateInfo {
    pub id: String,
    pub name: String,
    pub authors: Vec<String>,
    /// info, low, medium, high, critical or unknown.
    pub severity: String,
    pub description: String,
    pub tags: Vec<String>,
    pub references: Vec<String>,
    pub cve: Vec<String>,
    pub cwe: Vec<String>,
    pub cvss_score: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct ParsedTemplate {
    pub info: TemplateInfo,
    pub root: Map<String, Value>,
}

pub fn parse(text: &str) -> Result<ParsedTemplate, ParseError> {
    if text.len() > MAX_TEMPLATE_BYTES {
        return Err(ParseError::new(
            "too_large",
            format!("{} bytes", text.len()),
        ));
    }
    // Snippets would echo template text into every error; the code and
    // position are enough to find it.
    let options = serde_saphyr::options! { with_snippet: false };
    let value: Value = serde_saphyr::from_str_with_options(text, options)
        .map_err(|error| ParseError::new("yaml", error.to_string()))?;
    let Value::Object(root) = value else {
        return Err(ParseError::new("not_a_mapping", ""));
    };
    let id = root
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| ParseError::new("missing_id", ""))?;
    if !valid_id(id) {
        return Err(ParseError::new("invalid_id", id));
    }
    let Some(Value::Object(info)) = root.get("info") else {
        return Err(ParseError::new("missing_info", ""));
    };
    let info = read_info(id, info);
    Ok(ParsedTemplate { info, root })
}

/// Nuclei's own rule for template ids (`^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$`).
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 200
        && id
            .split(['-', '_'])
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn read_info(id: &str, info: &Map<String, Value>) -> TemplateInfo {
    let text = |key: &str| info.get(key).map(scalar_text).unwrap_or_default();
    let classification = info.get("classification").and_then(Value::as_object);
    let severity = text("severity").trim().to_ascii_lowercase();
    TemplateInfo {
        id: id.to_string(),
        name: text("name").trim().to_string(),
        authors: list_or_csv(info.get("author")),
        severity: match severity.as_str() {
            "info" | "low" | "medium" | "high" | "critical" => severity,
            _ => "unknown".into(),
        },
        description: text("description").trim().to_string(),
        tags: list_or_csv(info.get("tags")),
        references: list_or_csv(info.get("reference")),
        cve: list_or_csv(classification.and_then(|c| c.get("cve-id"))),
        cwe: list_or_csv(classification.and_then(|c| c.get("cwe-id"))),
        cvss_score: classification.and_then(|c| c.get("cvss-score")).and_then(
            |score| match score {
                Value::Number(number) => number.as_f64(),
                Value::String(text) => text.trim().parse().ok(),
                _ => None,
            },
        ),
    }
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        _ => String::new(),
    }
}

/// Authors, tags and references come as a list or as one comma-separated
/// string; ids are case-insensitive in Nuclei, tags lowercased.
fn list_or_csv(value: Option<&Value>) -> Vec<String> {
    let mut items: Vec<String> = match value {
        Some(Value::Array(items)) => items.iter().map(scalar_text).collect(),
        Some(Value::String(text)) => text.split(',').map(str::to_string).collect(),
        Some(other @ Value::Number(_)) => vec![scalar_text(other)],
        _ => Vec::new(),
    };
    items
        .iter_mut()
        .for_each(|item| *item = item.trim().to_string());
    items.retain(|item| !item.is_empty());
    items
}

/// How a template can be applied without sending anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PassiveKind {
    /// `global-matchers: true`: matchers meant for every HTTP response.
    Global,
    /// One `GET {{BaseURL}}` request: its matchers can judge a captured GET
    /// response as if the template had sent it, as Nuclei's passive mode does.
    BaseUrlGet,
}

#[derive(Clone, Debug, Default)]
pub struct Classification {
    pub protocol: &'static str,
    pub blocks: usize,
    /// Set when the template's shape allows passive use; the reasons below
    /// say whether Sniper can evaluate it.
    pub passive: Option<PassiveKind>,
    pub passive_reasons: BTreeSet<String>,
    /// Empty when the template can run as an active scan.
    pub active_reasons: BTreeSet<String>,
    pub functions: BTreeSet<String>,
    pub risks: BTreeSet<String>,
    /// Its requests carry `{{interactsh-url}}`: a scan sends it only where
    /// the session has an Interactsh server to hear the callback.
    pub oast: bool,
}

/// What a callback said, as Nuclei names it for matchers.
pub(super) const INTERACTION_PARTS: &[&str] = &[
    "interactsh_protocol",
    "interactsh_request",
    "interactsh_response",
    "interactsh_ip",
];

/// Markers a scan fills from the session's OAST server.
const OAST_MARKERS: &[&str] = &["interactsh-url", "interactsh-server"];

impl Classification {
    pub fn passive_supported(&self) -> bool {
        self.passive.is_some() && self.passive_reasons.is_empty()
    }

    pub fn active_supported(&self) -> bool {
        self.active_reasons.is_empty()
    }
}

/// Protocol keys other than HTTP. Their templates are listed, never run:
/// code and javascript execute on this machine, the rest open sockets Sniper
/// cannot scope or record.
const OTHER_PROTOCOLS: &[(&str, &str)] = &[
    ("dns", "dns"),
    ("file", "file"),
    ("network", "network"),
    ("tcp", "network"),
    ("ssl", "ssl"),
    ("headless", "headless"),
    ("code", "code"),
    ("javascript", "javascript"),
    ("websocket", "websocket"),
    ("whois", "whois"),
    ("workflows", "workflow"),
];

/// Root keys that change nothing about execution.
const ROOT_KEYS: &[&str] = &["id", "info", "http", "requests", "variables"];

/// Request keys that change nothing Sniper does: request names and limits
/// Sniper applies on its own.
const INERT_REQUEST_KEYS: &[&str] = &[
    "id",
    "name",
    "max-size",
    "read-all",
    "threads",
    "skip-variables-check",
];

/// Request keys of features planned for later milestones, by reason code.
const LATER_REQUEST_KEYS: &[(&str, &str)] = &[
    ("iterate-all", "req:iterate_all"),
    ("fuzzing", "req:fuzzing"),
    ("pre-condition", "req:fuzzing"),
    ("analyzer", "req:fuzzing"),
    ("race", "req:race"),
    ("race_count", "req:race"),
    ("pipeline", "req:pipeline"),
    ("pipeline-concurrent-connections", "req:pipeline"),
    ("pipeline-requests-per-connection", "req:pipeline"),
    ("unsafe", "req:unsafe"),
    ("digest-username", "req:digest_auth"),
    ("digest-password", "req:digest_auth"),
    ("signature", "req:signature"),
];

const MATCHER_KEYS: &[&str] = &[
    "type",
    "name",
    "part",
    "condition",
    "negative",
    "internal",
    "case-insensitive",
    "encoding",
    "match-all",
    "words",
    "regex",
    "status",
    "size",
    "binary",
    "dsl",
];

const EXTRACTOR_KEYS: &[&str] = &[
    "type",
    "name",
    "part",
    "regex",
    "group",
    "kval",
    "json",
    "dsl",
    "internal",
    "case-insensitive",
];

/// Tags whose templates change data, guess credentials, attack availability
/// or reach third parties. An active scan excludes them unless each is named.
pub const RISK_TAGS: &[&str] = &[
    "intrusive",
    "dos",
    "default-login",
    "bruteforce",
    "token-spray",
    "credential-stuffing",
    "fuzz",
    "fuzzing",
    "dast",
    "osint",
];

/// Variables Sniper fills from the target or the captured request.
const BUILTIN_VARIABLES: &[&str] = &[
    "BaseURL", "RootURL", "Hostname", "Host", "Port", "Path", "File", "Scheme",
];

pub fn classify(template: &ParsedTemplate) -> Classification {
    let mut out = Classification {
        protocol: "http",
        ..Classification::default()
    };
    let root = &template.root;

    for tag in &template.info.tags {
        let tag = tag.to_ascii_lowercase();
        if RISK_TAGS.contains(&tag.as_str()) {
            out.risks.insert(tag);
        }
    }

    let others: Vec<&str> = OTHER_PROTOCOLS
        .iter()
        .filter(|(key, _)| root.contains_key(*key))
        .map(|(_, name)| *name)
        .collect();
    let http = root.get("http").or_else(|| root.get("requests"));
    if let Some(first) = others.first() {
        out.protocol = first;
        both(&mut out, format!("protocol:{first}"));
    }
    if root.contains_key("http") && root.contains_key("requests") {
        both(&mut out, "root:http_and_requests".into());
    }
    for key in root.keys() {
        if ROOT_KEYS.contains(&key.as_str()) || OTHER_PROTOCOLS.iter().any(|(k, _)| k == key) {
            continue;
        }
        let reason = match key.as_str() {
            // Captured traffic never runs a flow; Template Scan sends one
            // that joins block calls, checked once the blocks are known.
            "flow" => {
                out.passive_reasons.insert("flow".into());
                continue;
            }
            "self-contained" => "self_contained".to_string(),
            other => format!("root:{other}"),
        };
        both(&mut out, reason);
    }
    let Some(http) = http else {
        if others.is_empty() {
            out.protocol = "none";
            both(&mut out, "protocol:none".into());
        }
        return out;
    };
    let Some(blocks) = http.as_array() else {
        both(&mut out, "http:not_a_list".into());
        return out;
    };
    out.blocks = blocks.len();
    if blocks.is_empty() {
        both(&mut out, "http:empty".into());
        return out;
    }
    let declared: BTreeSet<String> = match root.get("variables") {
        Some(Value::Object(variables)) => variables.keys().cloned().collect(),
        Some(_) => {
            both(&mut out, "variables:not_a_mapping".into());
            BTreeSet::new()
        }
        None => BTreeSet::new(),
    };
    if !declared.is_empty() {
        out.passive_reasons.insert("variables".into());
    }
    // Variables are worked out before the request is sent, from the target
    // and each other; a name that is neither would stay unresolved.
    if let Some(Value::Object(variables)) = root.get("variables") {
        for (name, value) in variables {
            let text = scalar_text(value);
            // `name: '{{name}}'` leaves the value to whoever runs the
            // template, as `nuclei -var name=…` would give it.
            if dsl::markers(&text).contains(&name.as_str()) {
                out.active_reasons.insert(format!("var:{name}"));
            }
            check_template_text(&mut out, &text, &declared, true);
        }
    }

    // A named internal extractor's first value fills the run's later
    // requests, as Nuclei hands it on.
    let mut declared = declared;
    for block in blocks.iter().filter_map(Value::as_object) {
        for extractor in block
            .get("extractors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if extractor.get("internal") == Some(&Value::Bool(true)) {
                if let Some(name) = extractor.get("name").map(scalar_text) {
                    declared.insert(name.trim().to_string());
                }
            }
        }
        // So does each payload set's value, pass by pass.
        declared.extend(
            used_payload_sets(block)
                .into_iter()
                .map(|(name, _)| name.clone()),
        );
    }

    for (index, block) in blocks.iter().enumerate() {
        let Some(block) = block.as_object() else {
            both(&mut out, "http:block_not_a_mapping".into());
            continue;
        };
        if index == 0 {
            out.passive = passive_shape(block, blocks.len());
        }
        check_block(&mut out, block, &declared);
    }
    if let Some(flow) = root.get("flow") {
        let ids: Vec<Option<String>> = blocks
            .iter()
            .map(|block| block.get("id").map(scalar_text))
            .collect();
        if super::flow::compile(&scalar_text(flow), &ids).is_err() {
            out.active_reasons.insert("flow".into());
        }
    }
    if out.passive.is_none() {
        out.passive_reasons.clear();
    }
    out
}

fn both(out: &mut Classification, reason: String) {
    out.passive_reasons.insert(reason.clone());
    out.active_reasons.insert(reason);
}

/// Whether the template, by its shape alone, can judge a response it did not
/// send.
fn passive_shape(block: &Map<String, Value>, blocks: usize) -> Option<PassiveKind> {
    if blocks != 1 {
        return None;
    }
    if block.get("global-matchers") == Some(&Value::Bool(true)) {
        return (!block.contains_key("path") && !block.contains_key("raw"))
            .then_some(PassiveKind::Global);
    }
    let method = block.get("method").map(scalar_text).unwrap_or_default();
    if !(method.is_empty() || method.eq_ignore_ascii_case("GET")) {
        return None;
    }
    let paths = block.get("path")?.as_array()?;
    let base_only = !paths.is_empty()
        && paths.iter().all(|path| {
            matches!(
                path.as_str().map(str::trim),
                Some("{{BaseURL}}" | "{{BaseURL}}/")
            )
        });
    base_only.then_some(PassiveKind::BaseUrlGet)
}

fn check_block(out: &mut Classification, block: &Map<String, Value>, declared: &BTreeSet<String>) {
    let global = block.get("global-matchers") == Some(&Value::Bool(true));
    if global {
        // Global matchers judge other templates' responses and send nothing:
        // there is no request to run actively.
        out.active_reasons.insert("global_matchers".into());
    }
    for (key, value) in block {
        let key = key.as_str();
        if INERT_REQUEST_KEYS.contains(&key) {
            continue;
        }
        if let Some((_, reason)) = LATER_REQUEST_KEYS.iter().find(|(k, _)| *k == key) {
            // A false flag is the default and changes nothing.
            if value == &Value::Bool(false) {
                continue;
            }
            out.passive_reasons.insert((*reason).to_string());
            out.active_reasons.insert((*reason).to_string());
            continue;
        }
        match key {
            "global-matchers" | "matchers-condition" | "stop-at-first-match" => {}
            // A run keeps its cookies unless told not to, and its earlier
            // answers when its matchers read them: `cookie-reuse` and
            // `req-condition` ask for what Nuclei now does anyway.
            "disable-cookie" | "cookie-reuse" | "req-condition" => {}
            // An active scan follows them while they stay in Scope. Captured
            // traffic already followed whatever redirects the client did, each
            // hop its own response, so a passive template judges every hop.
            "redirects" | "host-redirects" | "max-redirects" => {}
            "method" => check_method(out, &scalar_text(value)),
            "path" => check_paths(out, value, declared),
            "raw" => check_raw(out, block, value, declared),
            "payloads" => check_payloads(out, block, value, declared),
            "attack" => {
                let attack = scalar_text(value).trim().to_ascii_lowercase();
                if !matches!(
                    attack.as_str(),
                    "batteringram" | "pitchfork" | "clusterbomb"
                ) {
                    out.active_reasons.insert("req:attack".into());
                }
            }
            "headers" => {
                out.passive_reasons.insert("req:headers".into());
                match value.as_object() {
                    Some(headers) => {
                        for (name, value) in headers {
                            let text = scalar_text(value);
                            if name.eq_ignore_ascii_case("host") && text.trim() != "{{Hostname}}" {
                                out.active_reasons.insert("req:host_header".into());
                            }
                            check_template_text(out, &text, declared, true);
                        }
                    }
                    None => {
                        out.active_reasons.insert("req:headers".into());
                    }
                }
            }
            "body" => {
                out.passive_reasons.insert("req:body".into());
                check_template_text(out, &scalar_text(value), declared, true);
            }
            "matchers" => check_matchers(out, value, declared),
            "extractors" => check_extractors(out, value),
            other => {
                let reason = format!("req:{other}");
                out.passive_reasons.insert(reason.clone());
                out.active_reasons.insert(reason);
            }
        }
    }
}

fn check_method(out: &mut Classification, method: &str) {
    let method = method.to_ascii_uppercase();
    if !method
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b == b'-' || b == b'_')
        || method.is_empty()
        || method == "CONNECT"
    {
        out.active_reasons.insert("req:method".into());
    } else if matches!(method.as_str(), "PUT" | "DELETE" | "PATCH") {
        out.risks
            .insert(format!("method:{}", method.to_ascii_lowercase()));
    }
}

/// Raw requests are read as Nuclei reads them, with their markers still in.
/// The target supplies the host, so Host may only be the target's, and an
/// annotation may only set a timeout.
fn check_raw(
    out: &mut Classification,
    block: &Map<String, Value>,
    value: &Value,
    declared: &BTreeSet<String>,
) {
    // Nuclei sends the paths instead when both are set, and lays the block's
    // headers and body over the raw ones.
    if ["path", "method", "headers", "body"]
        .iter()
        .any(|key| block.contains_key(*key))
    {
        out.active_reasons.insert("req:raw_mixed".into());
    }
    let Some(requests) = value.as_array().filter(|requests| !requests.is_empty()) else {
        out.active_reasons.insert("req:raw".into());
        return;
    };
    for request in requests {
        let Some(text) = request.as_str() else {
            out.active_reasons.insert("req:raw".into());
            continue;
        };
        check_template_text(out, text, declared, true);
        if super::active::raw_timeout(text).is_none() {
            out.active_reasons.insert("req:raw_annotation".into());
        }
        let Some(raw) = super::active::read_raw(text, &dsl::masked(text)) else {
            out.active_reasons.insert("req:raw".into());
            continue;
        };
        check_method(out, raw.method);
        if raw
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("host") && *value != "{{Hostname}}")
        {
            out.active_reasons.insert("req:host_header".into());
        }
    }
}

/// The payload sets a request block uses, in the order it lists them.
/// Nuclei drops a set that no request part or operator names before it
/// counts them.
pub(super) fn used_payload_sets(block: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let Some(Value::Object(sets)) = block.get("payloads") else {
        return Vec::new();
    };
    let named: String = [
        "headers",
        "matchers",
        "extractors",
        "body",
        "path",
        "raw",
        "fuzzing",
    ]
    .iter()
    .filter_map(|key| block.get(*key))
    .map(Value::to_string)
    .collect();
    sets.iter()
        .filter(|(name, _)| named.contains(name.as_str()))
        .collect()
}

/// A payload file's path inside the release, as templates name them
/// (`helpers/wordlists/users.txt`): `./` and empty parts dropped. None when it
/// is absolute or climbs out with `..`.
pub(super) fn helper_path(path: &str) -> Option<String> {
    let path = path.trim();
    if path.starts_with('/') || path.contains('\\') {
        return None;
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            part => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Payload values run as Nuclei combines them, written in the template or
/// read from a file of the release; a fuzzing aggression level does not yet.
fn check_payloads(
    out: &mut Classification,
    block: &Map<String, Value>,
    value: &Value,
    declared: &BTreeSet<String>,
) {
    out.passive_reasons.insert("req:payloads".into());
    if !value.is_object() {
        out.active_reasons.insert("req:payloads".into());
        return;
    }
    let sets = used_payload_sets(block);
    let attack = block
        .get("attack")
        .map(scalar_text)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    // Nuclei's default attack, batteringram, takes a single set.
    if sets.len() > 1 && matches!(attack.as_str(), "" | "batteringram") {
        out.active_reasons.insert("req:payloads".into());
    }
    for (_, values) in sets {
        match values {
            Value::Array(items) if !items.is_empty() => {
                for item in items {
                    check_template_text(out, &scalar_text(item), declared, true);
                }
            }
            Value::String(text) if text.contains('\n') => {
                for line in text.split('\n') {
                    check_template_text(out, line, declared, true);
                }
            }
            // A file of the release, which the library looks up; a path
            // that could leave the release is never read.
            Value::String(path) => {
                if helper_path(path).is_none() {
                    out.active_reasons.insert("req:payload_file".into());
                }
            }
            Value::Object(_) => {
                out.active_reasons.insert("req:payload_aggression".into());
            }
            _ => {
                out.active_reasons.insert("req:payloads".into());
            }
        }
    }
}

fn check_paths(out: &mut Classification, value: &Value, declared: &BTreeSet<String>) {
    let Some(paths) = value.as_array() else {
        out.active_reasons.insert("req:path".into());
        return;
    };
    for path in paths {
        let path = scalar_text(path);
        let trimmed = path.trim_start();
        // The target supplies scheme, host and port; a template may only add
        // to the path, so it can never point a scan somewhere else.
        if !(trimmed.starts_with("{{BaseURL}}") || trimmed.starts_with("{{RootURL}}")) {
            out.active_reasons.insert("req:path_not_base".into());
        }
        check_template_text(out, &path, declared, true);
    }
}

/// Checks the `{{…}}` markers of request text, or of a variable's value.
fn check_template_text(
    out: &mut Classification,
    text: &str,
    declared: &BTreeSet<String>,
    request: bool,
) {
    for marker in dsl::markers(text) {
        if BUILTIN_VARIABLES.contains(&marker) || declared.contains(marker) {
            continue;
        }
        if marker == "randstr" || marker.strip_prefix("randstr_").is_some_and(is_digits) {
            out.passive_reasons.insert("randomness".into());
            continue;
        }
        if marker.starts_with("interactsh") {
            // A captured response never carries a callback; a scan can ask
            // for one.
            out.passive_reasons.insert("oast".into());
            if !OAST_MARKERS.contains(&marker) {
                out.active_reasons.insert("oast".into());
            } else if request && marker == "interactsh-url" {
                out.oast = true;
            }
            continue;
        }
        if marker.contains("{{") {
            check_template_text(out, marker, declared, request);
            check_expression(out, &dsl::without_markers(marker), request, declared);
        } else {
            check_expression(out, marker, request, declared);
        }
    }
}

fn check_expression(
    out: &mut Classification,
    expression: &str,
    request: bool,
    declared: &BTreeSet<String>,
) {
    let tokens = match dsl::tokenize(expression) {
        Ok(tokens) => tokens,
        Err(error) => {
            let reason = format!("dsl:{}", error.reason);
            out.passive_reasons.insert(reason.clone());
            out.active_reasons.insert(reason);
            return;
        }
    };
    let (functions, variables) = dsl::names(&tokens);
    for function in functions {
        match dsl::function_kind(&function) {
            Some(dsl::FuncKind::Pure) => {}
            // A random value is one the template sent; a captured response
            // cannot contain it.
            Some(dsl::FuncKind::Random) => {
                out.passive_reasons.insert("randomness".into());
            }
            None => {
                out.passive_reasons.insert(format!("fn:{function}"));
                out.active_reasons.insert(format!("fn:{function}"));
            }
        }
        out.functions.insert(function);
    }
    for variable in variables {
        if variable.starts_with("interactsh") {
            out.passive_reasons.insert("oast".into());
            if !INTERACTION_PARTS.contains(&variable.as_str()) {
                out.active_reasons.insert("oast".into());
            }
        } else if variable
            .rsplit_once('_')
            .is_some_and(|(_, suffix)| is_digits(suffix))
        {
            // An earlier answer (`body_1`) is there for a scan's matchers,
            // never for a request or a captured response.
            out.passive_reasons.insert("multi_request".into());
            if request {
                out.active_reasons.insert("multi_request".into());
            }
        } else if request
            && !BUILTIN_VARIABLES.contains(&variable.as_str())
            && !declared.contains(&variable)
        {
            // A bare name in a request is a payload or a user variable; with
            // neither declared it would stay unresolved.
            out.active_reasons.insert(format!("var:{variable}"));
        }
    }
}

fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

fn check_part(out: &mut Classification, part: Option<&Value>) {
    let Some(part) = part else { return };
    let part = scalar_text(part);
    match part.as_str() {
        "body" | "header" | "all_headers" | "all" | "response" | "raw" => {}
        "request" => {
            out.passive_reasons.insert("part:request".into());
        }
        p if p.starts_with("interactsh") => {
            out.passive_reasons.insert("oast".into());
            if !INTERACTION_PARTS.contains(&p) {
                out.active_reasons.insert("oast".into());
            }
        }
        p if p
            .rsplit_once('_')
            .is_some_and(|(_, suffix)| is_digits(suffix)) =>
        {
            out.passive_reasons.insert("multi_request".into());
        }
        p if !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()) => {}
        _ => {
            out.passive_reasons.insert("part:unknown".into());
            out.active_reasons.insert("part:unknown".into());
        }
    }
}

fn check_matchers(out: &mut Classification, value: &Value, declared: &BTreeSet<String>) {
    let Some(matchers) = value.as_array() else {
        out.passive_reasons.insert("matchers:not_a_list".into());
        out.active_reasons.insert("matchers:not_a_list".into());
        return;
    };
    for matcher in matchers {
        let Some(matcher) = matcher.as_object() else {
            out.passive_reasons.insert("matcher:not_a_mapping".into());
            out.active_reasons.insert("matcher:not_a_mapping".into());
            continue;
        };
        let mut reasons = BTreeSet::new();
        for key in matcher.keys() {
            if !MATCHER_KEYS.contains(&key.as_str()) {
                reasons.insert(format!("matcher:{key}"));
            }
        }
        match matcher.get("type").map(scalar_text).as_deref() {
            Some("word" | "regex" | "status" | "size" | "binary") => {
                for key in ["words", "regex"] {
                    for value in matcher
                        .get(key)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        check_template_text(out, &scalar_text(value), declared, false);
                    }
                }
            }
            Some("dsl") => {
                for expression in matcher
                    .get("dsl")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let expression = scalar_text(expression);
                    check_template_text(out, &expression, declared, false);
                    check_expression(out, &dsl::without_markers(&expression), false, declared);
                }
            }
            Some(other) => {
                reasons.insert(format!("matcher:{other}"));
            }
            None => {
                reasons.insert("matcher:no_type".into());
            }
        }
        if let Some(encoding) = matcher.get("encoding") {
            if scalar_text(encoding) != "hex" {
                reasons.insert("matcher:encoding".into());
            }
        }
        check_part(out, matcher.get("part"));
        for reason in reasons {
            out.passive_reasons.insert(reason.clone());
            out.active_reasons.insert(reason);
        }
    }
}

fn check_extractors(out: &mut Classification, value: &Value) {
    let Some(extractors) = value.as_array() else {
        out.passive_reasons.insert("extractors:not_a_list".into());
        out.active_reasons.insert("extractors:not_a_list".into());
        return;
    };
    for extractor in extractors {
        let Some(extractor) = extractor.as_object() else {
            out.passive_reasons.insert("extractor:not_a_mapping".into());
            out.active_reasons.insert("extractor:not_a_mapping".into());
            continue;
        };
        let mut reasons = BTreeSet::new();
        for key in extractor.keys() {
            if !EXTRACTOR_KEYS.contains(&key.as_str()) {
                reasons.insert(format!("extractor:{key}"));
            }
        }
        match extractor.get("type").map(scalar_text).as_deref() {
            // A json query is checked when the template compiles.
            Some("regex" | "kval" | "json") => {}
            Some("dsl") => {
                for expression in extractor
                    .get("dsl")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    check_expression(out, &scalar_text(expression), false, &BTreeSet::new());
                }
            }
            Some(other) => {
                reasons.insert(format!("extractor:{other}"));
            }
            None => {
                reasons.insert("extractor:no_type".into());
            }
        }
        check_part(out, extractor.get("part"));
        for reason in reasons {
            out.passive_reasons.insert(reason.clone());
            out.active_reasons.insert(reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_text(text: &str) -> Classification {
        classify(&parse(text).unwrap())
    }

    #[test]
    fn reads_info_leniently() {
        let parsed = parse(
            "id: example-check\ninfo:\n  name: ' Example '\n  author: a, b\n  severity: HIGH\n  tags: x,Y\n  reference: https://example.com/advisory\n  classification:\n    cve-id: CVE-2024-0001\n    cvss-score: '7.5'\nhttp: []\n",
        )
        .unwrap();
        assert_eq!(parsed.info.name, "Example");
        assert_eq!(parsed.info.authors, ["a", "b"]);
        assert_eq!(parsed.info.severity, "high");
        assert_eq!(parsed.info.tags, ["x", "Y"]);
        assert_eq!(parsed.info.references, ["https://example.com/advisory"]);
        assert_eq!(parsed.info.cve, ["CVE-2024-0001"]);
        assert_eq!(parsed.info.cvss_score, Some(7.5));
        let unknown = parse("id: a\ninfo:\n  severity: weird\n").unwrap();
        assert_eq!(unknown.info.severity, "unknown");
    }

    #[test]
    fn rejects_documents_it_cannot_identify() {
        assert_eq!(parse("- a\n").unwrap_err().code, "not_a_mapping");
        assert_eq!(parse("info: {}\n").unwrap_err().code, "missing_id");
        assert_eq!(
            parse("id: '../x'\ninfo: {}\n").unwrap_err().code,
            "invalid_id"
        );
        assert_eq!(parse("id: a\n").unwrap_err().code, "missing_info");
        assert_eq!(parse("id: a\nid: b\ninfo: {}\n").unwrap_err().code, "yaml");
        let large = format!("id: a\ninfo: {{}}\n#{}", "x".repeat(MAX_TEMPLATE_BYTES));
        assert_eq!(parse(&large).unwrap_err().code, "too_large");
    }

    #[test]
    fn a_base_url_get_template_runs_both_ways() {
        let classified = classify_text(
            "id: example-detect\ninfo:\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}'\n    matchers-condition: and\n    matchers:\n      - type: word\n        part: header\n        words: [example]\n      - type: dsl\n        dsl:\n          - \"status_code == 200 && !contains(tolower(body), '<html')\"\n",
        );
        assert_eq!(classified.passive, Some(PassiveKind::BaseUrlGet));
        assert!(
            classified.passive_supported(),
            "{:?}",
            classified.passive_reasons
        );
        assert!(
            classified.active_supported(),
            "{:?}",
            classified.active_reasons
        );
        assert_eq!(
            classified
                .functions
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["contains", "tolower"]
        );
    }

    #[test]
    fn global_matchers_are_passive_only() {
        let classified = classify_text(
            "id: example-global\ninfo: {}\nhttp:\n  - global-matchers: true\n    matchers:\n      - type: regex\n        regex: ['(?i)example']\n",
        );
        assert_eq!(classified.passive, Some(PassiveKind::Global));
        assert!(classified.passive_supported());
        assert!(classified.active_reasons.contains("global_matchers"));
    }

    #[test]
    fn unsupported_constructs_are_named() {
        let classified = classify_text(
            "id: example-cve\ninfo:\n  tags: cve,intrusive\nhttp:\n  - path: ['{{BaseURL}}/?c={{status_code_1}}']\n    payloads:\n      p:\n        low: [a]\n    matchers:\n      - type: xpath\n        xpath: ['/a']\n      - type: word\n        part: interactsh_protocol\n        words: [dns]\n      - type: dsl\n        dsl: ['generate_java_gadget(body) == 1', 'status_code_2 == 200']\n",
        );
        for reason in [
            "req:payload_aggression",
            "matcher:xpath",
            "fn:generate_java_gadget",
            "multi_request",
        ] {
            assert!(classified.active_reasons.contains(reason), "{reason}");
        }
        assert!(classified.risks.contains("intrusive"));
        let other = classify_text("id: example-dns\ninfo: {}\ndns:\n  - name: '{{FQDN}}'\n");
        assert_eq!(other.protocol, "dns");
        assert!(other.active_reasons.contains("protocol:dns"));
        // A flow that only joins block calls is sent, but never runs on
        // captured traffic; any other flow is a script, which never runs.
        let flow = classify_text(
            "id: a\ninfo: {}\nflow: http(1) && http(2)\nhttp:\n  - path: ['{{BaseURL}}']\n  - path: ['{{BaseURL}}/b']\n",
        );
        assert!(
            !flow.active_reasons.contains("flow"),
            "{:?}",
            flow.active_reasons
        );
        let one = classify_text(
            "id: a\ninfo: {}\nflow: http(1)\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers: [{type: status, status: [200]}]\n",
        );
        assert!(one.active_supported(), "{:?}", one.active_reasons);
        assert!(!one.passive_supported());
        let script = classify_text(
            "id: a\ninfo: {}\nflow: |\n  http(1)\n  set('a', 1)\nhttp:\n  - path: ['{{BaseURL}}']\n",
        );
        assert!(script.active_reasons.contains("flow"));
    }

    #[test]
    fn oast_templates_are_sent_but_never_run_on_captured_traffic() {
        let classified = classify_text(
            "id: example-oast\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/?u=http://{{interactsh-url}}']\n    matchers-condition: and\n    matchers:\n      - type: word\n        part: interactsh_protocol\n        words: [http]\n      - type: dsl\n        dsl: ['contains(interactsh_request, \"example\")', 'len(interactsh_ip) > 0']\n",
        );
        assert!(
            classified.active_supported(),
            "{:?}",
            classified.active_reasons
        );
        assert!(classified.oast);
        assert!(!classified.passive_supported());
        let global = classify_text(
            "id: example-oast-global\ninfo: {}\nhttp:\n  - global-matchers: true\n    matchers:\n      - type: word\n        part: interactsh_protocol\n        words: [dns]\n",
        );
        assert!(global.passive_reasons.contains("oast"));
        // What an earlier request's callback said is not kept.
        let numbered = classify_text(
            "id: example-oast-2\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}/{{interactsh-url}}']\n    matchers:\n      - type: dsl\n        dsl: ['interactsh_protocol_2 == \"dns\"']\n",
        );
        assert!(numbered.active_reasons.contains("oast"));
    }

    #[test]
    fn requests_may_only_extend_the_target_path() {
        let classified = classify_text(
            "id: example-path\ninfo: {}\nhttp:\n  - method: GET\n    path:\n      - 'https://example.net/x'\n      - '{{BaseURL}}/{{payload}}'\n    headers:\n      Host: example.net\n",
        );
        for reason in ["req:path_not_base", "var:payload", "req:host_header"] {
            assert!(classified.active_reasons.contains(reason), "{reason}");
        }
        assert_eq!(classified.passive, None);
    }

    #[test]
    fn nested_markers_are_read_inside_out() {
        let classified = classify_text(
            "id: example-nested\ninfo: {}\nvariables:\n  command: id\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/?q={{url_encode(\"{{command}}\")}}'\n",
        );
        assert!(
            classified.active_supported(),
            "{:?}",
            classified.active_reasons
        );
    }

    #[test]
    fn redirects_run_both_ways() {
        let classified = classify_text(
            "id: example-redirect\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    redirects: true\n    max-redirects: 2\n    matchers:\n      - type: word\n        words: ['{{randstr}}']\n",
        );
        assert_eq!(classified.passive, Some(PassiveKind::BaseUrlGet));
        assert!(
            classified.active_supported(),
            "{:?}",
            classified.active_reasons
        );
        // The matcher looks for a value the template itself would have sent.
        assert!(classified.passive_reasons.contains("randomness"));
        let undeclared = classify_text(
            "id: example-var\ninfo: {}\nvariables:\n  a: '{{payload}}'\nhttp:\n  - method: CONNECT\n    path: ['{{BaseURL}}/{{a}}']\n",
        );
        for reason in ["var:payload", "req:method"] {
            assert!(undeclared.active_reasons.contains(reason), "{reason}");
        }
    }

    #[test]
    fn request_helpers_and_declared_variables_are_active_only() {
        let classified = classify_text(
            "id: example-rand\ninfo: {}\nvariables:\n  token: '{{rand_base(8)}}'\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/{{token}}?n={{randstr}}&h={{md5(token)}}'\n",
        );
        assert!(
            classified.active_supported(),
            "{:?}",
            classified.active_reasons
        );
    }

    #[test]
    fn a_variable_left_for_whoever_runs_the_template_is_not_run() {
        let classified = classify_text(
            "id: example-login\ninfo: {}\nvariables:\n  username: '{{username}}'\n  token: '{{randstr}}'\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/?u={{username}}&t={{token}}']\n    matchers:\n      - type: status\n        status: [200]\n",
        );
        assert_eq!(
            classified.active_reasons.iter().collect::<Vec<_>>(),
            ["var:username"]
        );
    }

    #[test]
    fn later_answers_are_read_by_matchers_and_internal_values_by_requests() {
        let template = |paths: &str, extra: &str| {
            classify_text(
                &"id: example-steps\ninfo: {}\nEXTRAhttp:\n  - path: [PATHS]\n    extractors:\n      - type: regex\n        name: token\n        internal: true\n        regex: ['t=(\\w+)']\n      - type: regex\n        name: shown\n        regex: ['s=(\\w+)']\n      - type: regex\n        part: body_2\n        regex: ['n=(\\w+)']\n    matchers:\n      - type: dsl\n        dsl: ['status_code_1 == 200 && contains(body_2, \"ok\")']\n      - type: word\n        part: body_1\n        words: [ok]\n"
                    .replace("PATHS", paths)
                    .replace("EXTRA", extra),
            )
            .active_reasons
        };
        let runnable = template("'{{BaseURL}}/a', '{{BaseURL}}/b?t={{token}}'", "");
        assert!(runnable.is_empty(), "{runnable:?}");
        for (paths, extra, reason) in [
            // A request cannot read an earlier answer.
            (
                "'{{BaseURL}}/a', '{{BaseURL}}/b?c={{status_code_1}}'",
                "",
                "multi_request",
            ),
            // Only internal extractors hand values on.
            (
                "'{{BaseURL}}/a', '{{BaseURL}}/b?s={{shown}}'",
                "",
                "var:shown",
            ),
            // Variables are worked out before any request is sent.
            (
                "'{{BaseURL}}/a'",
                "variables:\n  auth: 'Bearer {{token}}'\n",
                "var:token",
            ),
        ] {
            let found = template(paths, extra);
            assert!(found.contains(reason), "{reason}: {found:?}");
        }
        // Nuclei keeps the history without being asked now, but does not
        // run every value of an extractor.
        let all = classify_text(
            "id: example-all\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}']\n    req-condition: true\n    iterate-all: true\n    matchers:\n      - type: status\n        status: [200]\n",
        );
        assert_eq!(
            all.active_reasons.iter().collect::<Vec<_>>(),
            ["req:iterate_all"]
        );
    }

    fn payload_reasons(block: serde_json::Value) -> BTreeSet<String> {
        let mut base = serde_json::json!({
            "path": ["{{BaseURL}}/{{word}}"],
            "matchers": [{"type": "word", "words": ["{{word}}"]}],
        });
        base.as_object_mut()
            .unwrap()
            .extend(block.as_object().unwrap().clone());
        let template = serde_json::json!({"id": "example-words", "info": {}, "http": [base]});
        classify_text(&template.to_string()).active_reasons
    }

    #[test]
    fn payloads_run_inline_or_from_the_release_files() {
        use serde_json::json;
        // A list, the lines of one string, or a file of the release; the
        // library checks the file is there.
        for payloads in [
            json!({"word": ["a", "{{Hostname}}", 7]}),
            json!({"word": "a\nb"}),
            json!({"word": "helpers/wordlists/words.txt"}),
        ] {
            let found = payload_reasons(json!({ "payloads": payloads }));
            assert!(found.is_empty(), "{found:?}");
        }
        // Nuclei drops a set no request or matcher names before it counts
        // them, and takes two sets only with an attack that combines them.
        let unused = payload_reasons(json!({"payloads": {"word": ["a"], "unused": ["x"]}}));
        assert!(unused.is_empty(), "{unused:?}");
        let two = json!({"path": ["{{BaseURL}}/{{word}}?{{n}}"], "payloads": {"word": ["a"], "n": ["1"]}});
        assert!(payload_reasons(two.clone()).contains("req:payloads"));
        let mut pitchfork = two.clone();
        pitchfork["attack"] = " Pitchfork ".into();
        let found = payload_reasons(pitchfork);
        assert!(found.is_empty(), "{found:?}");
        let mut battering = two;
        battering["attack"] = "batteringram".into();
        assert!(payload_reasons(battering).contains("req:payloads"));
        for (block, reason) in [
            (
                json!({"payloads": {"word": "../words.txt"}}),
                "req:payload_file",
            ),
            (
                json!({"payloads": {"word": "/etc/words.txt"}}),
                "req:payload_file",
            ),
            (
                json!({"payloads": {"word": {"low": ["a"]}}}),
                "req:payload_aggression",
            ),
            (json!({"payloads": {"word": []}}), "req:payloads"),
            (
                json!({"payloads": {"word": ["a"]}, "attack": "sniper"}),
                "req:attack",
            ),
            (
                json!({"payloads": {"word": ["{{nothing}}"]}}),
                "var:nothing",
            ),
        ] {
            let found = payload_reasons(block.clone());
            assert!(found.contains(reason), "{block}: {found:?}");
        }
    }

    fn raw_reasons(raws: serde_json::Value, extra: serde_json::Value) -> Classification {
        let mut block = serde_json::json!({
            "raw": raws,
            "matchers": [{"type": "status", "status": [200]}],
        });
        block
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let template = serde_json::json!({
            "id": "example-raw",
            "info": {},
            "variables": {"verb": "GET"},
            "http": [block],
        });
        classify_text(&template.to_string())
    }

    #[test]
    fn raw_requests_run_actively_when_the_target_supplies_the_host() {
        let classified = raw_reasons(
            serde_json::json!([
                "@timeout: 20s\nPOST /login?next={{BaseURL}} HTTP/1.1\nHost: {{Hostname}}\nAuthorization: Basic {{base64(\"a:b\")}}\n\nuser=admin\n",
                "@timeout 10s\nGET {{BaseURL}}/home HTTP/1.1\n",
            ]),
            serde_json::json!({}),
        );
        assert!(
            classified.active_supported(),
            "{:?}",
            classified.active_reasons
        );
        assert!(classified.passive.is_none());
        assert!(classified.risks.is_empty());
        let put = raw_reasons(
            serde_json::json!(["PUT /x HTTP/1.1\nHost: {{Hostname}}\n\nbody"]),
            serde_json::json!({}),
        );
        assert!(put.active_supported(), "{:?}", put.active_reasons);
        assert!(put.risks.contains("method:put"));
    }

    #[test]
    fn raw_requests_that_go_elsewhere_or_read_oddly_are_not_run() {
        let reasons = |raws: serde_json::Value, extra: serde_json::Value| {
            raw_reasons(raws, extra).active_reasons
        };
        let none = serde_json::json!({});
        for (raw, reason) in [
            // The target supplies Host; a template naming another is not sent.
            ("GET /x HTTP/1.1\nHost: localhost\n", "req:host_header"),
            // These would send it elsewhere, or change how it connects.
            (
                "@Host: https://example.net\nGET /x HTTP/1.1\n",
                "req:raw_annotation",
            ),
            (
                "@tls-sni: example.net\nGET /x HTTP/1.1\n",
                "req:raw_annotation",
            ),
            ("@once\nGET /x HTTP/1.1\n", "req:raw_annotation"),
            ("@timeout: soon\nGET /x HTTP/1.1\n", "req:raw_annotation"),
            // Nuclei refuses these as malformed.
            ("GET\n", "req:raw"),
            ("GET /x HTTP/1.1", "req:raw"),
            ("\nGET /x HTTP/1.1\n", "req:raw"),
            ("GET /x HTTP/1.1\nX-Broken\n\n", "req:raw"),
            ("{{verb}} /x HTTP/1.1\n", "req:method"),
            ("CONNECT /x HTTP/1.1\n", "req:method"),
        ] {
            let found = reasons(serde_json::json!([raw]), none.clone());
            assert!(found.contains(reason), "{raw:?}: {found:?}");
        }
        assert!(reasons(serde_json::json!("GET / HTTP/1.1\n"), none.clone()).contains("req:raw"));
        assert!(reasons(serde_json::json!([]), none).contains("req:raw"));
        // Nuclei would ignore the raw requests beside a path, or lay these
        // over them.
        for extra in [
            serde_json::json!({"path": ["{{BaseURL}}/x"]}),
            serde_json::json!({"headers": {"X-A": "b"}}),
            serde_json::json!({"body": "a=b"}),
            serde_json::json!({"method": "POST"}),
        ] {
            let found = reasons(serde_json::json!(["GET /x HTTP/1.1\n"]), extra);
            assert!(found.contains("req:raw_mixed"), "{found:?}");
        }
    }

    /// Classifies a Nuclei templates release and prints what Sniper can run.
    /// The archive is never committed; point SNIPER_TEMPLATE_ARCHIVE at a
    /// downloaded `nuclei-templates-<version>.tar.gz`:
    /// `SNIPER_TEMPLATE_ARCHIVE=… cargo test --release --lib census -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn census() {
        use std::collections::BTreeMap;
        use std::io::Read;

        let path = std::env::var("SNIPER_TEMPLATE_ARCHIVE").expect("SNIPER_TEMPLATE_ARCHIVE");
        let started = std::time::Instant::now();
        let file = std::fs::File::open(&path).unwrap();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
        let mut parse_errors: BTreeMap<&str, usize> = BTreeMap::new();
        let mut protocols: BTreeMap<&str, usize> = BTreeMap::new();
        let mut rows: Vec<(String, Classification, String)> = Vec::new();
        let mut compiled = Vec::new();
        let mut compile_errors: BTreeMap<String, usize> = BTreeMap::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            let relative = name
                .split_once('/')
                .map_or(name.as_str(), |(_, rest)| rest)
                .to_string();
            if !relative.ends_with(".yaml") || relative.split('/').any(|part| part.starts_with('.'))
            {
                continue;
            }
            let mut text = String::new();
            if entry
                .by_ref()
                .take(MAX_TEMPLATE_BYTES as u64 + 1)
                .read_to_string(&mut text)
                .is_err()
            {
                *parse_errors.entry("not_utf8").or_default() += 1;
                continue;
            }
            match parse(&text) {
                Ok(parsed) => {
                    let classified = classify(&parsed);
                    *protocols.entry(classified.protocol).or_default() += 1;
                    if classified.passive_supported() {
                        match super::super::engine::compile_passive(&parsed, &classified) {
                            Ok(template) => compiled.push(std::sync::Arc::new(template)),
                            Err(error) => *compile_errors.entry(error.0).or_default() += 1,
                        }
                    }
                    rows.push((relative, classified, parsed.info.severity));
                }
                Err(error) => *parse_errors.entry(error.code).or_default() += 1,
            }
        }
        let elapsed = started.elapsed();

        println!(
            "parsed {} templates in {:?}; errors {:?}",
            rows.len(),
            elapsed,
            parse_errors
        );
        println!("protocols {protocols:?}");

        let http: Vec<_> = rows
            .iter()
            .filter(|(_, c, _)| c.protocol == "http")
            .collect();
        let passive_global = http
            .iter()
            .filter(|(_, c, _)| c.passive == Some(PassiveKind::Global))
            .count();
        let passive_global_ok = http
            .iter()
            .filter(|(_, c, _)| c.passive == Some(PassiveKind::Global) && c.passive_supported())
            .count();
        let passive_get = http
            .iter()
            .filter(|(_, c, _)| c.passive == Some(PassiveKind::BaseUrlGet))
            .count();
        let passive_get_ok = http
            .iter()
            .filter(|(_, c, _)| c.passive == Some(PassiveKind::BaseUrlGet) && c.passive_supported())
            .count();
        println!("passive: global {passive_global_ok}/{passive_global}, BaseURL GET {passive_get_ok}/{passive_get}");
        let mut passive_blockers: BTreeMap<&str, usize> = BTreeMap::new();
        for (_, c, _) in http.iter().filter(|(_, c, _)| c.passive.is_some()) {
            for reason in &c.passive_reasons {
                *passive_blockers.entry(reason).or_default() += 1;
            }
        }
        println!("passive blockers {passive_blockers:?}");
        let built = std::time::Instant::now();
        let compiled_count = compiled.len();
        let set = super::super::engine::PassiveSet::new(compiled);
        println!(
            "passive engine: {compiled_count} compiled, errors {compile_errors:?}; set built in {:?}, {} always evaluated",
            built.elapsed(),
            set.always_evaluated()
        );

        let active_ok = http.iter().filter(|(_, c, _)| c.active_supported()).count();
        let active_safe = http
            .iter()
            .filter(|(_, c, _)| c.active_supported() && c.risks.is_empty())
            .count();
        println!(
            "active: {active_ok}/{} http templates runnable, {active_safe} without risk tags",
            http.len()
        );

        let mut by_dir: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for (path, c, _) in &http {
            let dir = path.split('/').take(2).collect::<Vec<_>>().join("/");
            let slot = by_dir.entry(dir).or_default();
            slot.1 += 1;
            if c.active_supported() || c.passive_supported() {
                slot.0 += 1;
            }
        }
        println!("runnable (active or passive) by directory:");
        for (dir, (ok, total)) in &by_dir {
            if *total >= 20 {
                println!(
                    "  {dir:<40} {ok:>5}/{total:<5} {:>5.1}%",
                    100.0 * *ok as f64 / *total as f64
                );
            }
        }
        let mut by_severity: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for (_, c, severity) in &http {
            let slot = by_severity.entry(severity.as_str()).or_default();
            slot.1 += 1;
            if c.active_supported() {
                slot.0 += 1;
            }
        }
        println!("active runnable by severity {by_severity:?}");

        let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
        let mut sole: BTreeMap<&str, usize> = BTreeMap::new();
        for (_, c, _) in &http {
            for reason in &c.active_reasons {
                *reasons.entry(reason).or_default() += 1;
            }
            if c.active_reasons.len() == 1 {
                *sole.entry(c.active_reasons.first().unwrap()).or_default() += 1;
            }
        }
        let mut reasons: Vec<_> = reasons.into_iter().collect();
        reasons.sort_by(|a, b| b.1.cmp(&a.1));
        println!("active blockers (templates having it):");
        for (reason, count) in reasons.iter().take(40) {
            println!(
                "  {reason:<32} {count:>5}  sole blocker: {}",
                sole.get(reason).copied().unwrap_or(0)
            );
        }

        let mut functions: BTreeMap<&str, usize> = BTreeMap::new();
        for (_, c, _) in &http {
            for function in &c.functions {
                *functions.entry(function).or_default() += 1;
            }
        }
        let mut functions: Vec<_> = functions.into_iter().collect();
        functions.sort_by(|a, b| b.1.cmp(&a.1));
        println!("dsl functions (templates using):");
        for (function, count) in functions {
            let known = dsl::function_kind(function).is_some();
            println!(
                "  {function:<28} {count:>5} {}",
                if known { "" } else { "UNSUPPORTED" }
            );
        }
        let mut risks: BTreeMap<&str, usize> = BTreeMap::new();
        for (_, c, _) in &http {
            for risk in &c.risks {
                *risks.entry(risk).or_default() += 1;
            }
        }
        println!("risk tags {risks:?}");
        // SNIPER_CENSUS_REGEX=<id> explains each pattern of one template Rust rejects.
        if let Ok(wanted) = std::env::var("SNIPER_CENSUS_REGEX") {
            let file = std::fs::File::open(&path).unwrap();
            let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
            for entry in archive.entries().unwrap() {
                let mut entry = entry.unwrap();
                let mut text = String::new();
                if entry.read_to_string(&mut text).is_err() {
                    continue;
                }
                let Ok(parsed) = parse(&text) else { continue };
                if parsed.info.id != wanted {
                    continue;
                }
                let blocks = parsed
                    .root
                    .get("http")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for block in blocks {
                    let items = block
                        .get("matchers")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .chain(
                            block
                                .get("extractors")
                                .and_then(Value::as_array)
                                .into_iter()
                                .flatten(),
                        );
                    for item in items {
                        for pattern in item
                            .get("regex")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                        {
                            if let Some(error) = dsl::regex_error(&scalar_text(pattern)) {
                                println!("  {wanted}: {}\n  {error}", scalar_text(pattern));
                            }
                        }
                    }
                }
            }
        }
        // SNIPER_CENSUS_SHOW=<reason> lists templates blocked by one reason.
        if let Ok(show) = std::env::var("SNIPER_CENSUS_SHOW") {
            for (path, c, _) in http
                .iter()
                .filter(|(_, c, _)| {
                    c.active_reasons.contains(&show) || c.passive_reasons.contains(&show)
                })
                .take(15)
            {
                println!("  {show}: {path} (active {:?})", c.active_reasons);
            }
        }
    }
}
