//! Templates that send requests. A request block names a method, paths under
//! `{{BaseURL}}` or `{{RootURL}}`, headers and a body, or writes each request
//! out raw; the target the operator chose supplies the scheme, host and port.
//! A path is only ever a path: `{{BaseURL}}@example.net` asks the target for
//! `/@example.net`, and a raw request line naming another host keeps only
//! its path.

use std::{borrow::Cow, cell::RefCell, collections::HashMap, time::Duration};

use serde_json::{Map, Value};

use super::dsl::{self, Allow, CompileError, EvalError, Interp, Val, Vars};
use super::engine::{self, CompiledTemplate, UrlVars};
use super::flow::{self, Step};
use super::model::{Classification, ParsedTemplate};

/// Nuclei follows ten redirects unless a template asks for another number;
/// Sniper never follows more.
pub const MAX_REDIRECTS: usize = 10;

/// A template that would send more to one target than a scan sends by
/// default is listed, not sent: it would crowd out every other template.
pub const MAX_TEMPLATE_REQUESTS: usize = 10_000;

/// Nuclei caps a raw request's `@timeout:` at five minutes.
const MAX_TIMEOUT_SECS: f64 = 300.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Follow {
    None,
    /// `redirects: true`.
    All,
    /// `host-redirects: true`: only while the host stays the one the chain
    /// started on.
    SameHost,
}

#[derive(Clone, Debug)]
struct PathSpec {
    /// `{{RootURL}}`: from the origin, leaving out the target's own path.
    root: bool,
    rest: Interp,
}

/// How payload sets combine, as Nuclei's `attack` names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attack {
    /// One set, one value at a time.
    BatteringRam,
    /// Every set's nth value together.
    Pitchfork,
    /// Every combination.
    ClusterBomb,
}

#[derive(Clone, Debug)]
struct PayloadSet {
    name: String,
    values: Vec<Interp>,
}

#[derive(Clone, Debug)]
struct RawSpec {
    text: Interp,
    timeout: Option<Duration>,
}

/// A template compiled for sending: its request blocks, which a run sends
/// one after another to a target, sharing the template's variables, the
/// cookies and the values earlier blocks extract, as Nuclei's template
/// context shares them.
#[derive(Clone, Debug)]
pub struct ActiveTemplate {
    pub blocks: Vec<Block>,
    /// The order the blocks run in: the flow's, or each once as listed.
    pub steps: Vec<Step>,
    variables: Vec<(String, Interp)>,
    /// Its requests carry `{{interactsh-url}}`.
    pub oast: bool,
}

/// One request block: its requests and the matchers that judge their answers.
#[derive(Clone, Debug)]
pub struct Block {
    pub template: CompiledTemplate,
    method: String,
    paths: Vec<PathSpec>,
    raws: Vec<RawSpec>,
    attack: Attack,
    payloads: Vec<PayloadSet>,
    headers: Vec<(String, Interp)>,
    body: Option<Interp>,
    pub stop_at_first_match: bool,
    pub follow: Follow,
    pub max_redirects: usize,
    /// The run keeps the cookies its responses set and sends them on, as
    /// Nuclei does unless `disable-cookie` is set.
    pub cookies: bool,
    /// The run keeps each answer for later matchers that read it (`body_1`).
    pub history: bool,
    /// Its matchers read a callback (`interactsh_protocol`), so an answer
    /// waits for one before it is judged with it.
    pub reads_interaction: bool,
}

/// One request, ready to send to the target it was built for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltRequest {
    pub method: String,
    /// Path and query for the request line, starting with `/`.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// A raw request's `@timeout:`; the scan's own otherwise.
    pub timeout: Option<Duration>,
}

/// Compiles a template for sending. `files` holds the release's payload
/// files by path.
pub fn compile_active(
    template: &ParsedTemplate,
    classification: &Classification,
    files: &HashMap<String, String>,
) -> Result<ActiveTemplate, CompileError> {
    if let Some(first) = classification.active_reasons.first() {
        return Err(CompileError(first.clone()));
    }
    let listed = template
        .root
        .get("http")
        .or_else(|| template.root.get("requests"))
        .and_then(Value::as_array)
        .filter(|blocks| !blocks.is_empty())
        .ok_or_else(|| engine::reason("http:empty"))?;
    let blocks = listed
        .iter()
        .map(|block| {
            let block = block
                .as_object()
                .ok_or_else(|| engine::reason("http:block_not_a_mapping"))?;
            compile_block(template, block, files)
        })
        .collect::<Result<Vec<_>, _>>()?;
    // A block without matchers only sets up a later one, as a login does,
    // and Nuclei sends it all the same; a template that judges nothing is
    // not worth sending.
    if blocks
        .iter()
        .all(|block| block.template.operators.is_empty())
    {
        return Err(engine::reason("operators:empty"));
    }
    let steps = match template.root.get("flow") {
        Some(source) => {
            let ids: Vec<Option<String>> = listed
                .iter()
                .map(|block| block.get("id").map(engine::text_of))
                .collect();
            flow::compile(&engine::text_of(source), &ids)?
        }
        None => vec![Step::Run((0..blocks.len()).collect())],
    };
    let variables = match template.root.get("variables") {
        Some(Value::Object(map)) => map
            .iter()
            .map(|(name, value)| {
                Ok((
                    name.clone(),
                    Interp::compile(&engine::text_of(value), Allow { random: true })?,
                ))
            })
            .collect::<Result<Vec<_>, CompileError>>()?,
        _ => Vec::new(),
    };
    let compiled = ActiveTemplate {
        blocks,
        steps,
        variables,
        oast: classification.oast,
    };
    if compiled.request_count() > MAX_TEMPLATE_REQUESTS {
        return Err(engine::reason("req:too_many_requests"));
    }
    Ok(compiled)
}

fn compile_block(
    template: &ParsedTemplate,
    block: &Map<String, Value>,
    files: &HashMap<String, String>,
) -> Result<Block, CompileError> {
    let allow = Allow { random: true };
    // The request is known when its answer is judged, so matchers may read it.
    let operators = engine::compile_operators(block, allow, true)?;
    let method = block
        .get("method")
        .map(engine::text_of)
        .unwrap_or_default()
        .trim()
        .to_ascii_uppercase();
    let method = if method.is_empty() {
        "GET".to_string()
    } else {
        method
    };
    // A tunnel request through a pooled client is not a probe.
    if method == "CONNECT" {
        return Err(engine::reason("req:method"));
    }
    let paths = if block.contains_key("path") {
        engine::strings(block, "path")?
    } else {
        Vec::new()
    };
    let paths = paths
        .iter()
        .map(|path| {
            let path = path.trim_start();
            let (root, rest) = match (
                path.strip_prefix("{{BaseURL}}"),
                path.strip_prefix("{{RootURL}}"),
            ) {
                (Some(rest), _) => (false, rest),
                (None, Some(rest)) => (true, rest),
                (None, None) => return Err(engine::reason("req:path_not_base")),
            };
            Ok(PathSpec {
                root,
                rest: Interp::compile(rest, allow)?,
            })
        })
        .collect::<Result<Vec<_>, CompileError>>()?;
    let raws = if block.contains_key("raw") {
        engine::strings(block, "raw")?
    } else {
        Vec::new()
    };
    let raws = raws
        .iter()
        .map(|raw| {
            let raw = crlf(raw);
            Ok(RawSpec {
                timeout: raw_timeout(&raw).ok_or_else(|| engine::reason("req:raw_annotation"))?,
                text: Interp::compile(&raw, allow)?,
            })
        })
        .collect::<Result<Vec<_>, CompileError>>()?;
    if paths.is_empty() && raws.is_empty() {
        return Err(engine::reason("req:path"));
    }
    let attack = match block
        .get("attack")
        .map(engine::text_of)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "batteringram" => Attack::BatteringRam,
        "pitchfork" => Attack::Pitchfork,
        "clusterbomb" => Attack::ClusterBomb,
        _ => return Err(engine::reason("req:attack")),
    };
    let payloads = super::model::used_payload_sets(block)
        .into_iter()
        .map(|(name, value)| {
            let values: Vec<String> = match value {
                Value::Array(items) => items.iter().map(engine::text_of).collect(),
                Value::String(text) if text.contains('\n') => {
                    text.split('\n').map(str::to_string).collect()
                }
                // Nuclei reads a payload file line by line, skipping blank
                // lines.
                Value::String(path) => super::model::helper_path(path)
                    .and_then(|path| files.get(&path))
                    .ok_or_else(|| engine::reason("req:payload_file"))?
                    .lines()
                    .filter(|line| !line.is_empty())
                    .map(str::to_string)
                    .collect(),
                _ => return Err(engine::reason("req:payloads")),
            };
            if values.is_empty() {
                return Err(engine::reason("req:payloads"));
            }
            Ok(PayloadSet {
                name: name.clone(),
                values: values
                    .iter()
                    .map(|value| Interp::compile(value, allow))
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect::<Result<Vec<_>, CompileError>>()?;
    let mut headers = Vec::new();
    if let Some(map) = block.get("headers") {
        let map = map
            .as_object()
            .ok_or_else(|| engine::reason("req:headers"))?;
        for (name, value) in map {
            // The classifier allowed only `{{Hostname}}` here, which is the
            // Host every request to the target carries anyway.
            if name.eq_ignore_ascii_case("host") {
                continue;
            }
            if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
                return Err(engine::reason("req:header_name"));
            }
            headers.push((
                name.clone(),
                Interp::compile(&engine::text_of(value), allow)?,
            ));
        }
    }
    let body = block
        .get("body")
        .map(|body| Interp::compile(&crlf(&engine::text_of(body)), allow))
        .transpose()?;
    // Nuclei applies host-redirects over redirects when both are set.
    let follow = if engine::flag(block, "host-redirects")? {
        Follow::SameHost
    } else if engine::flag(block, "redirects")? {
        Follow::All
    } else {
        Follow::None
    };
    let max_redirects = match block.get("max-redirects") {
        None | Some(Value::Null) => MAX_REDIRECTS,
        Some(value) => match engine::text_of(value).trim().parse::<usize>() {
            // Zero means Nuclei's default, as there.
            Ok(0) => MAX_REDIRECTS,
            Ok(count) => count.min(MAX_REDIRECTS),
            Err(_) => return Err(engine::reason("field:max-redirects")),
        },
    };
    Ok(Block {
        template: CompiledTemplate {
            info: template.info.clone(),
            passive: None,
            body_sensitive: engine::body_sensitive(&operators),
            operators,
        },
        method,
        paths,
        raws,
        attack,
        payloads,
        headers,
        body,
        stop_at_first_match: engine::flag(block, "stop-at-first-match")?,
        follow,
        max_redirects,
        cookies: !engine::flag(block, "disable-cookie")?,
        history: reads_history(block),
        reads_interaction: reads_interaction(block),
    })
}

/// Whether matchers or extractors read an earlier answer (`body_1`), as
/// Nuclei decides it: an underscore and a digit in an expression or a part.
fn reads_history(block: &Map<String, Value>) -> bool {
    let numbered = |value: &Value| {
        engine::text_of(value)
            .as_bytes()
            .windows(2)
            .any(|pair| pair[0] == b'_' && pair[1].is_ascii_digit())
    };
    ["matchers", "extractors"]
        .iter()
        .filter_map(|key| block.get(*key).and_then(Value::as_array))
        .flatten()
        .any(|item| {
            ["dsl", "part"].iter().any(|key| match item.get(*key) {
                Some(Value::Array(items)) => items.iter().any(numbered),
                Some(value) => numbered(value),
                None => false,
            })
        })
}

/// The session's Interactsh server, which a run's `{{interactsh-url}}`
/// markers point at.
#[derive(Clone, Debug)]
pub struct OastUrls {
    pub correlation_id: String,
    pub domain: String,
}

/// Whether matchers or extractors read a callback, as Nuclei decides it: an
/// `interactsh` part, or the word in an expression.
fn reads_interaction(block: &Map<String, Value>) -> bool {
    let mentions = |value: &Value| match value {
        Value::Array(items) => items
            .iter()
            .any(|item| engine::text_of(item).contains("interactsh")),
        value => engine::text_of(value).contains("interactsh"),
    };
    ["matchers", "extractors"]
        .iter()
        .filter_map(|key| block.get(*key).and_then(Value::as_array))
        .flatten()
        .any(|item| {
            item.get("part")
                .is_some_and(|part| engine::text_of(part).starts_with("interactsh"))
                || item.get("dsl").is_some_and(mentions)
        })
}

/// What a template's markers read while one run on one target builds its
/// requests: the target, the template's variables, and random strings made
/// on first use and kept for the run, so a matcher looking for a reflected
/// `{{randstr}}` sees the value the request carried.
pub struct RunValues<'a> {
    url: &'a UrlVars,
    values: RefCell<HashMap<String, String>>,
    /// The current pass's payload values, which come before every other
    /// value, as in Nuclei.
    payloads: RefCell<HashMap<String, String>>,
    oast: Option<&'a OastUrls>,
    /// The id of each OAST URL handed out, and the last URL, which matchers
    /// read as `interactsh-url`.
    oast_ids: RefCell<Vec<String>>,
    oast_url: RefCell<Option<String>>,
}

impl RunValues<'_> {
    /// The variables, random strings and payload values made so far, for
    /// the matchers.
    pub fn values(&self) -> HashMap<String, String> {
        let mut values = self.values.borrow().clone();
        values.extend(
            self.payloads
                .borrow()
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        if let Some(url) = self.oast_url.borrow().as_ref() {
            values.insert("interactsh-url".into(), url.clone());
        }
        values
    }

    /// The ids of the OAST URLs `built` carries, wherever in the run they
    /// were handed out: a callback filed under one answers this request.
    pub fn oast_ids_in(&self, built: &BuiltRequest) -> Vec<String> {
        self.oast_ids
            .borrow()
            .iter()
            .filter(|id| {
                built.target.contains(id.as_str())
                    || built.body.contains(id.as_str())
                    || built
                        .headers
                        .iter()
                        .any(|(_, value)| value.contains(id.as_str()))
            })
            .cloned()
            .collect()
    }
}

fn is_random_name(name: &str) -> bool {
    name == "randstr"
        || name
            .strip_prefix("randstr_")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

impl Vars for RunValues<'_> {
    fn get(&self, name: &str) -> Option<Val<'_>> {
        if let Some(value) = self.payloads.borrow().get(name) {
            return Some(Val::Str(Cow::Owned(value.clone())));
        }
        if let Some(value) = self.url.get(name) {
            return Some(Val::Str(Cow::Borrowed(value)));
        }
        if let Some(value) = self.values.borrow().get(name) {
            return Some(Val::Str(Cow::Owned(value.clone())));
        }
        match name {
            // Each marker is a URL of its own, as Nuclei hands them out, so a
            // callback says which request caused it.
            "interactsh-url" => {
                let oast = self.oast?;
                let url = crate::oast::interactsh_payload(&oast.correlation_id, &oast.domain);
                let id = url.split('.').next().unwrap_or_default().to_string();
                self.oast_ids.borrow_mut().push(id);
                *self.oast_url.borrow_mut() = Some(url.clone());
                return Some(Val::Str(Cow::Owned(url)));
            }
            "interactsh-server" => {
                return self
                    .oast
                    .map(|oast| Val::Str(Cow::Owned(oast.domain.clone())))
            }
            _ => {}
        }
        if !is_random_name(name) {
            return None;
        }
        let value = dsl::random_id();
        self.values
            .borrow_mut()
            .insert(name.to_string(), value.clone());
        Some(Val::Str(Cow::Owned(value)))
    }
}

impl ActiveTemplate {
    /// Hands values an answer's internal extractors found to the run's later
    /// requests. A template variable of the same name keeps its own value,
    /// as in Nuclei.
    pub fn carry(&self, run: &RunValues<'_>, values: Vec<(String, String)>) {
        let mut stored = run.values.borrow_mut();
        for (name, value) in values {
            if !self.variables.iter().any(|(variable, _)| *variable == name) {
                stored.insert(name, value);
            }
        }
    }

    /// Requests one run sends before any redirect: those of every block a
    /// step calls, which is the most a flow can send.
    pub fn request_count(&self) -> usize {
        self.steps
            .iter()
            .filter_map(|step| match step {
                Step::Run(blocks) => Some(blocks),
                Step::SkipIf(..) => None,
            })
            .flatten()
            .map(|&block| self.blocks[block].request_count())
            .fold(0, usize::saturating_add)
    }

    /// Starts a run on one target: the template's variables are worked out
    /// once, each after the ones it names, whatever order the file lists them.
    /// `oast` is the server its OAST markers point at; without one they do
    /// not resolve.
    pub fn start_run<'a>(
        &self,
        url: &'a UrlVars,
        oast: Option<&'a OastUrls>,
    ) -> Result<RunValues<'a>, EvalError> {
        let run = RunValues {
            url,
            values: RefCell::new(HashMap::new()),
            payloads: RefCell::new(HashMap::new()),
            oast,
            oast_ids: RefCell::new(Vec::new()),
            oast_url: RefCell::new(None),
        };
        let mut pending: Vec<&(String, Interp)> = self.variables.iter().collect();
        while !pending.is_empty() {
            let before = pending.len();
            let mut last_error = EvalError("unresolved");
            pending.retain(|(name, value)| match value.render(&run) {
                Ok(text) => {
                    run.values.borrow_mut().insert(name.clone(), text);
                    false
                }
                Err(error) => {
                    last_error = error;
                    true
                }
            });
            if pending.len() == before {
                return Err(last_error);
            }
        }
        Ok(run)
    }
}

impl Block {
    /// Requests one run sends before any redirect.
    pub fn request_count(&self) -> usize {
        self.sequence_len().saturating_mul(self.passes())
    }

    /// The block's requests, which each pass sends in order.
    pub fn sequence_len(&self) -> usize {
        self.paths.len() + self.raws.len()
    }

    /// How many times the run sends its requests: once per payload
    /// combination, or once without payloads.
    pub fn passes(&self) -> usize {
        let sizes = self.payloads.iter().map(|set| set.values.len());
        match self.attack {
            _ if self.payloads.is_empty() => 1,
            Attack::BatteringRam => sizes.sum(),
            Attack::Pitchfork => sizes.min().unwrap_or(0),
            Attack::ClusterBomb => sizes.fold(1, usize::saturating_mul),
        }
    }

    /// Fills the run's payload values for one pass. With a clusterbomb the
    /// first set changes fastest. A value's own markers are filled first,
    /// without the pass's payloads, as Nuclei fills them.
    pub fn load_pass(&self, run: &RunValues<'_>, pass: usize) -> Result<(), EvalError> {
        run.payloads.borrow_mut().clear();
        let mut values = HashMap::new();
        let mut rest = pass;
        for set in &self.payloads {
            let index = match self.attack {
                Attack::ClusterBomb => {
                    let index = rest % set.values.len().max(1);
                    rest /= set.values.len().max(1);
                    index
                }
                Attack::BatteringRam | Attack::Pitchfork => pass,
            };
            let value = set
                .values
                .get(index)
                .ok_or(EvalError("payload"))?
                .render(run)?;
            values.insert(set.name.clone(), value);
        }
        *run.payloads.borrow_mut() = values;
        Ok(())
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    /// The `index`th request of a run. `base_path` is the target's own path
    /// without a trailing slash, which `{{BaseURL}}` carries and
    /// `{{RootURL}}` leaves out.
    pub fn build(
        &self,
        index: usize,
        base_path: &str,
        run: &RunValues<'_>,
    ) -> Result<BuiltRequest, EvalError> {
        if !self.raws.is_empty() {
            return self.build_raw(index, base_path, run);
        }
        let spec = self.paths.get(index).ok_or(EvalError("path"))?;
        let rest = spec.rest.render(run)?;
        let prefix = if spec.root { "" } else { base_path };
        let target = request_target(&format!("{prefix}{rest}")).ok_or(EvalError("path"))?;
        let mut headers = Vec::with_capacity(self.headers.len());
        for (name, value) in &self.headers {
            let value = value.render(run)?;
            if http::HeaderValue::from_str(&value).is_err() {
                return Err(EvalError("header"));
            }
            headers.push((name.clone(), value));
        }
        let body = match &self.body {
            Some(body) => body.render(run)?,
            None => String::new(),
        };
        Ok(BuiltRequest {
            method: self.method.clone(),
            target,
            headers,
            body,
            timeout: None,
        })
    }

    fn build_raw(
        &self,
        index: usize,
        base_path: &str,
        run: &RunValues<'_>,
    ) -> Result<BuiltRequest, EvalError> {
        let spec = self.raws.get(index).ok_or(EvalError("raw"))?;
        let text = spec.text.render(run)?;
        let raw = read_raw(&text, &text).ok_or(EvalError("raw"))?;
        let target =
            request_target(&raw_request_path(base_path, raw.target)).ok_or(EvalError("path"))?;
        let mut headers: Vec<(String, String)> = Vec::new();
        for (name, value) in raw.headers {
            // The sender sets Host from the target and the length from the
            // body.
            if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if http::HeaderName::from_bytes(name.as_bytes()).is_err()
                || http::HeaderValue::from_str(value).is_err()
            {
                return Err(EvalError("header"));
            }
            // Nuclei keeps headers in a map: a repeated one sends its last
            // value.
            match headers.iter_mut().find(|(seen, _)| seen == name) {
                Some(header) => header.1 = value.to_string(),
                None => headers.push((name.to_string(), value.to_string())),
            }
        }
        Ok(BuiltRequest {
            method: raw.method.to_string(),
            target,
            headers,
            body: raw.body.to_string(),
            timeout: spec.timeout,
        })
    }
}

/// Nuclei sends CRLF line ends: request text written with bare line feeds
/// gets them, and text that already has a CRLF is sent as written.
fn crlf(text: &str) -> Cow<'_, str> {
    if text.contains("\r\n") {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(text.replace('\n', "\r\n"))
    }
}

/// A raw request split the way Nuclei reads one.
pub struct RawRequest<'a> {
    pub method: &'a str,
    /// The request line's second field; empty for `GET HTTP/1.1`.
    pub target: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body: &'a str,
}

/// Reads a raw request as Nuclei does: annotation lines before the request
/// line are skipped, the request line gives the method and target, header
/// lines run to the first blank one, and the rest is the body, without its
/// last CRLF unless it is multipart. Positions are found in `structure`,
/// which is `text` itself or `text` with its markers masked, so a template's
/// request can be read before its markers are filled. None when Nuclei
/// would refuse the request, or a header line has no colon.
pub fn read_raw<'a>(text: &'a str, structure: &str) -> Option<RawRequest<'a>> {
    if text.len() != structure.len() {
        return None;
    }
    let at = |part: &str, whole: &str| part.as_ptr() as usize - whole.as_ptr() as usize;
    let mut lines = structure.split_inclusive('\n');
    let line = lines.find(|line| !line.starts_with('@'))?;
    if !line.ends_with('\n') {
        return None;
    }
    let start = at(line, structure);
    let fields: Vec<(usize, usize)> = line
        .split_ascii_whitespace()
        .map(|field| {
            let from = start + at(field, line);
            (from, from + field.len())
        })
        .collect();
    let (method, target) = match fields.as_slice() {
        [method, version] if structure[version.0..version.1].contains("HTTP") => (*method, None),
        [method, target, _, ..] => (*method, Some(*target)),
        _ => return None,
    };
    let mut headers = Vec::new();
    let mut multipart = false;
    let mut body_start = text.len();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if line.ends_with('\n') {
                body_start = at(line, structure) + line.len();
                break;
            }
            continue;
        }
        let from = at(trimmed, structure);
        let colon = from + trimmed.find(':')?;
        let name = &text[from..colon];
        let value = text[colon + 1..from + trimmed.len()].trim();
        multipart |= name.contains("Content-Type") && value.contains("multipart/");
        headers.push((name, value));
    }
    let body = &text[body_start..];
    Some(RawRequest {
        method: &text[method.0..method.1],
        target: target.map_or("", |(start, end)| &text[start..end]),
        headers,
        body: if multipart {
            body
        } else {
            body.strip_suffix("\r\n").unwrap_or(body)
        },
    })
}

/// The `@timeout:` a raw request asks for, which Nuclei reads from the first
/// line starting with it. None when an annotation would send the request
/// elsewhere, connect differently or change the flow, or the timeout is not
/// a duration.
pub fn raw_timeout(text: &str) -> Option<Option<Duration>> {
    let mut timeout = None;
    for line in text.lines() {
        let Some(annotation) = line.strip_prefix('@') else {
            continue;
        };
        if annotation.starts_with("Host:")
            || annotation.starts_with("tls-sni:")
            || annotation.trim_end() == "once"
        {
            return None;
        }
        if let (None, Some(value)) = (timeout, annotation.strip_prefix("timeout:")) {
            timeout = Some(go_duration(value.trim())?);
        }
    }
    Some(timeout)
}

/// A duration as Go's `time.ParseDuration` reads one, such as `20s` or
/// `1m30s`, capped as Nuclei caps a timeout.
fn go_duration(text: &str) -> Option<Duration> {
    if text == "0" {
        return Some(Duration::ZERO);
    }
    let mut rest = text;
    let mut seconds = 0.0;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let value: f64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let unit = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        seconds += value
            * match &rest[..unit] {
                "ns" => 1e-9,
                "us" | "\u{b5}s" | "\u{3bc}s" => 1e-6,
                "ms" => 1e-3,
                "s" => 1.0,
                "m" => 60.0,
                "h" => 3600.0,
                _ => return None,
            };
        rest = &rest[unit..];
    }
    (!text.is_empty()).then(|| Duration::from_secs_f64(seconds.min(MAX_TIMEOUT_SECS)))
}

/// The path and query a raw request line's target asks for, joined to the
/// target's own path as Nuclei joins them. An absolute target keeps only its
/// path and query: the target the operator chose supplies the host.
fn raw_request_path(base_path: &str, target: &str) -> String {
    let scheme = target.get(..8).unwrap_or(target).to_ascii_lowercase();
    let relative = if scheme.starts_with("http://") || scheme.starts_with("https://") {
        let rest = &target[target.find("//").map_or(0, |at| at + 2)..];
        &rest[rest.find(['/', '?', '#']).unwrap_or(rest.len())..]
    } else {
        target
    };
    // `GET / HTTP/1.1` asks for the target itself.
    if relative.is_empty() || relative == "/" {
        return base_path.to_string();
    }
    let relative = relative.split('#').next().unwrap_or("");
    let (path, query) = relative.split_once('?').unwrap_or((relative, ""));
    let path = if path.is_empty() || path.starts_with('/') {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(format!("/{path}"))
    };
    // Nuclei's join, quirks included: a path that already starts with the
    // target's, or that the target's ends with, is not repeated.
    let joined = if base_path.is_empty() || base_path == path {
        path.into_owned()
    } else if path.is_empty()
        || (base_path.len() > path.len() && base_path.ends_with(path.as_ref()))
    {
        base_path.to_string()
    } else if path.starts_with(base_path) {
        path.into_owned()
    } else {
        format!("{base_path}{path}")
    };
    if query.is_empty() {
        joined
    } else {
        format!("{joined}?{query}")
    }
}

/// A path and query fit for a request line, as Go sends what Nuclei builds:
/// the fragment left off, and what a request line cannot carry
/// percent-encoded. None when it still is not one.
pub fn request_target(raw: &str) -> Option<String> {
    let raw = raw.split('#').next().unwrap_or("");
    let mut out = String::with_capacity(raw.len() + 1);
    if !raw.starts_with('/') {
        out.push('/');
    }
    for byte in raw.bytes() {
        if byte <= b' ' || byte >= 0x7f || matches!(byte, b'"' | b'<' | b'>' | b'`') {
            out.push_str(&format!("%{byte:02X}"));
        } else {
            out.push(byte as char);
        }
    }
    http::uri::PathAndQuery::try_from(out.as_str()).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::model::{classify, parse};

    fn compiled(yaml: &str) -> ActiveTemplate {
        let parsed = parse(yaml).unwrap();
        let classification = classify(&parsed);
        compile_active(&parsed, &classification, &HashMap::new()).unwrap()
    }

    fn target(url: &str) -> (UrlVars, String) {
        let url = url::Url::parse(url).unwrap();
        let base_path = url.path().trim_end_matches('/').to_string();
        (UrlVars::of_url(&url, &base_path).unwrap(), base_path)
    }

    #[test]
    fn each_oast_marker_gets_its_own_url_under_the_sessions_server() {
        let template = compiled(
            "id: example-oast\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}/?a=http://{{interactsh-url}}&b={{interactsh-url}}']\n    headers:\n      X-Server: '{{interactsh-server}}'\n    matchers:\n      - type: word\n        part: interactsh_protocol\n        words: [http]\n",
        );
        let (url, base_path) = target("https://example.com/");
        let oast = OastUrls {
            correlation_id: "c".repeat(20),
            domain: "oast.example.com".into(),
        };
        let run = template.start_run(&url, Some(&oast)).unwrap();
        let built = template.blocks[0].build(0, &base_path, &run).unwrap();
        let ids = run.oast_ids_in(&built);
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        for id in &ids {
            assert_eq!(id.len(), 33);
            assert!(id.starts_with(&oast.correlation_id));
            assert!(built.target.contains(&format!("{id}.oast.example.com")));
        }
        assert_eq!(built.headers[0].1, "oast.example.com");
        // Matchers may look for the URL the request carried.
        assert!(run.values()["interactsh-url"].ends_with(".oast.example.com"));
        // With no server to hear a callback the request is not built.
        let bare = template.start_run(&url, None).unwrap();
        assert!(template.blocks[0].build(0, &base_path, &bare).is_err());
    }

    #[test]
    fn paths_extend_the_target_and_never_leave_it() {
        let template = compiled(
            "id: example-paths\ninfo: {}\nhttp:\n  - method: post\n    path:\n      - '{{BaseURL}}/.git/config'\n      - '{{RootURL}}/admin?q=<b> c#frag'\n      - '{{BaseURL}}@example.net'\n      - '{{BaseURL}}?next={{BaseURL}}/x'\n    headers:\n      Host: '{{Hostname}}'\n      X-Probe: '{{Host}}:{{Port}}'\n    body: 'a={{Path}}'\n    matchers:\n      - type: status\n        status: [200]\n",
        );
        let (url, base_path) = target("https://example.com:8443/app/");
        assert_eq!(url.hostname, "example.com:8443");
        assert_eq!(url.base_url, "https://example.com:8443/app");
        let run = template.start_run(&url, None).unwrap();
        let built: Vec<BuiltRequest> = (0..template.request_count())
            .map(|index| template.blocks[0].build(index, &base_path, &run).unwrap())
            .collect();
        assert_eq!(built[0].method, "POST");
        assert_eq!(built[0].target, "/app/.git/config");
        assert_eq!(built[1].target, "/admin?q=%3Cb%3E%20c");
        assert_eq!(built[2].target, "/app@example.net");
        assert_eq!(built[3].target, "/app?next=https://example.com:8443/app/x");
        // Host comes from the target alone.
        assert_eq!(
            built[0].headers,
            [("X-Probe".to_string(), "example.com:8443".to_string())]
        );
        let (root, root_path) = target("http://example.com");
        assert_eq!(root.hostname, "example.com");
        let run = template.start_run(&root, None).unwrap();
        assert_eq!(
            template.blocks[0]
                .build(0, &root_path, &run)
                .unwrap()
                .target,
            "/.git/config"
        );
        assert_eq!(
            template.blocks[0]
                .build(2, &root_path, &run)
                .unwrap()
                .target,
            "/@example.net"
        );
    }

    #[test]
    fn variables_and_random_values_are_shared_by_the_run() {
        let template = compiled(
            "id: example-vars\ninfo: {}\nvariables:\n  a_digest: '{{md5(z_token)}}'\n  z_token: '{{randstr}}'\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/?t={{z_token}}&d={{a_digest}}&r={{randstr}}'\n    matchers:\n      - type: word\n        words: ['{{z_token}}']\n",
        );
        let (url, base_path) = target("https://example.com");
        let run = template.start_run(&url, None).unwrap();
        let built = template.blocks[0].build(0, &base_path, &run).unwrap();
        let values = run.values();
        let token = &values["z_token"];
        assert_eq!(token.len(), 27);
        assert_eq!(values["randstr"], *token);
        assert_eq!(
            built.target,
            format!("/?t={token}&d={}&r={token}", values["a_digest"])
        );
        // Each run makes its own.
        let other = template.start_run(&url, None).unwrap();
        assert_ne!(other.values()["z_token"], *token);
    }

    fn raw_template(raws: &[&str]) -> ActiveTemplate {
        let template = serde_json::json!({
            "id": "example-raw",
            "info": {},
            "http": [{"raw": raws, "matchers": [{"type": "status", "status": [200]}]}],
        });
        compiled(&template.to_string())
    }

    fn built_all(template: &ActiveTemplate, url: &str) -> (Vec<BuiltRequest>, String) {
        let (url, base_path) = target(url);
        let run = template.start_run(&url, None).unwrap();
        let built = (0..template.request_count())
            .map(|index| template.blocks[0].build(index, &base_path, &run).unwrap())
            .collect();
        let token = run.values().get("randstr").cloned().unwrap_or_default();
        (built, token)
    }

    #[test]
    fn raw_requests_are_read_as_nuclei_reads_them() {
        let template = raw_template(&[
            "POST /login?next=/home HTTP/1.1\nHost: {{Hostname}}\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 999\nX-Dup: one\nX-Dup: two\n\nuser=admin&token={{randstr}}\n",
            "GET {{BaseURL}}/cobbler_api HTTP/1.1\nHost: {{Hostname}}\n",
            "GET / HTTP/1.1\n",
            "GET https://example.net/x?a=1#frag HTTP/1.1\n",
            "GET admin HTTP/1.1\n",
            "GET /app/z HTTP/1.1\n",
            "GET HTTP/1.1\n",
        ]);
        let (built, token) = built_all(&template, "https://example.com:8443/app/");
        assert_eq!(built[0].method, "POST");
        assert_eq!(built[0].target, "/app/login?next=/home");
        // The target supplies Host, the sender the length, and a repeated
        // header keeps its last value.
        assert_eq!(
            built[0].headers,
            [
                (
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string()
                ),
                ("X-Dup".to_string(), "two".to_string()),
            ]
        );
        // Lines end in CRLF, and the body's last line end is not sent.
        assert_eq!(built[0].body, format!("user=admin&token={token}"));
        assert_eq!(built[0].timeout, None);
        assert_eq!(built[1].target, "/app/cobbler_api");
        assert_eq!(built[2].target, "/app");
        // An absolute target keeps only its path and query: the target the
        // operator chose supplies the host.
        assert_eq!(built[3].target, "/app/x?a=1");
        assert_eq!(built[4].target, "/app/admin");
        // Nuclei merges a path that already starts with the target's own.
        assert_eq!(built[5].target, "/app/z");
        assert_eq!(built[6].target, "/app");
        let (root, _) = built_all(&template, "http://example.com");
        assert_eq!(root[2].target, "/");
        assert_eq!(root[4].target, "/admin");
        assert_eq!(root[6].target, "/");
    }

    #[test]
    fn a_multipart_raw_body_keeps_its_last_line_end_and_timeouts_are_read() {
        let template = raw_template(&[
            "@timeout: 20s\nPOST /upload HTTP/1.1\nContent-Type: multipart/form-data; boundary=b\n\n--b\nContent-Disposition: form-data; name=\"f\"\n\nx\n--b--\n",
            "@timeout: 2h\nGET / HTTP/1.1\n",
            "GET / HTTP/1.1\r\nX-A: b\r\n\r\nkept\n",
        ]);
        let (built, _) = built_all(&template, "https://example.com");
        assert_eq!(
            built[0].body,
            "--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx\r\n--b--\r\n"
        );
        assert_eq!(built[0].timeout, Some(std::time::Duration::from_secs(20)));
        // Nuclei caps a template's timeout at five minutes.
        assert_eq!(built[1].timeout, Some(std::time::Duration::from_secs(300)));
        // Text that already has CRLF line ends is sent as written.
        assert_eq!(built[2].body, "kept\n");
        assert_eq!(built[2].headers, [("X-A".to_string(), "b".to_string())]);
    }

    fn payload_template(
        attack: Option<&str>,
        paths: &[&str],
        sets: serde_json::Value,
    ) -> ActiveTemplate {
        let mut block = serde_json::json!({
            "path": paths,
            "payloads": sets,
            "matchers": [{"type": "status", "status": [200]}],
        });
        if let Some(attack) = attack {
            block["attack"] = attack.into();
        }
        compiled(
            &serde_json::json!({"id": "example-words", "info": {}, "http": [block]}).to_string(),
        )
    }

    /// Each pass's request targets, and the values the run's matchers see.
    fn passes(template: &ActiveTemplate) -> Vec<(Vec<String>, HashMap<String, String>)> {
        let (url, base_path) = target("https://example.com");
        let run = template.start_run(&url, None).unwrap();
        (0..template.blocks[0].passes())
            .map(|pass| {
                template.blocks[0].load_pass(&run, pass).unwrap();
                let targets = (0..template.blocks[0].sequence_len())
                    .map(|index| {
                        template.blocks[0]
                            .build(index, &base_path, &run)
                            .unwrap()
                            .target
                    })
                    .collect();
                (targets, run.values())
            })
            .collect()
    }

    fn file_template(path: &str) -> Result<ActiveTemplate, CompileError> {
        let yaml = serde_json::json!({"id": "example-words", "info": {}, "http": [{
            "path": ["{{BaseURL}}/{{word}}"],
            "payloads": {"word": path},
            "matchers": [{"type": "status", "status": [200]}],
        }]})
        .to_string();
        let parsed = parse(&yaml).unwrap();
        let files = HashMap::from([(
            "helpers/wordlists/words.txt".to_string(),
            "admin\n\nlogin\r\n".to_string(),
        )]);
        compile_active(&parsed, &classify(&parsed), &files)
    }

    #[test]
    fn payload_files_are_read_line_by_line_from_the_release() {
        for path in [
            "helpers/wordlists/words.txt",
            "./helpers/wordlists/words.txt",
        ] {
            let template = file_template(path).unwrap();
            let targets: Vec<String> = passes(&template)
                .into_iter()
                .map(|(targets, _)| targets[0].clone())
                .collect();
            // Blank lines are skipped, as Nuclei skips them.
            assert_eq!(targets, ["/admin", "/login"], "{path}");
        }
        for path in ["helpers/wordlists/missing.txt", "helpers/../../words.txt"] {
            assert_eq!(
                file_template(path).unwrap_err().0,
                "req:payload_file",
                "{path}"
            );
        }
    }

    #[test]
    fn a_template_that_would_send_too_much_is_not_compiled() {
        let numbers = |count: usize| (0..count).map(|n| n.to_string()).collect::<Vec<_>>();
        let yaml = serde_json::json!({"id": "example-many", "info": {}, "http": [{
            "path": ["{{BaseURL}}/{{a}}/{{b}}"],
            "attack": "clusterbomb",
            "payloads": {"a": numbers(101), "b": numbers(100)},
            "matchers": [{"type": "status", "status": [200]}],
        }]})
        .to_string();
        let parsed = parse(&yaml).unwrap();
        let error = compile_active(&parsed, &classify(&parsed), &HashMap::new()).unwrap_err();
        assert_eq!(error.0, "req:too_many_requests");
    }

    #[test]
    fn payloads_combine_as_nuclei_attacks_do() {
        let sets = serde_json::json!({"a": ["1", "2"], "b": ["x", "y", "z"]});
        let paths = ["{{BaseURL}}/{{a}}-{{b}}", "{{BaseURL}}/second"];
        let cluster = payload_template(Some("clusterbomb"), &paths, sets.clone());
        assert_eq!(cluster.request_count(), 12);
        let run = passes(&cluster);
        let firsts: Vec<&str> = run.iter().map(|(targets, _)| targets[0].as_str()).collect();
        // The first set changes fastest.
        assert_eq!(firsts, ["/1-x", "/2-x", "/1-y", "/2-y", "/1-z", "/2-z"]);
        assert_eq!(run[0].0[1], "/second");
        let fork = payload_template(Some("pitchfork"), &paths, sets);
        let firsts: Vec<String> = passes(&fork)
            .into_iter()
            .map(|(targets, _)| targets[0].clone())
            .collect();
        assert_eq!(firsts, ["/1-x", "/2-y"]);
        // One set by default; its values fill their markers but a marker
        // that names nothing stays as written.
        let ram = payload_template(
            None,
            &["{{BaseURL}}/{{a}}"],
            serde_json::json!({"a": "1\n{{Hostname}}\n{{7*7}}"}),
        );
        assert_eq!(ram.request_count(), 3);
        let run = passes(&ram);
        let targets: Vec<&str> = run.iter().map(|(targets, _)| targets[0].as_str()).collect();
        assert_eq!(targets, ["/1", "/example.com", "/{{7*7}}"]);
        // Matchers see the pass's values.
        assert_eq!(run[1].1["a"], "example.com");
    }

    #[test]
    fn a_body_with_bare_line_feeds_is_sent_with_crlf_as_nuclei_does() {
        let template = compiled(
            "id: example-body\ninfo: {}\nhttp:\n  - method: POST\n    path: ['{{BaseURL}}/x']\n    body: |\n      a\n      b\n    matchers:\n      - type: status\n        status: [200]\n",
        );
        let (built, _) = built_all(&template, "https://example.com");
        assert_eq!(built[0].body, "a\r\nb\r\n");
        assert!(template.blocks[0].cookies);
        let template = compiled(
            "id: example-no-cookie\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}/x']\n    disable-cookie: true\n    matchers:\n      - type: status\n        status: [200]\n",
        );
        assert!(!template.blocks[0].cookies);
    }

    #[test]
    fn redirect_settings_follow_nuclei() {
        let none = compiled(
            "id: a\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: status\n        status: [200]\n",
        );
        assert_eq!(none.blocks[0].follow, Follow::None);
        let all = compiled(
            "id: b\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}']\n    redirects: true\n    max-redirects: 3\n    matchers:\n      - type: status\n        status: [200]\n",
        );
        assert_eq!(
            (all.blocks[0].follow, all.blocks[0].max_redirects),
            (Follow::All, 3)
        );
        let host = compiled(
            "id: c\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}']\n    redirects: true\n    host-redirects: true\n    max-redirects: 40\n    stop-at-first-match: true\n    matchers:\n      - type: status\n        status: [200]\n",
        );
        assert_eq!(
            (
                host.blocks[0].follow,
                host.blocks[0].max_redirects,
                host.blocks[0].stop_at_first_match,
            ),
            (Follow::SameHost, MAX_REDIRECTS, true)
        );
    }

    #[test]
    fn request_targets_are_what_a_request_line_carries() {
        assert_eq!(request_target("").as_deref(), Some("/"));
        assert_eq!(request_target("?a=1").as_deref(), Some("/?a=1"));
        assert_eq!(
            request_target("/x?q=\"é\"`").as_deref(),
            Some("/x?q=%22%C3%A9%22%60")
        );
        assert_eq!(
            request_target("/..;/a/%2e%2e/{x}").as_deref(),
            Some("/..;/a/%2e%2e/{x}")
        );
    }

    #[test]
    fn an_unbuildable_request_says_so_instead_of_sending_part() {
        let template = compiled(
            "id: example-bad\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/{{base64_decode(\"%%%\")}}']\n    matchers:\n      - type: status\n        status: [200]\n",
        );
        let (url, base_path) = target("https://example.com");
        let run = template.start_run(&url, None).unwrap();
        assert!(template.blocks[0].build(0, &base_path, &run).is_err());
    }
}
