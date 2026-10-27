//! An OpenAPI 3.1 description of one origin's API, built from its retained
//! rows as Burp's API Exporter and mitmproxy2swagger build one from captured
//! traffic. It lists only what the rows showed: each method and path template,
//! the parameter names its requests carried with a type guessed from their
//! values, the statuses and media types it answered with, and the credentials
//! its rows showed. No captured value is copied into it; each operation names
//! its newest row (`x-sniper-newest-transaction`), Sniper's own ID for it.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    service_map_auth::AuthSignal,
    service_map_parameters::{body_parameter_location, EndpointParameter},
};

#[cfg(test)]
#[path = "service_map_openapi_coverage_tests.rs"]
mod coverage_tests;

/// Operations described per origin, the most recently used first.
pub const MAX_OPERATIONS: usize = 500;
/// Each operation's newest rows whose parameters are read.
pub const MAX_ROWS_PER_OPERATION: usize = 20;

/// The methods a path item holds. OPTIONS is left out: captured, it is nearly
/// always a browser's CORS preflight rather than part of the API.
pub const METHODS: [&str; 7] = ["get", "put", "post", "delete", "head", "patch", "trace"];

/// What one method and path template's rows showed.
#[derive(Default)]
pub struct Operation {
    pub requests: usize,
    /// Each response status, with the media types answered with it.
    pub responses: BTreeMap<u16, BTreeSet<String>>,
    /// Media types of the request bodies sent.
    pub request_types: BTreeSet<String>,
    pub auth: BTreeSet<AuthSignal>,
    pub parameters: Vec<EndpointParameter>,
    /// At least one contributing pre-merge tally dropped (location, name)
    /// entries at the parameter cap. This is not a count of distinct names
    /// missing from the merged operation or an overall completeness claim.
    pub parameter_cap_truncated: bool,
    /// The newest row's capture sequence and transaction ID, to open or
    /// send on; the sequence picks the newest of merged paths.
    pub newest: Option<(u64, Uuid)>,
    /// Native JSON field types, retained before display examples lose their types.
    /// Missing or empty evidence leaves that field unconstrained.
    pub json_types: BTreeMap<String, BTreeSet<&'static str>>,
}

/// A path ending in one of these names a static file, whatever it was answered
/// with: a font sent as `application/octet-stream`, a 304 with no type.
const STATIC_EXTENSIONS: [&str; 22] = [
    "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp",
    "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "wav",
];

/// The OpenAPI path for a captured path: its ID segments as templates
/// (`path_group`), a brace it had escaped so it is not read as one, and no
/// matrix parameters: `;jsessionid=8F1E…` is a session, not a path.
pub fn operation_path(path: &str) -> String {
    let path = path
        .split('/')
        .map(|segment| segment.split(';').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("/")
        .replace('{', "%7B")
        .replace('}', "%7D");
    crate::service_map::path_group(&path).unwrap_or(path)
}

/// Whether a path names a static file, whatever it was answered with.
pub fn static_path(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or("");
    file.rsplit_once('.').is_some_and(|(_, extension)| {
        STATIC_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
    })
}

/// A content type's media type, without parameters and lowercased.
pub fn media_type(content_type: &str) -> Option<String> {
    let media = content_type.split(';').next()?.trim().to_ascii_lowercase();
    media.contains('/').then_some(media)
}

/// `operations` by path template and lowercase method. `omitted` counts the
/// operations the rows showed beyond `MAX_OPERATIONS`.
pub fn document(
    origin: &str,
    operations: &BTreeMap<(String, String), Operation>,
    omitted: usize,
    static_requests: usize,
) -> Value {
    let (mut paths, mut schemes) = (Map::new(), Map::new());
    let (mut requests, mut site_only) = (static_requests, 0);
    let mut grouped: BTreeMap<String, (BTreeSet<&str>, BTreeMap<&str, Vec<&Operation>>)> =
        BTreeMap::new();
    for ((path, method), operation) in operations {
        requests += operation.requests;
        if !api(path, operation) {
            site_only += 1;
            continue;
        }
        // OAS forbids separate paths that differ only in template names.
        // Keep all methods and evidence when numeric, UUID or hex IDs coexist.
        let (variants, methods) = grouped.entry(path_shape(path)).or_default();
        variants.insert(path);
        methods.entry(method).or_default().push(operation);
    }
    for (variants, methods) in grouped.values() {
        let (template, path_parameters) = path_template(variants);
        let item = paths.entry(template).or_insert_with(|| json!({}));
        if !path_parameters.is_empty() {
            item["parameters"] = path_parameters.into();
        }
        for (method, observations) in methods {
            let operation = merge_operations(observations);
            let mut value = json!({
                "responses": responses(&operation),
                "x-sniper-requests": operation.requests,
            });
            if operation.parameter_cap_truncated {
                value["x-sniper-parameter-cap-truncated"] = true.into();
            }
            if let Some((_, newest)) = operation.newest {
                value["x-sniper-newest-transaction"] = newest.to_string().into();
            }
            let query: Vec<Value> = operation
            .parameters
            .iter()
            .filter(|parameter| parameter.location == "query")
            .map(|parameter| {
                json!({"name": parameter.name, "in": "query", "schema": schema(&parameter.examples)})
            })
            .collect();
            if !query.is_empty() {
                value["parameters"] = query.into();
            }
            if let Some(body) = request_body(&operation) {
                value["requestBody"] = body;
            }
            // Each credential the rows showed is one way in; the rows cannot
            // tell which ones the server requires.
            let security: Vec<Value> = operation
                .auth
                .iter()
                .filter_map(|signal| scheme_key(signal, &mut schemes))
                .map(|key| json!({ key: [] }))
                .collect();
            if !security.is_empty() {
                value["security"] = security.into();
            }
            item[*method] = value;
        }
    }
    let mut notes = vec![format!(
        "Observed by Sniper in {requests} captured requests to {origin}. It lists only what \
         they showed: methods, paths with ID segments as {{number}}, {{uuid}}, {{hex}} or mixed {{id}}, \
         parameter names with observed JSON types or types guessed from text, response statuses and media \
         types, and the credentials the rows carried. No captured value is included."
    )];
    if static_requests > 0 {
        notes.push(format!(
            "{static_requests} requests for static files (scripts, styles, images, fonts, media) are left out."
        ));
    }
    if site_only > 0 {
        notes.push(format!(
            "{site_only} operations that only answered with pages or static files are left out."
        ));
    }
    if omitted > 0 {
        notes.push(format!(
            "{omitted} less recently used operations are left out; at most {MAX_OPERATIONS} are listed."
        ));
    }
    let mut document = json!({
        "openapi": "3.1.0",
        "info": {"title": origin, "version": "observed", "description": notes.join(" ")},
        "servers": [{"url": origin}],
        "paths": paths,
    });
    if !schemes.is_empty() {
        document["components"] = json!({ "securitySchemes": schemes });
    }
    document
}

/// An operation that only ever answered with pages or static files (HTML,
/// styles, scripts, images, fonts, media, a web app manifest), or whose path
/// names a static file, belongs to the site rather than its API. One that
/// answered with anything else, or with no typed body, is kept.
fn api(path: &str, operation: &Operation) -> bool {
    if static_path(path) {
        return false;
    }
    let mut types = operation.responses.values().flatten().peekable();
    types.peek().is_none()
        || types.any(|media| {
            ![
                "html",
                "css",
                "javascript",
                "ecmascript",
                "manifest",
                "font",
                "image/",
                "audio/",
                "video/",
            ]
            .iter()
            .any(|word| media.contains(word))
        })
}

/// The identity of a templated hierarchy, independent of its parameter names.
fn path_shape(path: &str) -> String {
    path.split('/')
        .map(|segment| match segment {
            "{number}" | "{uuid}" | "{hex}" => "{id}",
            _ => segment,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Names are specific when all observations agree, otherwise `id`; repeated
/// names are numbered. Literal braces were escaped before grouping.
fn path_template(paths: &BTreeSet<&str>) -> (String, Vec<Value>) {
    let segments: Vec<Vec<_>> = paths.iter().map(|path| path.split('/').collect()).collect();
    let mut counts = BTreeMap::new();
    let mut parameters = Vec::new();
    let template = segments[0]
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            let kinds: BTreeSet<_> = segments.iter().map(|parts| parts[index]).collect();
            let schemas: Vec<_> = kinds
                .iter()
                .filter_map(|kind| match *kind {
                    "{number}" => Some(json!({"type": "integer"})),
                    "{uuid}" => Some(json!({"type": "string", "format": "uuid"})),
                    "{hex}" => Some(json!({"type": "string", "pattern": "^[0-9A-Fa-f]+$"})),
                    _ => None,
                })
                .collect();
            if schemas.is_empty() {
                return segment.to_string();
            }
            let (kind, schema) = if schemas.len() == 1 {
                (
                    &segment[1..segment.len() - 1],
                    schemas.into_iter().next().unwrap(),
                )
            } else {
                ("id", json!({"anyOf": schemas}))
            };
            let count = counts.entry(kind).and_modify(|n| *n += 1).or_insert(1);
            let name = match *count {
                1 => kind.to_string(),
                count => format!("{kind}{count}"),
            };
            parameters
                .push(json!({"name": name, "in": "path", "required": true, "schema": schema}));
            format!("{{{name}}}")
        })
        .collect::<Vec<_>>()
        .join("/");
    (template, parameters)
}

fn merge_operations(sources: &[&Operation]) -> Operation {
    let mut target = Operation::default();
    let mut parameters: BTreeMap<(&str, &str), (usize, BTreeSet<&str>)> = BTreeMap::new();
    for source in sources {
        target.requests += source.requests;
        target.parameter_cap_truncated |= source.parameter_cap_truncated;
        target.newest = target.newest.max(source.newest);
        for (status, types) in &source.responses {
            target
                .responses
                .entry(*status)
                .or_default()
                .extend(types.iter().cloned());
        }
        target
            .request_types
            .extend(source.request_types.iter().cloned());
        target.auth.extend(source.auth.iter().cloned());
        for parameter in &source.parameters {
            if parameter.location == "json" {
                let types = source
                    .json_types
                    .get(&parameter.name)
                    .cloned()
                    .unwrap_or_default();
                target
                    .json_types
                    .entry(parameter.name.clone())
                    .and_modify(|known| {
                        if known.is_empty() || types.is_empty() {
                            known.clear();
                        } else {
                            known.extend(&types);
                        }
                    })
                    .or_insert(types);
            }
            let (rows, examples) = parameters
                .entry((&parameter.location, &parameter.name))
                .or_default();
            *rows += parameter.rows;
            // Index both names and examples: many colliding variants can have
            // distinct fields. Repeated vector scans would make merging quadratic.
            // Keep every retained example for textual type inference.
            examples.extend(parameter.examples.iter().map(String::as_str));
        }
    }
    target.parameters = parameters
        .into_iter()
        .map(|((location, name), (rows, examples))| EndpointParameter {
            name: name.into(),
            location: location.into(),
            rows,
            examples: examples.into_iter().map(str::to_string).collect(),
        })
        .collect();
    target
}

/// A type every value seen fits, or a string. A leading zero (`007`) marks a
/// code rather than a number.
fn schema(examples: &[String]) -> Value {
    let every = |test: &dyn Fn(&str) -> bool| {
        !examples.is_empty() && examples.iter().all(|value| test(value))
    };
    let numeric = |value: &str| {
        !(value.len() > 1 && value.starts_with('0') && value.as_bytes()[1].is_ascii_digit())
            && value.parse::<f64>().is_ok_and(f64::is_finite)
    };
    let kind = if every(&|value| numeric(value) && value.parse::<i64>().is_ok()) {
        "integer"
    } else if every(&numeric) {
        "number"
    } else if every(&|value| value == "true" || value == "false") {
        "boolean"
    } else {
        "string"
    };
    json!({ "type": kind })
}

fn json_schema(types: Option<&BTreeSet<&str>>) -> Value {
    let Some(types) = types.filter(|types| !types.is_empty()) else {
        return json!({});
    };
    let mut types = types.clone();
    if types.contains("number") {
        types.remove("integer");
    }
    let mut schema = if types.len() == 1 {
        json!({"type": types.first().unwrap()})
    } else {
        json!({"type": types})
    };
    if types.contains("array") {
        // Element types are not sampled; every observed array must still fit.
        schema["items"] = json!({});
    }
    schema
}

/// Each request media type, with the form, JSON or multipart fields sent as
/// it, matched as `ParameterTally` read them.
fn request_body(operation: &Operation) -> Option<Value> {
    let content: Map<String, Value> = operation
        .request_types
        .iter()
        .map(|media| {
            let location = body_parameter_location(media).unwrap_or("");
            let properties: Map<String, Value> = operation
                .parameters
                .iter()
                .filter(|parameter| parameter.location == location)
                .map(|parameter| {
                    let schema = if location == "json" {
                        json_schema(operation.json_types.get(&parameter.name))
                    } else {
                        schema(&parameter.examples)
                    };
                    (parameter.name.clone(), schema)
                })
                .collect();
            let value = if properties.is_empty() {
                json!({})
            } else {
                json!({"schema": {"type": "object", "properties": properties}})
            };
            (media.clone(), value)
        })
        .collect();
    (!content.is_empty()).then(|| json!({ "content": content }))
}

fn responses(operation: &Operation) -> Value {
    let mut responses: Map<String, Value> = operation
        .responses
        .iter()
        .map(|(status, types)| {
            let reason = http::StatusCode::from_u16(*status)
                .ok()
                .and_then(|status| status.canonical_reason())
                .unwrap_or("Observed");
            let mut response = json!({ "description": reason });
            if !types.is_empty() {
                let content: Map<String, Value> = types
                    .iter()
                    .map(|media| (media.clone(), json!({})))
                    .collect();
                response["content"] = content.into();
            }
            (status.to_string(), response)
        })
        .collect();
    if responses.is_empty() {
        responses.insert(
            "default".into(),
            json!({"description": "No response was captured"}),
        );
    }
    responses.into()
}

/// The key of the security scheme a signal stands for, added to `schemes` on
/// first use. OAuth, OpenID Connect and SAML are sign-in exchanges rather than
/// credentials a request carries, so they have none.
fn scheme_key(signal: &AuthSignal, schemes: &mut Map<String, Value>) -> Option<String> {
    let name = signal.name.as_deref();
    let value = match (signal.kind, name) {
        ("bearer_jwt", _) => json!({"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}),
        ("bearer" | "basic" | "digest" | "negotiate" | "ntlm", _) => {
            json!({"type": "http", "scheme": signal.kind})
        }
        ("aws_sigv4", _) => json!({"type": "http", "scheme": "AWS4-HMAC-SHA256"}),
        ("scheme", Some(name)) => json!({"type": "http", "scheme": name}),
        ("scheme", None) => json!({"type": "apiKey", "in": "header", "name": "Authorization"}),
        ("api_key_header", Some(name)) => json!({"type": "apiKey", "in": "header", "name": name}),
        ("session_cookie" | "jwt_cookie", Some(name)) => {
            json!({"type": "apiKey", "in": "cookie", "name": name})
        }
        ("query_key", Some(name)) => json!({"type": "apiKey", "in": "query", "name": name}),
        _ => return None,
    };
    // A component key allows letters, digits, `.`, `-` and `_` only; two
    // names that read the same once cleaned get numbered keys.
    let base: String = name
        .map_or_else(
            || signal.kind.to_string(),
            |name| format!("{}_{name}", signal.kind),
        )
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => c,
            _ => '_',
        })
        .collect();
    let mut key = base.clone();
    for n in 2.. {
        match schemes.get(&key) {
            Some(existing) if *existing == value => break,
            Some(_) => key = format!("{base}_{n}"),
            None => {
                schemes.insert(key.clone(), value);
                break;
            }
        }
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameter(location: &str, name: &str, examples: &[&str]) -> EndpointParameter {
        EndpointParameter {
            name: name.into(),
            location: location.into(),
            rows: 1,
            examples: examples.iter().map(|value| value.to_string()).collect(),
        }
    }

    #[test]
    fn body_schemas_use_the_same_exact_media_types_as_parameter_extraction() {
        let operation = Operation {
            request_types: [
                "application/json",
                "application/problem+json",
                "application/notjson",
                "application/x-www-form-urlencoded-fake",
                "multipart/form-data",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            parameters: vec![
                parameter("json", "json_field", &["42"]),
                parameter("form", "form_field", &["value"]),
                parameter("multipart", "file", &[]),
            ],
            ..Operation::default()
        };
        let body = request_body(&operation).unwrap();
        let content = &body["content"];
        assert!(content["application/json"]["schema"]["properties"]
            .get("json_field")
            .is_some());
        assert!(content["application/problem+json"]["schema"]["properties"]
            .get("json_field")
            .is_some());
        assert!(content["multipart/form-data"]["schema"]["properties"]
            .get("file")
            .is_some());
        assert_eq!(content["application/notjson"], json!({}));
        assert_eq!(content["application/x-www-form-urlencoded-fake"], json!({}));
    }

    fn signal(kind: &'static str, name: Option<&str>) -> AuthSignal {
        AuthSignal {
            kind,
            name: name.map(str::to_string),
        }
    }

    #[test]
    fn a_matrix_parameter_is_a_value_not_part_of_the_path() {
        assert_eq!(
            operation_path("/app/list.do;jsessionid=8F1E0A"),
            "/app/list.do"
        );
        assert_eq!(operation_path("/a;v=1/items/12"), "/a/items/{number}");
        assert!(static_path("/static/app.JS") && !static_path("/api/items"));
    }

    #[test]
    fn a_path_names_its_id_segments_and_braces_stay_literal() {
        assert_eq!(
            operation_path("/chats/12/posts/507f1f77bcf86cd799439011"),
            "/chats/{number}/posts/{hex}"
        );
        assert_eq!(operation_path("/raw/{x}"), "/raw/%7Bx%7D");
        let (template, parameters) =
            path_template(&BTreeSet::from(["/a/{number}/b/{number}/c/{uuid}"]));
        assert_eq!(template, "/a/{number}/b/{number2}/c/{uuid}");
        assert_eq!(
            parameters,
            [
                json!({"name": "number", "in": "path", "required": true, "schema": {"type": "integer"}}),
                json!({"name": "number2", "in": "path", "required": true, "schema": {"type": "integer"}}),
                json!({"name": "uuid", "in": "path", "required": true, "schema": {"type": "string", "format": "uuid"}}),
            ]
        );
    }

    #[test]
    fn types_are_guessed_from_values_that_are_then_dropped() {
        let kind = |values: &[&str]| {
            let values: Vec<String> = values.iter().map(|value| value.to_string()).collect();
            schema(&values)["type"].as_str().unwrap().to_string()
        };
        assert_eq!(kind(&["1", "-20"]), "integer");
        assert_eq!(kind(&["1", "2.5"]), "number");
        assert_eq!(kind(&["007"]), "string");
        assert_eq!(kind(&["true", "false"]), "boolean");
        assert_eq!(kind(&["[\"a\"]"]), "string");
        assert_eq!(kind(&["inf"]), "string");
        assert_eq!(kind(&[]), "string");
    }

    fn json_operation(bodies: &[&str]) -> Operation {
        let mut tally = crate::service_map_parameters::ParameterTally::default();
        for body in bodies {
            tally.add_row(None, Some("application/json"), body);
        }
        Operation {
            requests: bodies.len(),
            request_types: BTreeSet::from(["application/json".into()]),
            json_types: tally.json_types(),
            parameters: tally.finish().0,
            ..Default::default()
        }
    }

    #[test]
    fn json_fields_keep_native_types_including_null_and_mixed_observations() {
        let operation = json_operation(&[
            r#"{"count":"42","enabled":"false","list_label":"[draft","object_label":"{draft","nothing":null,"actual_count":42,"actual_float":1.5,"actual_bool":false,"actual_array":[1,"a",null],"actual_object":{},"mixed":1}"#,
            r#"{"mixed":"1"}"#,
            r#"{"mixed":null}"#,
            r#"{"mixed":[],"actual_count":1.5}"#,
        ]);
        let body = request_body(&operation).unwrap();
        let properties = &body["content"]["application/json"]["schema"]["properties"];
        for name in ["count", "enabled", "list_label", "object_label"] {
            assert_eq!(properties[name], json!({"type": "string"}));
        }
        assert_eq!(properties["nothing"], json!({"type": "null"}));
        assert_eq!(properties["actual_count"], json!({"type": "number"}));
        assert_eq!(properties["actual_float"], json!({"type": "number"}));
        assert_eq!(properties["actual_bool"], json!({"type": "boolean"}));
        assert_eq!(
            properties["actual_array"],
            json!({"type": "array", "items": {}})
        );
        assert_eq!(properties["actual_object"], json!({"type": "object"}));
        assert_eq!(
            properties["mixed"],
            json!({"type": ["array", "integer", "null", "string"], "items": {}})
        );
        assert!(!body.to_string().contains("draft"));
    }

    #[test]
    fn unknown_json_types_are_unconstrained_and_text_fields_keep_inference() {
        let operation = Operation {
            request_types: BTreeSet::from([
                "application/json".into(),
                "application/x-www-form-urlencoded".into(),
            ]),
            parameters: vec![
                parameter("json", "unknown", &["42"]),
                parameter("form", "count", &["42"]),
            ],
            ..Default::default()
        };
        let body = request_body(&operation).unwrap();
        assert_eq!(
            body["content"]["application/json"]["schema"]["properties"]["unknown"],
            json!({})
        );
        assert_eq!(
            body["content"]["application/x-www-form-urlencoded"]["schema"]["properties"]["count"],
            json!({"type": "integer"})
        );
        for scalar in ["\"42\"", "42", "false", "null", "[1,false]"] {
            assert!(request_body(&json_operation(&[scalar])).unwrap()["content"]
                ["application/json"]
                .get("schema")
                .is_none());
        }
    }

    #[test]
    fn colliding_templates_merge_methods_counts_responses_auth_and_parameters() {
        let mut number = json_operation(&[r#"{"value":"42","number_only":1}"#]);
        number.requests = 3;
        number.responses = BTreeMap::from([(200, BTreeSet::from(["application/json".into()]))]);
        number.auth.insert(signal("basic", None));
        number.parameters.push(parameter("query", "page", &["1"]));
        let mut uuid = json_operation(&[r#"{"value":42,"uuid_only":null}"#]);
        uuid.requests = 2;
        uuid.responses = BTreeMap::from([
            (200, BTreeSet::from(["application/problem+json".into()])),
            (404, BTreeSet::new()),
        ]);
        uuid.auth.insert(signal("bearer", None));
        uuid.parameters.push(parameter("query", "page", &["2.5"]));
        number.newest = Some((9, Uuid::from_u128(9)));
        uuid.newest = Some((5, Uuid::from_u128(5)));
        let operations = BTreeMap::from([
            ((operation_path("/items/42"), "get".into()), number),
            (
                (
                    operation_path("/items/550e8400-e29b-41d4-a716-446655440000"),
                    "get".into(),
                ),
                uuid,
            ),
            (
                (
                    operation_path("/items/507f1f77bcf86cd799439011"),
                    "post".into(),
                ),
                Operation {
                    requests: 7,
                    ..Default::default()
                },
            ),
            (
                (operation_path("/items/{id}"), "get".into()),
                Operation {
                    requests: 1,
                    ..Default::default()
                },
            ),
            (
                (operation_path("/items/latest"), "get".into()),
                Operation {
                    requests: 1,
                    ..Default::default()
                },
            ),
        ]);
        let document = document("https://api.example.com", &operations, 0, 0);
        let paths = document["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 3);
        assert!(paths.contains_key("/items/%7Bid%7D"));
        assert!(paths.contains_key("/items/latest"));
        let item = &paths["/items/{id}"];
        assert_eq!(
            item["parameters"][0]["schema"]["anyOf"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(item["get"]["x-sniper-requests"], 5);
        assert_eq!(item["post"]["x-sniper-requests"], 7);
        // The merged operation sends on the newest row of any variant.
        assert_eq!(
            item["get"]["x-sniper-newest-transaction"],
            Uuid::from_u128(9).to_string()
        );
        assert!(item["post"].get("x-sniper-newest-transaction").is_none());
        assert_eq!(
            item["get"]["responses"]["200"]["content"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
        assert!(item["get"]["responses"].get("404").is_some());
        assert_eq!(item["get"]["security"].as_array().unwrap().len(), 2);
        assert_eq!(
            item["get"]["parameters"],
            json!([{"name":"page", "in":"query", "schema":{"type":"number"}}])
        );
        let properties =
            &item["get"]["requestBody"]["content"]["application/json"]["schema"]["properties"];
        assert_eq!(properties["value"], json!({"type": ["integer", "string"]}));
        assert!(properties.get("number_only").is_some());
        assert!(properties.get("uuid_only").is_some());
        assert!(document["info"]["description"]
            .as_str()
            .unwrap()
            .contains("14 captured requests"));
        assert!(
            !document.to_string().contains("operationId"),
            "no conflicting operation IDs are invented"
        );
    }

    #[test]
    fn mixed_path_positions_get_unique_names_without_merging_literal_hierarchies() {
        let (path, parameters) = path_template(&BTreeSet::from([
            "/a/{number}/{number}/{number}",
            "/a/{uuid}/{number}/{hex}",
        ]));
        assert_eq!(path, "/a/{id}/{number}/{id2}");
        assert_eq!(
            parameters
                .iter()
                .map(|p| p["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["id", "number", "id2"]
        );
        assert_ne!(
            path_shape("/a/{number}/details"),
            path_shape("/a/details/{uuid}")
        );
        assert_ne!(path_shape("/a/{number}"), path_shape("/a/{number}/"));
    }

    #[test]
    fn merging_unknown_json_evidence_does_not_invent_a_known_type() {
        let known = json_operation(&[r#"{"value":42}"#]);
        let unknown = Operation {
            parameters: vec![parameter("json", "value", &["false"])],
            ..Default::default()
        };
        let known = merge_operations(&[&known, &unknown]);
        assert_eq!(json_schema(known.json_types.get("value")), json!({}));
        let known = merge_operations(&[&known, &json_operation(&[r#"{"value":"str"}"#])]);
        assert_eq!(json_schema(known.json_types.get("value")), json!({}));
    }

    #[test]
    fn merging_many_variants_preserves_distinct_fields_without_a_lossy_cap() {
        let observations: Vec<_> = (0..MAX_OPERATIONS)
            .map(|variant| Operation {
                requests: 1,
                parameters: (0..crate::service_map_parameters::MAX_PARAMETERS)
                    .map(|field| {
                        parameter(
                            "query",
                            &format!("field_{variant}_{field}"),
                            &["1", "2", "3"],
                        )
                    })
                    .collect(),
                ..Default::default()
            })
            .collect();
        let merged = merge_operations(&observations.iter().collect::<Vec<_>>());
        assert_eq!(merged.requests, MAX_OPERATIONS);
        assert_eq!(
            merged.parameters.len(),
            MAX_OPERATIONS * crate::service_map_parameters::MAX_PARAMETERS
        );
        assert!(merged
            .parameters
            .iter()
            .all(|parameter| parameter.rows == 1 && parameter.examples.len() == 3));
    }

    #[test]
    fn an_origin_becomes_an_openapi_document_without_its_values() {
        let mut operations = BTreeMap::new();
        operations.insert(
            ("/api/users/{number}".to_string(), "get".to_string()),
            Operation {
                requests: 3,
                responses: BTreeMap::from([
                    (200, BTreeSet::from(["application/json".to_string()])),
                    (404, BTreeSet::new()),
                ]),
                request_types: BTreeSet::new(),
                auth: BTreeSet::from([
                    signal("bearer_jwt", None),
                    signal("session_cookie", Some("SID")),
                ]),
                parameters: vec![parameter("query", "page", &["2"])],
                parameter_cap_truncated: false,
                newest: Some((7, Uuid::from_u128(7))),
                json_types: BTreeMap::new(),
            },
        );
        operations.insert(
            ("/api/users".to_string(), "post".to_string()),
            Operation {
                requests: 1,
                responses: BTreeMap::from([(
                    201,
                    BTreeSet::from(["application/json".to_string()]),
                )]),
                request_types: BTreeSet::from(["application/json".to_string()]),
                auth: BTreeSet::from([signal("oauth2", None)]),
                parameters: vec![parameter("json", "name", &["kim-secret-value"])],
                parameter_cap_truncated: false,
                newest: None,
                json_types: BTreeMap::from([("name".into(), BTreeSet::from(["string"]))]),
            },
        );
        operations.insert(
            ("/".to_string(), "get".to_string()),
            Operation {
                requests: 5,
                responses: BTreeMap::from([(200, BTreeSet::from(["text/html".to_string()]))]),
                ..Default::default()
            },
        );
        operations.insert(
            ("/beacon".to_string(), "post".to_string()),
            Operation {
                requests: 1,
                ..Default::default()
            },
        );
        operations.insert(
            ("/fonts/Brand.woff2".to_string(), "get".to_string()),
            Operation {
                requests: 1,
                responses: BTreeMap::from([(304, BTreeSet::new())]),
                ..Default::default()
            },
        );
        let document = document("https://api.example.com", &operations, 2, 0);
        assert_eq!(document["openapi"], "3.1.0");
        assert_eq!(
            document["servers"],
            json!([{"url": "https://api.example.com"}])
        );
        let paths = document["paths"].as_object().unwrap();
        assert_eq!(
            paths.keys().collect::<Vec<_>>(),
            ["/api/users", "/api/users/{number}", "/beacon"]
        );
        let get = &paths["/api/users/{number}"]["get"];
        assert_eq!(
            paths["/api/users/{number}"]["parameters"][0]["name"],
            "number"
        );
        assert_eq!(
            get["parameters"],
            json!([{"name": "page", "in": "query", "schema": {"type": "integer"}}])
        );
        assert_eq!(get["responses"]["200"]["description"], "OK");
        assert_eq!(
            get["responses"]["200"]["content"],
            json!({"application/json": {}})
        );
        assert_eq!(get["responses"]["404"], json!({"description": "Not Found"}));
        assert_eq!(
            get["security"],
            json!([{"bearer_jwt": []}, {"session_cookie_SID": []}])
        );
        assert_eq!(get["x-sniper-requests"], 3);
        assert_eq!(
            get["x-sniper-newest-transaction"],
            "00000000-0000-0000-0000-000000000007"
        );
        let post = &paths["/api/users"]["post"];
        assert_eq!(
            post["requestBody"],
            json!({"content": {"application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string"}}}}}})
        );
        assert!(post.get("security").is_none());
        assert_eq!(
            paths["/beacon"]["post"]["responses"],
            json!({"default": {"description": "No response was captured"}})
        );
        assert_eq!(
            document["components"]["securitySchemes"],
            json!({
                "bearer_jwt": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                "session_cookie_SID": {"type": "apiKey", "in": "cookie", "name": "SID"},
            })
        );
        let description = document["info"]["description"].as_str().unwrap();
        assert!(description.contains("11 captured requests"));
        assert!(
            description.contains("2 operations that only answered with pages"),
            "a page, and a font by its name"
        );
        assert!(description.contains("2 less recently used operations"));
        assert!(!document.to_string().contains("kim-secret-value"));
    }

    #[test]
    fn names_that_read_the_same_once_cleaned_get_their_own_keys() {
        let mut schemes = Map::new();
        let first = scheme_key(&signal("api_key_header", Some("x-a+b")), &mut schemes);
        let second = scheme_key(&signal("api_key_header", Some("x-a$b")), &mut schemes);
        let again = scheme_key(&signal("api_key_header", Some("x-a+b")), &mut schemes);
        assert_eq!(first.as_deref(), Some("api_key_header_x-a_b"));
        assert_eq!(second.as_deref(), Some("api_key_header_x-a_b_2"));
        assert_eq!(again, first);
        assert_eq!(scheme_key(&signal("saml", None), &mut schemes), None);
    }
}
