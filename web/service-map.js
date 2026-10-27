/* Read-only retained metadata map with explicit, bounded retained relationship
   inspections. No capture, replay, remote fetch, or UUID-only detail navigation. */
(function (root) {
  "use strict";
  const MAX_CARDS = 24;
  const MAX_EDGES = 40;
  // A dense cyclic graph layers into one long chain; five columns hold a typical
  // sign-in redirect chain. ponytail: deeper cards share the last column; wrap
  // them into extra rows if long chains turn out to matter.
  const MAX_COLUMNS = 5;
  const MAX_RELATION_LAYERS = 8;
  const MAX_REFERENCE_CARDS = 100;
  const MAX_REFERENCE_SOURCES = 30;
  const API_PAGE_SIZE = 50;
  const GRAPH_GEOMETRY = Object.freeze({ cardWidth: 220, cardHeight: 84, columnPitch: 300, rowPitch: 104, padding: 24, loopInset: 8, lineHeight: 1.5 });
  const ZOOM_LIMITS = Object.freeze({ min: 0.1, max: 2, step: 0.1 });
  const BODY_REFERENCE_LIMITS = Object.freeze({ scan_bytes: 262144, serialized_row_bytes: 2097152, origins: 100, candidates: 4096, candidate_bytes: 4096, offsets_per_origin: 5 });
  const BODY_REFERENCE_REASONS = {
    capture_preview_truncated: "Capture preview is truncated", scan_prefix_truncated: "Scan prefix limit reached",
    candidate_limit: "URL candidate limit reached", candidate_bytes: "An oversized URL candidate was skipped",
    origin_limit: "Origin output limit reached", offset_limit: "Offset output limit reached",
    inactive_session: "Only the active session can be inspected", invalid_evidence_id: "Evidence token is invalid",
    session_mismatch: "The source session changed", stale_generation: "Retained history changed",
    record_missing: "The source row is no longer retained", record_changed: "The source row changed",
    body_identity_unverifiable: "The retained body identity could not be verified",
    body_storage_unavailable: "Retained body storage is unavailable", body_read_failed: "The retained body could not be read",
    serialized_row_limit: "The retained row exceeds the read limit", malformed_retained_row: "The retained row could not be verified",
    response_unavailable: "No retained response is available", retained_preview_unavailable: "No retained response preview is available",
    unsupported_metadata: "Source metadata is unsupported", metadata_limit: "Source metadata exceeds its limit",
    unsupported_content_type: "Only retained HTML and JavaScript text previews are supported",
    unsupported_body_encoding: "The retained preview is not UTF-8 text",
    unsupported_content_encoding: "The retained response encoding is unsupported", body_scan_failed: "The retained preview could not be inspected",
    session_source_changed: "The active session source changed", metadata_unavailable: "Retained response metadata is unavailable",
  };
  const SOURCE_LIFETIME_MESSAGES = Object.freeze({
    invalid_evidence_id: "Source verification unavailable for this evidence token; verify again.",
    session_mismatch: "Source session does not match; verify again.",
    stale_generation: "Retained history changed; verify again.",
    record_missing: "The source row is no longer retained. Reload the map to select current evidence.",
    record_changed: "The source row changed. Reload the map to select current evidence.",
    session_source_changed: "Session context changed; verify again.",
  });
  const INACTIVE_SESSION_NOTICE = "This session must be active for supplementary inspection. Switch to it again, then verify the source.";
  const BODY_REFERENCE_PARTIAL_REASONS = new Set(["capture_preview_truncated", "scan_prefix_truncated", "candidate_limit", "candidate_bytes", "origin_limit", "offset_limit"]);
  const BODY_REFERENCE_UNSUPPORTED_REASONS = new Set(["unsupported_metadata", "metadata_limit", "unsupported_content_type", "unsupported_body_encoding", "unsupported_content_encoding"]);
  const BODY_REFERENCE_UNAVAILABLE_REASONS = new Set(Object.keys(BODY_REFERENCE_REASONS).filter((reason) => !BODY_REFERENCE_PARTIAL_REASONS.has(reason) && !BODY_REFERENCE_UNSUPPORTED_REASONS.has(reason)));
  const escape = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[char]);
  const count = (value) => Number.isSafeInteger(value) && value >= 0 ? value : 0;
  const array = (value) => Array.isArray(value) ? value : [];
  // What kind of request each Origin/Referer link stood for, as the server
  // counts it per link (Sec-Fetch-Dest, else the response type).
  const REQUEST_KINDS = ["api", "navigation", "frame", "script", "static", "other"];
  const REQUEST_KIND_LABELS = { api: "API calls", navigation: "Page navigations", frame: "Frames", script: "Scripts", static: "Static files", other: "Other requests" };
  // API calls, page navigations and unclassified requests stay drawn.
  const DEFAULT_HIDDEN_LINK_KINDS = Object.freeze(["frame", "script", "static"]);
  // Older servers count nothing: such a link is one row of an unknown kind.
  const linkKindCounts = (link) => {
    const kinds = REQUEST_KINDS.filter((kind) => count(link.request_kinds?.[kind]) > 0).map((kind) => [kind, count(link.request_kinds[kind])]);
    return kinds.length ? kinds : [["other", Math.max(1, count(link.request_count))]];
  };
  // Rows whose response let the source origin read it, of all the link's rows.
  const linkCors = (link) => [count(link.cors_allowed_count), count(link.cors_credentials_count), Math.max(1, count(link.request_count), count(link.cors_allowed_count))];
  const corsText = ([allowed, credentials, rows]) => allowed ? `CORS allowed ${allowed} of ${rows} row${rows === 1 ? "" : "s"}${credentials ? `, ${credentials} with credentials` : ""}` : "";
  // Sites group origins by registrable domain, as Caido's sitemap groups
  // subdomains under their root domain. ponytail: a short list of two-level
  // public suffixes stands in for the Public Suffix List, so a host under an
  // unlisted suffix (or a hosting suffix such as github.io) groups by its last
  // two labels; add the list if that merges different owners.
  const TWO_LEVEL_SUFFIXES = new Set(["co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "re.kr", "pe.kr", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "com.cn", "com.tw", "com.hk", "com.sg", "com.br", "co.in", "co.nz"]);
  function siteKey(origin) {
    let host = "";
    // The DNS root dot is not a label. Normalize only this display key, never
    // the captured origin, so dotted hosts do not all become one TLD card.
    try { host = new URL(origin).hostname.replace(/\.$/, ""); } catch { return null; }
    // An address or a single label names one host, not a site.
    if (!host || host.startsWith("[") || /^\d+(?:\.\d+){3}$/.test(host)) return null;
    const labels = host.split(".");
    if (labels.length < 2 || labels.some((label) => !label)) return null;
    return labels.slice(labels.length > 2 && TWO_LEVEL_SUFFIXES.has(labels.slice(-2).join(".")) ? -3 : -2).join(".");
  }
  // Two or more origins of one site become one card unless the site is kept
  // apart. Links follow their origins onto the card: links inside the site
  // disappear, and links of several members share the card's arrow.
  function groupSites(origins, keepApart = () => false) {
    const members = new Map();
    for (const origin of origins) {
      const site = origin.endpointNode ? null : siteKey(origin.origin);
      if (!site || keepApart(site)) continue;
      if (!members.has(site)) members.set(site, []);
      members.get(site).push(origin);
    }
    for (const [site, items] of members) if (items.length < 2) members.delete(site);
    if (!members.size) return { cards: origins, card: (id) => id };
    const cardOf = new Map([...members].flatMap(([site, items]) => items.map((item) => [item.origin, `site:${site}`])));
    const card = (id) => cardOf.get(id) || id;
    const relinked = (origin) => ({
      redirects: origin.redirects.map((redirect) => ({ ...redirect, target_origin: card(redirect.target_origin) })),
      header_links: origin.header_links.map((link) => ({ ...link, source_origin: card(link.source_origin) })),
    });
    const sites = new Map([...members].map(([site, items]) => {
      const links = items.map(relinked);
      return [`site:${site}`, { ...referenceOrigin(`site:${site}`), site, members: items, favicon: items.find((item) => item.favicon)?.favicon, captured: items.some((item) => item.captured !== false),
        in_scope: items.some((item) => item.in_scope), request_count: items.reduce((sum, item) => sum + count(item.request_count), 0),
        redirects: links.flatMap((item) => item.redirects), header_links: links.flatMap((item) => item.header_links) }];
    }));
    const cards = [];
    for (const origin of origins) {
      const site = sites.get(card(origin.origin));
      if (!site) cards.push(origin.endpointNode ? origin : { ...origin, ...relinked(origin) });
      else if (!cards.includes(site)) cards.push(site);
    }
    return { cards, card };
  }
  const safePath = (value) => String(value || "/").split(/[?#]/, 1)[0];
  function safeOrigin(value) {
    try {
      const url = new URL(value);
      return ["http:", "https:"].includes(url.protocol) ? url.origin : "";
    } catch (_) { return ""; }
  }
  const MAP_ERROR_HEADER = "x-sniper-service-map-error";
  const SWAGGER_EDITOR_URL = "https://editor.swagger.io/";
  // Busy answers in a row before refresh pauses; the server waits up to 20 s
  // for the running read before each.
  const MAX_BUSY_RETRIES = 5;
  const AUTO_REFRESH_MS = 5000;
  const MAP_FAILURES = new Map([
    ["busy", { status: 429, message: "Service map is busy." }],
    ["scope_work_limit", { status: 422, message: "Scope matching exceeded the service map work limit. Simplify scope rules or use a smaller CLI --max-records window." }],
    ["session_changed", { status: 409, message: "The selected session source changed while the service map was being built." }],
    ["scope_changed", { status: 409, message: "Scope rules changed while the service map was being built." }],
    ["history_changed", { status: 409, message: "Retained history changed while the service map was being built." }],
    ["build_failed", { status: 500, message: "The service map could not be built." }],
  ]);
  function mapFailure(response) {
    // Fetch joins duplicate response headers with commas. Exact tokens reject
    // these, unfamiliar markers and status mismatches without reading the body.
    const token = response.headers?.get(MAP_ERROR_HEADER);
    const failure = MAP_FAILURES.get(token);
    return failure?.status === response.status ? failure : null;
  }
  // This closed catalog mirrors the passive header extractor. Display names and
  // categories never come from arbitrary header text or describe deployed roles.
  const TECHNOLOGY_CATALOG_VERSION = 2;
  const TECHNOLOGY_CATALOG_HEADER = "X-Sniper-Technology-Catalog-Version";
  const LEGACY_CATALOG_NOTICE = "Legacy server: catalog v1; additional declarations were not inspected.";
  const TECHNOLOGY_CATALOG_V1 = new Map([
    ["nginx", ["nginx", "web_server", "nginx", ["server"]]],
    ["apache_http_server", ["Apache", "web_server", "Apache", ["server"]]],
    ["caddy", ["Caddy", "web_server", "Caddy", ["server"]]],
    ["cloudflare", ["Cloudflare", "edge_service", "Cloudflare", ["server"]]],
    ["microsoft_iis", ["Microsoft IIS", "web_server", "Microsoft-IIS", ["server"]]],
    ["envoy", ["Envoy", "edge_service", "Envoy", ["server"]]],
    ["php", ["PHP", "language_runtime", "PHP", ["server", "x-powered-by"]]],
    ["jetty", ["Jetty", "application_server", "Jetty", ["server"]]],
    ["apache_coyote", ["Apache-Coyote", "connector", "Apache-Coyote", ["server"]]],
    ["apache_tomcat", ["Apache Tomcat", "application_server", "Apache Tomcat", ["server"]]],
    ["express", ["Express", "application_framework", "Express", ["x-powered-by"]]],
    ["asp_net", ["ASP.NET", "application_framework", "ASP.NET", ["x-powered-by"]]],
    ["wordpress", ["WordPress", "cms", "WordPress", ["x-generator"]]],
    ["drupal", ["Drupal", "cms", "Drupal", ["x-generator"]]],
  ]);
  const TECHNOLOGY_CATALOG_V2 = new Map([
    ...TECHNOLOGY_CATALOG_V1,
    ["gunicorn", ["Gunicorn", "application_server", "gunicorn", ["server"]]],
    ["uvicorn", ["Uvicorn", "application_server", "uvicorn", ["server"]]],
    ["waitress", ["Waitress", "application_server", "waitress", ["server"]]],
    ["openresty", ["OpenResty", "web_server", "openresty", ["server"]]],
    ["litespeed", ["LiteSpeed", "web_server", "LiteSpeed", ["server"]]],
    ["next_js", ["Next.js", "application_framework", "Next.js", ["x-powered-by"]]],
  ]);
  function technologyCatalogVersion(payload, requestedVersion = TECHNOLOGY_CATALOG_VERSION) {
    if (![1, 2].includes(requestedVersion)) throw new Error("Invalid requested technology catalog version");
    // Old servers ignore the version header. An absent marker permits only the
    // closed v1 catalog on this response, never a retry or cached negotiation.
    if (!Object.prototype.hasOwnProperty.call(payload, "technology_catalog_version")) return 1;
    if (payload.technology_catalog_version !== requestedVersion) throw new Error("Invalid retained technology catalog version");
    return requestedVersion;
  }
  function technologyCatalog(version) {
    if (version === 1) return TECHNOLOGY_CATALOG_V1;
    if (version === 2) return TECHNOLOGY_CATALOG_V2;
    throw new Error("Invalid retained technology catalog version");
  }
  const TECHNOLOGY_FIELDS = ["product_id", "name", "catalog_category", "reported_version", "version_status", "source", "strength", "header_name"];
  const TECHNOLOGY_CATEGORIES = { web_server: "Web server", edge_service: "Edge service", language_runtime: "Language runtime", application_server: "Application server", connector: "Connector", application_framework: "Application framework", cms: "CMS" };
  const technologyInteger = (value, max) => Number.isSafeInteger(value) && value >= 0 && value <= max;
  const exactFields = (value, fields) => value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === fields.length && fields.every((field) => Object.prototype.hasOwnProperty.call(value, field));
  const invalidTechnology = () => { throw new Error("Invalid retained technology observations"); };
  function observationTime(value) {
    const parts = typeof value === "string" && value.length <= 40
      && /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
    if (!parts) return null;
    const [, year, month, day, hour, minute, second, fraction = ""] = parts;
    const leap = Number(year) % 4 === 0 && (Number(year) % 100 !== 0 || Number(year) % 400 === 0);
    const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (Number(month) < 1 || Number(month) > 12 || Number(day) < 1 || Number(day) > monthDays[Number(month) - 1]
      || Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59) return null;
    const milliseconds = Date.parse(value.replace(/\.\d+(?=Z|[+-])/, ""));
    // Retained timestamps can carry nanoseconds. Keep that precision when
    // proving an observation stays inside its origin's retained time window.
    return Number.isFinite(milliseconds) ? BigInt(milliseconds) * 1000000n + BigInt(fraction.padEnd(9, "0")) : null;
  }
  function technologyBase(item, catalogVersion) {
    const catalog = technologyCatalog(catalogVersion).get(item?.product_id);
    if (!catalog || item.name !== catalog[0] || item.catalog_category !== catalog[1] || !catalog[3].includes(item.header_name)
      || item.source !== "response_header" || item.strength !== "literal_declaration"
      || !["reported", "not_reported", "unsupported_format", "non_product_version"].includes(item.version_status)
      || item.version_status === "non_product_version" && item.product_id !== "apache_coyote"
      || item.version_status === "reported" && (item.product_id === "apache_coyote" || typeof item.reported_version !== "string"
        || item.reported_version.length > 32 || !/^[0-9]+(?:\.[0-9]+)*$/.test(item.reported_version))
      || item.version_status !== "reported" && item.reported_version !== null) invalidTechnology();
    return Object.fromEntries(TECHNOLOGY_FIELDS.map((field) => [field, item[field]]));
  }
  function technologyList(value, max) {
    if (value === undefined) return [];
    if (!Array.isArray(value) || value.length > max) invalidTechnology();
    return value;
  }
  function normalizeRowTechnologies(value, catalogVersion = 1) {
    const positions = new Set(), headers = new Map(), headerSpans = new Map();
    return technologyList(value, 8).map((item) => {
      if (!exactFields(item, [...TECHNOLOGY_FIELDS, "header_index", "product_span", "version_span", "offset_basis", "rule_id"])) invalidTechnology();
      const base = technologyBase(item, catalogVersion), catalog = technologyCatalog(catalogVersion).get(item.product_id);
      const span = (value) => exactFields(value, ["start", "end"]) && technologyInteger(value.start, 4096)
        && technologyInteger(value.end, 4096) && value.start < value.end;
      const rule = `${item.header_name.replaceAll("-", "_")}.${item.product_id}.v1`;
      if (!technologyInteger(item.header_index, 127) || item.offset_basis !== "retained_header_value_utf8"
        || !span(item.product_span) || item.product_span.end - item.product_span.start !== catalog[2].length
        || item.rule_id !== rule && !(item.product_id === "jetty" && item.rule_id === "server.jetty_parenthesized.v1")
        || item.rule_id === "server.jetty_parenthesized.v1" && !["reported", "unsupported_format"].includes(item.version_status)
        || item.version_status === "reported" && (!span(item.version_span) || item.version_span.start <= item.product_span.end
          || item.version_span.end - item.version_span.start !== item.reported_version.length
          || item.header_name !== "x-generator" && item.version_span.start !== item.product_span.end + 1)
        || item.version_status !== "reported" && item.version_span !== null) invalidTechnology();
      const position = JSON.stringify([item.header_index, item.product_span.start, item.product_span.end]);
      if (positions.has(position) || headers.has(item.header_index) && headers.get(item.header_index) !== item.header_name) invalidTechnology();
      const spans = [item.product_span, ...(item.version_span ? [item.version_span] : [])];
      const previousSpans = headerSpans.get(item.header_index) || [];
      if (spans.some((span) => previousSpans.some((previous) => span.start < previous.end && previous.start < span.end))) invalidTechnology();
      positions.add(position);
      headers.set(item.header_index, item.header_name);
      headerSpans.set(item.header_index, [...previousSpans, ...spans]);
      return { ...base, header_index: item.header_index, product_span: { ...item.product_span },
        version_span: item.version_span ? { ...item.version_span } : null, offset_basis: item.offset_basis, rule_id: item.rule_id };
    });
  }
  function technologyLiteral(id) {
    const entry = TECHNOLOGY_CATALOG_V2.get(id);
    return entry ? { literal: entry[2], headers: [...entry[3]] } : null;
  }
  function freezePacket(value) {
    for (const side of [value.request, value.response]) if (side) {
      if (side.message) {
        for (const header of side.message.headers) Object.freeze(header);
        Object.freeze(side.message.headers); Object.freeze(side.message.body); Object.freeze(side.message);
      }
      Object.freeze(side);
    }
    if (value.source) Object.freeze(value.source);
    if (value.originals) Object.freeze(value.originals);
    Object.freeze(value.limits);
    return Object.freeze(value);
  }
  function normalizePacket(value, owner) {
    const fail = () => { throw new Error("Retained packet source changed"); };
    const nullableString = item => item === null || typeof item === "string";
    const integer = item => Number.isSafeInteger(item) && item >= 0;
    if (!exactFields(value, ["schema_version", "session_id", "evidence_id", "variant", "available", "status", "reason", "source", "limits", "originals", "request", "response"]) || value.schema_version !== 1 || value.session_id !== owner.sessionId || value.evidence_id !== owner.evidenceId
      || value.variant !== owner.variant || !["current", "original"].includes(value.variant)
      || !exactFields(value.limits, ["packet_bytes", "serialized_row_bytes"]) || value.limits.packet_bytes !== 2097152 || value.limits?.serialized_row_bytes !== 2097152
      || !validTechnologyEvidence(value.evidence_id, owner.sessionId, value.evidence_id.split(".")[2])) fail();
    if (value.available === false) {
      if (value.status !== "unavailable" || !["invalid_evidence_id", "session_mismatch", "stale_generation", "record_missing", "record_changed", "body_identity_unverifiable", "serialized_row_limit", "packet_view_limit", "packet_read_failed", "inactive_session", "read_busy", "session_source_changed"].includes(value.reason)
        || value.source !== null || value.originals !== null || value.request !== null || value.response !== null) fail();
      return freezePacket(value);
    }
    const source = value.source, fields = value.evidence_id.split(".");
    if (!exactFields(source, ["record_id", "sequence", "started_at"]) || !exactFields(value.originals, ["request", "response"])) fail();
    if (value.available !== true || value.status !== "available" || value.reason !== null
      || source?.record_id !== owner.recordId || source?.sequence !== owner.sequence || source.record_id !== fields[5] || source.sequence !== fields[3]
      || typeof source.started_at !== "string" || owner.startedAt && source.started_at !== owner.startedAt
      || typeof value.originals?.request !== "boolean" || typeof value.originals?.response !== "boolean") fail();
    for (const side of ["request", "response"]) {
      const item = value[side];
      if (!exactFields(item, ["status", "message"])) fail();
      if (value.variant === "current" && side === "request" && item.status !== "retained"
        || value.variant === "original" && (item.status === "retained") !== value.originals[side]) fail();
      if (item.status === "not_retained" && item.message === null) continue;
      const message = item?.message, body = message?.body;
      if (item?.status !== "retained" || !exactFields(message, ["method", "scheme", "authority", "path", "http_version", "status_code", "headers", "body"]) || !["method", "scheme", "authority", "path", "http_version"].every(key => nullableString(message[key]))
        || !(message.status_code === null || Number.isInteger(message.status_code) && message.status_code >= 0 && message.status_code <= 65535)
        || !Array.isArray(message.headers) || message.headers.some(header => !exactFields(header, ["name", "value"]) || typeof header.name !== "string" || typeof header.value !== "string")
        || !exactFields(body, ["available", "reason", "body_preview", "body_encoding", "body_size", "decoded_body_size", "preview_truncated", "content_decoded", "content_type"]) || typeof body.available !== "boolean" || !["utf8", "base64"].includes(body.body_encoding) || !integer(body.body_size)
        || !(body.decoded_body_size === null || integer(body.decoded_body_size)) || typeof body.preview_truncated !== "boolean"
        || typeof body.content_decoded !== "boolean" || !nullableString(body.content_type)
        || (body.available ? typeof body.body_preview !== "string" || body.reason !== null : body.body_preview !== null || !["body_identity_unverifiable", "retained_preview_unavailable", "body_storage_unavailable", "body_read_failed", "malformed_retained_row"].includes(body.reason))) fail();
      if (side === "request" && message.status_code !== null
        || side === "response" && ["method", "scheme", "authority", "path"].some(key => message[key] !== null)) fail();
      if (value.variant === "original" && (message.scheme !== null || message.authority !== null || message.http_version !== null || message.status_code !== null)) fail();
    }
    return freezePacket(value);
  }
  function validTechnologyEvidence(value, sessionId, generation) {
    if (typeof value !== "string" || value.length > 200) return false;
    const fields = value.split("."), uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return fields.length === 6 && fields[0] === "v1" && fields[1] === sessionId && fields[2] === generation
      && [fields[1], fields[2], fields[4], fields[5]].every((field) => uuid.test(field))
      && /^(?:0|[1-9][0-9]{0,19})$/.test(fields[3]) && BigInt(fields[3]) <= 18446744073709551615n;
  }
  function normalizeOriginTechnologies(origin, sessionId, generation, catalogVersion) {
    const keys = new Set();
    return technologyList(origin?.technology_observations, 32).map((item) => {
      if (!exactFields(item, [...TECHNOLOGY_FIELDS, "row_count", "first_seen", "last_seen", "evidence"])) invalidTechnology();
      const base = technologyBase(item, catalogVersion), first = observationTime(item.first_seen), last = observationTime(item.last_seen);
      const originFirst = observationTime(origin.first_seen), originLast = observationTime(origin.last_seen);
      // The map covers every retained row, so an origin a fuzzer hit has far more than a window's 50,000.
      if (!technologyInteger(origin.request_count, Number.MAX_SAFE_INTEGER) || !technologyInteger(item.row_count, origin.request_count) || !item.row_count
        || first === null || last === null || first > last
        || originFirst === null || originLast === null || first < originFirst || last > originLast
        || !Array.isArray(item.evidence) || !item.evidence.length || item.evidence.length > Math.min(3, item.row_count)
        || new Set(item.evidence).size !== item.evidence.length
        || item.evidence.some((id) => !validTechnologyEvidence(id, sessionId, generation))
        || new Set(item.evidence.map((id) => id.split(".")[3])).size !== item.evidence.length) invalidTechnology();
      const key = JSON.stringify([item.product_id, item.header_name, item.reported_version, item.version_status]);
      if (keys.has(key)) invalidTechnology();
      keys.add(key);
      return { ...base, row_count: item.row_count, first_seen: item.first_seen, last_seen: item.last_seen, evidence: [...item.evidence] };
    });
  }
  // A product's name with the version it reported, if it reported one.
  const productText = (item) => item.version_status === "reported" ? `${item.name} ${item.reported_version}` : item.name;
  const PRODUCT_VERSION_OPTIONS = Object.freeze([
    ["multiple", "Multiple reported versions"],
    ["status:not_reported", "Unknown: not reported"],
    ["status:unsupported_format", "Unknown: unsupported format"],
    ["status:non_product_version", "Unknown: non-product version"],
  ]);
  function reportedProducts(origin) {
    // Only validated default-map aggregates participate. Missing metadata and
    // exact-source inspections must never turn into an origin-level claim.
    const products = new Map();
    const product = (id, name) => {
      if (!products.has(id)) products.set(id, { id, name, category: HEADER_CATEGORIES[id] || null, versions: new Set(), statuses: new Set(), observations: [], declared: [], seen: [] });
      return products.get(id);
    };
    for (const item of origin?.technology_observations_present ? origin.technology_observations : []) {
      const entry = product(item.product_id, item.name);
      if (item.version_status === "reported") entry.versions.add(item.reported_version);
      else entry.statuses.add(item.version_status);
      entry.observations.push(item);
    }
    // A version a retained script, page or asset URL names supersedes a header
    // that named none.
    for (const item of origin?.front_technologies || []) {
      const entry = product(item.product_id, item.name);
      entry.category = item.category;
      if (item.version) {
        entry.versions.add(item.version);
        entry.statuses.delete("not_reported");
      }
      entry.declared.push(item);
    }
    // What the origin's own responses say about its servers. An exposure is
    // a finding, not a product.
    for (const item of origin?.server_technologies || []) {
      if (item.category === "exposure") continue;
      const entry = product(item.product_id, item.name);
      entry.category ??= item.category;
      if (item.version) {
        entry.versions.add(item.version);
        entry.statuses.delete("not_reported");
      }
      entry.seen.push(item);
    }
    return [...products.values()].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  }
  function productMatches(origin, productId = "", version = "") {
    if (!productId && !version) return true;
    return reportedProducts(origin).some((product) => (!productId || product.id === productId)
      && (!version || version === "multiple" && product.versions.size > 1
        || version.startsWith("reported:") && product.versions.has(version.slice(9))
        || version.startsWith("status:") && product.statuses.has(version.slice(7))));
  }
  // Clients the map names from each row's User-Agent; never the header itself.
  const CLIENT_KINDS = ["browser", "webview", "app", "tool", "library", "bot", "unknown"];
  const CLIENT_SYSTEMS = ["Windows", "macOS", "iOS", "Android", "ChromeOS", "Linux"];
  const CLIENT_LABELS = { browser: "Browser", webview: "WebView", app: "App", tool: "Tool", library: "Library", bot: "Crawler", unknown: "Client" };
  const MAX_CLIENT_CARDS = 4;
  // An evidence token, v1.<session>.<generation>.<sequence>.<revision>.<record>.
  const FAVICON_TOKEN = /^v1\.[0-9a-f-]{36}\.[0-9a-f-]{36}\.[0-9]{1,20}\.[0-9a-f-]{36}\.[0-9a-f-]{36}$/;
  const clientId = (client) => `client:${client.kind}:${client.name}:${client.os ?? ""}`;
  const clientName = (client) => client?.name || "";
  const directRows = (item) => Object.values(item.entry_kinds).reduce((sum, rows) => sum + rows, 0);
  const rowCount = (rows) => `${rows.toLocaleString()} row${rows === 1 ? "" : "s"}`;
  // Front-end categories in the order a card presents them. Header-declared
  // front-end products take the category their bodies would give them.
  const FRONT_CATEGORIES = ["meta_framework", "cms", "framework", "ui", "library", "analytics"];
  const HEADER_CATEGORIES = { next_js: "meta_framework", nuxt: "meta_framework", gatsby: "meta_framework", astro: "meta_framework",
    wordpress: "cms", drupal: "cms", react: "framework", vue: "framework", angular: "framework", angularjs: "framework",
    express: "backend", asp_net: "backend", apache_tomcat: "app_server", jetty: "app_server", apache_coyote: "app_server", gunicorn: "app_server",
    uvicorn: "app_server", waitress: "app_server", nginx: "web_server", apache_http_server: "web_server", microsoft_iis: "web_server",
    caddy: "web_server", openresty: "web_server", litespeed: "web_server", envoy: "gateway", cloudflare: "edge", php: "language" };
  // Server layers, outermost first, as the origin's own responses name them.
  const SERVER_CATEGORIES = ["exposure", "edge", "gateway", "platform", "web_server", "app_server", "backend", "monitoring", "language", "database", "os"];
  const SERVER_SIGNALS = ["header", "cookie", "body"];
  const SERVER_LABELS = { edge: "Edge", gateway: "Gateway", platform: "Platform", web_server: "Web server", app_server: "App server",
    backend: "Backend", monitoring: "Monitoring", language: "Language", database: "Database", os: "OS" };
  // What the site is built with leads a card, then the backend and the
  // servers in front of it, then the kits, libraries and trackers it loads.
  const RANKS = { meta_framework: 0, cms: 1, framework: 2, backend: 3, app_server: 4, web_server: 5, gateway: 6, edge: 7, platform: 8,
    language: 9, database: 10, os: 11, monitoring: 11.5, ui: 12, library: 13, analytics: 14 };
  // How requests authenticate, as the server names them: what a request
  // carries first, then the flows that hand credentials out. Each kind has a
  // word for a card's chip and an endpoint's tag, and a name for the inspector.
  const AUTH_KINDS = ["bearer_jwt", "bearer", "basic", "digest", "negotiate", "ntlm", "aws_sigv4", "scheme", "api_key_header",
    "session_cookie", "jwt_cookie", "query_key", "oauth2", "oidc", "saml"];
  const AUTH_FLOWS = ["oauth2", "oidc", "saml"];
  const AUTH_LABELS = { bearer_jwt: ["JWT", "Bearer JWT"], bearer: ["Bearer", "Bearer token"], basic: ["Basic", "Basic authentication"],
    digest: ["Digest", "Digest authentication"], negotiate: ["Negotiate", "Negotiate (Kerberos or NTLM)"], ntlm: ["NTLM", "NTLM"],
    aws_sigv4: ["SigV4", "AWS Signature Version 4"], scheme: ["Scheme", "Another Authorization scheme"], api_key_header: ["API key", "API key header"],
    session_cookie: ["Cookie", "Session cookie"], jwt_cookie: ["JWT cookie", "JWT in a cookie"], query_key: ["URL key", "Credential in the URL"],
    oauth2: ["OAuth", "OAuth 2.0"], oidc: ["OIDC", "OpenID Connect"], saml: ["SAML", "SAML"] };
  const authWord = (item) => item.kind === "scheme" && item.name ? item.name : AUTH_LABELS[item.kind][0];
  const authName = (item) => item.kind === "scheme" && item.name ? `${item.name} scheme` : AUTH_LABELS[item.kind][1];
  const LOCK_ICON = '<svg class="service-map-product-icon" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm-3 8V7a3 3 0 0 1 6 0v3H9Z"/></svg>';
  // What a card's ⚠ chip calls each exposure: short enough to leave a product
  // beside it. The inspector keeps the full name.
  const EXPOSURE_LABELS = { django_debug: "Debug page", werkzeug_debugger: "Debugger", laravel_debug: "Debug page",
    symfony_debug: "Debug page", symfony_profiler: "Profiler", rails_debug: "Debug page", aspnet_error: "Error detail",
    iis_error: "Error detail", php_error: "PHP error", phpinfo: "phpinfo()", java_stack_trace: "Stack trace",
    dotnet_stack_trace: "Stack trace", python_traceback: "Traceback", node_stack_trace: "Stack trace", go_panic: "Go panic",
    sql_error: "SQL error", directory_listing: "Dir listing", spring_actuator: "Actuator", api_docs: "API docs",
    elasticsearch_root: "Elasticsearch", backend_address: "Backend IP", backend_host_header: "Backend host",
    git_config: "Git config", dotenv: ".env file", go_expvar: "Go expvar", go_pprof: "Go pprof", jolokia: "Jolokia",
    apache_server_status: "server-status", apache_server_info: "server-info", nginx_status: "nginx status",
    prometheus_metrics: "Metrics", h2_console: "H2 console", graphql_ide: "GraphQL IDE",
    source_map: "Source map", aws_access_key: "AWS key", google_api_key: "Google key", slack_token: "Slack token",
    slack_webhook: "Slack hook", github_token: "GitHub token", stripe_secret_key: "Stripe key", sendgrid_key: "SendGrid key",
    private_key: "Private key", jwt: "JWT", private_ip: "Private IP" };
  const productRank = (product) => RANKS[product.category] ?? (product.observations.length ? 5 : 15);
  function productSummaryMarkup(origin) {
    const products = reportedProducts(origin).sort((a, b) => productRank(a) - productRank(b) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    const exposures = (origin?.server_technologies || []).filter((item) => item.category === "exposure");
    const methods = origin?.auth || [];
    if (!products.length && !exposures.length && !methods.length) return "";
    // Exposures lead: a debug page or a stack trace is the first thing to see.
    // An exposure says what it is: a bare count read as nothing. Hovering it
    // lists them all, as +N does.
    const warning = exposures.length ? `<span class="service-map-exposure" aria-label="Exposures: ${escape(exposures.map((item) => item.name).join(", "))}" data-more="${escape(exposures.map((item) => item.name).join("\n"))}" title="">⚠ ${escape(EXPOSURE_LABELS[exposures[0].product_id] || exposures[0].name)}${exposures.length > 1 ? ` +${exposures.length - 1}` : ""}</span>` : "";
    // A credential leads a sign-in flow, the busiest first, as the server sorts them.
    const primary = methods.find((item) => !AUTH_FLOWS.includes(item.kind)) || methods[0];
    const lock = primary ? `<span class="service-map-auth" aria-label="Authentication: ${escape(methods.map(authName).join(", "))}" data-more="${escape(methods.map((item) => `${authName(item)}${item.name && item.kind !== "scheme" ? ` (${item.name})` : ""}`).join("\n"))}" title="">${LOCK_ICON}${escape(authWord(primary))}${methods.length > 1 ? ` +${methods.length - 1}` : ""}</span>` : "";
    // An exposure and the way requests authenticate each take a product place.
    const shown = 2 - (warning ? 1 : 0) - (lock ? 1 : 0);
    const full = (product) => [product.observations.length ? "Header-reported declarations; versions unverified." : "",
      ...product.observations.map((item) => `${productText(item)} · ${item.header_name} header · ${item.row_count} retained row${item.row_count === 1 ? "" : "s"} · First: ${item.first_seen} · Last: ${item.last_seen}`),
      ...product.declared.map((item) => `${item.name}${item.version ? ` ${item.version}` : ""} · ${item.row_count} retained row${item.row_count === 1 ? "" : "s"} from ${item.source_origin}`),
      ...product.seen.map((item) => `${item.name}${item.version ? ` ${item.version}` : ""} · ${item.row_count} retained row${item.row_count === 1 ? "" : "s"} · ${item.signals.join(", ")}`)].filter(Boolean).join("\n");
    const label = (product) => `${product.name}${product.versions.size > 1 ? ` · ${product.versions.size} versions` : product.versions.size ? ` ${[...product.versions][0]}` : ""}`;
    return `<span class="service-map-clues service-map-products" title="${escape(products.map(full).join("\n"))}">${warning}${lock}${products.slice(0, shown).map((product) => `<span title="${escape(full(product))}">${productIcon(product.id)}${escape(label(product))}</span>`).join("")}${products.length > shown ? `<span class="service-map-products-more" aria-label="${products.length - shown} additional products" data-more="${escape(products.slice(shown).map(label).join("\n"))}" title="">+${products.length - shown}</span>` : ""}</span>`;
  }
  // What an origin serves, read from the response types of its loaded
  // endpoints: pages (Front), API data, or static files. A front-end framework
  // or CMS names the front end however its endpoints respond.
  const FRONT_BUILT_WITH = new Set(["meta_framework", "cms", "framework"]);
  // An authentication server: an identity provider's own product, or an
  // origin whose typed paths are mostly sign-in, token and logout endpoints
  // (OAuth, OpenID Connect, SAML, CAS), or that a client asked for a token by
  // OAuth parameters, or whose host says so. An app that also signs its users
  // in keeps its own role: its other pages and APIs outnumber those paths.
  const AUTH_PATH = /(?:^|\/)(?:oauth2?|openid-connect|oidc|saml2?|sso|cas|adfs|idp|authorize|token|userinfo|jwks(?:\.json)?|login|logout|signin|sign-in|signout|sign-out|openid-configuration|oauth-authorization-server)(?=[/?.;]|$)/i;
  const AUTH_HOST = /^(?:sso|auth|login|accounts?|id|idp|oauth2?|signin|cas|iam|keycloak)[.-]/i;
  const AUTH_PRODUCTS = new Set(["keycloak"]);
  const STATIC_TYPE = /^(?:image|font|audio|video)\/|css|javascript|ecmascript/;
  function authServer(origin) {
    if (reportedProducts(origin).some((product) => AUTH_PRODUCTS.has(product.id))) return true;
    const typed = (origin.endpoints || []).filter((endpoint) => !(endpoint.content_types || []).some((type) => STATIC_TYPE.test(type)));
    const signIn = typed.filter((endpoint) => AUTH_PATH.test(endpoint.path || ""));
    if (!signIn.length) return false;
    let host = "";
    try { host = new URL(origin.origin).hostname; } catch (_) { /* a site card has no URL */ }
    return signIn.length >= 2 && signIn.length * 2 >= typed.length || AUTH_HOST.test(host)
      || (origin.auth || []).some((item) => item.kind === "oauth2" || item.kind === "oidc");
  }
  function originRole(origin) {
    if (origin.site) return "site";
    if (origin.captured === false || origin.peerInspectionOnly) return "ref";
    if (authServer(origin)) return "auth";
    const tally = { front: 0, api: 0, static: 0 };
    for (const endpoint of origin.endpoints || []) {
      // An API's error page is HTML too: a path that only ever failed does
      // not show that the origin serves pages.
      const failed = endpoint.statuses?.length > 0 && endpoint.statuses.every((status) => status >= 400);
      for (const type of endpoint.content_types || []) {
        // A web app manifest is JSON, but it is page metadata, not API data.
        const role = /html/.test(type) ? "front" : /^(?:image|font|audio|video)\/|css|javascript|ecmascript/.test(type) ? "static"
          : /json|xml|protobuf|grpc|graphql/.test(type) && !/manifest/.test(type) ? "api" : null;
        if (role && !(failed && role === "front")) tally[role] += 1;
      }
    }
    // A front-end product makes the origin Front when a header names it, the
    // origin serves pages, or one of its pages loaded the script naming it. A
    // CDN that only serves that script stays Static.
    if (reportedProducts(origin).some((product) => FRONT_BUILT_WITH.has(product.category) && (tally.front || product.observations.length
      || product.declared.some((item) => item.source_origin !== origin.origin)))) return "front";
    const [role, endpoints] = Object.entries(tally).sort((a, b) => b[1] - a[1])[0];
    return endpoints ? role : "unknown";
  }
  // A card that serves pages and API data both names both: a Next.js app with
  // its /api routes, a Spring app with its pages. A manifest or a JSON error is
  // not an API.
  function originRoles(origin) {
    const role = originRole(origin);
    if (role !== "front" && role !== "api") return [role];
    const serves = (pattern) => (origin.endpoints || []).some((endpoint) => !(endpoint.statuses?.length && endpoint.statuses.every((status) => status >= 400))
      && !/manifest/i.test(endpoint.path || "") && (endpoint.content_types || []).some((type) => pattern.test(type) && !/manifest/i.test(type)));
    return (role === "front" ? serves(/json|xml|protobuf|grpc|graphql/) : serves(/html/)) ? ["front", "api"] : [role];
  }
  const ROLE_LABELS = { front: "Front", api: "API", auth: "Auth", static: "Static", unknown: "Unknown", ref: "Ref", site: "Site" };
  const ROLE_TITLES = { front: "Serves pages", api: "Serves API data", auth: "Signs users in: an authentication server", static: "Serves static files", unknown: "No typed responses loaded", ref: "Referenced only", site: "Origins of one site" };
  const svg = (paths) => `<svg viewBox="0 0 16 16" aria-hidden="true">${paths}</svg>`;
  const ROLE_ICONS = {
    front: svg('<rect x="1.5" y="2.5" width="13" height="11" rx="1.5"/><path d="M1.5 5.5h13"/>'),
    api: svg('<path d="M6 2.5c-1.4 0-2 .6-2 2v1.6c0 .9-.5 1.4-1.5 1.9 1 .5 1.5 1 1.5 1.9v1.6c0 1.4.6 2 2 2M10 2.5c1.4 0 2 .6 2 2v1.6c0 .9.5 1.4 1.5 1.9-1 .5-1.5 1-1.5 1.9v1.6c0 1.4-.6 2-2 2"/>'),
    auth: svg('<rect x="3.5" y="7" width="9" height="6.5" rx="1"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>'),
    static: svg('<rect x="2" y="2.5" width="12" height="11" rx="1.5"/><circle cx="6" cy="6.5" r="1.2"/><path d="M2.5 12l3.5-3.5 2.5 2.5 2-2 3 3"/>'),
    unknown: svg('<path d="M6 6a2 2 0 1 1 3 1.7c-.7.4-1 .8-1 1.6M8 11.6v.4"/>'),
    ref: svg('<path d="M7 3H3v10h10V9M9.5 3H13v3.5M13 3 7.5 8.5"/>'),
    site: svg('<rect x="4.5" y="1.5" width="10" height="8" rx="1"/><rect x="1.5" y="6.5" width="10" height="8" rx="1"/>'),
  };
  const CLIENT_ICONS = {
    browser: svg('<circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c2.2 2 2.2 10 0 12M8 2c-2.2 2-2.2 10 0 12"/>'),
    webview: svg('<rect x="4" y="1.5" width="8" height="13" rx="1.5"/><path d="M4 4.5h8M4 11.5h8"/>'),
    app: svg('<rect x="4" y="1.5" width="8" height="13" rx="1.5"/><path d="M7 12.5h2"/>'),
    tool: svg('<path d="M2.5 4.5l3 3-3 3M7.5 11.5h6"/>'),
    library: svg('<path d="M5 3.5l-3 4.5 3 4.5M11 3.5l3 4.5-3 4.5"/>'),
    bot: svg('<rect x="3" y="5" width="10" height="8" rx="2"/><path d="M8 2.5v2.5M6 9h.01M10 9h.01"/>'),
    unknown: ROLE_ICONS.unknown,
  };
  function clientRoleMarkup(client) {
    return `<span class="service-map-card-role role-client" title="${CLIENT_LABELS[client.kind]}"><span class="service-map-card-symbol" aria-hidden="true">${CLIENT_ICONS[client.kind]}</span><span class="service-map-card-role-label">${CLIENT_LABELS[client.kind]}</span></span>`;
  }
  // A declared application product shows its own mark in place of the role icon.
  const PRODUCT_MARKS = { next_js: ["N", "#000", "#fff"], nuxt: ["N", "#00dc82", "#020420"], sveltekit: ["S", "#ff3e00", "#fff"],
    remix: ["R", "#121212", "#fff"], gatsby: ["G", "#663399", "#fff"], astro: ["A", "#ff5d01", "#fff"], wordpress: ["W", "#21759b", "#fff"],
    drupal: ["D", "#0678be", "#fff"], joomla: ["J", "#f44321", "#fff"], magento: ["M", "#ee672f", "#fff"], shopify: ["S", "#95bf47", "#fff"],
    wix: ["W", "#000", "#fff"], squarespace: ["S", "#000", "#fff"], angular: ["A", "#dd0031", "#fff"], angularjs: ["A", "#b52e31", "#fff"],
    react: ["R", "#20232a", "#61dafb"], vue: ["V", "#42b883", "#fff"], svelte: ["S", "#ff3e00", "#fff"], ember: ["E", "#e04e39", "#fff"],
    preact: ["P", "#673ab8", "#fff"], lit: ["L", "#324fff", "#fff"], qwik: ["Q", "#ac7ef4", "#fff"], alpine_js: ["A", "#2d3441", "#77c1d2"],
    jquery: ["$", "#0769ad", "#fff"], express: ["ex", "#353535", "#fff"], asp_net: [".N", "#512bd4", "#fff"], php: ["php", "#777bb4", "#fff"],
    spring_boot: ["S", "#6db33f", "#fff"], django: ["dj", "#0c4b33", "#fff"], laravel: ["L", "#ff2d20", "#fff"], ruby_on_rails: ["R", "#cc0000", "#fff"],
    fastapi: ["F", "#009688", "#fff"], symfony: ["sf", "#000", "#fff"], asp_net_core: [".N", "#512bd4", "#fff"] };
  // A product's logo from product-icons.js: its brand colour and how light it is.
  const productLogo = (id) => {
    const entry = root.SniperProductIcons?.[id];
    if (!entry) return null;
    const value = parseInt(entry[0], 16);
    return { hex: `#${entry[0]}`, path: entry[1], light: (0.2126 * (value >> 16) + 0.7152 * ((value >> 8) & 255) + 0.0722 * (value & 255)) / 255 };
  };
  // Beside a product's name, in its brand colour unless that colour would
  // vanish on a dark or a light theme.
  const productIcon = (id) => {
    const logo = productLogo(id);
    return logo ? `<svg class="service-map-product-icon" viewBox="0 0 24 24" aria-hidden="true"><path fill="${logo.light < 0.2 || logo.light > 0.92 ? "currentColor" : logo.hex}" d="${logo.path}"/></svg>` : "";
  };
  function roleMarkup(origin, pinned = false, favicon = null) {
    const roles = originRoles(origin);
    const role = roles[0];
    const products = reportedProducts(origin);
    const product = products.filter((item) => productLogo(item.id) || PRODUCT_MARKS[item.id]).sort((a, b) => productRank(a) - productRank(b))[0];
    const logo = product && productLogo(product.id);
    const [text, background, color] = product && !logo ? PRODUCT_MARKS[product.id] : [];
    const icon = favicon ? `<img class="service-map-favicon" src="${escape(favicon)}" alt="">`
      : logo ? `<span class="service-map-mark" style="background:${logo.hex}" title="${escape(product.name)}"><svg viewBox="0 0 24 24" aria-hidden="true"><path fill="${logo.light > 0.6 ? "#000" : "#fff"}" d="${logo.path}"/></svg></span>`
      : product ? `<span class="service-map-mark" style="background:${background};color:${color}" title="${escape(product.name)}">${escape(text)}</span>` : ROLE_ICONS[role];
    return `<span class="service-map-card-role role-${role}" title="${pinned ? "Pinned anchor · " : ""}${roles.map((item) => ROLE_TITLES[item]).join(" · ")}"><span class="service-map-card-symbol" aria-hidden="true">${icon}</span><span class="service-map-card-role-label">${roles.map((item) => ROLE_LABELS[item]).join("<br>")}</span></span>`;
  }
  function normalizeEvidenceObservations(row, catalogVersion) {
    const invalid = () => { throw new Error("Invalid retained source observations"); };
    const text = (value, limit) => typeof value === "string" && value.length > 0 && value.length <= limit;
    const origin = (value) => text(value, 1024) && !!safeOrigin(value);
    const list = (value, limit) => {
      if (value === undefined) return [];
      if (!Array.isArray(value) || value.length > limit) invalid();
      return value;
    };
    // Validate the small per-row projection before publishing it. A malformed
    // nested observation must not leave a row that crashes every inspector render.
    const technology_clues = list(row.technology_clues, 8).map((clue) => {
      if (!clue || !text(clue.name, 128) || !text(clue.header_name, 128)) invalid();
      return { name: clue.name, header_name: clue.header_name };
    });
    const header_links = list(row.header_links, 2).map((link) => {
      if (!link || !origin(link.source_origin) || !["origin_header", "referer_header"].includes(link.relationship)) invalid();
      return { source_origin: safeOrigin(link.source_origin), relationship: link.relationship };
    });
    const omitted = list(row.omitted, 32);
    if (omitted.some((reason) => !text(reason, 80))) invalid();
    let redirect = null;
    if (row.redirect !== undefined && row.redirect !== null) {
      if (!origin(row.redirect.target_origin) || !text(row.redirect.target_path, 2048)) invalid();
      redirect = { target_origin: safeOrigin(row.redirect.target_origin), target_path: safePath(row.redirect.target_path) };
    }
    const technology_observations = normalizeRowTechnologies(row.technology_observations, catalogVersion);
    if (row.technology_observations !== undefined && (row.metadata_complete !== (omitted.length === 0)
      || omitted.includes("technology_observations_limit") && technology_observations.length !== 8)
      || omitted.includes("technology_token_scan_limit") && row.metadata_complete !== false) invalidTechnology();
    return { ...row, technology_clues, technology_observations, technology_observations_present: Object.prototype.hasOwnProperty.call(row, "technology_observations"), header_links, redirect, omitted: [...omitted] };
  }
  function normalizeSocketPeer(payload) {
    // This extension is independently optional on older servers. Only typed
    // socket observations enter the inspector; arbitrary record fields never do.
    if (payload === undefined) return { status: "unsupported" };
    if (!payload || !["observed", "not_recorded", "unavailable"].includes(payload.status)) return { status: "invalid" };
    if (payload.status === "not_recorded") return payload.observation === null ? { status: "not_recorded" } : { status: "invalid" };
    const observation = payload.observation;
    if (!observation || observation.source !== "http_response_remote_addr"
      || !["direct", "http_proxy", "socks_proxy", "unknown"].includes(observation.route)
      || typeof observation.observed_at !== "string" || observation.observed_at.length > 40
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(observation.observed_at)
      || !Number.isFinite(Date.parse(observation.observed_at.replace(/\.(\d{1,9})(?=Z|[+-])/, (_, digits) => `.${digits.slice(0, 3).padEnd(3, "0")}`)))) return { status: "invalid" };
    const normalized = { status: payload.status, source: observation.source, observedAt: observation.observed_at, route: observation.route };
    if (payload.status === "unavailable") return observation.address === null && observation.reason === "remote_addr_unavailable"
      ? normalized : { status: "invalid" };
    const address = observation.address;
    if (observation.reason !== null || !address || typeof address.ip !== "string" || address.ip.length > 45
      || !Number.isInteger(address.port) || address.port < 0 || address.port > 65535) return { status: "invalid" };
    const ip = address.ip;
    let validIp = /^(0|[1-9]\d{0,2})(?:\.(0|[1-9]\d{0,2})){3}$/.test(ip) && ip.split(".").every((part) => Number(part) <= 255);
    if (!validIp && ip.includes(":") && /^[0-9a-fA-F:.]+$/.test(ip)) {
      try { validIp = new URL(`http://[${ip}]/`).hostname.startsWith("["); } catch (_) { /* Invalid IPv6 literal. */ }
    }
    return validIp ? { ...normalized, ip, port: address.port } : { status: "invalid" };
  }

  const PEER_MATCH_LIMITS = Object.freeze({ max_records: 10000, origin_groups: 100, samples_per_origin: 3, projection_bytes: 262144, host_bytes: 512, scheme_bytes: 8, scope_pattern_entries: 500, scope_pattern_bytes: 512, scope_work_units: 8388608 });
  const PEER_MATCH_REASONS = Object.freeze({
    invalid_evidence_id: "The exact evidence token is invalid", session_mismatch: "The source session changed", stale_generation: "Retained history changed",
    record_missing: "The source row is no longer retained", record_changed: "The source row changed", inactive_session: "Only the active session can be inspected",
    session_source_changed: "The active source changed", unsupported_source_context: "This source is not an ordinary captured HTTP row",
    observation_not_recorded: "No peer was recorded for this source", observation_unavailable: "The recorded source address is unavailable",
    non_direct_observation: "Proxy and unknown routes are diagnostics only", invalid_observation: "The recorded source address is not eligible for matching",
    metadata_unavailable: "The captured source origin could not be verified", source_out_of_scope: "The source is excluded by In scope only",
    scope_work_limit: "Scope matching reached the inspection work limit. Narrow the scope rules or use a smaller latest-row window in the CLI.",
    peer_inspection_failed: "The retained peer inspection is unavailable", max_records: "Newest-row window limit reached",
    source_outside_window: "The source is outside the considered candidate window", invalid_metadata: "Some matching rows have unusable origin metadata",
    origin_group_limit: "Origin-group result limit reached", projection_byte_limit: "Result byte limit reached", sample_limit: "Exact source samples were omitted",
  });
  const PEER_PARTIAL_REASONS = new Set(["max_records", "source_outside_window", "invalid_metadata", "origin_group_limit", "projection_byte_limit", "sample_limit"]);
  const PEER_COUNT_FIELDS = ["non_http_rows", "not_recorded_rows", "unavailable_observation_rows", "non_direct_rows", "invalid_observation_rows", "different_peer_rows", "invalid_metadata_rows", "scope_excluded_rows", "matching_rows", "returned_matching_rows", "omitted_matching_rows", "sample_rows", "omitted_sample_rows"];
  const PEER_PRIVACY = "Matches retained address values. Shared addresses and imported history do not establish the same physical endpoint or origin ownership. Addresses may reveal internal infrastructure.";
  const PEER_NODE_ID = "recorded-socket-peer";
  function peerAddressKey(ip) {
    if (typeof ip !== "string" || ip.length > 45) return null;
    if (/^(0|[1-9]\d{0,2})(?:\.(0|[1-9]\d{0,2})){3}$/.test(ip) && ip.split(".").every((part) => Number(part) <= 255)) return { family: "ipv4", ip, v4: ip.split(".").map(Number) };
    if (!ip.includes(":") || !/^[0-9a-fA-F:.]+$/.test(ip)) return null;
    try {
      const canonical = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
      const parts = canonical.split("::"), left = parts[0] ? parts[0].split(":") : [], right = parts[1] ? parts[1].split(":") : [];
      const words = [...left, ...Array(8 - left.length - right.length).fill("0"), ...right].map((part) => parseInt(part, 16));
      if (words.length !== 8 || words.some((word) => !Number.isInteger(word))) return null;
      const mapped = words.slice(0, 5).every((word) => word === 0) && words[5] === 65535;
      const v4 = mapped ? [words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255] : null;
      return { family: "ipv6", ip: canonical, wire: mapped ? `::ffff:${v4.join(".")}` : canonical, words, v4 };
    } catch (_) { return null; }
  }
  function usableSocketPeer(peer) {
    if (peer?.status !== "observed" || peer.route !== "direct" || peer.source !== "http_response_remote_addr"
      || !Number.isInteger(peer.port) || peer.port < 1 || peer.port > 65535 || observationTime(peer.observedAt) === null) return false;
    const key = peerAddressKey(peer.ip);
    if (!key) return false;
    if (key.v4) return key.v4[0] !== 0 && key.v4[0] < 224 && !(key.v4[0] === 169 && key.v4[1] === 254);
    return key.words.some(Boolean) && (key.words[0] & 0xff00) !== 0xff00 && (key.words[0] & 0xffc0) !== 0xfe80;
  }
  function peerEquals(peer, recorded) {
    const left = peerAddressKey(peer?.address?.ip), right = peerAddressKey(recorded?.ip);
    return usableSocketPeer(recorded) && left && right && left.family === peer.address_family && left.family === right.family
      && left.ip === right.ip && peer.address.port === recorded.port && peer.route === recorded.route && peer.source === recorded.source;
  }
  const validPeerEvidence = (value, sessionId, generation) => validTechnologyEvidence(value, sessionId, generation) && value === value.toLowerCase();
  function normalizePeerMatches(payload, sessionId, evidenceId, row, recordedPeer, scopeOnly, generation) {
    const invalid = () => { throw new Error("Invalid recorded socket peer matches"); };
    const uuid = (value) => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
    const integer = (value, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && value >= 0 && value <= max;
    const sequence = (value) => typeof value === "string" && /^(?:0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= 18446744073709551615n;
    const origin = (value) => typeof value === "string" && value.length <= 544 && value === safeOrigin(value);
    if (!exactFields(payload, ["schema_version", "session_id", "evidence_id", "available", "status", "complete", "reasons", "in_scope_only", "coverage", "peer", "source", "snapshot", "counts", "origins", "limits"])
      || payload.schema_version !== 1 || payload.session_id !== sessionId || payload.evidence_id !== evidenceId
      || !validPeerEvidence(evidenceId, sessionId, generation) || payload.in_scope_only !== scopeOnly
      || payload.coverage !== "retained_direct_socket_peer_equality" || typeof payload.available !== "boolean" || typeof payload.complete !== "boolean"
      || !["matched", "no_matches", "unavailable"].includes(payload.status)
      || !Array.isArray(payload.reasons) || new Set(payload.reasons).size !== payload.reasons.length
      || payload.reasons.length > 6 || payload.reasons.some((reason, index) => typeof reason !== "string" || !Object.hasOwn(PEER_MATCH_REASONS, reason) || index && payload.reasons[index - 1] >= reason)
      || !exactFields(payload.counts, PEER_COUNT_FIELDS) || PEER_COUNT_FIELDS.some((field) => !integer(payload.counts[field]))
      || !exactFields(payload.limits, Object.keys(PEER_MATCH_LIMITS)) || Object.entries(PEER_MATCH_LIMITS).some(([key, value]) => payload.limits[key] !== value)
      || !Array.isArray(payload.origins) || payload.origins.length > PEER_MATCH_LIMITS.origin_groups) invalid();
    if (!payload.available) {
      if (payload.status !== "unavailable" || payload.complete || payload.reasons.length !== 1 || payload.reasons.some((reason) => PEER_PARTIAL_REASONS.has(reason))
        || payload.reasons[0] === "source_out_of_scope" && !scopeOnly
        || payload.peer !== null || payload.source !== null || payload.snapshot !== null || payload.origins.length || PEER_COUNT_FIELDS.some((field) => payload.counts[field] !== 0)) invalid();
      return { ...payload, reasons: [...payload.reasons], origins: [], counts: { ...payload.counts }, limits: { ...payload.limits } };
    }
    const source = payload.source, snapshot = payload.snapshot, peer = payload.peer, counts = payload.counts;
    if (payload.status === "unavailable" || payload.complete !== (payload.reasons.length === 0) || payload.reasons.some((reason) => !PEER_PARTIAL_REASONS.has(reason))
      || !exactFields(peer, ["source", "route", "address_family", "address"]) || !exactFields(peer.address, ["ip", "port"])
      || peer.source !== "http_response_remote_addr" || peer.route !== "direct" || !peerEquals(peer, recordedPeer)
      || peer.address.ip !== (peerAddressKey(peer.address.ip).wire || peerAddressKey(peer.address.ip).ip)
      || !exactFields(source, ["evidence_id", "sequence", "origin", "started_at", "observed_at", "in_scope", "in_window"])
      || source.evidence_id !== evidenceId || source.sequence !== row.sequence || source.sequence !== evidenceId.split(".")[3]
      || source.origin !== row.origin || !origin(source.origin) || source.started_at !== row.started_at || observationTime(source.started_at) === null
      || source.observed_at !== recordedPeer.observedAt || typeof source.in_scope !== "boolean" || typeof source.in_window !== "boolean" || scopeOnly && !source.in_scope
      || !exactFields(snapshot, ["id", "generation", "captured_at", "window_order", "retained_rows", "considered_rows", "oldest_considered_sequence", "latest_considered_sequence"])
      || !uuid(snapshot.id) || snapshot.generation !== generation || !uuid(snapshot.generation) || observationTime(snapshot.captured_at) === null
      || snapshot.window_order !== "latest_retained_sequence" || !integer(snapshot.retained_rows) || !integer(snapshot.considered_rows, PEER_MATCH_LIMITS.max_records)
      || snapshot.considered_rows !== Math.min(snapshot.retained_rows, PEER_MATCH_LIMITS.max_records)
      || !snapshot.retained_rows || !snapshot.considered_rows
      || !sequence(snapshot.oldest_considered_sequence) || !sequence(snapshot.latest_considered_sequence)
      || BigInt(snapshot.oldest_considered_sequence) > BigInt(snapshot.latest_considered_sequence)
      || snapshot.considered_rows === 1 && snapshot.oldest_considered_sequence !== snapshot.latest_considered_sequence
      || BigInt(snapshot.considered_rows) > BigInt(snapshot.latest_considered_sequence) - BigInt(snapshot.oldest_considered_sequence) + 1n
      || BigInt(source.sequence) > BigInt(snapshot.latest_considered_sequence)
      || snapshot.considered_rows === snapshot.retained_rows && !source.in_window
      || source.in_window !== (BigInt(source.sequence) >= BigInt(snapshot.oldest_considered_sequence) && BigInt(source.sequence) <= BigInt(snapshot.latest_considered_sequence))
      || payload.reasons.includes("source_outside_window") === source.in_window
      || payload.reasons.includes("max_records") !== (snapshot.retained_rows > snapshot.considered_rows)
      || payload.reasons.includes("invalid_metadata") !== (counts.invalid_metadata_rows > 0)
      || PEER_COUNT_FIELDS.some((key) => counts[key] > snapshot.considered_rows)
      || counts.returned_matching_rows + counts.omitted_matching_rows !== counts.matching_rows
      || (payload.status === "matched") !== (counts.matching_rows > 0)
      || PEER_COUNT_FIELDS.slice(0, 9).reduce((sum, key) => sum + counts[key], 0) !== snapshot.considered_rows - (source.in_window ? 1 : 0)
      || scopeOnly === false && counts.scope_excluded_rows !== 0) invalid();
    const seenOrigins = new Set(), seenTokens = new Set([evidenceId]), seenSequences = new Set([source.sequence]);
    const origins = payload.origins.map((group, groupIndex) => {
      const first = observationTime(group?.first_observed_at), last = observationTime(group?.last_observed_at);
      if (!exactFields(group, ["origin", "in_scope", "matching_rows", "first_observed_at", "last_observed_at", "samples", "omitted_samples"])
        || !origin(group.origin) || seenOrigins.has(group.origin) || groupIndex && payload.origins[groupIndex - 1].origin >= group.origin || typeof group.in_scope !== "boolean" || scopeOnly && !group.in_scope
        || !integer(group.matching_rows, counts.matching_rows) || !group.matching_rows || first === null || last === null || first > last
        || !Array.isArray(group.samples) || group.samples.length > Math.min(3, group.matching_rows)
        || group.omitted_samples !== group.matching_rows - group.samples.length) invalid();
      seenOrigins.add(group.origin);
      const samples = group.samples.map((sample, sampleIndex) => {
        const at = observationTime(sample?.observed_at);
        if (!exactFields(sample, ["evidence_id", "sequence", "started_at", "observed_at"])
          || !validPeerEvidence(sample.evidence_id, sessionId, generation) || sample.sequence !== sample.evidence_id.split(".")[3]
          || seenTokens.has(sample.evidence_id) || seenSequences.has(sample.sequence)
          || sampleIndex && BigInt(group.samples[sampleIndex - 1].sequence) <= BigInt(sample.sequence) || observationTime(sample.started_at) === null || at === null || at < first || at > last
          || BigInt(sample.sequence) < BigInt(snapshot.oldest_considered_sequence) || BigInt(sample.sequence) > BigInt(snapshot.latest_considered_sequence)) invalid();
        seenTokens.add(sample.evidence_id); seenSequences.add(sample.sequence);
        return Object.freeze({ ...sample });
      });
      const knownTimes = new Set(samples.map((sample) => observationTime(sample.observed_at).toString()));
      const missingTimes = new Set([first.toString(), last.toString()].filter((value) => !knownTimes.has(value))).size;
      if (missingTimes > group.omitted_samples) invalid();
      if (!group.omitted_samples && (samples.reduce((min, item) => observationTime(item.observed_at) < min ? observationTime(item.observed_at) : min, last) !== first
        || samples.reduce((max, item) => observationTime(item.observed_at) > max ? observationTime(item.observed_at) : max, first) !== last)) invalid();
      return Object.freeze({ ...group, samples: Object.freeze(samples) });
    });
    const knownWindowRows = seenSequences.size - (source.in_window ? 0 : 1);
    const unknownWindowRows = snapshot.considered_rows - knownWindowRows;
    const missingEndpoints = new Set([snapshot.oldest_considered_sequence, snapshot.latest_considered_sequence].filter((value) => !seenSequences.has(value))).size;
    if (missingEndpoints > unknownWindowRows) invalid();
    const admittedBytes = 8192 + origins.reduce((sum, group) => sum + group.origin.length * 12 + 512, 0) + counts.sample_rows * 1024;
    const remainingBytes = PEER_MATCH_LIMITS.projection_bytes - admittedBytes;
    const byteRejectedSample = origins.some((group) => group.samples.length < 3 && group.omitted_samples > 0);
    if (remainingBytes < 0 || byteRejectedSample && remainingBytes >= 1024 || payload.reasons.includes("origin_group_limit") && (origins.length !== PEER_MATCH_LIMITS.origin_groups || !counts.omitted_matching_rows)
      || payload.reasons.includes("sample_limit") !== origins.some((group) => group.samples.length === 3 && group.omitted_samples > 0)
      || byteRejectedSample && !payload.reasons.includes("projection_byte_limit")
      || payload.reasons.includes("projection_byte_limit") && !(counts.omitted_matching_rows > 0 && remainingBytes < 7040 || byteRejectedSample && remainingBytes < 1024)
      || JSON.stringify(payload).length > PEER_MATCH_LIMITS.projection_bytes
      || origins.reduce((sum, group) => sum + group.matching_rows, 0) !== counts.returned_matching_rows
      || origins.reduce((sum, group) => sum + group.samples.length, 0) !== counts.sample_rows
      || origins.reduce((sum, group) => sum + group.omitted_samples, 0) !== counts.omitted_sample_rows
      || counts.omitted_matching_rows > 0 && !payload.reasons.some((reason) => ["origin_group_limit", "projection_byte_limit"].includes(reason))
      || counts.omitted_sample_rows > 0 && !payload.reasons.some((reason) => ["sample_limit", "projection_byte_limit"].includes(reason))) invalid();
    return Object.freeze({ ...payload, source: Object.freeze({ ...source }), peer: Object.freeze({ ...peer, address: Object.freeze({ ...peer.address }) }),
      snapshot: Object.freeze({ ...snapshot }), reasons: Object.freeze([...payload.reasons]), counts: Object.freeze({ ...counts }), origins: Object.freeze(origins), limits: Object.freeze({ ...payload.limits }) });
  }

  function normalizeBodyReferences(payload, sessionId, evidenceId, row) {
    const invalid = () => { throw new Error("Invalid retained body-reference response"); };
    const integer = (value, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && value >= 0 && value <= max;
    const canonical = (value) => typeof value === "string" && value.length <= BODY_REFERENCE_LIMITS.candidate_bytes && value === safeOrigin(value) && !!value;
    const scanned = payload?.status === "scanned" || payload?.status === "partial";
    if (payload?.schema_version !== 1 || payload.session_id !== sessionId || payload.evidence_id !== evidenceId
      || !["scanned", "partial", "unsupported", "unavailable"].includes(payload.status)
      || payload.available !== scanned || payload.complete !== (payload.status === "scanned")
      || payload.coverage !== "literal_absolute_http_urls" || payload.offset_basis !== "retained_utf8_preview"
      || !Array.isArray(payload.references) || payload.references.length > BODY_REFERENCE_LIMITS.origins
      || !Array.isArray(payload.reasons)
      || (scanned ? payload.reasons.length > BODY_REFERENCE_PARTIAL_REASONS.size
        || payload.reasons.some((reason, index, reasons) => !BODY_REFERENCE_PARTIAL_REASONS.has(reason) || index > 0 && reasons[index - 1] >= reason)
        : payload.reasons.length !== 1 || !(payload.status === "unsupported" ? BODY_REFERENCE_UNSUPPORTED_REASONS : BODY_REFERENCE_UNAVAILABLE_REASONS).has(payload.reasons[0]))
      || !Object.entries(BODY_REFERENCE_LIMITS).every(([key, value]) => payload.limits?.[key] === value)
      || !integer(payload.scanned_bytes, BODY_REFERENCE_LIMITS.scan_bytes)
      || !integer(payload.candidates_scanned, BODY_REFERENCE_LIMITS.candidates)
      || !integer(payload.omitted_reference_occurrences, payload.candidates_scanned)
      || typeof payload.capture_preview_truncated !== "boolean" || typeof payload.scan_prefix_truncated !== "boolean") invalid();
    if (scanned && (!canonical(payload.source_origin) || payload.source_origin !== row.origin)
      || scanned && (typeof payload.source_sequence !== "string" || payload.source_sequence !== row.sequence)
      || scanned && (typeof payload.source_started_at !== "string" || payload.source_started_at !== row.started_at)
      || scanned && (!integer(payload.retained_preview_bytes) || payload.scanned_bytes > payload.retained_preview_bytes)
      || !scanned && (payload.references.length || payload.scanned_bytes || payload.candidates_scanned || payload.omitted_reference_occurrences
        || payload.capture_preview_truncated || payload.scan_prefix_truncated
        || [payload.source_origin, payload.source_sequence, payload.source_started_at, payload.retained_preview_bytes].some((value) => value != null))
      || payload.status === "scanned" && (payload.reasons.length || payload.capture_preview_truncated || payload.scan_prefix_truncated || payload.omitted_reference_occurrences)
      || payload.status === "partial" && !payload.reasons.length) invalid();
    const seen = new Set();
    let occurrences = payload.omitted_reference_occurrences;
    const references = payload.references.map((item) => {
      if (!canonical(item?.target_origin) || seen.has(item.target_origin)
        || !integer(item.occurrences, payload.candidates_scanned) || !item.occurrences
        || !Array.isArray(item.preview_byte_offsets) || item.preview_byte_offsets.length !== Math.min(item.occurrences, BODY_REFERENCE_LIMITS.offsets_per_origin)
        || !integer(item.omitted_offsets, item.occurrences) || item.occurrences !== item.preview_byte_offsets.length + item.omitted_offsets
        || payload.status === "scanned" && item.omitted_offsets
        || item.preview_byte_offsets.some((offset, index, offsets) => !integer(offset) || offset >= payload.scanned_bytes || index > 0 && offset <= offsets[index - 1])) invalid();
      seen.add(item.target_origin);
      occurrences += item.occurrences;
      return { target_origin: item.target_origin, occurrences: item.occurrences, preview_byte_offsets: [...item.preview_byte_offsets], omitted_offsets: item.omitted_offsets };
    });
    if (occurrences > payload.candidates_scanned) invalid();
    const has = (reason) => payload.reasons.includes(reason);
    if (scanned && (has("capture_preview_truncated") !== payload.capture_preview_truncated
      || has("scan_prefix_truncated") !== payload.scan_prefix_truncated
      || payload.scan_prefix_truncated !== (payload.scanned_bytes < payload.retained_preview_bytes)
      || (payload.retained_preview_bytes <= BODY_REFERENCE_LIMITS.scan_bytes ? payload.scanned_bytes !== payload.retained_preview_bytes
        : payload.scanned_bytes < BODY_REFERENCE_LIMITS.scan_bytes - 3)
      || has("candidate_limit") && payload.candidates_scanned !== BODY_REFERENCE_LIMITS.candidates
      || has("candidate_bytes") && !payload.candidates_scanned
      || has("origin_limit") !== (payload.omitted_reference_occurrences > 0)
      || has("origin_limit") && references.length !== BODY_REFERENCE_LIMITS.origins
      || has("offset_limit") !== references.some((item) => item.omitted_offsets > 0))) invalid();
    // Keep a bounded allowlist. Unexpected payload fields, including body content,
    // never become inspector state or markup.
    return { status: payload.status, complete: payload.complete, reasons: [...payload.reasons], references,
      retained_preview_bytes: scanned ? payload.retained_preview_bytes : null, scanned_bytes: payload.scanned_bytes,
      candidates_scanned: payload.candidates_scanned, omitted_reference_occurrences: payload.omitted_reference_occurrences,
      capture_preview_truncated: payload.capture_preview_truncated, scan_prefix_truncated: payload.scan_prefix_truncated };
  }
  const LINK_DECLARATION_LIMITS = Object.freeze({ headers: 128, header_bytes: 32768, link_field_bytes: 4096, target_bytes: 4096, candidates: 128, parameters_per_member: 32, relation_tokens_per_member: 32, observations: 32, target_origin_bytes: 268 });
  const LINK_RELATIONS = Object.freeze({
    "service-doc": { type: "link_service_doc", label: "Link service-doc declaration", rule: "response_link.service_doc.v1" },
    "service-desc": { type: "link_service_desc", label: "Link service-desc declaration", rule: "response_link.service_desc.v1" },
    describedby: { type: "link_describedby", label: "Link describedby declaration", rule: "response_link.describedby.v1" },
    preconnect: { type: "link_preconnect", label: "Link preconnect hint", rule: "response_link.preconnect.v1" },
  });
  const LINK_ACQUISITION_REASONS = new Set(["invalid_evidence_id", "session_mismatch", "stale_generation", "record_missing", "record_changed", "response_unavailable", "unsupported_source_context", "inactive_session", "session_source_changed", "metadata_unavailable", "link_inspection_failed"]);
  const LINK_PARSER_REASONS = {
    header_count_limit: "Retained header count limit reached", header_byte_limit: "Retained header byte limit reached",
    link_field_byte_limit: "An oversized Link field was skipped", candidate_limit: "Link member candidate limit reached",
    parameter_limit: "A member parameter limit was reached", relation_token_limit: "A member relation-token limit was reached",
    observation_limit: "Declaration output limit reached", malformed_field: "A Link field has unsupported framing",
    unsupported_target: "A target is outside the supported absolute HTTP(S) grammar", anchor_present: "A member with an anchor was excluded",
    missing_relation: "A member has no rel parameter", unsupported_relation_syntax: "A rel value uses unsupported syntax",
  };
  const LINK_REASONS = { ...BODY_REFERENCE_REASONS, ...LINK_PARSER_REASONS, unsupported_source_context: "Only retained HTTP(S) GET or HEAD responses with status 200 are supported", session_source_changed: "The active session source changed", metadata_unavailable: "Retained response metadata is unavailable", link_inspection_failed: "Retained Link headers could not be inspected" };
  function normalizeLinkDeclarations(payload, sessionId, evidenceId, row) {
    const invalid = () => { throw new Error("Invalid retained Link-declaration response"); };
    const integer = (value, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && value >= 0 && value <= max;
    const canonical = (value, max = LINK_DECLARATION_LIMITS.target_origin_bytes) => {
      if (typeof value !== "string" || !value || value.length > max || !/^[\x21-\x7e]+$/.test(value) || value !== safeOrigin(value)) return false;
      if (max !== LINK_DECLARATION_LIMITS.target_origin_bytes) return true;
      const host = new URL(value).hostname;
      if (host.startsWith("[")) return true;
      const dns = host.endsWith(".") ? host.slice(0, -1) : host;
      return dns.length > 0 && dns.length <= 253 && host.length <= 254 && dns.split(".").every((label) => label.length <= 63
        && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
    };
    const sourceFields = ["source_origin", "source_sequence", "source_started_at", "source_method", "source_status", "retained_header_count"];
    const countFields = ["headers_inspected", "header_bytes_admitted", "link_fields_inspected", "candidates_inspected", "members_framed", "parameters_inspected", "relation_tokens_inspected", "unknown_relation_tokens_inspected"];
    if (!exactFields(payload, ["schema_version", "relation_catalog_version", "session_id", "evidence_id", "available", "status", "complete", "reasons", ...sourceFields, "coverage", "offset_basis", "counts", "observations", "limits"])
      || payload.schema_version !== 1 || payload.relation_catalog_version !== 1 || payload.session_id !== sessionId || payload.evidence_id !== evidenceId
      || !validHtmlGeneratorEvidence(evidenceId, sessionId, typeof evidenceId === "string" ? evidenceId.split(".")[2] : null)
      || !["scanned", "unsupported", "unavailable"].includes(payload.status) || payload.available !== (payload.status === "scanned")
      || typeof payload.complete !== "boolean" || payload.coverage !== "absolute_http_link_declarations" || payload.offset_basis !== "retained_header_value_utf8"
      || !exactFields(payload.limits, Object.keys(LINK_DECLARATION_LIMITS)) || !Object.entries(LINK_DECLARATION_LIMITS).every(([key, value]) => payload.limits[key] === value)
      || !exactFields(payload.counts, countFields) || countFields.some((key) => !integer(payload.counts[key]))
      || !Array.isArray(payload.observations) || payload.observations.length > LINK_DECLARATION_LIMITS.observations
      || !Array.isArray(payload.reasons) || payload.reasons.length > Object.keys(LINK_PARSER_REASONS).length
      || payload.reasons.some((reason, index) => typeof reason !== "string" || index > 0 && payload.reasons[index - 1] >= reason)) invalid();
    const c = payload.counts;
    if (!payload.available) {
      if (payload.complete || payload.reasons.length !== 1 || !LINK_ACQUISITION_REASONS.has(payload.reasons[0])
        || payload.status === "unsupported" && payload.reasons[0] !== "unsupported_source_context"
        || sourceFields.some((key) => payload[key] !== null) || countFields.some((key) => c[key] !== 0) || payload.observations.length) invalid();
    } else {
      if (!canonical(payload.source_origin, 4096) || payload.source_origin !== row.origin || payload.source_sequence !== row.sequence
        || payload.source_sequence !== evidenceId.split(".")[3] || payload.source_started_at !== row.started_at || observationTime(payload.source_started_at) === null
        || !["GET", "HEAD"].includes(payload.source_method) || payload.source_method !== row.method || payload.source_status !== 200 || row.status !== 200
        || !integer(payload.retained_header_count) || payload.complete !== (payload.reasons.length === 0)
        || payload.reasons.some((reason) => !Object.prototype.hasOwnProperty.call(LINK_PARSER_REASONS, reason))
        || !integer(c.headers_inspected, Math.min(payload.retained_header_count, 128)) || !integer(c.header_bytes_admitted, 32768)
        || c.headers_inspected === 0 && c.header_bytes_admitted !== 0 || c.header_bytes_admitted < c.link_fields_inspected * 4
        || !integer(c.link_fields_inspected, c.headers_inspected) || c.link_fields_inspected === 0 && c.candidates_inspected !== 0 || !integer(c.candidates_inspected, 128) || !integer(c.members_framed, c.candidates_inspected)
        || !integer(c.parameters_inspected, c.candidates_inspected * 32) || !integer(c.relation_tokens_inspected, c.members_framed * 32)
        || !integer(c.unknown_relation_tokens_inspected, c.relation_tokens_inspected) || payload.observations.length > c.relation_tokens_inspected - c.unknown_relation_tokens_inspected
        || c.headers_inspected < payload.retained_header_count && !["header_count_limit", "header_byte_limit", "candidate_limit"].some((reason) => payload.reasons.includes(reason))
        || payload.reasons.includes("header_byte_limit") && c.headers_inspected >= payload.retained_header_count
        || payload.reasons.includes("parameter_limit") && c.parameters_inspected < 32
        || payload.reasons.includes("relation_token_limit") && c.relation_tokens_inspected < 32
        || payload.reasons.includes("link_field_byte_limit") && (!c.link_fields_inspected || c.header_bytes_admitted < 4101)
        || payload.complete && (c.headers_inspected !== payload.retained_header_count || c.candidates_inspected !== c.members_framed || payload.observations.length !== c.relation_tokens_inspected - c.unknown_relation_tokens_inspected)
        || payload.reasons.includes("candidate_limit") && c.candidates_inspected !== 128
        || payload.reasons.includes("observation_limit") && (payload.observations.length !== 32 || c.relation_tokens_inspected - c.unknown_relation_tokens_inspected < 33)
        || payload.reasons.includes("header_count_limit") && (c.headers_inspected !== 128 || payload.retained_header_count <= 128)) invalid();
    }
    const headers = new Map(), members = new Set();
    let previous = null;
    const observations = payload.observations.map((item) => {
      const relation = Object.prototype.hasOwnProperty.call(LINK_RELATIONS, item?.relation) ? LINK_RELATIONS[item.relation] : null;
      const span = (value) => exactFields(value, ["start", "end"]) && integer(value.start, item.header_value_bytes) && integer(value.end, item.header_value_bytes) && value.start < value.end;
      if (!exactFields(item, ["relation", "target_origin", "source", "strength", "header_name", "header_index", "header_value_bytes", "link_value_span", "target_span", "relation_span", "rule_id", "offset_basis"])
        || !relation || !canonical(item.target_origin) || item.source !== "response_link_header" || item.strength !== "literal_declaration"
        || item.header_name !== "link" || item.rule_id !== relation.rule || item.offset_basis !== "retained_header_value_utf8"
        || !integer(item.header_index, c.headers_inspected - 1) || !integer(item.header_value_bytes, 4096)
        || !span(item.link_value_span) || !span(item.target_span) || !span(item.relation_span)
        || item.target_span.start !== item.link_value_span.start + 1 || item.target_span.end >= item.relation_span.start
        || item.target_span.end - item.target_span.start > 4096 || item.relation_span.end > item.link_value_span.end
        || item.relation_span.end - item.relation_span.start !== item.relation.length
        || headers.has(item.header_index) && headers.get(item.header_index) !== item.header_value_bytes) invalid();
      if (previous) {
        const sameMember = item.header_index === previous.header_index && item.link_value_span.start === previous.link_value_span.start;
        if (item.header_index < previous.header_index || item.header_index === previous.header_index && (sameMember
          ? item.link_value_span.end !== previous.link_value_span.end || item.target_span.start !== previous.target_span.start || item.target_span.end !== previous.target_span.end
            || item.target_origin !== previous.target_origin || item.relation_span.start <= previous.relation_span.end
          : item.link_value_span.start <= previous.link_value_span.end)) invalid();
      }
      headers.set(item.header_index, item.header_value_bytes);
      members.add(JSON.stringify([item.header_index, item.link_value_span.start])); previous = item;
      return { ...item, link_value_span: { ...item.link_value_span }, target_span: { ...item.target_span }, relation_span: { ...item.relation_span } };
    });
    if (headers.size > c.link_fields_inspected || members.size > c.members_framed || members.size > c.parameters_inspected
      || [...headers.values()].reduce((sum, size) => sum + size + 4, 0) > c.header_bytes_admitted) invalid();
    return { status: payload.status, complete: payload.complete, reasons: [...payload.reasons], observations, counts: { ...c }, retained_header_count: payload.retained_header_count };
  }
  const HTML_GENERATOR_LIMITS = Object.freeze({ scan_bytes: 262144, serialized_row_bytes: 2097152, tag_candidates: 4096, tag_bytes: 4096, attributes: 32, observations: 8, version_bytes: 32, version_separator_bytes: 32 });
  const HTML_GENERATOR_ACQUISITION_REASONS = new Set([
    "invalid_evidence_id", "session_mismatch", "stale_generation", "record_missing", "record_changed", "body_identity_unverifiable",
    "response_unavailable", "metadata_limit", "unsupported_content_type", "unsupported_body_encoding", "unsupported_content_encoding",
    "unsupported_metadata", "serialized_row_limit", "body_storage_unavailable", "body_read_failed", "malformed_retained_row",
    "retained_preview_unavailable", "body_scan_failed", "inactive_session", "session_source_changed", "metadata_unavailable",
  ]);
  // Missing constructors also accept eligibility reasons; only unsupported is narrower.
  const HTML_GENERATOR_UNSUPPORTED_REASONS = new Set(["metadata_limit", "unsupported_content_type", "unsupported_body_encoding", "unsupported_content_encoding", "unsupported_metadata"]);
  const HTML_GENERATOR_STOP_REASONS = {
    end_of_preview: "Preview ended before a supported closing head", input_limit: "Input limit reached before a supported closing head",
    tag_candidate_limit: "Tag candidate limit reached", tag_byte_limit: "Tag byte limit reached", attribute_limit: "Attribute limit reached",
    observation_limit: "Generator declaration output limit reached", unsupported_document_context: "Document context is unsupported",
    unsupported_head_context: "Head context is unsupported", unsupported_doctype: "Doctype is unsupported",
    unsupported_comment: "Comment context is unsupported", unsupported_script_escape: "Script escape context is unsupported",
    unsupported_entity: "Entity spelling is unsupported", unsupported_self_closing: "Self-closing context is unsupported",
    malformed_tag: "Tag structure is unsupported", duplicate_attribute: "Duplicate attribute encountered", null_byte: "Null byte encountered",
  };
  const HTML_GENERATOR_REASONS = { ...BODY_REFERENCE_REASONS, ...HTML_GENERATOR_STOP_REASONS,
    unsupported_content_type: "Only retained HTML text previews are supported", session_source_changed: "The active session source changed",
    metadata_unavailable: "Retained metadata is unavailable" };
  function validHtmlGeneratorEvidence(value, sessionId, generation) {
    if (typeof value !== "string") return false;
    const fields = value.split("."), uuid = (part) => typeof part === "string" && part.length === 36
      && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(part);
    return fields.length === 6 && [fields[1], fields[2], fields[4], fields[5]].every(uuid)
      && !/[^0-9]/.test(fields[3]) && validTechnologyEvidence(value, sessionId, generation);
  }
  function normalizeHtmlGenerators(payload, sessionId, evidenceId, row) {
    const invalid = () => { throw new Error("Invalid retained HTML-generator response"); };
    const integer = (value, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && value >= 0 && value <= max;
    const fields = ["schema_version", "generator_catalog_version", "session_id", "evidence_id", "available", "status", "complete", "reasons",
      "source_origin", "source_sequence", "source_started_at", "retained_preview_bytes", "scan_prefix_bytes", "capture_preview_truncated",
      "scan_prefix_truncated", "coverage", "head_closed", "parser_stop", "tag_candidates_inspected", "additional_tag_candidate_encountered",
      "additional_observation_encountered", "unknown_product_declarations", "observations", "limits", "offset_basis"];
    if (!exactFields(payload, fields) || payload.schema_version !== 1 || payload.generator_catalog_version !== 1
      || payload.session_id !== sessionId || payload.evidence_id !== evidenceId
      || !validHtmlGeneratorEvidence(evidenceId, sessionId, typeof evidenceId === "string" ? evidenceId.split(".")[2] : null)
      || !["scanned", "unsupported", "unavailable"].includes(payload.status) || payload.available !== (payload.status === "scanned")
      || ["complete", "capture_preview_truncated", "scan_prefix_truncated", "head_closed", "additional_tag_candidate_encountered", "additional_observation_encountered"].some((key) => typeof payload[key] !== "boolean")
      || payload.coverage !== "literal_html_generator_explicit_head" || payload.offset_basis !== "retained_utf8_preview"
      || !exactFields(payload.limits, Object.keys(HTML_GENERATOR_LIMITS))
      || !Object.entries(HTML_GENERATOR_LIMITS).every(([key, value]) => payload.limits[key] === value)
      || !integer(payload.scan_prefix_bytes, HTML_GENERATOR_LIMITS.scan_bytes)
      || !integer(payload.tag_candidates_inspected, HTML_GENERATOR_LIMITS.tag_candidates)
      || !integer(payload.unknown_product_declarations, payload.tag_candidates_inspected)
      || !Array.isArray(payload.observations) || payload.observations.length > HTML_GENERATOR_LIMITS.observations
      || !Array.isArray(payload.reasons) || payload.reasons.length > 3
      || payload.reasons.some((reason, index) => typeof reason !== "string" || index > 0 && payload.reasons[index - 1] >= reason)) invalid();
    const scanned = payload.available;
    if (!scanned) {
      if (payload.complete || payload.reasons.length !== 1 || payload.reasons.some((reason) => !HTML_GENERATOR_ACQUISITION_REASONS.has(reason))
        || payload.status === "unsupported" && !HTML_GENERATOR_UNSUPPORTED_REASONS.has(payload.reasons[0])
        || ["source_origin", "source_sequence", "source_started_at", "retained_preview_bytes", "parser_stop"].some((key) => payload[key] !== null)
        || payload.scan_prefix_bytes || payload.tag_candidates_inspected || payload.unknown_product_declarations || payload.observations.length
        || payload.head_closed || payload.capture_preview_truncated || payload.scan_prefix_truncated
        || payload.additional_tag_candidate_encountered || payload.additional_observation_encountered) invalid();
    } else {
      if (typeof payload.source_origin !== "string" || payload.source_origin.length > 4096 || payload.source_origin !== safeOrigin(payload.source_origin)
        || payload.source_origin !== row.origin || payload.source_sequence !== row.sequence || payload.source_sequence !== evidenceId.split(".")[3]
        || payload.source_started_at !== row.started_at || observationTime(payload.source_started_at) === null
        || !integer(payload.retained_preview_bytes) || payload.scan_prefix_bytes > payload.retained_preview_bytes
        || (payload.retained_preview_bytes <= HTML_GENERATOR_LIMITS.scan_bytes ? payload.scan_prefix_bytes !== payload.retained_preview_bytes
          : payload.scan_prefix_bytes < HTML_GENERATOR_LIMITS.scan_bytes - 3)
        || payload.scan_prefix_truncated !== (payload.scan_prefix_bytes < payload.retained_preview_bytes)
        || payload.head_closed !== (payload.parser_stop === null)) invalid();
      const stop = payload.parser_stop;
      if (stop !== null && (!exactFields(stop, ["reason", "byte_cursor"]) || !Object.prototype.hasOwnProperty.call(HTML_GENERATOR_STOP_REASONS, stop.reason)
        || !integer(stop.byte_cursor, payload.scan_prefix_bytes)
        || stop.reason === "input_limit" && (!payload.scan_prefix_truncated || stop.byte_cursor !== payload.scan_prefix_bytes)
        || stop.reason === "end_of_preview" && (payload.scan_prefix_truncated || stop.byte_cursor !== payload.scan_prefix_bytes))) invalid();
      const declarations = payload.observations.length + payload.unknown_product_declarations + Number(payload.additional_observation_encountered);
      const minimumTags = declarations ? declarations + 2 + Number(payload.head_closed) : payload.head_closed ? 3 : 0;
      const reasons = [...(payload.capture_preview_truncated ? ["capture_preview_truncated"] : []),
        ...(payload.scan_prefix_truncated ? ["scan_prefix_truncated"] : []), ...(stop ? [stop.reason] : [])].sort();
      if (JSON.stringify(payload.reasons) !== JSON.stringify(reasons) || payload.complete !== (payload.head_closed && !reasons.length)
        || payload.additional_tag_candidate_encountered !== (stop?.reason === "tag_candidate_limit")
        || payload.additional_tag_candidate_encountered && payload.tag_candidates_inspected !== HTML_GENERATOR_LIMITS.tag_candidates
        || payload.additional_observation_encountered !== (stop?.reason === "observation_limit")
        || payload.additional_observation_encountered && payload.observations.length !== HTML_GENERATOR_LIMITS.observations
        || payload.tag_candidates_inspected < minimumTags || payload.tag_candidates_inspected > payload.scan_prefix_bytes
        || stop && payload.tag_candidates_inspected > stop.byte_cursor + 1) invalid();
    }
    let previousTagEnd = 0;
    const observations = payload.observations.map((item) => {
      const name = item?.product_id === "wordpress" ? "WordPress" : item?.product_id === "drupal" ? "Drupal" : null;
      const span = (value) => exactFields(value, ["start", "end"]) && integer(value.start, payload.scan_prefix_bytes)
        && integer(value.end, payload.scan_prefix_bytes) && value.start < value.end;
      if (!exactFields(item, ["product_id", "name", "catalog_category", "reported_version", "version_status", "source", "strength", "rule_id", "tag_span", "content_span", "product_span", "version_span", "offset_basis"])
        || !name || item.name !== name || item.catalog_category !== "cms" || item.source !== "response_html_meta_generator"
        || item.strength !== "literal_declaration" || item.rule_id !== `html_meta_generator.${item.product_id}.v1`
        || item.offset_basis !== "retained_utf8_preview" || !["reported", "not_reported", "unsupported_format"].includes(item.version_status)
        || !span(item.tag_span) || !span(item.content_span) || !span(item.product_span)
        || item.tag_span.start < previousTagEnd || item.tag_span.end - item.tag_span.start > HTML_GENERATOR_LIMITS.tag_bytes
        || item.content_span.start <= item.tag_span.start || item.content_span.end >= item.tag_span.end
        || item.product_span.start !== item.content_span.start || item.product_span.end > item.content_span.end
        || item.product_span.end - item.product_span.start !== name.length
        || payload.parser_stop && item.tag_span.end > payload.parser_stop.byte_cursor) invalid();
      if (item.version_status === "reported") {
        if (typeof item.reported_version !== "string" || item.reported_version.length > HTML_GENERATOR_LIMITS.version_bytes
          || !item.reported_version.split(".").every((part) => part.length > 0 && !/[^0-9]/.test(part)) || !span(item.version_span)
          || item.version_span.start <= item.product_span.end || item.version_span.start - item.product_span.end > HTML_GENERATOR_LIMITS.version_separator_bytes
          || item.version_span.end !== item.content_span.end || item.version_span.end - item.version_span.start !== item.reported_version.length) invalid();
      } else if (item.reported_version !== null || item.version_span !== null
        || item.version_status === "not_reported" && item.product_span.end !== item.content_span.end
        || item.version_status === "unsupported_format" && item.product_span.end === item.content_span.end) invalid();
      previousTagEnd = item.tag_span.end;
      return { product_id: item.product_id, name, catalog_category: "cms", reported_version: item.reported_version, version_status: item.version_status,
        source: item.source, strength: item.strength, rule_id: item.rule_id, tag_span: { ...item.tag_span }, content_span: { ...item.content_span },
        product_span: { ...item.product_span }, version_span: item.version_span ? { ...item.version_span } : null, offset_basis: item.offset_basis };
    });
    return { status: payload.status, complete: payload.complete, reasons: [...payload.reasons], source_origin: payload.source_origin,
      source_sequence: payload.source_sequence, source_started_at: payload.source_started_at, retained_preview_bytes: payload.retained_preview_bytes,
      scan_prefix_bytes: payload.scan_prefix_bytes, capture_preview_truncated: payload.capture_preview_truncated, scan_prefix_truncated: payload.scan_prefix_truncated,
      head_closed: payload.head_closed, parser_stop: payload.parser_stop ? { ...payload.parser_stop } : null,
      tag_candidates_inspected: payload.tag_candidates_inspected, additional_tag_candidate_encountered: payload.additional_tag_candidate_encountered,
      additional_observation_encountered: payload.additional_observation_encountered, unknown_product_declarations: payload.unknown_product_declarations, observations };
  }
  function normalizeSnapshot(payload, sessionId, requestedVersion = TECHNOLOGY_CATALOG_VERSION) {
    if (payload?.schema_version !== 1 || payload.session_id !== sessionId || !payload.snapshot || !Array.isArray(payload.origins)) {
      throw new Error("Invalid service map response");
    }
    const catalogVersion = technologyCatalogVersion(payload, requestedVersion);
    for (const [key, limit] of Object.entries({ technology_observations_per_row: 8, technology_observations_per_origin: 32, technology_observations: 2000, technology_version_bytes: 32, technology_token_candidates_per_row: 128 })) {
      if (payload.snapshot.limits?.[key] !== undefined && payload.snapshot.limits[key] !== limit) invalidTechnology();
    }
    if (array(payload.snapshot.stopped_by).includes("technology_token_scan_limit") && payload.snapshot.complete !== false) invalidTechnology();
    let technologyCount = 0;
    const technologySources = new Map();
    const technologies = payload.origins.map((item) => {
      const observations = normalizeOriginTechnologies(item, sessionId, payload.snapshot.generation, catalogVersion);
      technologyCount += observations.length;
      if (technologyCount > 2000) invalidTechnology();
      for (const observation of observations) for (const id of observation.evidence) {
        const sequence = id.split(".")[3], previous = technologySources.get(sequence);
        if (previous && (previous.origin !== item.origin || previous.id !== id)) invalidTechnology();
        technologySources.set(sequence, { origin: item.origin, id });
      }
      return observations;
    });
    // The same retained sequence must retain one complete token identity across
    // new observations and legacy evidence collections, including record revision.
    for (const item of payload.origins) {
      for (const source of [...array(item?.endpoints), ...array(item?.technology_clues), ...array(item?.redirects), ...array(item?.header_links)]) {
        for (const id of array(source?.evidence)) {
          const previous = typeof id === "string" && technologySources.get(id.split(".")[3]);
          if (previous && (previous.origin !== item.origin || previous.id !== id)) invalidTechnology();
        }
      }
    }
    const seen = new Set();
    const origins = payload.origins.flatMap((item, index) => {
      const origin = safeOrigin(item?.origin);
      if (!origin || seen.has(origin)) return [];
      seen.add(origin);
      return [{
        origin, captured: true, in_scope: item.in_scope === true, request_count: count(item.request_count),
        first_seen: item.first_seen, last_seen: item.last_seen, technology_observations: technologies[index],
        technology_observations_present: Object.prototype.hasOwnProperty.call(item, "technology_observations"),
        endpoints: array(item.endpoints).map((endpoint) => ({
          method: String(endpoint.method || "?"), path: safePath(endpoint.path), path_group: safePath(endpoint.path_group || endpoint.path),
          request_count: count(endpoint.request_count), statuses: array(endpoint.statuses), content_types: array(endpoint.content_types),
          evidence: array(endpoint.evidence).filter((id) => typeof id === "string" && id.length > 0),
          auth: array(endpoint.auth).filter((kind) => AUTH_KINDS.includes(kind)).slice(0, AUTH_KINDS.length),
        })),
        technology_clues: array(item.technology_clues).filter((clue) => clue.source === "response_header" && clue.confidence === "observed_header").map((clue) => ({
          name: String(clue.name || "Header clue"), evidence: array(clue.evidence).filter((id) => typeof id === "string" && id.length > 0),
        })),
        header_links: array(item.header_links).filter((link) => link.source === "request_header_declaration" && ["origin_header", "referer_header"].includes(link.relationship) && safeOrigin(link.source_origin)).map((link) => ({
          source_origin: safeOrigin(link.source_origin), relationship: link.relationship,
          evidence: array(link.evidence).filter((id) => typeof id === "string" && id.length > 0),
          request_count: count(link.request_count),
          request_kinds: Object.fromEntries(REQUEST_KINDS.filter((kind) => count(link.request_kinds?.[kind]) > 0).map((kind) => [kind, count(link.request_kinds[kind])])),
          cors_allowed_count: count(link.cors_allowed_count), cors_credentials_count: count(link.cors_credentials_count),
        })),
        header_sources: array(item.header_sources).filter((source) => safeOrigin(source?.source_origin)).map((source) => ({
          source_origin: safeOrigin(source.source_origin), request_count: count(source.request_count),
          request_kinds: Object.fromEntries(REQUEST_KINDS.filter((kind) => count(source.request_kinds?.[kind]) > 0).map((kind) => [kind, count(source.request_kinds[kind])])),
          cors_allowed_count: count(source.cors_allowed_count), cors_credentials_count: count(source.cors_credentials_count),
        })),
        redirects: array(item.redirects).filter((redirect) => redirect.relationship === "redirect_instruction" && safeOrigin(redirect.target_origin)).map((redirect) => ({
          target_origin: safeOrigin(redirect.target_origin), target_path: safePath(redirect.target_path),
          evidence: array(redirect.evidence).filter((id) => typeof id === "string" && id.length > 0),
          request_count: count(redirect.request_count),
        })),
        ...(FAVICON_TOKEN.test(item.favicon) ? { favicon: item.favicon } : {}),
        // How its requests authenticate, by name and shape only.
        auth: array(item.auth).filter((entry) => AUTH_KINDS.includes(entry?.kind) && (entry.name == null || /^[A-Za-z0-9._-]{1,64}$/.test(entry.name)))
          .slice(0, 16).map((entry) => ({ kind: entry.kind, ...(entry.name == null ? {} : { name: entry.name }), row_count: count(entry.row_count),
            evidence: array(entry.evidence).filter((id) => typeof id === "string" && id.length > 0) })),
        // What the origin's own responses say about its servers, and expose.
        server_technologies: array(item.server_technologies).filter((entry) => /^[a-z0-9_]{1,40}$/.test(entry?.product_id)
          && /^[A-Za-z.][A-Za-z0-9 .()!+_-]{0,39}$/.test(entry.name) && SERVER_CATEGORIES.includes(entry.category)
          && (entry.version == null || /^[0-9][0-9A-Za-z.+-]{0,39}$/.test(entry.version))
          && array(entry.signals).length > 0 && array(entry.signals).every((signal) => SERVER_SIGNALS.includes(signal))).map((entry) => ({
          product_id: entry.product_id, name: entry.name, category: entry.category, ...(entry.version == null ? {} : { version: entry.version }),
          signals: array(entry.signals), row_count: count(entry.row_count), evidence: array(entry.evidence).filter((id) => typeof id === "string" && id.length > 0),
        })),
        // Front-end technologies retained scripts, pages and asset URLs name.
        front_technologies: array(item.front_technologies).filter((entry) => /^[a-z0-9_]{1,40}$/.test(entry?.product_id)
          // A brand may open with a digit: 6sense, 33Across.
          && /^[A-Za-z0-9][A-Za-z0-9 .!+_-]{0,39}$/.test(entry.name) && FRONT_CATEGORIES.includes(entry.category)
          && (entry.version == null || /^[0-9][0-9A-Za-z.+-]{0,39}$/.test(entry.version)) && safeOrigin(entry.source_origin)).map((entry) => ({
          product_id: entry.product_id, name: entry.name, category: entry.category, ...(entry.version == null ? {} : { version: entry.version }),
          source_origin: safeOrigin(entry.source_origin), row_count: count(entry.row_count),
          evidence: array(entry.evidence).filter((id) => typeof id === "string" && id.length > 0),
        })),
        // What no rule names: a banner, a header name, a cookie name.
        unnamed: Object.fromEntries(["banners", "headers", "cookies"].map((kind) => [kind, array(item.unnamed?.[kind])
          .filter((signal) => typeof signal?.value === "string" && /^[\x20-\x7e]{1,80}$/.test(signal.value)).slice(0, 16)
          .map((signal) => ({ value: signal.value, row_count: count(signal.row_count), evidence: array(signal.evidence).filter((id) => typeof id === "string" && id.length > 0) }))])),
      }];
    });
    // Clients each row's User-Agent named, and the rows they sent each origin.
    const clients = array(payload.clients).filter((client) => CLIENT_KINDS.includes(client?.kind) && /^[A-Za-z][A-Za-z0-9 ./-]{0,39}$/.test(client.name)
      && (client.os == null || CLIENT_SYSTEMS.includes(client.os)))
      .slice(0, 16).map((client) => ({ kind: client.kind, name: client.name, versions: array(client.versions).filter((version) => Number.isSafeInteger(version) && version >= 0).slice(0, 8),
        ...(client.os == null ? {} : { os: client.os }),
        request_count: count(client.request_count),
        // The addresses it connected to the proxy from, kept only as IPs.
        addresses: array(client.addresses).filter((address) => typeof address === "string" && /^[0-9A-Fa-f:.]{2,45}$/.test(address)).slice(0, 8),
        origins: array(client.origins).filter((item) => safeOrigin(item?.origin)).slice(0, 64).map((item) => ({ origin: safeOrigin(item.origin), request_count: count(item.request_count),
          entry_kinds: Object.fromEntries(REQUEST_KINDS.filter((kind) => count(item.entry_kinds?.[kind]) > 0).map((kind) => [kind, count(item.entry_kinds[kind])])) })) }));
    return { snapshot: payload.snapshot, origins, clients, warningCount: array(payload.warnings).length, technologyCatalogVersion: catalogVersion, legacyCatalog: catalogVersion !== requestedVersion };
  }
  function stableOrder(previous, origins) {
    const ids = new Set(origins.map((origin) => origin.origin));
    const previousIds = new Set(previous);
    return [...previous.filter((id) => ids.has(id)), ...[...ids].filter((id) => !previousIds.has(id)).sort()];
  }
  // Only the first MAX_CARDS cards are drawn, and an arrow needs both ends on
  // screen. Picked by name, related origins land on either side of the cap: a
  // session with 67 relationships among 86 origins drew none. Lead with the
  // best-connected captured origin, follow it with its neighbours breadth first,
  // and repeat for each connected group; unrelated and reference-only origins
  // follow by name.
  function relationshipOrder(origins, hiddenKinds = []) {
    const hidden = new Set(hiddenKinds);
    const captured = new Set(origins.filter((origin) => origin.captured !== false).map((origin) => origin.origin));
    const neighbors = new Map();
    const link = (a, b) => {
      if (a === b || !captured.has(a) || !captured.has(b)) return;
      for (const [from, to] of [[a, b], [b, a]]) {
        if (!neighbors.has(from)) neighbors.set(from, new Set());
        neighbors.get(from).add(to);
      }
    };
    for (const origin of origins) {
      for (const redirect of origin.redirects || []) link(origin.origin, redirect.target_origin);
      // A link made only of hidden kinds (images a page loaded) ranks nothing.
      for (const header of origin.header_links || []) {
        if (linkKindCounts(header).some(([kind]) => !hidden.has(kind))) link(header.source_origin, origin.origin);
      }
    }
    const degree = (id) => neighbors.get(id)?.size || 0;
    const rank = (a, b) => degree(b) - degree(a) || a.localeCompare(b);
    const order = [];
    const placed = new Set();
    for (const seed of [...neighbors.keys()].sort(rank)) {
      if (placed.has(seed)) continue;
      placed.add(seed);
      for (const queue = [seed]; queue.length;) {
        const id = queue.shift();
        order.push(id);
        for (const next of [...neighbors.get(id)].sort(rank)) {
          if (!placed.has(next)) { placed.add(next); queue.push(next); }
        }
      }
    }
    const rest = (wanted) => origins.filter((origin) => !placed.has(origin.origin) && captured.has(origin.origin) === wanted).map((origin) => origin.origin).sort();
    return [...order, ...rest(true), ...rest(false)];
  }
  function graphGeometry(textSize = 12) {
    const size = Math.max(8, Math.min(20, Number.isFinite(textSize) ? textSize : 12));
    // Three text rows (name, products, counts), two gaps, two card
    // paddings/borders, and clue borders. Larger Display text must grow the
    // graph as well as its text, otherwise fixed compact rows clip glyphs and
    // leave SVG arrows at the wrong height.
    const cardHeight = Math.max(GRAPH_GEOMETRY.cardHeight, Math.ceil((Math.max(10, size - 1) + 2 * Math.max(9, size - 2)) * GRAPH_GEOMETRY.lineHeight + 36));
    return { ...GRAPH_GEOMETRY, cardHeight, rowPitch: cardHeight + GRAPH_GEOMETRY.rowPitch - GRAPH_GEOMETRY.cardHeight };
  }
  // Each linked card sits one column right of its furthest linked source
  // (longest-path layering), so a chain reads left to right and no arrow joins
  // two cards of one column. Two fixed columns put a real session's hub alone on
  // the left and its 23 targets in one column, drawing their 17 links to each
  // other as loops piled on the column edge. Only a link that closes a cycle is
  // turned around, found by a depth-first walk from the sources. Columns are
  // centered on the tallest and sorted by their sources' rows to limit
  // crossings; unlinked cards fill a grid below.
  function layeredSlots(visibleOrigins, connections) {
    const ids = visibleOrigins.map((origin) => origin.origin);
    const rank = new Map(ids.map((id, index) => [id, index]));
    const inspected = new Set(visibleOrigins.filter((origin) => origin.inspectedSource).map((origin) => origin.origin));
    const next = new Map(ids.map((id) => [id, new Set()]));
    for (const [source, target] of connections) next.get(source).add(target);
    const linked = new Set(connections.flat());
    const targets = new Set(connections.map(([, target]) => target));
    const visiting = new Set(), done = new Set(), forward = [];
    const visit = (id) => {
      visiting.add(id);
      for (const target of next.get(id)) {
        if (visiting.has(target)) {
          forward.push([target, id]);
        } else {
          forward.push([id, target]);
          if (!done.has(target)) visit(target);
        }
      }
      visiting.delete(id);
      done.add(id);
    };
    for (const id of [...ids.filter((id) => !targets.has(id)), ...ids]) {
      if (linked.has(id) && !done.has(id)) visit(id);
    }
    const layer = new Map([...linked].map((id) => [id, 0]));
    for (let changed = true; changed;) {
      changed = false;
      for (const [source, target] of forward) {
        if (layer.get(target) <= layer.get(source)) {
          layer.set(target, layer.get(source) + 1);
          changed = true;
        }
      }
    }
    const columns = Array.from({ length: linked.size ? Math.min(MAX_COLUMNS, Math.max(...layer.values()) + 1) : 0 }, () => []);
    for (const id of ids) if (linked.has(id)) columns[Math.min(MAX_COLUMNS - 1, layer.get(id))].push(id);
    const tallest = Math.max(0, ...columns.map((column) => column.length));
    const slots = new Map();
    columns.forEach((column, index) => {
      const center = new Map(column.map((id) => {
        const rows = forward.filter(([source, target]) => target === id && slots.has(source)).map(([source]) => slots.get(source).row);
        return [id, rows.length ? rows.reduce((sum, row) => sum + row, 0) / rows.length : Infinity];
      }));
      column.sort((a, b) => Number(inspected.has(b)) - Number(inspected.has(a)) || center.get(a) - center.get(b) || rank.get(a) - rank.get(b));
      const offset = Math.floor((tallest - column.length) / 2);
      column.forEach((id, row) => slots.set(id, { column: index, row: offset + row }));
    });
    const gridColumns = Math.max(2, columns.length);
    ids.filter((id) => !linked.has(id)).forEach((id, index) => {
      slots.set(id, { column: index % gridColumns, row: tallest + Math.floor(index / gridColumns) });
    });
    return slots;
  }
  const LINK_LABELS = { origin_header: "Origin header", referer_header: "Referer header", client_request: "Direct request" };
  // The Flow view: the selected origin's requests and those of the origins it
  // links to, in time order, a band per page load, the client on the left.
  const FLOW = Object.freeze({ gutter: 64, clientX: 136, laneWidth: 220, laneBox: 180, top: 12, header: 46, kicker: 30, step: 42, padding: 20 });
  const FLOW_STOPS = Object.freeze({ max_records: "older rows left out", metadata_bytes: "metadata read limit reached", lanes_limit: "more origins link here; the five with the most rows are shown", steps_limit: "older steps left out",
    request_header_scan_limit: "request-header read limit reached", request_header_value_limit: "oversized request headers left links unproven",
    ambiguous_origin_header: "ambiguous Origin headers", ambiguous_referer_header: "ambiguous Referer headers",
    header_scan_limit: "response-header read limit reached", header_value_limit: "oversized response headers left redirects unproven",
    ambiguous_location_headers: "ambiguous redirect headers", unsupported_location: "unsupported redirect target" });
  const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const hostOf = (origin) => { try { return new URL(origin).host; } catch { return String(origin); } };
  const flowStepLabel = (step) => `${step.method} ${step.path}${step.count > 1 ? ` ×${step.count}` : ""}${step.status == null ? "" : ` ${step.status}`}`;
  const flowRedirectLabel = (step) => `${step.status ?? "3xx"} to ${hostOf(step.redirect.origin)}${step.redirect.path}`;
  const flowPageLabel = (phase) => phase.page ? `Page load: ${hostOf(phase.page.origin)}${phase.page.path}` : "Before the first page load";
  const FLOW_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
  const flowStatusClass = (status) => status == null ? "" : status >= 500 ? " status-error" : status >= 400 ? " status-warn" : status >= 300 ? " status-info" : " status-ok";
  const flowTime = (ms) => ms < 1000 ? `+${Math.round(ms)}ms` : ms < 60000 ? `+${(ms / 1000).toFixed(1)}s`
    : `+${Math.floor(ms / 60000)}m${String(Math.floor(ms % 60000 / 1000)).padStart(2, "0")}s`;
  // SVG text is placed, not measured: a character of the 12px monospace path
  // is about 7.2px wide and one of an 11px bold pill about 7px.
  const flowFit = (text, room, perChar = 7.2) => text.length * perChar <= room ? text : `${text.slice(0, Math.max(3, Math.floor(room / perChar) - 1))}…`;
  function flowPill(x, y, text, kind) {
    const width = 14 + text.length * 7;
    return { width, markup: `<g class="service-map-flow-pill${kind}"><rect x="${x}" y="${y - 9}" width="${width}" height="18" rx="9"></rect><text x="${x + width / 2}" y="${y}" text-anchor="middle" dominant-baseline="central">${escape(text)}</text></g>` };
  }

  // A flow read that does not match the origin and session asked for, or
  // names a lane it does not list, shows nothing rather than a wrong diagram.
  function normalizeFlow(raw, sessionId, origin) {
    if (!raw || raw.schema_version !== 1 || raw.session_id !== sessionId || raw.origin !== origin) return null;
    const lanes = array(raw.lanes).map((lane) => safeOrigin(lane));
    if (!lanes.length || lanes[0] !== origin || lanes.some((lane, index) => lane !== raw.lanes[index])) return null;
    const target = (value) => value && safeOrigin(value.origin) ? { origin: safeOrigin(value.origin), path: safePath(value.path) } : null;
    const phases = array(raw.phases).map((phase) => ({
      page: target(phase?.page),
      steps: array(phase?.steps).filter((step) => lanes.includes(step?.origin) && UUID_PATTERN.test(String(step.record_id || ""))).map((step) => ({
        origin: step.origin, method: String(step.method || "?").slice(0, 16), path: safePath(step.path),
        status: Number.isInteger(step.status) ? step.status : null, kind: REQUEST_KINDS.includes(step.request_kind) ? step.request_kind : "other",
        count: Math.max(1, count(step.count)), recordId: step.record_id, redirect: target(step.redirect), firstSeen: Date.parse(step.first_seen),
      })),
    })).filter((phase) => phase.steps.length);
    return { origin, lanes, phases, flowRows: count(raw.flow_rows), consideredRows: count(raw.considered_rows), complete: raw.complete === true, stoppedBy: array(raw.stopped_by).map(String) };
  }

  // A card per page load with a row per shown step and one more for its
  // redirect; a page load whose steps are all of hidden kinds gets no card.
  function flowLayout(flow, hiddenKinds = []) {
    const hidden = new Set(hiddenKinds);
    const laneX = new Map(flow.lanes.map((origin, index) => [origin, FLOW.clientX + FLOW.laneWidth * (index + 1)]));
    const laneRequests = new Map(flow.lanes.map((origin) => [origin, 0]));
    const phases = flow.phases.map((phase) => ({ phase, steps: phase.steps.filter((step) => !hidden.has(step.kind)) })).filter(({ steps }) => steps.length);
    const start = Math.min(...phases.flatMap(({ steps }) => steps.map((step) => step.firstSeen)).filter(Number.isFinite));
    const bands = [], arrows = [];
    let y = FLOW.top + FLOW.header + 16;
    for (const { phase, steps } of phases) {
      const top = y;
      y += FLOW.kicker;
      for (const step of steps) {
        laneRequests.set(step.origin, laneRequests.get(step.origin) + step.count);
        const at = Number.isFinite(step.firstSeen) && Number.isFinite(start) ? step.firstSeen - start : null;
        for (const redirect of step.redirect ? [false, true] : [false]) {
          arrows.push({ top: y, y: y + FLOW.step - 13, x: laneX.get(step.origin), step, redirect, at: redirect ? null : at });
          y += FLOW.step;
        }
      }
      y += 8;
      bands.push({ y: top, height: y - top, page: phase.page });
      y += 14;
    }
    return { lanes: flow.lanes, laneX, laneRequests, bands, arrows, width: FLOW.clientX + FLOW.laneWidth * flow.lanes.length + FLOW.laneBox / 2 + FLOW.padding, height: y + FLOW.padding };
  }

  function flowMarkup(layout) {
    const bottom = layout.height - FLOW.padding / 2, right = layout.width - FLOW.padding;
    const requests = (value) => `${value} request${value === 1 ? "" : "s"}`;
    const total = [...layout.laneRequests.values()].reduce((sum, value) => sum + value, 0);
    const lane = (x, name, detail, title, attributes = "") => `<g class="service-map-flow-lane"${attributes}><title>${escape(title)}</title>`
      + `<rect x="${x - FLOW.laneBox / 2}" y="${FLOW.top}" width="${FLOW.laneBox}" height="${FLOW.header}" rx="8"></rect>`
      + `<text class="service-map-flow-lane-name" x="${x}" y="${FLOW.top + 17}" text-anchor="middle" dominant-baseline="central">${escape(flowFit(name, FLOW.laneBox - 20, 7))}</text>`
      + `<text class="service-map-flow-lane-detail" x="${x}" y="${FLOW.top + 33}" text-anchor="middle" dominant-baseline="central">${escape(detail)}</text></g>`;
    const xs = [FLOW.clientX, ...layout.lanes.map((origin) => layout.laneX.get(origin))];
    const lifelines = xs.map((x) => `<line class="service-map-flow-life" x1="${x}" y1="${FLOW.top + FLOW.header}" x2="${x}" y2="${bottom}"></line>`);
    const lanes = [lane(FLOW.clientX, "Client", requests(total), "Requests as the client sent them"),
      ...layout.lanes.map((origin, index) => lane(layout.laneX.get(origin), hostOf(origin), requests(layout.laneRequests.get(origin)),
        index ? `${origin} · show its flow` : origin, index ? ` data-service-flow-lane="${escape(origin)}" role="button" tabindex="0"` : ' data-selected="true"'))];
    // The headers come last, over a backdrop, so they can stay in view while
    // the steps scroll under them.
    const heads = `<g class="service-map-flow-heads"><rect class="service-map-flow-heads-backdrop" x="0" y="0" width="${layout.width}" height="${FLOW.top + FLOW.header + 6}"></rect>${lanes.join("")}</g>`;
    const cards = layout.bands.map((band) => `<rect class="service-map-flow-phase" x="8" y="${band.y}" width="${layout.width - 16}" height="${band.height}" rx="8"></rect>`
      + `<rect class="service-map-flow-phase-accent" x="8" y="${band.y + 8}" width="3" height="${band.height - 16}" rx="1.5"></rect>`);
    // A card's title sits on a patch of its own colour so the lifelines pass behind it.
    const titles = layout.bands.map((band) => {
      const kicker = band.page ? "PAGE LOAD" : "BEFORE THE FIRST PAGE LOAD";
      const place = band.page ? flowFit(`${hostOf(band.page.origin)}${band.page.path}`, right - 120) : "";
      const width = 16 + kicker.length * 6.6 + (place ? 8 + place.length * 7.2 : 0);
      return `<g class="service-map-flow-phase-title"><rect x="18" y="${band.y + 6}" width="${width}" height="20" rx="4"></rect>`
        + `<text x="26" y="${band.y + 16}" dominant-baseline="central"><tspan class="service-map-flow-kicker">${kicker}</tspan>${place ? `<tspan class="service-map-flow-place" dx="8">${escape(place)}</tspan>` : ""}</text></g>`;
    });
    const arrows = layout.arrows.map(({ x, y, top, step, redirect, at }) => {
      const label = redirect ? flowRedirectLabel(step) : flowStepLabel(step);
      const labelY = y - 15, parts = [];
      let cursor = FLOW.clientX + 12;
      const pill = (text, kind) => { const made = flowPill(cursor, labelY, text, kind); parts.push(made.markup); cursor += made.width + 6; };
      const words = (text, room) => {
        const fitted = flowFit(text, room);
        parts.push(`<text class="service-map-flow-path" x="${cursor}" y="${labelY}" dominant-baseline="central">${escape(fitted)}</text>`);
        cursor += fitted.length * 7.2 + 8;
      };
      if (redirect) {
        pill(String(step.status ?? "3xx"), flowStatusClass(step.status));
        words(`to ${hostOf(step.redirect.origin)}${step.redirect.path}`, right - cursor);
      } else {
        const method = step.method.toUpperCase();
        pill(method, FLOW_METHODS.has(method) ? ` method-${method.toLowerCase()}` : "");
        const after = (step.count > 1 ? 20 + String(step.count).length * 7 : 0) + (step.status == null ? 0 : 41);
        words(step.path, right - cursor - after);
        if (step.count > 1) pill(`×${step.count}`, " count");
        if (step.status != null) pill(String(step.status), flowStatusClass(step.status));
      }
      // A request runs from the client to its origin; a redirect back again.
      const [from, to, back] = redirect ? [x, FLOW.clientX, 1] : [FLOW.clientX, x, -1];
      const head = `M${to + back * 9},${y - 5} L${to},${y} L${to + back * 9},${y + 5} Z`;
      return `<g class="service-map-flow-step kind-${step.kind}${redirect ? " redirect" : ""}" data-service-flow-record="${escape(step.recordId)}" role="button" tabindex="0">`
        + `<title>${escape(`${label} · ${step.origin}${step.path} · open in HTTP history`)}</title>`
        + `<rect class="service-map-flow-row" x="14" y="${top + 2}" width="${layout.width - 28}" height="${FLOW.step - 4}" rx="6"></rect>`
        + (at == null ? "" : `<text class="service-map-flow-time" x="${FLOW.gutter}" y="${y}" text-anchor="end" dominant-baseline="central">${flowTime(at)}</text>`)
        + `${parts.join("")}<line x1="${from}" y1="${y}" x2="${to + back * 8}" y2="${y}"></line><path class="service-map-flow-head" d="${head}"></path></g>`;
    });
    return `<svg class="service-map-flow" width="${layout.width}" height="${layout.height}" viewBox="0 0 ${layout.width} ${layout.height}" role="group" aria-label="Requests in time order">`
      + `${cards.join("")}${lifelines.join("")}${titles.join("")}${arrows.join("")}${heads}</svg>`;
  }

  // How far the flow's top has scrolled above the viewport's, in flow units:
  // where its lane headers go to stay in view.
  function flowHeadsOffset(viewportTop, flowTop, scale) {
    return Math.max(0, (viewportTop - flowTop) / (scale || 1));
  }

  // Mermaid entity codes preserve label text without introducing markup or
  // ending a message. Line separators stay on the same statement.
  function flowMermaid(flow, hiddenKinds = []) {
    const hidden = new Set(hiddenKinds);
    const ids = new Map(flow.lanes.map((origin, index) => [origin, `O${index}`]));
    const text = (value) => String(value).replace(/[\r\n\u2028\u2029]/g, " ").replace(/[&<>;#]/g, (character) => `#${character.charCodeAt(0)};`);
    const shown = flow.phases.flatMap((phase) => phase.steps).filter((step) => !hidden.has(step.kind));
    // A copied diagram must not turn a bounded or filtered view into apparent
    // full coverage. Keep exact bounds in the source, and truncation visible.
    const provenance = { origin: flow.origin, considered_rows: flow.consideredRows, flow_rows: flow.flowRows, complete: flow.complete,
      stopped_by: flow.stoppedBy, hidden_request_kinds: [...hidden], shown_steps: shown.length, shown_rows: shown.reduce((sum, step) => sum + step.count, 0) };
    const metadata = JSON.stringify(provenance).replace(/[&<>\u2028\u2029]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
    const lines = ["sequenceDiagram", `  %% Sniper Flow: ${metadata}`, "  participant C as Client", ...flow.lanes.map((origin) => `  participant ${ids.get(origin)} as ${text(hostOf(origin))}`)];
    const last = ids.get(flow.lanes.at(-1));
    const span = last ? `C,${last}` : "C";
    if (!flow.complete || flow.stoppedBy.length) {
      const reasons = flow.stoppedBy.map((reason) => FLOW_STOPS[reason] || reason).join(" · ");
      lines.push(`  Note over ${span}: ${text(`Partial flow${reasons ? `: ${reasons}` : ""}`)}`);
    }
    for (const phase of flow.phases) {
      const steps = phase.steps.filter((step) => !hidden.has(step.kind));
      if (!steps.length) continue;
      lines.push(`  Note over ${span}: ${text(flowPageLabel(phase))}`);
      for (const step of steps) {
        lines.push(`  C->>${ids.get(step.origin)}: ${text(flowStepLabel(step))}`);
        if (step.redirect) lines.push(`  ${ids.get(step.origin)}-->>C: ${text(flowRedirectLabel(step))}`);
      }
    }
    return `${lines.join("\n")}\n`;
  }

  function graphLayout(origins, order, previousSlots = new Map(), anchor = null, bodyEdges = [], geometry = GRAPH_GEOMETRY, hiddenKinds = [], clientCards = 0) {
    const byOrigin = new Map(origins.map((origin) => [origin.origin, origin]));
    const visibleOrigins = order.filter((id) => byOrigin.has(id)).slice(0, MAX_CARDS + clientCards).map((id) => byOrigin.get(id));
    const visibleIds = new Set(visibleOrigins.map((origin) => origin.origin));
    const hidden = new Set(hiddenKinds);
    // An Origin/Referer link is drawn for the kinds of request it stood for
    // that are not hidden, weighted by their rows and coloured by the first of
    // them in REQUEST_KINDS order: one API call among a CDN's image loads still
    // reads as an API link, however many images there are.
    const headerEdge = (origin, link) => {
      const kinds = linkKindCounts(link).filter(([kind]) => !hidden.has(kind));
      if (!kinds.length) return [];
      return [{ source: link.source_origin, target: origin.origin, relationship: link.relationship, label: LINK_LABELS[link.relationship] || "Referer header",
        kind: kinds[0][0], kinds: Object.fromEntries(kinds), count: kinds.reduce((sum, [, rows]) => sum + rows, 0), cors: linkCors(link) }];
    };
    // Origin and Referer from one source make one arrow that counts requests: a
    // row naming the source in both is one request in the server's
    // header_sources. An older server sends no such count; each header then
    // keeps its own.
    const headerEdges = (origin) => {
      const bySource = new Map();
      for (const link of origin.header_links) bySource.set(link.source_origin, [...(bySource.get(link.source_origin) || []), link]);
      return [...bySource].flatMap(([source, links]) => {
        const rows = (origin.header_sources || []).find((item) => item.source_origin === source);
        if (!rows || links.length < 2) return links.flatMap((link) => headerEdge(origin, link));
        return headerEdge(origin, { ...rows, relationship: links[0].relationship }).map((edge) => ({ ...edge,
          relationships: links.map((link) => link.relationship), labels: links.map((link) => LINK_LABELS[link.relationship] || "Referer header") }));
      });
    };
    // The explicit overlay gets the first arrow slots. Metadata remains distinct
    // even when the same pair also occurs in a retained response body.
    const declaredEdges = [...bodyEdges.map((edge) => ({ ...edge, inspected: true })), ...visibleOrigins.flatMap((origin) => [
      ...origin.redirects.map((redirect) => ({ source: origin.origin, target: redirect.target_origin, relationship: "redirect_instruction", label: "Redirect instruction", kind: "redirect", count: Math.max(1, count(redirect.request_count)) })),
      ...headerEdges(origin),
    ])];
    const seen = new Map();
    const shown = [];
    let edgeCount = 0;
    for (const edge of declaredEdges) {
      // The overview draws one arrow per direction: whatever one card has to
      // another (a redirect, Origin and Referer, an inspection) shares it, drawn
      // as the first of them, its title naming them all. Direct relations does
      // the same for what the metadata says, so a page that called its API
      // through redirects, Origin and Referer is one arrow, not three; only an
      // inspection the operator ran keeps each type's own arrow there, the typed
      // view it is for. Redirects to several paths of one origin share an arrow
      // and their rows, as do the links of one site's origins; inspected body and
      // Link references count no rows.
      const key = JSON.stringify(!anchor ? [edge.source, edge.target]
        : edge.inspected ? [edge.source, edge.target, edge.relationship] : [edge.source, edge.target, "metadata"]);
      if (edge.source === edge.target || !visibleIds.has(edge.source) || !visibleIds.has(edge.target)
        || anchor && edge.source !== anchor && edge.target !== anchor) continue;
      if (seen.has(key)) {
        const drawn = seen.get(key), labels = edge.labels || [edge.label];
        (edge.relationships || [edge.relationship]).forEach((relationship, index) => {
          if (!drawn.relationships.includes(relationship)) { drawn.relationships.push(relationship); drawn.labels.push(labels[index]); }
        });
        if (edge.layers) drawn.layers = [...new Set([...(drawn.layers || []), ...edge.layers])];
        if (edge.count) drawn.count = (drawn.count || 0) + edge.count;
        if (edge.kinds) {
          drawn.kinds = { ...drawn.kinds };
          for (const [kind, rows] of Object.entries(edge.kinds)) drawn.kinds[kind] = (drawn.kinds[kind] || 0) + rows;
          drawn.kind = REQUEST_KINDS.find((kind) => drawn.kinds[kind]);
        }
        if (edge.cors) drawn.cors = drawn.cors ? drawn.cors.map((value, index) => value + edge.cors[index]) : [...edge.cors];
        continue;
      }
      const drawn = { ...edge, relationships: [...(edge.relationships || [edge.relationship])], labels: [...(edge.labels || [edge.label])] };
      seen.set(key, drawn);
      edgeCount += 1;
      if (shown.length < MAX_EDGES) shown.push(drawn);
    }
    // Cards are placed by the arrows actually drawn, so a card whose links all
    // fall past the arrow cap is not laid out among linked cards with no arrow.
    // Clients are not: they keep the first column, whichever is selected.
    const clientIds = visibleOrigins.filter((origin) => origin.client).map((origin) => origin.origin);
    const connections = shown.filter((edge) => !clientIds.includes(edge.source)).map((edge) => [edge.source, edge.target]);
    let preferred;
    if (anchor && bodyEdges.length) {
      // A pinned direct neighborhood is a star. Keep every neighbor
      // opposite the source so mixed incoming/outgoing declarations cannot
      // become same-column loops. The source sits level with the middle of its
      // neighbors, as a layered hub does, so the star opens both ways.
      const neighbors = visibleOrigins.filter((origin) => origin.origin !== anchor);
      preferred = new Map([[anchor, { column: 0, row: Math.floor(Math.max(0, neighbors.length - 1) / 2) }], ...neighbors.map((origin, row) => [origin.origin, { column: 1, row }])]);
    } else {
      preferred = layeredSlots(visibleOrigins.filter((origin) => !origin.client), connections);
      if (clientIds.length) {
        // The column sits level with the middle of the graph, not above it, so
        // it reads as where the traffic came from however tall the map grows.
        const rows = Math.max(0, ...[...preferred.values()].map((slot) => slot.row)) + 1;
        const top = Math.max(0, Math.floor((rows - clientIds.length) / 2));
        preferred = new Map([...clientIds.map((id, row) => [id, { column: 0, row: top + row }]),
          ...[...preferred].map(([id, slot]) => [id, { ...slot, column: slot.column + 1 }])]);
      }
    }
    const slots = new Map(visibleOrigins.filter((origin) => previousSlots.has(origin.origin)).map((origin) => [origin.origin, previousSlots.get(origin.origin)]));
    for (const origin of visibleOrigins) {
      if (slots.has(origin.origin)) continue;
      const column = preferred.get(origin.origin).column;
      let row = previousSlots.size ? 0 : preferred.get(origin.origin).row;
      while ([...slots.values()].some((slot) => slot.column === column && slot.row === row)) row += 1;
      slots.set(origin.origin, { column, row });
    }
    const width = geometry.padding * 2 + Math.max(1, ...[...slots.values()].map((slot) => slot.column)) * geometry.columnPitch + geometry.cardWidth;
    const visible = visibleOrigins.map((origin) => ({ ...origin, x: geometry.padding + slots.get(origin.origin).column * geometry.columnPitch, y: geometry.padding + slots.get(origin.origin).row * geometry.rowPitch }));
    const positions = new Map(visible.map((origin) => [origin.origin, origin]));
    const gap = geometry.columnPitch - geometry.cardWidth;
    const rowGap = geometry.rowPitch - geometry.cardHeight;
    const lastRow = Math.max(0, ...[...slots.values()].map((slot) => slot.row));
    // Arrows between neighbouring columns cross one gap. Bent at its middle, their
    // vertical runs fused into a single band that no arrow could be followed
    // through. Each gets its own track instead, the longest nearest its source, so
    // a fan opens out without crossing itself.
    const turns = new Map();
    const tracks = new Map();
    for (const edge of shown) {
      const source = positions.get(edge.source), target = positions.get(edge.target);
      if (Math.abs(target.x - source.x) !== geometry.columnPitch || source.y === target.y) continue;
      const key = Math.min(source.x, target.x);
      if (!tracks.has(key)) tracks.set(key, []);
      tracks.get(key).push(edge);
    }
    for (const group of tracks.values()) {
      const span = (edge) => Math.abs(positions.get(edge.target).y - positions.get(edge.source).y);
      group.sort((a, b) => span(b) - span(a));
      group.forEach((edge, index) => turns.set(edge, group.length > 1 ? 0.25 + 0.5 * index / (group.length - 1) : 0.5));
    }
    const pairCounts = new Map();
    const laneCounts = new Map();
    const edges = shown.map((edge) => {
      const source = positions.get(edge.source);
      const target = positions.get(edge.target);
      const pair = JSON.stringify([edge.source, edge.target].sort());
      const pairIndex = pairCounts.get(pair) || 0;
      pairCounts.set(pair, pairIndex + 1);
      // Ten typed/reverse metadata + Link arrows can share a pair. Keep
      // distinct attachment lanes inside the card with marker clearance.
      const lane = (geometry.cardHeight - 24) / 10;
      const offset = [0, -1, 1, -2, 2, -3, 3, -4, 4, -5][Math.min(pairIndex, 9)] * lane;
      const toRight = target.x > source.x;
      const sameColumn = target.x === source.x;
      const x1 = source.x + (sameColumn ? geometry.cardWidth : toRight ? geometry.cardWidth : 0);
      const x2 = target.x + (sameColumn ? geometry.cardWidth : toRight ? 0 : geometry.cardWidth);
      const y1 = source.y + geometry.cardHeight / 2 + offset;
      const y2 = target.y + geometry.cardHeight / 2 + offset;
      if (Math.abs(target.x - source.x) > geometry.columnPitch) {
        // An arrow that skips a column runs along the gap between two rows, so it
        // never passes behind a card it does not join. Drawn straight, a sign-in
        // chain's return redirect ran through both middle cards, under the
        // forward arrows, and seemed to start at the card next to its target.
        const step = toRight ? gap : -gap;
        const row = Math.min(lastRow + 1, Math.max(1, Math.round(((y1 + y2) / 2 - geometry.padding + rowGap / 2) / geometry.rowPitch)));
        const used = laneCounts.get(row) || 0;
        laneCounts.set(row, used + 1);
        const laneY = geometry.padding + row * geometry.rowPitch - rowGap / 2 + [0, -4, 4, -8, 8][used % 5];
        const xa = x1 + step, xb = x2 - step;
        return { ...edge, path: `M ${x1} ${y1} C ${(x1 + xa) / 2} ${y1}, ${(x1 + xa) / 2} ${laneY}, ${xa} ${laneY} L ${xb} ${laneY} C ${(xb + x2) / 2} ${laneY}, ${(xb + x2) / 2} ${y2}, ${x2} ${y2}` };
      }
      // Keep right-column loops inside the SVG, with room for stroke and markers.
      // Attachment offsets still distinguish typed links without widening cards.
      const bend = sameColumn ? Math.min(x1 + geometry.padding + Math.abs(offset), width - geometry.loopInset) : x1 + (x2 - x1) * (turns.get(edge) ?? 0.5);
      return { ...edge, path: `M ${x1} ${y1} C ${bend} ${y1}, ${bend} ${y2}, ${x2} ${y2}` };
    });
    return { nodes: visible, edges, edgeCount, slots, geometry, width, height: Math.max(geometry.padding * 2 + geometry.cardHeight, ...visible.map((origin) => origin.y + geometry.cardHeight + geometry.padding)) };
  }

  function peerGraphLayout(origins, sourceOrigin, geometry = GRAPH_GEOMETRY) {
    // This visualization contains observations only. No metadata or domain-to-
    // domain arrows are carried over from the normal service map.
    const ordered = [...origins.filter((item) => item.origin === sourceOrigin), ...origins.filter((item) => item.origin !== sourceOrigin)].slice(0, MAX_CARDS - 1);
    const width = geometry.padding * 2 + geometry.columnPitch + geometry.cardWidth;
    const endpoint = { origin: PEER_NODE_ID, endpointNode: true, x: geometry.padding, y: geometry.padding };
    const nodes = [endpoint, ...ordered.map((item, index) => ({ ...item, x: geometry.padding + geometry.columnPitch, y: geometry.padding + index * geometry.rowPitch }))];
    const x1 = endpoint.x + geometry.cardWidth, y1 = endpoint.y + geometry.cardHeight / 2;
    const edges = nodes.slice(1, MAX_EDGES + 1).map((item) => ({ source: item.origin, target: PEER_NODE_ID, relationship: "recorded_peer_observation", label: "Recorded address observation", undirected: true,
      path: `M ${x1} ${y1} C ${(x1 + item.x) / 2} ${y1}, ${(x1 + item.x) / 2} ${item.y + geometry.cardHeight / 2}, ${item.x} ${item.y + geometry.cardHeight / 2}` }));
    return { nodes, edges, edgeCount: ordered.length, slots: new Map(), geometry, width,
      height: Math.max(geometry.padding * 2 + geometry.cardHeight, ...nodes.map((item) => item.y + geometry.cardHeight + geometry.padding)) };
  }
  function* metadataRelations(origins) {
    for (const origin of origins) {
      for (const link of origin.header_links) yield {
        sourceOrigin: link.source_origin, targetOrigin: origin.origin, capturedOrigin: origin.origin,
        relationship: link.relationship, label: `${link.relationship === "origin_header" ? "Origin" : "Referer"} header declaration`, evidence: link.evidence[0] || "",
      };
      for (const redirect of origin.redirects) yield {
        sourceOrigin: origin.origin, targetOrigin: redirect.target_origin, targetPath: redirect.target_path, capturedOrigin: origin.origin,
        relationship: "redirect_instruction", label: "Redirect instruction", evidence: redirect.evidence[0] || "",
      };
    }
  }
  const referenceOrigin = (id) => ({ origin: id, captured: false, in_scope: false, endpoints: [], technology_clues: [], technology_observations: [], technology_observations_present: false, redirects: [], header_links: [], references: [], referencesOmitted: 0 });
  function createController({ elements: els, getSessionId, getEventStreamReady = () => true, getFilterQuery = () => ({}), getFilterSummary = () => null, getHiddenLinkKinds = null, setHiddenLinkKinds = null, getSiteDisplay = null, setSiteDisplay = null, request: sendRequest, packetViewerMarkup = null, mountPacketViewer = null, copyText = null, sendToReplay = null, openInHistory = null, openUrl = null, onApiDocsOpen = null, isActiveModal = () => true, restoreFocus = null, document: doc = root.document }) {
    // Request kinds whose links are not drawn. The app keeps them in UI
    // settings; without it they live for this controller only.
    let localHiddenLinkKinds = [...DEFAULT_HIDDEN_LINK_KINDS];
    const hiddenLinkKinds = () => array(getHiddenLinkKinds ? getHiddenLinkKinds() : localHiddenLinkKinds).filter((kind) => REQUEST_KINDS.includes(kind));
    const saveHiddenLinkKinds = (kinds) => { if (setHiddenLinkKinds) setHiddenLinkKinds(kinds); else localHiddenLinkKinds = kinds; };
    // How the map groups sites and which origins or sites it hides; the app
    // keeps this in UI settings, shared by every session.
    let localSiteDisplay = { groupSites: true, expandedSites: [], hidden: [] };
    const siteDisplay = () => {
      const value = getSiteDisplay ? getSiteDisplay() : localSiteDisplay;
      return { groupSites: value?.groupSites !== false, expandedSites: array(value?.expandedSites), hidden: array(value?.hidden) };
    };
    const saveSiteDisplay = (changes) => {
      const next = { ...siteDisplay(), ...changes };
      if (setSiteDisplay) setSiteDisplay(next); else localSiteDisplay = next;
      render();
    };
    // A local retained-data read must not turn an API redirect into another
    // request. Enforce this for every map/inspector read, preserving its signal.
    const request = (path, options) => sendRequest(path, { ...options, redirect: "error" });
    const productFilterContainer = els.productFilters || els.panel.querySelector?.("#serviceMapProductFilters");
    const productFilterDisclosure = productFilterContainer?.parentElement;
    let packetAbort = null, packetViewer = null, packetViewerElement = null;
    const state = {
      sessionId: null, snapshot: null, order: [], selectedOrigin: null, selectedClient: null, selectedSite: null, selectionInitialized: false,
      query: "", scopeOnly: false, view: "service-map", detailTab: "apis", endpointIndex: null, endpointSelection: null,
      endpointMethod: "", endpointPath: "", productId: "", productVersion: "", pageAnchor: null, detailPageAnchor: null,
      expandedEndpointGroups: new Set(), loading: false, backgroundLoading: false, error: "", refreshPaused: false, requestId: 0, evidenceRequestId: 0, evidence: null,
      packet: null, packetVariant: "current", packetOriginals: null, packetLoading: false, packetError: "", packetRequestId: 0, packetInspection: "",
      evidenceLoading: false, evidenceError: "", evidenceId: null, evidenceCatalogVersion: null, evidenceLegacyCatalog: false, socketPeer: null, page: 0, detailPage: 0,
      peerMatches: null, peerMatchesSource: null, peerMatchesLoading: false, peerMatchesError: "", peerMatchesRequestId: 0, peerEvidenceBinding: null,
      bodyReferences: null, bodyReferencesLoading: false, bodyReferencesError: "", bodyReferencesRequestId: 0,
      bodyReferencesSource: null, relationLayers: Object.freeze([]), bodyOverlayNotice: "", apiDocs: null, apiDocsRequestId: 0,
      relationshipKind: "body", linkDeclarations: null, linkDeclarationsSource: null, linkDeclarationsError: "",
      parameters: null, parametersKey: null, parametersLoading: false, parametersError: "", parametersRequestId: 0, busyRetries: 0,
      htmlGenerators: null, htmlGeneratorsLoading: false, htmlGeneratorsError: "", htmlGeneratorsRequestId: 0, htmlGeneratorsSource: null,
      inactiveSessionId: null, historyVersion: 0, stale: false, anchorOrigin: null, modeNotice: "", zoomScale: 1,
      flowOrigin: null, flow: null, flowLoading: false, flowError: "", flowRequestId: 0,
    };
    Object.defineProperty(state, "bodyReferenceOverlay", { get: () => state.relationLayers.at(-1) || null });
    let abort = null;
    let flowAbort = null;
    let flowBinding = null;
    let evidenceAbort = null;
    let bodyReferencesAbort = null;
    let peerMatchesAbort = null;
    let htmlGeneratorsAbort = null;
    let parametersAbort = null;
    // Both exports target the same clipboard. Latest intent wins even when
    // that write fails; an older fallback must not revive afterward.
    let copyActionId = 0;
    let flowCopyKindsVersion = 0;
    let flowCopyKindsSignature = JSON.stringify(hiddenLinkKinds());
    let replayActionId = 0;
    let apiDocsReturnFocus = null;
    let detailRender = null;
    const renderedMarkup = new WeakMap();
    let visible = false;
    let destroyed = false;
    let pageHidden = false;
    let refreshTimer = null;
    let historyPresentationPending = false;
    const eventDisposers = [];
    function listen(element, type, handler, options) {
      const owned = (...args) => { if (!destroyed) return handler(...args); };
      element?.addEventListener?.(type, owned, options);
      eventDisposers.push(() => element?.removeEventListener?.(type, owned, options));
    }
    function closeProductFilters(returnFocus = false) {
      if (!productFilterDisclosure?.open) return false;
      const restore = returnFocus && productFilterDisclosure.contains(doc?.activeElement);
      productFilterDisclosure.open = false;
      if (restore) productFilterDisclosure.querySelector("summary")?.focus({ preventScroll: true });
      return true;
    }
    if (productFilterDisclosure) {
      listen(doc, "pointerdown", (event) => {
        if (visible && !productFilterDisclosure.contains(event.target)) closeProductFilters();
      }, true);
      listen(doc, "keydown", (event) => {
        if (!visible || event.key !== "Escape" || event.defaultPrevented || event.isComposing) return;
        if (closeProductFilters(true)) event.preventDefault();
      });
    }
    const canRefresh = () => visible && !destroyed && !pageHidden && doc?.hidden !== true;
    function clearRefreshTimer() {
      if (refreshTimer !== null) root.clearTimeout?.(refreshTimer);
      refreshTimer = null;
    }
    function scheduleAutomaticRefresh() {
      if (refreshTimer !== null || !canRefresh() || state.loading || state.refreshPaused || !getSessionId() || !root.setTimeout) return;
      // Start the delay after completion, so a slow map never accumulates polls.
      refreshTimer = root.setTimeout(() => {
        refreshTimer = null;
        refresh();
      }, AUTO_REFRESH_MS);
    }
    function suspendRefresh() {
      copyActionId += 1;
      clearRefreshTimer();
      state.requestId += 1;
      abort?.abort();
      abort = null;
      state.loading = false;
      state.backgroundLoading = false;
      cancelFlow();
    }
    function onVisibilityChange() {
      if (!canRefresh()) suspendRefresh();
      else {
        if (historyPresentationPending) render();
        else renderStatus();
        historyPresentationPending = false;
        resumeFlow();
        scheduleAutomaticRefresh();
      }
    }
    function onPageHide() { pageHidden = true; suspendRefresh(); }
    function onPageShow() { pageHidden = false; onVisibilityChange(); }
    function renderHistoryChange(graphChanged) {
      if (!canRefresh()) { historyPresentationPending = true; return; }
      // A history event changes freshness and inspection ownership, not the
      // loaded graph. Do not lay it out per captured/retained row.
      if (graphChanged) render();
      else { renderStatus(); renderDetail(); renderOverlayStatus(); }
    }
    doc?.addEventListener?.("visibilitychange", onVisibilityChange);
    root.addEventListener?.("pagehide", onPageHide);
    root.addEventListener?.("pageshow", onPageShow);
    let currentLayout = null;
    function viewportSize() {
      return { width: Number(els.viewport?.clientWidth) || 0, height: Number(els.viewport?.clientHeight) || 0 };
    }
    function zoomAvailable() {
      const size = viewportSize();
      return visible && state.view === "service-map" && !!currentLayout?.nodes.length && size.width > 0 && size.height > 0;
    }
    function updateZoomControls() {
      const available = zoomAvailable();
      els.zoomControls?.classList.toggle("hidden", state.view === "apis");
      if (els.zoomOut) els.zoomOut.disabled = !available || state.zoomScale <= ZOOM_LIMITS.min;
      if (els.zoomIn) els.zoomIn.disabled = !available || state.zoomScale >= ZOOM_LIMITS.max;
      if (els.zoomReset) {
        els.zoomReset.disabled = !available;
        els.zoomReset.textContent = `${Math.round(state.zoomScale * 100)}%`;
        els.zoomReset.setAttribute("aria-label", `Zoom ${Math.round(state.zoomScale * 100)}%. Fit the map, or back to 100% once fitted`);
      }
    }
    function applyGraphScale() {
      // Mutating the canvas variables leaves card DOM, focus, inspector and
      // in-flight exact-source reads untouched, including during polling.
      if (currentLayout && els.canvas.style) {
        els.canvas.style.setProperty("--service-map-scale", String(state.zoomScale));
        els.canvas.style.setProperty("--service-map-scaled-width", `${currentLayout.width * state.zoomScale}px`);
        els.canvas.style.setProperty("--service-map-scaled-height", `${currentLayout.height * state.zoomScale}px`);
      }
      updateZoomControls();
      pinFlowHeads();
    }
    // An SVG holds no sticky element, so a flow's lane headers follow the
    // scroll instead.
    function pinFlowHeads() {
      const heads = els.canvas?.querySelector?.(".service-map-flow-heads");
      const flow = heads?.ownerSVGElement;
      if (!flow || !els.viewport?.getBoundingClientRect) return;
      const offset = flowHeadsOffset(els.viewport.getBoundingClientRect().top, flow.getBoundingClientRect().top, state.zoomScale);
      heads.setAttribute("transform", `translate(0 ${offset})`);
    }
    // `anchor` is a point in the viewport, such as the fingers of a pinch, that
    // stays over the same part of the graph; without one it is the center.
    function setZoom(value, { fit = false, anchor = null } = {}) {
      if (!zoomAvailable() || !Number.isFinite(value)) return false;
      const viewport = els.viewport, size = viewportSize();
      const previous = state.zoomScale;
      const next = Math.max(ZOOM_LIMITS.min, Math.min(ZOOM_LIMITS.max, (fit ? Math.floor(value * 10000) : Math.round(value * 10000)) / 10000));
      const anchorX = Number.isFinite(anchor?.x) ? Math.max(0, Math.min(size.width, anchor.x)) : size.width / 2;
      const anchorY = Number.isFinite(anchor?.y) ? Math.max(0, Math.min(size.height, anchor.y)) : size.height / 2;
      // The canvas centers a small graph. Include that inset when preserving
      // the point under the anchor across either scrollbar boundary.
      const pointX = (viewport.scrollLeft + anchorX - Math.max(0, (size.width - currentLayout.width * previous) / 2)) / previous;
      const pointY = (viewport.scrollTop + anchorY - Math.max(0, (size.height - currentLayout.height * previous) / 2)) / previous;
      state.zoomScale = next;
      applyGraphScale();
      const scaledWidth = currentLayout.width * next, scaledHeight = currentLayout.height * next;
      const nextSize = viewportSize();
      viewport.scrollLeft = fit ? 0 : Math.max(0, Math.min(scaledWidth - nextSize.width, pointX * next + Math.max(0, (nextSize.width - scaledWidth) / 2) - anchorX));
      viewport.scrollTop = fit ? 0 : Math.max(0, Math.min(scaledHeight - nextSize.height, pointY * next + Math.max(0, (nextSize.height - scaledHeight) / 2) - anchorY));
      return true;
    }
    function fitGraph() {
      if (!zoomAvailable()) return false;
      const size = viewportSize();
      return setZoom(Math.min(1, size.width / currentLayout.width, size.height / currentLayout.height), { fit: true });
    }
    // The zoom percentage is the map's one fit control, where a Fit button
    // stood beside it: it fits the map, and once fitted, returns to 100%. F and
    // 0 do each from the keyboard.
    function fitOrReset() {
      if (!zoomAvailable()) return false;
      const size = viewportSize();
      const fitted = Math.max(ZOOM_LIMITS.min, Math.floor(Math.min(1, size.width / currentLayout.width, size.height / currentLayout.height) * 10000) / 10000);
      return state.zoomScale === fitted ? setZoom(1) : fitGraph();
    }
    function replace(element, html, force = false) {
      if (!element) return;
      // Compare our last output, not browser serialization: boolean attributes
      // and native control/disclosure state can change innerHTML without a new
      // render. Replacing an unchanged select dismisses its native popup.
      const previous = renderedMarkup.get(element);
      if (!force && previous?.sessionId === state.sessionId && previous.html === html) return;
      const focused = doc?.activeElement;
      const key = focused?.dataset?.serviceFocus;
      const owned = key && element.contains(focused);
      const caret = owned && focused.dataset.serviceEndpointFilter === "path"
        ? [focused.selectionStart, focused.selectionEnd, focused.selectionDirection] : null;
      element.innerHTML = html;
      renderedMarkup.set(element, { sessionId: state.sessionId, html });
      // Only restore the element that this replacement detached. A newly focused
      // dialog or control is never displaced by a background refresh.
      if (owned && visible && (!doc.activeElement || doc.activeElement === doc.body || doc.activeElement === focused && !focused.isConnected)
        && !doc.querySelector?.(".modal-backdrop:not(.hidden), dialog[open]")) {
        const next = [...element.querySelectorAll("[data-service-focus]")].find((candidate) => candidate.dataset.serviceFocus === key);
        if (next && !next.disabled && next.getClientRects().length) {
          next.focus({ preventScroll: true });
          if (caret && typeof caret[0] === "number") next.setSelectionRange?.(...caret);
        }
      }
    }
    function graphOrigins() {
      if (state.graphSnapshot === state.snapshot && state.graphLayers === state.relationLayers) return state.graphOriginsCache || [];
      const captured = state.snapshot?.origins || [];
      let referenceCards = 0;
      state.omittedGraphReferences = 0;
      state.relationsByOrigin = new Map();
      const origins = new Map(captured.map((origin) => [origin.origin, origin]));
      const reference = (id, source, label, inspected = false) => {
        if (!origins.has(id)) {
          if (!inspected && referenceCards >= MAX_REFERENCE_CARDS) { state.omittedGraphReferences += 1; return; }
          if (!inspected) referenceCards += 1;
          origins.set(id, referenceOrigin(id));
        }
        const item = origins.get(id);
        if (!item.captured && !item.references.some((ref) => ref.origin === source.origin && ref.label === label)) {
          if (item.references.length >= MAX_REFERENCE_SOURCES) item.referencesOmitted += 1;
          else item.references.push({ origin: source.origin, label });
        }
      };
      const relation = (item) => {
        for (const id of new Set([item.sourceOrigin, item.targetOrigin])) {
          if (!origins.has(id)) continue;
          if (!state.relationsByOrigin.has(id)) state.relationsByOrigin.set(id, { items: [], omitted: 0 });
          const group = state.relationsByOrigin.get(id);
          if (group.items.length < MAX_REFERENCE_SOURCES) group.items.push(item);
          else group.omitted += 1;
        }
      };
      captured.forEach((origin) => {
        origin.header_links.forEach((link) => {
          // A page calling its own origin names it in Origin/Referer. That is
          // not a relationship to another service, and listing it showed
          // "a → a" rows in the inspector; arrows already skip it.
          if (link.source_origin === origin.origin) return;
          reference(link.source_origin, origin, `${link.relationship === "origin_header" ? "Origin" : "Referer"} header on`);
          relation({ sourceOrigin: link.source_origin, targetOrigin: origin.origin, capturedOrigin: origin.origin, relationship: link.relationship, label: `${link.relationship === "origin_header" ? "Origin" : "Referer"} header declaration`, evidence: link.evidence[0] || "", kinds: linkKindCounts(link), cors: linkCors(link) });
        });
        origin.redirects.forEach((redirect) => {
          reference(redirect.target_origin, origin, "Redirect instruction from");
          relation({ sourceOrigin: origin.origin, targetOrigin: redirect.target_origin, targetPath: redirect.target_path, capturedOrigin: origin.origin, relationship: "redirect_instruction", label: "Redirect instruction", evidence: redirect.evidence[0] || "" });
        });
      });
      for (const layer of state.relationLayers) {
        if (layer.kind === "peer") {
          for (const peerOrigin of peerOverlayOrigins(layer)) {
            const existing = origins.get(peerOrigin.origin);
            if (existing?.captured && !existing.peerInspectionOnly) continue;
            origins.set(peerOrigin.origin, peerOrigin);
          }
          const node = peerAddressNode(layer);
          const previous = origins.get(node.origin);
          if (previous?.endpointNode) node.observedOrigins = [...new Set([...previous.observedOrigins, ...node.observedOrigins])];
          origins.set(node.origin, node);
        } else {
          for (const item of layerReferences(layer)) reference(item.target_origin, layer.source,
            layer.kind === "link" ? "Retained Link declaration from" : "Literal body URL reference from", true);
        }
      }
      for (const layer of state.relationLayers) {
        const source = origins.get(layer.source.origin);
        if (source) origins.set(source.origin, { ...source, inspectedSource: true });
      }
      state.graphLayers = state.relationLayers;
      state.graphSnapshot = state.snapshot;
      state.graphOriginsCache = [...origins.values()];
      return state.graphOriginsCache;
    }
    function originFilterStages(origins) {
      const query = state.query.trim().toLowerCase();
      const actual = origins.filter((origin) => !origin.endpointNode);
      const searchedOrigins = actual.filter((origin) => !query || origin.origin.toLowerCase().includes(query));
      const matchedOrigins = searchedOrigins.filter((origin) => productMatches(origin, state.productId, state.productVersion));
      const withAddresses = (items) => {
        const ids = new Set(items.map((item) => item.origin));
        if (state.anchorOrigin) ids.add(state.anchorOrigin);
        return [...items, ...origins.filter((item) => item.endpointNode && item.observedOrigins.some((id) => ids.has(id)))];
      };
      const searched = withAddresses(searchedOrigins), matching = withAddresses(matchedOrigins);
      return { loaded: origins, searched, matching, queryHidden: actual.length - searchedOrigins.length, productHidden: searchedOrigins.length - matchedOrigins.length };
    }
    function filteredOrigins() {
      return originFilterStages(graphOrigins().filter((origin) => !origin.endpointNode && (!state.scopeOnly || origin.in_scope || !origin.captured))).matching;
    }
    function setProductFilter(kind, value) {
      if (!["product", "version", "clear"].includes(kind)) return;
      if (kind === "clear") { state.productId = ""; state.productVersion = ""; }
      else if (kind === "product") {
        // Any product the list offers: front-end and server products as well as
        // the header catalog's. Choosing one of those used to change nothing.
        if (value && !(typeof value === "string" && /^[a-z0-9_]{1,40}$/.test(value))) return;
        state.productId = value || "";
      } else {
        // Versions as the map reports them, `3.6.0-rc1` included.
        if (value && !PRODUCT_VERSION_OPTIONS.some(([key]) => key === value)
          && !(typeof value === "string" && /^reported:[0-9][0-9A-Za-z.+-]{0,39}$/.test(value))) return;
        state.productVersion = value || "";
      }
      replayActionId += 1;
      // Product filters change membership, never source identity or pending
      // reads. Retain exact catalog anchors and the independent inspector page.
      if (state.snapshot) reconcileEndpointPages();
      render();
    }
    function renderProductFilters() {
      if (!productFilterContainer) return;
      const all = (state.snapshot?.origins || []).flatMap(reportedProducts);
      const products = new Map(all.map((product) => [product.id, product.name]));
      const selected = all.filter((product) => !state.productId || product.id === state.productId);
      const versions = new Set(selected.flatMap((product) => [...product.versions]));
      const options = new Map([["", "Any version/status"], ...PRODUCT_VERSION_OPTIONS,
        ...[...versions].sort().map((version) => [`reported:${version}`, `Reported: ${version}`])]);
      const unavailableProduct = !!state.productId && !products.has(state.productId);
      const unavailableVersion = !!state.productVersion && !(state.snapshot?.origins || []).some((origin) => productMatches(origin, state.productId, state.productVersion));
      if (state.productId) products.set(state.productId, products.get(state.productId) ?? TECHNOLOGY_CATALOG_V2.get(state.productId)?.[0] ?? state.productId);
      if (state.productVersion.startsWith("reported:") && !options.has(state.productVersion)) options.set(state.productVersion, `Reported: ${state.productVersion.slice(9)} (unavailable)`);
      replace(productFilterContainer, `<div class="service-map-product-filter-controls"><label>Product (exact)<select data-service-product-filter="product" data-service-focus="products:product" aria-describedby="serviceMapProductHelp"><option value="">All products</option>${[...products].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([id, name]) => `<option value="${escape(id)}" ${state.productId === id ? "selected" : ""}>${escape(name)}${unavailableProduct && state.productId === id ? " (unavailable)" : ""}</option>`).join("")}</select></label><label>Version/status (exact)<select data-service-product-filter="version" data-service-focus="products:version" title="${escape(options.get(state.productVersion))}" aria-describedby="serviceMapProductHelp">${[...options].map(([id, name]) => `<option value="${escape(id)}" ${state.productVersion === id ? "selected" : ""}>${escape(name)}</option>`).join("")}</select></label><button class="secondary-action" type="button" data-service-product-filter-clear="true" data-service-focus="products:clear" ${!state.productId && !state.productVersion ? "disabled" : ""}>Clear</button></div><p id="serviceMapProductHelp" class="service-map-muted">Loaded response-header declarations only. Product and version/status match the same product. Versions are literal and unverified. Options are independent of origin search.</p>${unavailableProduct || unavailableVersion ? '<p class="service-map-filter-notice" role="status">Selected product/version is unavailable in the loaded snapshot. Filters retained; zero matching origins.</p>' : ""}`);
      productFilterContainer.parentElement?.classList.toggle("has-filter", !!state.productId || !!state.productVersion);
      const summary = productFilterContainer.parentElement?.querySelector("summary");
      if (summary) summary.textContent = state.productId || state.productVersion ? "Products / versions · active" : "Products / versions";
    }
    function findOrigin(id) {
      if (!id) return null;
      const existing = graphOrigins().find((origin) => origin.origin === id);
      if (existing) return existing;
      if (state.extraOriginSnapshot === state.snapshot && state.extraOriginId === id && state.extraOriginOverlay === state.relationLayers) return state.extraOrigin;
      // A direct neighbor can be outside the All origins reference-card budget.
      // Its inspector still uses only loaded declarations and the usual pane caps.
      const item = referenceOrigin(id), group = { items: [], omitted: 0 }, seen = new Set();
      const bodyReference = overlayReferences().find((reference) => reference.target_origin === id);
      if (bodyReference) item.references.push({ origin: bodyReference.layer.source.origin, label: bodyReference.layer.kind === "link" ? "Retained Link declaration from" : "Literal body URL reference from" });
      for (const relation of metadataRelations(state.snapshot?.origins || [])) {
        if (relation.sourceOrigin !== id && relation.targetOrigin !== id) continue;
        if (group.items.length < MAX_REFERENCE_SOURCES) group.items.push(relation); else group.omitted += 1;
        const label = relation.relationship === "redirect_instruction" ? "Redirect instruction from" : `${relation.relationship === "origin_header" ? "Origin" : "Referer"} header on`;
        const key = JSON.stringify([relation.capturedOrigin, label]);
        if (seen.has(key)) continue;
        seen.add(key);
        if (item.references.length < MAX_REFERENCE_SOURCES) item.references.push({ origin: relation.capturedOrigin, label }); else item.referencesOmitted += 1;
      }
      state.extraOriginSnapshot = state.snapshot; state.extraOriginId = id;
      state.extraOriginOverlay = state.relationLayers;
      state.extraOrigin = group.items.length || bodyReference ? item : null;
      if (group.items.length) state.relationsByOrigin.set(id, group);
      return state.extraOrigin;
    }
    function selectedOrigin() {
      return findOrigin(state.selectedOrigin);
    }
    function siteDetails(site) {
      if (!site) return null;
      // A site's inspector, like an origin's, belongs to the loaded snapshot.
      // Searching can ungroup or hide its card without removing its members.
      const members = graphOrigins().filter((origin) => !origin.endpointNode && siteKey(origin.origin) === site);
      return members.length ? { site, members } : null;
    }
    const layerKey = (layer) => `${layer.kind}:${layer.source.evidenceId}`;
    const layerReferences = (layer) => layer.kind === "body" ? layer.scan.references : layer.kind === "link" ? layer.scan.observations : [];
    function overlayReferences() {
      return state.relationLayers.flatMap((layer) => layerReferences(layer).map((item) => ({ ...item, layer })));
    }
    function peerAddressNode(layer) {
      const { scan } = layer, peer = scan.peer;
      // One node per exact equality key. Multiple inspected windows share a
      // visual address, but their counts, samples and coverage stay separate.
      const id = `${PEER_NODE_ID}:${JSON.stringify([peer.source, peer.route, peer.address_family, peer.address.ip, peer.address.port])}`;
      const address = `${peer.address_family === "ipv6" ? `[${peer.address.ip}]` : peer.address.ip}:${peer.address.port}`;
      return { ...referenceOrigin(id), endpointNode: true, address, family: peer.address_family,
        observedOrigins: [...new Set([scan.source.origin, ...scan.origins.map((group) => group.origin)])] };
    }
    function overlayEdges() {
      const edges = new Map();
      const add = (edge, layer) => {
        const key = JSON.stringify([edge.source, edge.target, edge.relationship]);
        if (!edges.has(key)) edges.set(key, { ...edge, layers: [] });
        if (!edges.get(key).layers.includes(layerKey(layer))) edges.get(key).layers.push(layerKey(layer));
      };
      for (const layer of state.relationLayers) {
        if (layer.kind === "peer") {
          const address = peerAddressNode(layer);
          for (const origin of address.observedOrigins) add({ source: origin, target: address.origin,
            relationship: "recorded_peer_observation", label: "Recorded direct address observation", undirected: true }, layer);
        } else for (const item of layerReferences(layer)) {
          if (item.target_origin === layer.source.origin) continue;
          const descriptor = layer.kind === "link" ? LINK_RELATIONS[item.relation] : { type: "body_url_reference", label: "Literal body URL reference" };
          add({ source: layer.source.origin, target: item.target_origin, relationship: descriptor.type, label: descriptor.label }, layer);
        }
      }
      return [...edges.values()];
    }
    function addRelationLayer(layer) {
      const key = layerKey(layer), previous = state.relationLayers.findIndex((item) => layerKey(item) === key);
      if (previous < 0 && state.relationLayers.length >= MAX_RELATION_LAYERS) {
        state.bodyOverlayNotice = `Inspection limit ${MAX_RELATION_LAYERS} reached. Remove a shown inspection before adding another; nothing was replaced.`;
        render();
        return false;
      }
      // Exact repeats replace in place; entries of another kind or source stay.
      const layers = [...state.relationLayers];
      if (previous < 0) layers.push(layer); else layers[previous] = layer;
      if (state.peerEvidenceBinding && state.peerEvidenceBinding.overlay === state.relationLayers[previous]) cancelEvidence();
      state.relationLayers = Object.freeze(layers);
      prunePeerState();
      state.extraOriginOverlay = null; state.extraOriginSnapshot = null; state.extraOrigin = null;
      state.neighborhoodOverlay = null; state.neighborhoodSnapshot = null; state.neighborhood = null;
      state.layoutSlots = new Map();
      state.bodyOverlayNotice = "";
      state.modeNotice = "";
      state.anchorOrigin = state.relationLayers.length === 1 && layer.kind !== "peer" ? layer.source.origin : null;
      state.order = stableOrder(state.order, graphOrigins());
      return true;
    }
    function sourceIsRetained(source, snapshot = state.snapshot) {
      if (!source || source.sessionId !== getSessionId() || source.sessionId !== state.sessionId
        || typeof source.generation !== "string" || !source.generation || source.generation !== snapshot?.snapshot.generation) return false;
      const origin = snapshot.origins.find((item) => item.origin === source.origin);
      return !!origin && [...origin.endpoints, ...origin.technology_clues, ...origin.technology_observations, ...origin.redirects, ...origin.header_links]
        .some((item) => item.evidence.includes(source.evidenceId));
    }
    function clearOverlay(notice = "", affected = () => true) {
      const removed = state.relationLayers.filter(affected);
      if (!removed.length) return false;
      state.relationLayers = Object.freeze(state.relationLayers.filter((layer) => !removed.includes(layer)));
      state.graphLayers = null;
      state.graphSnapshot = null;
      state.graphOriginsCache = null;
      currentLayout = null;
      notice = notice.replace(/Temporary body references/g, "Shown inspections");
      if (removed.includes(state.peerEvidenceBinding?.overlay)) cancelEvidence();
      state.neighborhoodOverlay = null;
      state.neighborhoodSnapshot = null;
      state.neighborhoodAnchor = null;
      state.neighborhood = null;
      state.extraOriginOverlay = null;
      state.extraOriginSnapshot = null;
      state.extraOriginId = null;
      state.extraOrigin = null;
      state.layoutSlots = new Map();
      state.bodyOverlayNotice = notice;
      prunePeerState();
      if (state.anchorOrigin && !findOrigin(state.anchorOrigin)) state.anchorOrigin = null;
      if (state.selectedOrigin && !findOrigin(state.selectedOrigin)) {
        cancelEvidence();
        state.selectedOrigin = null;
        state.endpointIndex = null;
        state.endpointSelection = null;
      }
      return true;
    }
    function clearBodyReferenceOverlay() {
      cancelPeerMatches();
      const cleared = clearOverlay("Shown inspections cleared. Showing loaded metadata only.");
      render();
      return cleared;
    }
    function showBodyReferencesOnMap() {
      if (state.sessionId !== getSessionId()) { reset(); return false; }
      const scan = state.bodyReferences, source = state.bodyReferencesSource;
      if (activeInspectionsBlocked() || state.relationshipKind !== "body" || !visible || !getEventStreamReady() || state.error || state.stale || !scan || !["scanned", "partial"].includes(scan.status) || !sourceIsRetained(source)
        || state.evidenceId !== source.evidenceId || state.selectedOrigin !== source.origin
        || !scan.references.some((item) => item.target_origin !== source.origin)) return false;
      // Copy only already-validated fields, never the response row or raw body.
      // The overlay must survive an unrelated inspector selection unchanged.
      const references = Object.freeze(scan.references.map((item) => Object.freeze({
        target_origin: item.target_origin, occurrences: item.occurrences,
        preview_byte_offsets: Object.freeze([...item.preview_byte_offsets]), omitted_offsets: item.omitted_offsets,
      })));
      const layer = Object.freeze({ kind: "body", source: Object.freeze({ ...source }), scan: Object.freeze({
        status: scan.status, complete: scan.complete, reasons: Object.freeze([...scan.reasons]), references,
        retained_preview_bytes: scan.retained_preview_bytes, scanned_bytes: scan.scanned_bytes,
        candidates_scanned: scan.candidates_scanned, omitted_reference_occurrences: scan.omitted_reference_occurrences,
        capture_preview_truncated: scan.capture_preview_truncated, scan_prefix_truncated: scan.scan_prefix_truncated,
      }) });
      if (!addRelationLayer(layer)) return false;
      if (state.view !== "service-map") {
        state.view = "service-map";
        onViewChange?.("service-map");
      }
      render();
      return true;
    }
    function directNeighborhood() {
      if (!state.anchorOrigin || !state.snapshot) {
        state.neighborhoodSnapshot = null; state.neighborhoodAnchor = null; state.neighborhood = null;
        return null;
      }
      if (state.neighborhoodSnapshot === state.snapshot && state.neighborhoodAnchor === state.anchorOrigin && state.neighborhoodOverlay === state.relationLayers) return state.neighborhood;
      const anchor = findOrigin(state.anchorOrigin);
      if (!anchor) return null;
      // Links are typed; arrows are what graphLayout draws: one per direction
      // for the metadata, one per type for an inspection.
      const ids = new Set(), seen = new Set(), metadataArrows = new Set(), inspectedArrows = new Set();
      const counts = { incoming: 0, outgoing: 0, redirect_instruction: 0, origin_header: 0, referer_header: 0, body_url_reference: 0 };
      for (const relation of metadataRelations(state.snapshot.origins)) {
        const { sourceOrigin, targetOrigin, relationship } = relation;
        if (sourceOrigin === targetOrigin || sourceOrigin !== anchor.origin && targetOrigin !== anchor.origin) continue;
        ids.add(sourceOrigin === anchor.origin ? targetOrigin : sourceOrigin);
        metadataArrows.add(JSON.stringify([sourceOrigin, targetOrigin]));
        const key = JSON.stringify([sourceOrigin, targetOrigin, relationship]);
        if (seen.has(key)) continue;
        seen.add(key);
        counts[sourceOrigin === anchor.origin ? "outgoing" : "incoming"] += 1;
        counts[relationship] += 1;
      }
      const bodyIds = new Set();
      for (const edge of overlayEdges()) {
        if (edge.source !== anchor.origin && edge.target !== anchor.origin) continue;
        const neighbor = edge.source === anchor.origin ? edge.target : edge.source;
        ids.add(neighbor); bodyIds.add(neighbor);
        const key = JSON.stringify([edge.source, edge.target, edge.relationship]);
        inspectedArrows.add(key);
        if (seen.has(key)) continue;
        seen.add(key);
        if (!edge.undirected) counts[edge.source === anchor.origin ? "outgoing" : "incoming"] += 1;
        counts[edge.relationship] = (counts[edge.relationship] || 0) + 1;
      }
      // Count the full loaded snapshot, not the capped relationship inspector or
      // All origins reference cache. Only rendering is clipped to 24 cards/40 arrows.
      const byOrigin = new Map(graphOrigins().map((origin) => [origin.origin, origin]));
      const neighbors = [...ids].sort().map((id) => byOrigin.get(id) || referenceOrigin(id));
      state.neighborhoodSnapshot = state.snapshot; state.neighborhoodAnchor = state.anchorOrigin;
      state.neighborhoodOverlay = state.relationLayers;
      state.neighborhood = { anchor, neighbors, counts, bodyIds, edgeCount: seen.size,
        metadataArrowCount: metadataArrows.size, arrowCount: metadataArrows.size + inspectedArrows.size };
      return state.neighborhood;
    }
    function setMapMode(direct) {
      if (state.sessionId !== getSessionId()) { reset(); return; }
      leaveFlow();
      if (direct) {
        if (state.anchorOrigin || !selectedOrigin()) return;
        state.anchorOrigin = state.selectedOrigin;
      } else {
        cancelPeerMatches();

        state.anchorOrigin = null;
      }
      state.modeNotice = "";
      render();
    }
    function cancelFlow() {
      flowAbort?.abort();
      flowAbort = null;
      flowBinding = null;
      state.flowRequestId += 1;
      Object.assign(state, { flow: null, flowLoading: false, flowError: "" });
    }
    function leaveFlow() {
      cancelFlow();
      state.flowOrigin = null;
    }
    function flowIsCurrent() {
      return canRefresh() && state.view === "service-map" && state.flow && !state.flowLoading && !state.error && flowBinding
        && state.sessionId === getSessionId() && flowBinding.sessionId === getSessionId()
        && state.flowOrigin === flowBinding.origin && state.scopeOnly === flowBinding.scopeOnly
        && JSON.stringify(getFilterQuery()) === flowBinding.filterSignature;
    }
    function syncFlowCopyKinds() {
      const signature = JSON.stringify(hiddenLinkKinds());
      if (signature !== flowCopyKindsSignature) {
        flowCopyKindsSignature = signature;
        flowCopyKindsVersion += 1;
      }
      return signature;
    }
    function copyFlow() {
      if (!flowIsCurrent()) return;
      const flow = state.flow, binding = flowBinding, requestId = state.flowRequestId;
      const kinds = syncFlowCopyKinds(), kindsVersion = flowCopyKindsVersion;
      const copyId = ++copyActionId;
      // Native writes already issued cannot be canceled. Own only the JS
      // fallback and feedback, without tying them to unrelated Map polling.
      const isCurrent = () => syncFlowCopyKinds() === kinds && kindsVersion === flowCopyKindsVersion
        && copyId === copyActionId && flow === state.flow && binding === flowBinding
        && requestId === state.flowRequestId && flowIsCurrent();
      copyText?.(flowMermaid(flow, hiddenLinkKinds()), "Copied the flow as a Mermaid sequence diagram", isCurrent);
    }
    function resumeFlow() {
      if (canRefresh() && state.view === "service-map" && state.snapshot && state.flowOrigin && !state.flow && !state.flowLoading
        && !state.loading && !state.stale && !state.error) loadFlow();
    }
    // Flow follows one origin: the selected one, or a lane clicked in a flow.
    function setFlowMode(origin) {
      if (state.sessionId !== getSessionId()) { reset(); return; }
      if (!origin) { leaveFlow(); render(); return; }
      Object.assign(state, { flowOrigin: origin, flow: null, flowError: "", anchorOrigin: null, modeNotice: "" });
      if (state.selectedOrigin !== origin) selectOrigin(origin);
      loadFlow();
    }
    async function loadFlow() {
      const origin = state.flowOrigin, sessionId = getSessionId();
      if (!origin || !canRefresh() || state.view !== "service-map" || state.sessionId !== sessionId) return;
      flowAbort?.abort();
      flowAbort = new AbortController();
      flowBinding = null;
      const requestId = ++state.flowRequestId;
      const scopeOnly = state.scopeOnly, filterQuery = getFilterQuery(), filterSignature = JSON.stringify(filterQuery);
      // Same-context polling may keep its diagram in place. Destructive
      // boundaries clear it through cancelFlow; neither can act until verified.
      Object.assign(state, { flowError: "", flowLoading: true });
      render();
      // The newest rows the server reads at most: a flow shows what happened
      // lately, and only a row window keeps the rows' order.
      const params = new URLSearchParams({ ...filterQuery, session_id: sessionId, origin, in_scope_only: String(scopeOnly), max_records: "50000" });
      let flow = null, error = "";
      try {
        const response = await request(`/api/target/service-map/flow?${params}`, { signal: flowAbort.signal });
        if (!response.ok) error = response.status === 404 ? "This Sniper cannot draw flows; update it." : "The flow could not be read.";
        else flow = normalizeFlow(await response.json(), sessionId, origin);
        if (!flow && !error) error = "The flow did not match the origin asked for.";
      } catch (failure) {
        if (failure?.name === "AbortError") return;
        error = "The flow could not be read.";
      }
      if (!canRefresh() || state.view !== "service-map" || requestId !== state.flowRequestId || state.flowOrigin !== origin || sessionId !== getSessionId()
        || scopeOnly !== state.scopeOnly || filterSignature !== JSON.stringify(getFilterQuery())) {
        if (requestId === state.flowRequestId) { cancelFlow(); render(); }
        return;
      }
      flowAbort = null;
      flowBinding = flow ? { sessionId, origin, scopeOnly, filterSignature } : null;
      Object.assign(state, { flow, flowError: error, flowLoading: false });
      render();
    }
    function renderModeButtons(selected) {
      const flow = !!state.flowOrigin;
      // Origins and Flow are the views; Direct relations narrows Origins.
      els.allOrigins?.setAttribute("aria-pressed", String(!flow));
      els.directRelations?.setAttribute("aria-pressed", String(!!state.anchorOrigin && !flow));
      els.directRelations?.classList.toggle("hidden", flow);
      els.flow?.setAttribute("aria-pressed", String(flow));
      if (els.directRelations) els.directRelations.disabled = !state.snapshot || !state.anchorOrigin && !selected;
      if (els.flow) els.flow.disabled = !state.snapshot || !flow && !selected;
      els.flowMermaid?.classList.toggle("hidden", !flow || !state.flow);
      if (els.flowMermaid) els.flowMermaid.disabled = !flowIsCurrent();
      els.linkKinds?.parentElement?.classList.toggle("flow-active", flow);
    }
    function renderFlow() {
      renderModeButtons(selectedOrigin());
      renderLinkKinds();
      els.mapControls?.classList.toggle("hidden", state.view === "apis");
      els.focusSelection?.classList.toggle("hidden", true);
      const flow = state.flow;
      const layout = flow && flowLayout(flow, hiddenLinkKinds());
      const shown = layout ? layout.arrows.filter((arrow) => !arrow.redirect).length : 0;
      const steps = flow ? flow.phases.reduce((sum, phase) => sum + phase.steps.length, 0) : 0;
      const coverage = flow ? [`${flow.flowRows} of the newest ${flow.consideredRows} rows`,
        ...flow.stoppedBy.map((reason) => FLOW_STOPS[reason] || `stopped by ${reason}`)].join(" · ") : "";
      if (!shown) {
        currentLayout = null;
        const message = !flow ? state.flowError || "Reading the flow…" : steps
          ? "No requests of the kinds shown. Turn more kinds on under Requests."
          : "No matching requests in this row window.";
        replace(els.canvas, `<div class="service-map-empty"><span class="service-map-empty-symbol" aria-hidden="true">◎</span><h3>${escape(message)}</h3></div>`);
        els.graphBounds.textContent = coverage;
        if (els.graphDiagnostics) els.graphDiagnostics.textContent = "";
        updateZoomControls();
        return;
      }
      currentLayout = { nodes: layout.lanes, edges: [], width: layout.width, height: layout.height };
      replace(els.canvas, `<div class="service-map-scaled"><div class="service-map-layout">${flowMarkup(layout)}</div></div>`);
      applyGraphScale();
      pinFlowHeads();
      els.graphBounds.textContent = `${shown} / ${steps} steps in ${layout.bands.length} page loads · ${coverage}`;
      if (els.graphDiagnostics) els.graphDiagnostics.textContent = "";
    }
    function focusSelection() {
      if (state.sessionId !== getSessionId()) { reset(); return; }
      if (!state.anchorOrigin || !selectedOrigin()) return;
      if (state.anchorOrigin !== state.selectedOrigin) {
        cancelPeerMatches();

      }
      if (!selectedOrigin()) { render(); return; }
      state.anchorOrigin = state.selectedOrigin;
      state.modeNotice = "";
      render();
    }

    function peerSnapshotKey(snapshot = state.snapshot) {
      if (!snapshot) return null;
      if (state.peerProjection?.snapshot === snapshot) return state.peerProjection.identity;
      // Poll response IDs/times vary without history changes. One comparison
      // string belongs to the controller; every peer source holds only a tiny
      // shared identity, never another whole-map serialization.
      const { id, captured_at, ...bounds } = snapshot.snapshot;
      const serialized = JSON.stringify([bounds, snapshot.origins]);
      const identity = state.peerProjection?.serialized === serialized ? state.peerProjection.identity : Object.freeze({});
      state.peerProjection = { snapshot, serialized, identity };
      return identity;
    }
    function peerSourceIsCurrent(source, snapshot = state.snapshot) {
      return !!source && source.sessionId === getSessionId() && source.sessionId === state.sessionId
        && source.generation === snapshot?.snapshot.generation && source.historyVersion === state.historyVersion
        && source.scopeOnly === state.scopeOnly && source.mapKey === peerSnapshotKey(snapshot);
    }
    function peerOverlayOrigins(overlay) {
      if (overlay?.kind !== "peer") return [];
      const scan = overlay.scan, ids = [scan.source.origin, ...scan.origins.map((group) => group.origin)];
      return [...new Set(ids)].map((id) => {
        const group = scan.origins.find((item) => item.origin === id);
        const aggregate = state.snapshot?.origins.find((origin) => origin.origin === id);
        return { ...referenceOrigin(id), captured: true, peerInspectionOnly: !aggregate,
          technology_observations: aggregate?.technology_observations || [], technology_observations_present: aggregate?.technology_observations_present === true, in_scope: id === scan.source.origin ? scan.source.in_scope : group.in_scope,
          peerGroup: group || null, peerSource: id === scan.source.origin, request_count: 0 };
      });
    }
    function peerSampleBinding(id, origin) {
      const overlay = state.relationLayers.find((layer) => layer.kind === "peer" && peerSourceIsCurrent(layer.source)
        && (layer.scan.source.evidence_id === id && layer.scan.source.origin === origin
          || layer.scan.origins.some((group) => group.origin === origin && group.samples.some((item) => item.evidence_id === id))));
      if (!overlay || state.peerUnavailableTokens?.has(id)) return null;
      const scan = overlay.scan;
      const sample = scan.source.evidence_id === id && scan.source.origin === origin ? scan.source
        : scan.origins.find((group) => group.origin === origin)?.samples.find((item) => item.evidence_id === id);
      return sample ? Object.freeze({ overlay, snapshotId: scan.snapshot.id, seedId: scan.evidence_id, origin, sample }) : null;
    }
    function peerBindingIsCurrent(binding) {
      if (!binding || !state.relationLayers.includes(binding.overlay) || binding.overlay?.kind !== "peer"
        || !visible || !getEventStreamReady() || state.error || state.stale || !peerSourceIsCurrent(binding.overlay.source)
        || binding.snapshotId !== binding.overlay.scan.snapshot.id || binding.seedId !== binding.overlay.scan.evidence_id) return false;
      return peerSampleBinding(binding.sample.evidence_id, binding.origin)?.sample === binding.sample;
    }
    function handlePeerSampleUnavailable(binding) {
      if (!state.relationLayers.includes(binding.overlay)) return;
      const id = binding.sample.evidence_id;
      // The same exact row may be a sample in one inspection and a seed in
      // several others. A failed read invalidates every seeded claim first.
      clearOverlay("Shown inspections removed: the exact inspected source is unavailable or changed.", (layer) => layer.source.evidenceId === id);
      if (!state.relationLayers.includes(binding.overlay)) { cancelPeerMatches(); return; }
      if (!state.peerUnavailableTokens) state.peerUnavailableTokens = new Set();
      state.peerUnavailableTokens.add(id);
      state.peerEvidenceBinding = null;
      state.evidenceError = "This matched sample is unavailable or changed. The shown counts remain a point-in-time inspection; other exact samples can still be checked. Inspect again to obtain new samples.";
    }
    function prunePeerState() {
      const peers = state.relationLayers.filter((layer) => layer.kind === "peer");
      const live = new Set(peers.flatMap((layer) => [layer.scan.evidence_id, ...layer.scan.origins.flatMap((group) => group.samples.map((sample) => sample.evidence_id))]));
      state.peerUnavailableTokens = new Set([...(state.peerUnavailableTokens || [])].filter((id) => live.has(id)));
      if (!peers.length && !state.peerMatchesSource) state.peerProjection = null;
    }
    function cancelPeerMatches() {
      state.peerMatchesRequestId += 1;
      peerMatchesAbort?.abort();
      peerMatchesAbort = null;
      state.peerMatches = null;
      state.peerMatchesSource = null;
      state.peerMatchesLoading = false;
      state.peerMatchesError = "";
      prunePeerState();
    }
    async function loadPeerMatches() {
      const row = state.evidence, peer = state.socketPeer, sessionId = getSessionId(), generation = state.snapshot?.snapshot.generation;
      if (activeInspectionsBlocked() || !visible || state.view !== "service-map" || !getEventStreamReady() || state.error || state.stale || state.sessionId !== sessionId
        || !row || row.evidence_id !== state.evidenceId || state.evidenceLoading || state.peerMatchesLoading || !usableSocketPeer(peer)
        || !validTechnologyEvidence(row.evidence_id, sessionId, generation) || row.sequence !== row.evidence_id.split(".")[3]
        || row.record_id !== row.evidence_id.split(".")[5] || safeOrigin(row.origin) !== row.origin || observationTime(row.started_at) === null
        || !(state.peerEvidenceBinding ? peerBindingIsCurrent(state.peerEvidenceBinding) : evidenceItems(selectedOrigin()).some((item) => item.id === row.evidence_id))) return false;
      state.packetInspection = "peer";
      cancelPeerMatches();
      const source = Object.freeze({ sessionId, generation, evidenceId: row.evidence_id, origin: row.origin, sequence: row.sequence,
        method: row.method, path: safePath(row.path), startedAt: row.started_at, observedAt: peer.observedAt,
        historyVersion: state.historyVersion, scopeOnly: state.scopeOnly, mapKey: peerSnapshotKey() });
      const requestId = ++state.peerMatchesRequestId, selected = state.selectedOrigin;
      const current = () => requestId === state.peerMatchesRequestId && visible && state.view === "service-map" && getEventStreamReady()
        && !state.error && !state.stale && row === state.evidence && peer === state.socketPeer && state.evidenceId === source.evidenceId
        && selected === state.selectedOrigin && peerSourceIsCurrent(source);
      state.peerMatchesSource = source;
      state.peerMatchesLoading = true;
      peerMatchesAbort = new AbortController();
      renderDetail();
      let unsupportedServer = false;
      try {
        const params = new URLSearchParams({ session_id: sessionId, evidence_id: source.evidenceId, in_scope_only: String(source.scopeOnly), max_records: String(PEER_MATCH_LIMITS.max_records) });
        const response = await request(`/api/target/service-map/socket-peer-matches?${params}`, { signal: peerMatchesAbort.signal });
        unsupportedServer = response.status === 404;
        if (!response.ok) throw new Error("Recorded peer matches unavailable");
        const payload = await response.json();
        if (!current()) return false;
        state.peerMatches = normalizePeerMatches(payload, sessionId, source.evidenceId, row, peer, source.scopeOnly, generation);
        state.peerMatchesLoading = false;
        peerMatchesAbort = null;
        if (!handleSupplementLifetime(state.peerMatches, source)) renderDetail();
        return true;
      } catch (_) {
        if (!current()) return false;
        state.peerMatchesLoading = false;
        peerMatchesAbort = null;
        state.peerMatches = null;
        state.peerMatchesError = unsupportedServer ? "This server does not support matching recorded socket peers. No matching inspection was performed."
          : "Could not verify matching recorded socket peers. Retry explicitly, or refresh the map and select the exact source again.";
        renderDetail();
        return false;
      }
    }
    function showPeerMatchesOnMap() {
      const scan = state.peerMatches, source = state.peerMatchesSource;
      if (activeInspectionsBlocked() || !visible || state.view !== "service-map" || !getEventStreamReady() || state.error || state.stale || !scan?.available
        || !peerSourceIsCurrent(source) || state.evidenceId !== source.evidenceId || state.selectedOrigin !== source.origin) return false;
      // Inspection and visualization are independent. Adding the shown entry
      // uses only this frozen response and never performs another read.
      if (!addRelationLayer(Object.freeze({ kind: "peer", source, scan }))) return false;
      if (!state.peerUnavailableTokens) state.peerUnavailableTokens = new Set();
      for (const id of [scan.evidence_id, ...scan.origins.flatMap((group) => group.samples.map((sample) => sample.evidence_id))]) state.peerUnavailableTokens.delete(id);
      state.selectedOrigin = source.origin;
      state.anchorOrigin = null;
      state.endpointIndex = null;
      state.endpointSelection = null;
      state.bodyOverlayNotice = "";
      state.modeNotice = "";
      state.layoutSlots = new Map();
      render();
      return true;
    }
    function peerCountsMarkup(scan) {
      if (!scan?.available) return "";
      const counts = scan.counts;
      return `<p>${scan.complete ? "Complete considered-window equality inspection" : "Partial retained-history inspection"} · ${scan.snapshot.considered_rows.toLocaleString()} rows considered / ${scan.snapshot.retained_rows.toLocaleString()} retained · ${counts.matching_rows.toLocaleString()} other matching rows</p><p>${scan.origins.length} returned origin groups · ${counts.returned_matching_rows.toLocaleString()} represented matching rows · ${counts.omitted_matching_rows.toLocaleString()} matching rows omitted by result caps · ${counts.sample_rows} exact samples · ${counts.omitted_sample_rows} samples omitted within returned groups.</p><p>Candidate sequences ${escape(scan.snapshot.oldest_considered_sequence)}–${escape(scan.snapshot.latest_considered_sequence)}. Source ${scan.source.in_window ? "is inside" : "is outside"} this window and is counted separately.</p>${scan.reasons.length ? `<p>${scan.reasons.map((reason) => escape(PEER_MATCH_REASONS[reason])).join(" · ")}</p>` : ""}`;
    }
    function peerMatchesMarkup() {
      const scan = state.peerMatches, source = state.peerMatchesSource;
      const ready = usableSocketPeer(state.socketPeer);
      const disabled = activeInspectionsBlocked() || !ready || !visible || !getEventStreamReady() || !!state.error || state.stale || state.evidenceLoading || state.peerMatchesLoading;
      const showDisabled = !scan?.available || !peerSourceIsCurrent(source) || source.evidenceId !== state.evidenceId || disabled;
      return `<section class="service-map-body-references service-map-peer-matches" aria-label="Matching recorded socket peers" aria-busy="${state.peerMatchesLoading}"><h4>Matching recorded socket peers</h4>${state.peerMatchesError ? `<p class="service-map-error" role="status">${escape(state.peerMatchesError)}</p>` : ""}${scan ? `<div class="service-map-body-reference-result" role="status">${scan.available ? `<p>${scan.status === "no_matches" ? "No other rows came from this address." : `${scan.counts.matching_rows.toLocaleString()} other rows came from this address.`}</p>` : `<p>Inspection unavailable. ${scan.reasons.map((reason) => escape(PEER_MATCH_REASONS[reason])).join(" · ")}</p>`}</div>` : ""}${scan?.available && scan.origins.length ? `<ul class="service-map-body-reference-list">${scan.origins.map((group) => `<li><span class="service-map-body-reference-origin">${escape(group.origin)}</span><span>${group.matching_rows} matching rows · ${group.samples.length} exact samples</span><span>Recorded first: ${escape(group.first_observed_at)} · last: ${escape(group.last_observed_at)}</span></li>`).join("")}</ul>` : ""}${showDisabled ? "" : `<button class="secondary-action" type="button" data-service-show-peer-matches="show" data-service-focus="peer:show" ${showDisabled ? "disabled" : ""}>Show recorded address group</button>`}${scan?.available ? `<details class="service-map-body-reference-limits"><summary data-service-focus="peer:limits">Coverage and omissions</summary>${peerCountsMarkup(scan)}<p>${PEER_PRIVACY}</p><p>Other considered rows: ${scan.counts.non_http_rows} non-HTTP · ${scan.counts.not_recorded_rows} not recorded · ${scan.counts.unavailable_observation_rows} unavailable · ${scan.counts.non_direct_rows} non-direct · ${scan.counts.invalid_observation_rows} unusable observations · ${scan.counts.different_peer_rows} different peer · ${scan.counts.invalid_metadata_rows} invalid origin metadata · ${scan.counts.scope_excluded_rows} scope excluded.</p><p>Limits: ${PEER_MATCH_LIMITS.max_records.toLocaleString()} newest retained rows · 100 origin groups · 3 samples per origin · 256 KiB result. Unreturned distinct origins are not counted. Exact samples can change after this point-in-time inspection and are verified again when opened.</p></details>` : ""}</section>`;
    }
    function peerOriginMarkup(origin) {
      return state.relationLayers.filter((layer) => layer.kind === "peer").map((overlay) => {
        const item = peerOverlayOrigins(overlay).find((item) => item.origin === origin.origin);
        return item ? peerLayerOriginMarkup(item, overlay) : "";
      }).join("");
    }
    function peerLayerOriginMarkup(origin, overlay) {
      const samples = [...(origin.peerSource ? [overlay.scan.source] : []), ...(origin.peerGroup?.samples || [])];
      return `<section class="service-map-peer-origin"><h4>${origin.peerInspectionOnly ? "Captured in this peer inspection" : "Recorded address observations"}</h4><p class="service-map-muted">${escape(peerAddressNode(overlay).address)} · ${origin.peerGroup?.matching_rows || 0} other matching rows</p>${origin.peerGroup ? `<p class="service-map-muted">First recorded: ${escape(origin.peerGroup.first_observed_at)} · Last recorded: ${escape(origin.peerGroup.last_observed_at)}</p>` : ""}<div class="service-map-evidence-list">${samples.map((sample) => `<button class="service-map-evidence-button" type="button" data-service-peer-origin="${escape(origin.origin)}" data-service-peer-evidence="${escape(sample.evidence_id)}" data-service-focus="peer-sample:${escape(sample.evidence_id)}" ${state.peerUnavailableTokens?.has(sample.evidence_id) ? "disabled" : ""}><span>${sample.evidence_id === overlay.scan.evidence_id ? "Inspected source" : "Matched sample"} · sequence ${escape(sample.sequence)}<br>Recorded ${escape(sample.observed_at)}</span><span>${state.peerUnavailableTokens?.has(sample.evidence_id) ? "Unavailable" : "Verify source ›"}</span></button>`).join("") || '<p class="service-map-muted">No sample returned.</p>'}</div></section>`;
    }
    function cancelBodyReferences() {
      state.bodyReferencesRequestId += 1;
      bodyReferencesAbort?.abort();
      bodyReferencesAbort = null;
      state.bodyReferences = null;
      state.bodyReferencesSource = null;
      state.linkDeclarations = null;
      state.linkDeclarationsSource = null;
      state.linkDeclarationsError = "";
      state.bodyReferencesLoading = false;
      state.bodyReferencesError = "";
    }
    function cancelHtmlGenerators() {
      state.htmlGeneratorsRequestId += 1;
      htmlGeneratorsAbort?.abort();
      htmlGeneratorsAbort = null;
      state.htmlGenerators = null;
      state.htmlGeneratorsSource = null;
      state.htmlGeneratorsLoading = false;
      state.htmlGeneratorsError = "";
    }
    function activeInspectionsBlocked() {
      return state.inactiveSessionId !== null && state.inactiveSessionId === getSessionId();
    }
    function handleSupplementLifetime(result, source) {
      // Called only after the request's identity fence and typed normalizer.
      // Eligibility/preview/parser failures cannot disprove ordinary metadata.
      if (result.status !== "unavailable") return false;
      const reason = result.reasons[0];
      const message = SOURCE_LIFETIME_MESSAGES[reason];
      if (message) {
        clearOverlay(`Shown inspections removed. ${message}`, (layer) => layer.source.sessionId === source.sessionId
          && (reason === "session_source_changed" || reason === "stale_generation" && layer.source.generation === source.generation
            || layer.source.evidenceId === source.evidenceId));
        cancelEvidence();
        state.evidenceError = `Source unavailable. ${message}`;
        render();
        return true;
      }
      if (reason !== "inactive_session") return false;
      state.inactiveSessionId = source.sessionId;
      // A peer overlay can also contain an independently allowlisted ordinary
      // row. Detach that binding before clearing, never restore orphan samples.
      const ordinaryOrigin = state.snapshot?.origins.find((origin) => origin.origin === state.selectedOrigin);
      if (state.evidence && evidenceItems(ordinaryOrigin).some((item) => item.id === state.evidence.evidence_id)) state.peerEvidenceBinding = null;
      clearOverlay(INACTIVE_SESSION_NOTICE);
      cancelPeerMatches();
      cancelBodyReferences();
      cancelHtmlGenerators();
      render();
      return true;
    }
    function cancelPacket() {
      state.packetRequestId += 1;
      packetAbort?.abort(); packetAbort = null;
      packetViewer?.destroy(); packetViewer = null; packetViewerElement = null;
      state.packet = null; state.packetLoading = false; state.packetError = "";
    }
    async function loadPacket(variant = state.packetVariant) {
      if (!mountPacketViewer || !visible || destroyed || !state.evidence || state.evidenceId !== state.evidence.evidence_id
        || state.sessionId !== getSessionId() || !["current", "original"].includes(variant)) return false;
      cancelPacket();
      const row = state.evidence, evidenceId = state.evidenceId, sessionId = state.sessionId, requestId = state.packetRequestId;
      const evidenceRequestId = state.evidenceRequestId, view = state.view;
      state.packetVariant = variant; state.packetLoading = true;
      const owns = () => !destroyed && visible && state.view === view && requestId === state.packetRequestId && evidenceRequestId === state.evidenceRequestId
        && sessionId === getSessionId() && state.sessionId === sessionId && state.evidence === row && state.evidenceId === evidenceId && state.packetVariant === variant;
      packetAbort = new AbortController(); renderDetail();
      try {
        const params = new URLSearchParams({ session_id: sessionId, evidence_id: evidenceId, variant });
        const response = await request(`/api/target/service-map/packet?${params}`, { signal: packetAbort.signal });
        if (!owns()) return false;
        if (!response.ok) throw new Error("Retained packet unavailable");
        const value = await response.json();
        if (!owns()) return false;
        const packet = normalizePacket(value, { sessionId, evidenceId, variant, recordId: row.record_id, sequence: row.sequence, startedAt: row.started_at });
        state.packet = packet.available ? packet : null;
        if (packet.available) state.packetOriginals = packet.originals;
        state.packetError = packet.available ? "" : packet.reason === "packet_view_limit" || packet.reason === "serialized_row_limit" ? "Retained packet exceeds the view limit." : "Retained packet unavailable.";
      } catch (_) { if (!owns()) return false; state.packetError = "Retained packet could not be read."; }
      if (!owns()) return false;
      state.packetLoading = false; packetAbort = null; renderDetail();
      return !!state.packet;
    }
    function selectDetails() {
      state.detailTab = "evidence";
      renderDetail();
      if (!mountPacketViewer || state.evidenceLoading || state.packetLoading) return;
      if (state.evidence) { if (!state.packet && !state.packetError) loadPacket(); return; }
      if (state.evidenceId) return;
      const first = evidenceItems(selectedOrigin())[0];
      if (first) loadEvidence(first.id);
    }
    function mountDetailsPacket() {
      const element = els.detail.querySelector?.("[data-service-packet]");
      if (!element || !state.packet || !mountPacketViewer || !visible || state.detailTab !== "evidence") return;
      if (packetViewerElement === element) return;
      packetViewer?.destroy();
      const packet = state.packet, requestId = state.packetRequestId, sessionId = state.sessionId, view = state.view;
      const isCurrent = () => !destroyed && visible && state.view === view && state.detailTab === "evidence" && sessionId === getSessionId()
        && state.sessionId === sessionId && requestId === state.packetRequestId && state.packet === packet;
      packetViewerElement = element;
      packetViewer = mountPacketViewer(element, { packet, row: state.evidence, isCurrent });
    }
    function selectedInspectionMarkup() {
      if (state.packetVariant !== "current") return "";
      if (state.packetInspection === "generator") return htmlGeneratorsMarkup();
      if (state.packetInspection === "peer") return peerMatchesMarkup();
      if (state.packetInspection === "body") return `<section class="service-map-body-references packet-inspection"><h4>Body references</h4>${bodyReferencesMarkup()}</section>`;
      if (state.packetInspection === "link") return `<section class="service-map-body-references packet-inspection"><h4>Link references</h4>${linkDeclarationsMarkup()}</section>`;
      return "";
    }
    function packetInspectOptions() {
      if (!state.packet || state.packetVariant !== "current" || !state.packet.response?.message || state.peerEvidenceBinding) return "";
      const message = state.packet.response.message, body = message.body;
      const types = [];
      if (body.available && body.body_encoding === "utf8" && /^(text\/html|application\/xhtml\+xml)(;|$)/i.test(body.content_type || "")) types.push(["generator", "HTML generators"]);
      if (body.available && body.body_encoding === "utf8" && /^(text\/html|application\/(xhtml\+xml|javascript)|text\/javascript)(;|$)/i.test(body.content_type || "")) types.push(["body", "Body references"]);
      if (message.headers.some(header => header.name.toLowerCase() === "link")) types.push(["link", "Link references"]);
      // Body inspection can use a freshly reverified exact row while only
      // aggregate counts are stale; the other existing inspectors cannot.
      const blocked = kind => activeInspectionsBlocked() || kind !== "body" && (state.stale || state.error || !getEventStreamReady());
      return types.length ? `<label class="packet-inspect"><select aria-label="Inspect retained response" data-service-packet-inspect="true" data-service-packet-owner="${state.packetRequestId}" ${types.every(([kind]) => blocked(kind)) ? "disabled" : ""}><option value="">Inspect</option>${types.map(([key, label]) => `<option value="${key}"${blocked(key) ? " disabled" : ""}>${label}</option>`).join("")}</select></label>` : "";
    }
    function cancelEvidence() {
      cancelPacket(); state.packetVariant = "current"; state.packetOriginals = null; state.packetInspection = "";
      cancelPeerMatches();
      state.peerEvidenceBinding = null;
      cancelHtmlGenerators();
      cancelBodyReferences();
      state.evidenceRequestId += 1;
      evidenceAbort?.abort();
      evidenceAbort = null;
      state.evidence = null;
      state.evidenceCatalogVersion = null;
      state.evidenceLegacyCatalog = false;
      state.socketPeer = null;
      state.evidenceLoading = false;
      state.evidenceError = "";
      state.evidenceId = null;
    }
    function reset() {
      replayActionId += 1;
      clearOverlay("Temporary body references cleared because the session changed.");
      suspendRefresh();
      cancelEvidence();
      closeApiDocs();
      cancelParameters();
      flowAbort?.abort();
      Object.assign(state, { flowOrigin: null, flow: null, flowLoading: false, flowError: "" });
      Object.assign(state, { sessionId: getSessionId(), snapshot: null, order: [], selectedOrigin: null, selectedClient: null, selectedSite: null,
        inactiveSessionId: null, selectionInitialized: false, endpointIndex: null, endpointSelection: null, endpointMethod: "", endpointPath: "", productId: "", productVersion: "", pageAnchor: null, detailPageAnchor: null, expandedEndpointGroups: new Set(), loading: false, backgroundLoading: false, error: "", refreshPaused: false, page: 0, detailPage: 0, stale: false, anchorOrigin: null, modeNotice: "", zoomScale: 1 });
      render();
      scheduleAutomaticRefresh();
    }
    function selectOrigin(origin, endpointIndex = null) {
      const item = findOrigin(origin);
      if (!item || endpointIndex !== null && (!Number.isSafeInteger(endpointIndex) || !item.endpoints[endpointIndex])) return;
      replayActionId += 1;
      const changedOrigin = state.selectedOrigin !== origin;
      const endpoint = endpointIndex === null ? null : item.endpoints[endpointIndex];
      if (changedOrigin || state.endpointSelection?.method !== endpoint?.method || state.endpointSelection?.path !== endpoint?.path) cancelParameters();
      state.highlightedRelation = null;
      state.selectedSite = null;
      state.selectedClient = null;
      if (changedOrigin || state.endpointIndex !== endpointIndex) cancelEvidence();
      if (changedOrigin) { state.detailPage = 0; state.detailPageAnchor = null; }
      state.selectedOrigin = origin;
      state.selectionInitialized = true;
      state.endpointIndex = endpointIndex;
      // Keep only the exact identity when invalidation clears all displayed data.
      // An array index cannot safely survive scope filtering or history removal.
      state.endpointSelection = endpoint ? { method: endpoint.method, path: endpoint.path } : null;
      if (endpoint) {
        const entry = { origin: item, endpoint, index: endpointIndex };
        const index = loadedEndpointEntries([item]).findIndex((candidate) => sameEndpoint(candidate, endpointIdentity(entry)));
        if (index >= 0) { state.detailPage = Math.floor(index / API_PAGE_SIZE); state.detailPageAnchor = endpointIdentity(entry); }
      }
      state.detailTab = endpointIndex === null ? "apis" : "evidence";
      render();
      if (endpoint) { loadParameters(origin, endpoint); selectDetails(); }
    }
    // An origin's API docs: its OpenAPI document laid out as Swagger UI lays
    // one out, read when asked for. Burp's OpenAPI Parser lists operations the
    // same way and sends each on to Repeater; here the newest row an operation
    // stands for (`x-sniper-newest-transaction`) goes to Replay. Every string
    // came from captured traffic, so all of it is escaped like the rest of the map.
    const API_DOC_METHODS = ["get", "post", "put", "patch", "delete", "head", "trace"];
    const TRANSACTION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    async function openApiDocs(originId) {
      if (!els.apiDocs) return;
      onApiDocsOpen?.();
      replayActionId += 1;
      const sessionId = getSessionId();
      const opening = !state.apiDocs;
      if (opening) apiDocsReturnFocus = doc?.activeElement;
      const requestId = ++state.apiDocsRequestId;
      state.apiDocs = { origin: originId, sessionId, document: null, error: "" };
      renderApiDocs(opening);
      try {
        const response = await request(`/api/target/service-map/openapi?${new URLSearchParams({ session_id: sessionId, origin: originId })}`);
        if (!response.ok) throw new Error(response.status === 409 ? "API docs are read from the active session only." : "API docs unavailable.");
        const document = await response.json();
        if (requestId !== state.apiDocsRequestId || sessionId !== getSessionId()) return;
        if (document?.openapi !== "3.1.0" || document.servers?.[0]?.url !== originId || typeof document.paths !== "object" || !document.paths) throw new Error("API docs unavailable.");
        state.apiDocs = { origin: originId, sessionId, document, error: "" };
      } catch (error) {
        if (requestId !== state.apiDocsRequestId || sessionId !== getSessionId()) return;
        state.apiDocs = { origin: originId, sessionId, document: null, error: error.message || "API docs unavailable." };
      }
      renderApiDocs();
    }
    function apiDocsOwnsFocus() {
      return !!doc?.activeElement && els.apiDocs?.contains(doc.activeElement) && isActiveModal(els.apiDocs);
    }
    function closeApiDocs(returnFocus = true) {
      if (state.apiDocs) replayActionId += 1;
      // A pointer press on the non-focusable backdrop can leave body focused
      // before its click dismisses the dialog.
      const restore = returnFocus && state.apiDocs && isActiveModal(els.apiDocs)
        && (apiDocsOwnsFocus() || !!doc?.body && doc.activeElement === doc.body);
      state.apiDocsRequestId += 1;
      state.apiDocs = null;
      renderApiDocs();
      if (restore) restoreFocus?.(apiDocsReturnFocus);
      apiDocsReturnFocus = null;
    }
    function sendApiDocsToReplay(id) {
      const apiDocs = state.apiDocs;
      if (!visible || !apiDocs?.document || apiDocs.sessionId !== getSessionId()
        || !TRANSACTION_ID.test(id) || !Object.values(apiDocs.document.paths).some((path) =>
          API_DOC_METHODS.some((method) => path?.[method]?.["x-sniper-newest-transaction"] === id))) return;
      // Sending deliberately closes the document. Capture a separate action
      // owner afterward so that close permits this read, while newer intent
      // (including leaving and returning to Map) cannot revive it.
      closeApiDocs();
      const actionId = replayActionId;
      const isCurrent = () => actionId === replayActionId && visible && apiDocs.sessionId === getSessionId();
      sendToReplay?.(id, isCurrent);
    }
    function copyApiDocs(label) {
      const apiDocs = state.apiDocs;
      if (!canRefresh() || !apiDocs?.document || apiDocs.sessionId !== getSessionId()) return false;
      const copyId = ++copyActionId, requestId = state.apiDocsRequestId;
      const isCurrent = () => canRefresh() && state.apiDocs === apiDocs && apiDocs.sessionId === getSessionId()
        && requestId === state.apiDocsRequestId && copyActionId === copyId;
      copyText?.(JSON.stringify(apiDocs.document, null, 2), label, isCurrent);
      return true;
    }
    function renderApiDocs(opening = false) {
      if (!els.apiDocs) return;
      els.apiDocs.classList.toggle("hidden", !state.apiDocs);
      // Replacing the loading markup detaches its focused Close button. Keep
      // that focus inside, but do not take it back from a newer dialog.
      const focus = state.apiDocs && isActiveModal(els.apiDocs) && (opening || apiDocsOwnsFocus());
      replace(els.apiDocs, state.apiDocs ? apiDocsMarkup(state.apiDocs) : "");
      if (focus) els.apiDocs.querySelector?.("[data-api-docs-close]")?.focus();
    }
    function apiDocsMarkup({ origin, document, error }) {
      const body = error ? `<p class="service-map-filter-notice" role="status">${escape(error)}</p>`
        : document ? apiDocsBodyMarkup(document) : '<p class="service-map-muted" role="status">Reading retained rows…</p>';
      return `<div class="modal-card modal-card-wide service-map-api-docs" role="dialog" aria-modal="true" aria-labelledby="serviceMapApiDocsTitle"><header class="modal-header"><div><p class="placeholder-kicker">API docs · OpenAPI 3.1</p><h2 id="serviceMapApiDocsTitle" title="${escape(origin)}">${escape(origin)}</h2></div></header><div class="modal-body">${body}</div><footer class="modal-footer"><button class="secondary-action" type="button" data-api-docs-copy ${document ? "" : "disabled"}>Copy OpenAPI JSON</button><button class="secondary-action" type="button" data-api-docs-editor title="Copies the document and opens editor.swagger.io, where you paste it" ${document ? "" : "disabled"}>Open in Swagger Editor</button><button class="secondary-action" type="button" data-api-docs-close>Close</button></footer></div>`;
    }
    function apiDocsBodyMarkup(document) {
      const schemes = document.components?.securitySchemes || {};
      const schemeText = (scheme) => scheme?.type === "http" ? `HTTP ${scheme.scheme}${scheme.bearerFormat ? ` (${scheme.bearerFormat})` : ""}`
        : `${{ cookie: "Cookie", query: "Query parameter" }[scheme?.in] || "Header"} ${scheme?.name || ""}`;
      const typeOf = (schema) => {
        const labels = new Set();
        let remaining = 32;
        const visit = (value, depth) => {
          remaining -= 1;
          if (depth > 4) { labels.add("…"); return; }
          const types = Array.isArray(value?.type);
          const label = types ? "" : [value?.type, value?.format].filter((part) => typeof part === "string" && part)
            .map((part) => part.length > 80 ? `${part.slice(0, 79)}…` : part).join(" · ");
          if (label) { labels.add(label); return; }
          const variants = types ? value.type : value?.anyOf;
          if (!Array.isArray(variants) || !variants.length) { labels.add("any"); return; }
          // Mixed path identifiers carry anyOf; JSON fields can have type arrays.
          // Bound even malformed nested schemas without changing Copy or Replay.
          for (const variant of variants) {
            if (!remaining) { labels.add("…"); break; }
            const branch = types ? (typeof variant === "string" && variant ? { type: variant, format: value.format } : null) : variant;
            visit(branch, depth + 1);
          }
        };
        visit(schema, 0);
        return [...labels].join(" | ");
      };
      const table = (head, rows) => rows.length ? `<table class="service-map-api-docs-table"><thead><tr>${head.map((cell) => `<th>${cell}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("")}</tbody></table>` : "";
      const operations = Object.entries(document.paths).flatMap(([path, item]) => API_DOC_METHODS.filter((method) => item?.[method]).map((method) => ({ path, method, item, operation: item[method] })));
      const operationMarkup = ({ path, method, item, operation }) => {
        const parameters = [...array(item.parameters), ...array(operation.parameters)];
        const bodies = Object.entries(operation.requestBody?.content || {});
        const security = array(operation.security).flatMap((requirement) => Object.keys(requirement || {}));
        const row = TRANSACTION_ID.test(operation["x-sniper-newest-transaction"] || "") ? operation["x-sniper-newest-transaction"] : null;
        return `<details class="service-map-api-op"><summary><span class="service-map-method ${methodTone(method)}">${escape(method.toUpperCase())}</span><code title="${escape(path)}">${escape(path)}</code>${security.length ? `<span class="service-map-api-auth" title="${escape(security.join(", "))}">${LOCK_ICON}</span>` : ""}<span class="service-map-muted">${rowCount(count(operation["x-sniper-requests"]))}</span></summary><div class="service-map-api-op-body">${parameters.length ? `<h5>Parameters</h5>${table(["Name", "In", "Type"], parameters.map((parameter) => [`<code>${escape(parameter.name)}</code>${parameter.required ? ' <span class="service-map-muted">required</span>' : ""}`, escape(parameter.in), escape(typeOf(parameter.schema))]))}` : ""}${bodies.length ? `<h5>Request body</h5>${bodies.map(([media, value]) => `<p><code>${escape(media)}</code></p>${table(["Field", "Type"], Object.entries(value?.schema?.properties || {}).map(([name, schema]) => [`<code>${escape(name)}</code>`, escape(typeOf(schema))]))}`).join("")}` : ""}<h5>Responses</h5>${table(["Status", "Description", "Media type"], Object.entries(operation.responses || {}).map(([status, response]) => [escape(status), escape(response?.description || ""), Object.keys(response?.content || {}).map((media) => `<code>${escape(media)}</code>`).join(" ")]))}${security.length ? `<h5>Credentials sent</h5><p>${security.map((key) => `<code>${escape(key)}</code>`).join(" · ")}</p>` : ""}${row ? `<button class="secondary-action" type="button" data-api-docs-replay="${escape(row)}">Send newest row to Replay</button>` : ""}</div></details>`;
      };
      return `<p class="service-map-muted">${escape(document.info?.description || "")}</p>${Object.keys(schemes).length ? `<h4>Credentials</h4>${table(["Scheme", "Sent as"], Object.entries(schemes).map(([key, scheme]) => [`<code>${escape(key)}</code>`, escape(schemeText(scheme))]))}` : ""}<h4>Operations · ${operations.length.toLocaleString()}</h4>${operations.map(operationMarkup).join("") || "<p class=\"empty-copy\">No API operations in this origin's retained rows.</p>"}`;
    }
    // An endpoint's parameters are read as soon as it is opened, not behind a
    // button: each name, where it was sent and a few values, from its newest rows.
    function cancelParameters() {
      state.parametersRequestId += 1;
      parametersAbort?.abort();
      parametersAbort = null;
      Object.assign(state, { parameters: null, parametersKey: null, parametersLoading: false, parametersError: "" });
    }
    // Not the history version: every captured row moves it, and would reread
    // an open endpoint's parameters each poll.
    const endpointParametersKey = (originId, endpoint) => JSON.stringify([
      getSessionId(), state.snapshot?.snapshot.generation, originId, endpoint.method, endpoint.path,
    ]);
    async function loadParameters(originId, endpoint) {
      const key = endpointParametersKey(originId, endpoint);
      if (state.parametersKey === key && (state.parameters || state.parametersLoading)) return;
      cancelParameters();
      const requestId = ++state.parametersRequestId;
      const sessionId = getSessionId();
      parametersAbort = new AbortController();
      const current = () => requestId === state.parametersRequestId && sessionId === getSessionId()
        && key === endpointParametersKey(originId, endpoint);
      Object.assign(state, { parametersKey: key, parameters: null, parametersLoading: true, parametersError: "" });
      renderDetail();
      try {
        const params = new URLSearchParams({ session_id: sessionId, origin: originId, method: endpoint.method, path: endpoint.path });
        const response = await request(`/api/target/service-map/parameters?${params}`, { signal: parametersAbort.signal });
        if (!response.ok) throw new Error("Parameters unavailable");
        const result = await response.json();
        if (!current()) return;
        if (result.schema_version !== 1 || result.session_id !== sessionId || result.origin !== originId || result.method !== endpoint.method || result.path !== endpoint.path) throw new Error("Parameters changed");
        state.parameters = result.available === true ? {
          rows: count(result.rows), moreRows: result.more_rows === true, omitted: count(result.omitted_parameters), unreadBodies: count(result.unread_bodies),
          items: array(result.parameters).filter((item) => typeof item?.name === "string" && ["query", "form", "json", "multipart"].includes(item.location))
            .map((item) => ({ name: item.name, location: item.location, rows: count(item.rows), examples: array(item.examples).filter((value) => typeof value === "string") })),
        } : null;
        state.parametersError = result.available === true ? "" : array(result.reasons).includes("inactive_session") ? "Parameters are read from the active session only." : "Parameters unavailable.";
      } catch {
        if (!current()) return;
        state.parametersError = "Parameters unavailable.";
      }
      state.parametersLoading = false;
      parametersAbort = null;
      renderDetail();
    }
    async function refresh({ force = false, retry = false } = {}) {
      if (!canRefresh()) return false;
      const sessionId = getSessionId();
      if (state.sessionId !== sessionId) reset();
      if (!sessionId || state.refreshPaused && !retry || state.loading && !force) return false;
      clearRefreshTimer();
      if (force || retry) state.busyRetries = 0;
      // A same-source background snapshot must
      // not erase an explicit inspection or continually abort its pending read.
      if (force) {
        replayActionId += 1;
        cancelFlow();
        cancelParameters();
        clearOverlay("Temporary body references cleared by Reload. Inspect and show references again when ready.");
        closeApiDocs();
        cancelBodyReferences();
        cancelHtmlGenerators();
        cancelPeerMatches();
      }
      abort?.abort();
      abort = new AbortController();
      const requestId = ++state.requestId;
      const scopeOnly = state.scopeOnly;
      const filterQuery = getFilterQuery();
      const filterSignature = JSON.stringify(filterQuery);
      const historyVersion = state.historyVersion;
      const current = () => canRefresh() && requestId === state.requestId && sessionId === getSessionId()
        && scopeOnly === state.scopeOnly && filterSignature === JSON.stringify(getFilterQuery());
      state.backgroundLoading = !!state.snapshot && !force;
      state.loading = true;
      state.error = "";
      renderStatus();
      if (!state.snapshot || force) render();
      let failure = null;
      try {
        // The Service Map filter's conditions use HTTP history's parameter names.
        // Every retained row, not a newest-rows window. The server serves an
        // unchanged or recent whole-history map from its cache. A history event
        // bypasses the build-cost cooldown without the manual Reload's resets;
        // fresh=true still reuses a complete, unchanged map. Clean polls keep
        // progressing body enrichment, whose completion is private to the cache
        // and is deliberately not inferred from snapshot.complete (display caps).
        const params = new URLSearchParams({ ...filterQuery, session_id: sessionId, in_scope_only: String(scopeOnly), all_rows: "true", ...(force || !state.snapshot || state.stale ? { fresh: "true" } : {}) });
        const response = await request(`/api/target/service-map?${params}`, { signal: abort.signal, headers: { [TECHNOLOGY_CATALOG_HEADER]: String(TECHNOLOGY_CATALOG_VERSION) } });
        if (!response.ok) {
          failure = mapFailure(response);
          throw new Error("Service map unavailable");
        }
        const snapshot = normalizeSnapshot(await response.json(), sessionId);
        if (!current()) return false;
        if (!force && !state.stale && historyVersion === state.historyVersion
          && typeof snapshot.snapshot.id === "string" && snapshot.snapshot.id
          && snapshot.snapshot.id === state.snapshot?.snapshot.id
          && snapshot.snapshot.generation === state.snapshot.snapshot.generation
          && snapshot.technologyCatalogVersion === state.snapshot.technologyCatalogVersion
          && filterSignature === state.filterSignature
          && state.kindSignature === JSON.stringify(hiddenLinkKinds())
          && state.siteDisplaySignature === JSON.stringify(siteDisplay())
          && !(state.flowOrigin && !state.flow)
          && !(state.endpointSelection && state.parametersKey === null)
          && JSON.stringify(snapshot) === JSON.stringify(state.snapshot)) {
          // Reusing serialized cache bytes must not rebuild the graph or disturb
          // an inspection, scroll position or focused input every five seconds.
          state.loading = false;
          state.busyRetries = 0;
          renderStatus();
          return true;
        }
        clearOverlay("Shown inspections removed: exact sources are no longer verified in the loaded projection or retained history changed.", (layer) =>
          !(layer.kind === "peer" ? peerSourceIsCurrent(layer.source, snapshot) : layer.kind === "link"
            ? htmlGeneratorSourceIsRetained(layer.source, snapshot) : sourceIsRetained(layer.source, snapshot)));
        if (state.snapshot && (state.snapshot.snapshot.generation !== snapshot.snapshot.generation
          || state.snapshot.technologyCatalogVersion !== snapshot.technologyCatalogVersion)) {
          cancelEvidence();
          closeApiDocs();
        }
        if (state.peerMatchesSource && !peerSourceIsCurrent(state.peerMatchesSource, snapshot)) cancelPeerMatches();
        if (state.linkDeclarationsSource && !htmlGeneratorSourceIsRetained(state.linkDeclarationsSource, snapshot)) cancelBodyReferences();
        if (state.htmlGeneratorsSource && !htmlGeneratorSourceIsRetained(state.htmlGeneratorsSource, snapshot)) cancelHtmlGenerators();
        state.snapshot = snapshot;
        state.refreshPaused = false;
        if (state.flowOrigin) loadFlow();
        state.busyRetries = 0;
        state.stale = historyVersion !== state.historyVersion;
        const allOrigins = graphOrigins();
        // Another filter counts other rows, and other hidden request kinds draw
        // other links, wherever either changed (the dialog, a loaded setting,
        // another window): rank the cards again for them.
        const kindSignature = JSON.stringify(hiddenLinkKinds());
        if (state.filterSignature !== undefined && (state.filterSignature !== filterSignature || state.kindSignature !== kindSignature)) {
          state.order = [];
          state.layoutSlots = new Map();
        }
        state.filterSignature = filterSignature;
        state.kindSignature = kindSignature;
        state.order = state.order.length ? stableOrder(state.order, allOrigins) : relationshipOrder(allOrigins, hiddenLinkKinds());
        if (state.anchorOrigin && !findOrigin(state.anchorOrigin)) {
          state.anchorOrigin = null;
          state.modeNotice = "Direct relations cleared: the pinned origin is absent from this snapshot.";
        }
        if (!findOrigin(state.selectedOrigin)) {
          cancelEvidence();
          state.selectedOrigin = state.selectionInitialized ? null : state.order[0] || null;
          state.endpointIndex = null;
          state.endpointSelection = null;
        }
        if (state.selectedOrigin) state.selectionInitialized = true;
        const origin = selectedOrigin();
        if (state.endpointSelection) {
          const index = origin?.endpoints.findIndex((endpoint) => endpoint.method === state.endpointSelection.method && endpoint.path === state.endpointSelection.path) ?? -1;
          state.endpointIndex = index < 0 ? null : index;
          if (index < 0) { state.endpointSelection = null; cancelEvidence(); }
        }
        const endpoint = origin?.endpoints[state.endpointIndex];
        if (!endpoint || state.parametersKey && state.parametersKey !== endpointParametersKey(origin.origin, endpoint)) cancelParameters();
        // Reload and history invalidation preserve selection, never the old
        // retained values. Resume only after a current map verifies the endpoint.
        if (visible && endpoint && !state.stale && state.parametersKey === null) loadParameters(origin.origin, endpoint);
        if (state.evidenceId && !(state.peerEvidenceBinding ? peerBindingIsCurrent(state.peerEvidenceBinding) : evidenceItems(origin).some((item) => item.id === state.evidenceId))) cancelEvidence();
        reconcileEndpointPages();
        state.loading = false;
        render();
        return true;
      } catch (_) {
        if (!current()) return false;
        // Another read outlasted the server's wait for it. It is still running
        // and finishes, so the next poll asks again and nothing shown is stale
        // for it; only a long run of these pauses, as other failures do.
        if (failure?.status === 429 && ++state.busyRetries <= MAX_BUSY_RETRIES) {
          state.loading = false;
          state.refreshPaused = false;
          render();
          return false;
        }
        clearOverlay("Temporary body references cleared because the current refresh failed.");
        cancelBodyReferences();
        cancelHtmlGenerators();
        state.loading = false;
        cancelPeerMatches();
        if (failure?.status === 409) {
          cancelFlow();
          cancelEvidence();
          closeApiDocs();
          cancelParameters();
        }
        // Polling, visibility and event reconnects must not turn a bounded
        // failure into an automatic retry loop, including with older servers.
        state.refreshPaused = true;
        state.stale = true;
        state.error = failure?.message || (state.snapshot ? "Reload failed." : "Could not load the service map.");
        render();
        return false;
      } finally {
        if (requestId === state.requestId) {
          abort = null;
          state.loading = false;
          renderStatus();
          scheduleAutomaticRefresh();
        }
      }
    }
    function evidenceItems(origin) {
      if (!origin || !origin.captured) return [];
      const endpoint = state.endpointIndex === null ? null : origin.endpoints[state.endpointIndex];
      const items = [];
      const seen = new Set();
      const add = (ids, label) => ids.forEach((id) => { if (!seen.has(id)) { seen.add(id); items.push({ id, label }); } });
      if (endpoint) add(endpoint.evidence, `${endpoint.method} ${endpoint.path}`);
      else {
        origin.endpoints.forEach((item) => add(item.evidence, `${item.method} ${item.path}`));
        origin.technology_clues.forEach((item) => add(item.evidence, `${item.name} · header clue`));
        origin.technology_observations.forEach((item) => add(item.evidence, productText(item)));
        origin.redirects.forEach((item) => add(item.evidence, `Redirect instruction → ${item.target_origin}`));
        origin.header_links.forEach((item) => add(item.evidence, `${item.relationship === "origin_header" ? "Origin" : "Referer"} header: ${item.source_origin}`));
        // Each section's own View source reads one of these. The endpoint
        // samples keep only the newest rows, so a token from an older row was
        // refused and the button did nothing.
        array(origin.auth).forEach((item) => add(item.evidence, `${authName(item)} · authentication`));
        array(origin.server_technologies).forEach((item) => add(item.evidence, `${item.name} · ${item.category === "exposure" ? "exposure" : "server"}`));
        ["banners", "headers", "cookies"].forEach((kind) => array(origin.unnamed?.[kind]).forEach((signal) => add(signal.evidence, `${signal.value} · unnamed`)));
        array(state.snapshot?.origins).forEach((page) => array(page.front_technologies)
          .filter((item) => item.source_origin === origin.origin).forEach((item) => add(item.evidence, `${item.name} · front-end`)));
      }
      return items;
    }
    async function loadEvidence(id) {
      // Preserve the ordinary evidence guard. When a default-map token is also
      // in the shown peer response, additionally revalidate its observation.
      if (!evidenceItems(selectedOrigin()).some((item) => item.id === id)) return false;
      return loadEvidenceInternal(id, peerSampleBinding(id, state.selectedOrigin));
    }
    async function loadPeerEvidence(id, originId) {
      const binding = peerSampleBinding(id, originId);
      if (!binding) return false;
      selectOrigin(originId);
      if (state.selectedOrigin !== originId) return false;
      return loadEvidenceInternal(id, binding);
    }
    async function loadEvidenceInternal(id, peerBinding) {
      const origin = selectedOrigin();
      if (peerBinding ? !peerBindingIsCurrent(peerBinding) || peerBinding.sample.evidence_id !== id || peerBinding.origin !== origin?.origin
        : !evidenceItems(origin).some((item) => item.id === id)) return false;
      cancelEvidence();
      state.peerEvidenceBinding = peerBinding;
      const requestId = ++state.evidenceRequestId;
      const sessionId = getSessionId();
      const selected = state.selectedOrigin;
      const overlaySource = () => state.relationLayers.find((layer) => layer.kind !== "peer"
        && layer.source.evidenceId === id && layer.source.origin === selected)?.source || null;
      const endpoint = state.endpointIndex === null ? null : origin.endpoints[state.endpointIndex];
      state.evidenceId = id;
      state.evidenceLoading = true;
      state.detailTab = "evidence";
      evidenceAbort = new AbortController();
      renderDetail();
      try {
        const params = new URLSearchParams({ session_id: sessionId, evidence_id: id, include_socket_peer: "true" });
        const response = await request(`/api/target/service-map/evidence?${params}`, { signal: evidenceAbort.signal, headers: { [TECHNOLOGY_CATALOG_HEADER]: String(TECHNOLOGY_CATALOG_VERSION) } });
        if (!response.ok) throw new Error("Evidence unavailable");
        const result = await response.json();
        if (requestId !== state.evidenceRequestId || sessionId !== getSessionId() || selected !== state.selectedOrigin) return false;
        if (result.schema_version !== 1 || result.session_id !== sessionId || result.evidence_id !== id
          || result.source !== "captured_http_metadata" || typeof result.available !== "boolean") throw new Error("Evidence source changed");
        const catalogVersion = technologyCatalogVersion(result);
        const row = result.row;
        if (result.available && (!row || row.evidence_id !== id || safeOrigin(row.origin) !== selected
          || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(row.record_id || "") || typeof row.sequence !== "string" || !/^[0-9]+$/.test(row.sequence)
          || typeof row.method !== "string" || typeof row.path !== "string"
          || endpoint && (row.method !== endpoint.method || safePath(row.path) !== endpoint.path))) throw new Error("Evidence row changed");
        // Legacy metadata treats evidence IDs as opaque. For versioned IDs,
        // bind every verified read to the exact retained identity, not just peer
        // reads: a well-formed UUID/sequence can still describe another row.
        if (result.available && id.startsWith("v1.") && (!validTechnologyEvidence(id, sessionId, state.snapshot?.snapshot.generation)
          || row.sequence !== id.split(".")[3] || row.record_id.toLowerCase() !== id.split(".")[5].toLowerCase())) throw new Error("Evidence identity changed");
        const normalizedPeer = result.available ? normalizeSocketPeer(result.socket_peer) : null;
        if (peerBinding && (!peerBindingIsCurrent(peerBinding) || result.available && (row.origin !== peerBinding.origin
          || row.sequence !== peerBinding.sample.sequence || row.sequence !== id.split(".")[3] || row.record_id !== id.split(".")[5]
          || row.started_at !== peerBinding.sample.started_at || normalizedPeer?.observedAt !== peerBinding.sample.observed_at
          || !peerEquals(peerBinding.overlay.scan.peer, normalizedPeer)))) throw new Error("Recorded peer source changed");
        const source = overlaySource();
        if (result.available && source && (row.method !== source.method || safePath(row.path) !== source.path
          || row.sequence !== source.sequence || row.started_at !== source.startedAt)) throw new Error("Overlay source changed");
        state.evidence = result.available === true ? normalizeEvidenceObservations(row, catalogVersion) : null;
        state.evidenceCatalogVersion = state.evidence ? catalogVersion : null;
        state.evidenceLegacyCatalog = !!state.evidence && catalogVersion !== TECHNOLOGY_CATALOG_VERSION;
        state.socketPeer = state.evidence ? normalizedPeer : null;
        state.evidenceError = state.evidence ? "" : "Source unavailable. The retained row may have changed or been removed. Reload the map to select current evidence.";
        state.evidenceLoading = false;
        if (!state.evidence && peerBinding) {
          handlePeerSampleUnavailable(peerBinding);
          render();
        } else if (!state.evidence && source) {
          clearOverlay("Shown inspections removed: the exact inspected source is no longer available.", (layer) => layer.source.evidenceId === id);
          render();
        } else renderDetail();
        if (state.evidence && mountPacketViewer) loadPacket("current");
        return !!state.evidence;
      } catch (_) {
        if (requestId !== state.evidenceRequestId || sessionId !== getSessionId() || selected !== state.selectedOrigin) return false;
        state.evidence = null;
        state.evidenceCatalogVersion = null;
        state.evidenceLegacyCatalog = false;
        state.socketPeer = null;
        cancelBodyReferences();
        cancelHtmlGenerators();
        state.evidenceLoading = false;
        state.evidenceError = "Source unavailable. The exact retained row could not be verified. Reload the map and try again.";
        if (peerBinding) {
          handlePeerSampleUnavailable(peerBinding);
          render();
        } else if (overlaySource()) {
          clearOverlay("Shown inspections removed: the exact inspected source could not be verified.", (layer) => layer.source.evidenceId === id);
          render();
        } else renderDetail();
        return false;
      }
    }
    async function loadBodyReferences() {
      const row = state.evidence;
      const sessionId = getSessionId();
      if (activeInspectionsBlocked() || state.relationshipKind !== "body" || !visible || state.sessionId !== sessionId || !row || state.evidenceId !== row.evidence_id
        || state.evidenceLoading || state.bodyReferencesLoading
        || !evidenceItems(selectedOrigin()).some((item) => item.id === row.evidence_id)) return false;
      state.packetInspection = "body";
      cancelBodyReferences();
      const requestId = ++state.bodyReferencesRequestId;
      const evidenceId = row.evidence_id;
      const selected = state.selectedOrigin;
      const generation = state.snapshot?.snapshot.generation;
      const current = () => requestId === state.bodyReferencesRequestId && state.relationshipKind === "body" && visible && sessionId === getSessionId()
        && sessionId === state.sessionId && selected === state.selectedOrigin && row === state.evidence && evidenceId === state.evidenceId
        && generation === state.snapshot?.snapshot.generation;
      state.bodyReferencesLoading = true;
      bodyReferencesAbort = new AbortController();
      renderDetail();
      try {
        const params = new URLSearchParams({ session_id: sessionId, evidence_id: evidenceId });
        const response = await request(`/api/target/service-map/body-references?${params}`, { signal: bodyReferencesAbort.signal });
        if (!response.ok) throw new Error("Retained body references unavailable");
        const payload = await response.json();
        if (!current()) return false;
        state.bodyReferences = normalizeBodyReferences(payload, sessionId, evidenceId, row);
        state.bodyReferencesSource = Object.freeze({ sessionId, generation, evidenceId, origin: safeOrigin(row.origin),
          method: row.method, path: safePath(row.path), sequence: row.sequence, startedAt: row.started_at });
        state.bodyReferencesLoading = false;
        bodyReferencesAbort = null;
        if (!handleSupplementLifetime(state.bodyReferences, state.bodyReferencesSource)) renderDetail();
        return true;
      } catch (_) {
        if (!current()) return false;
        state.bodyReferencesLoading = false;
        bodyReferencesAbort = null;
        state.bodyReferencesError = "Could not verify retained body references. Retry explicitly, or refresh the map and select the source again.";
        renderDetail();
        return false;
      }
    }
    function setRelationshipKind(kind) {
      if (!["body", "link"].includes(kind) || kind === state.relationshipKind) return false;
      replayActionId += 1;
      cancelBodyReferences();
      state.relationshipKind = kind;
      renderDetail();
      return true;
    }
    async function loadLinkDeclarations() {
      const row = state.evidence, sessionId = getSessionId(), generation = state.snapshot?.snapshot.generation;
      if (activeInspectionsBlocked() || state.relationshipKind !== "link" || !visible || !getEventStreamReady() || state.error || state.stale
        || state.sessionId !== sessionId || !row || state.evidenceId !== row.evidence_id || state.evidenceLoading || state.bodyReferencesLoading
        || !validHtmlGeneratorEvidence(row.evidence_id, sessionId, generation) || row.evidence_id.split(".")[3] !== row.sequence
        || row.evidence_id.split(".")[5] !== row.record_id || safeOrigin(row.origin) !== row.origin || observationTime(row.started_at) === null
        || !evidenceItems(selectedOrigin()).some((item) => item.id === row.evidence_id)) return false;
      state.packetInspection = "link";
      const source = Object.freeze({ sessionId, generation, evidenceId: row.evidence_id, origin: row.origin,
        method: row.method, path: safePath(row.path), sequence: row.sequence, startedAt: row.started_at });
      if (!htmlGeneratorSourceIsRetained(source)) return false;
      cancelBodyReferences();
      const requestId = ++state.bodyReferencesRequestId, selected = state.selectedOrigin;
      const current = () => requestId === state.bodyReferencesRequestId && state.relationshipKind === "link" && visible
        && getEventStreamReady() && !state.error && !state.stale && sessionId === getSessionId() && sessionId === state.sessionId
        && selected === state.selectedOrigin && row === state.evidence && source.evidenceId === state.evidenceId && htmlGeneratorSourceIsRetained(source);
      state.linkDeclarationsSource = source;
      state.bodyReferencesLoading = true;
      bodyReferencesAbort = new AbortController();
      renderDetail();
      let unsupportedServer = false;
      try {
        const params = new URLSearchParams({ session_id: sessionId, evidence_id: source.evidenceId });
        const response = await request(`/api/target/service-map/link-declarations?${params}`, { signal: bodyReferencesAbort.signal });
        unsupportedServer = response.status === 404;
        if (!response.ok) throw new Error("Retained Link headers unavailable");
        const payload = await response.json();
        if (!current()) return false;
        state.linkDeclarations = normalizeLinkDeclarations(payload, sessionId, source.evidenceId, row);
        state.bodyReferencesLoading = false;
        bodyReferencesAbort = null;
        if (!handleSupplementLifetime(state.linkDeclarations, source)) renderDetail();
        return true;
      } catch (_) {
        if (!current()) return false;
        state.bodyReferencesLoading = false;
        bodyReferencesAbort = null;
        state.linkDeclarations = null;
        state.linkDeclarationsError = unsupportedServer
          ? "This server does not support retained Link header inspection. No Link declarations were inspected."
          : "Could not verify retained Link headers. Retry explicitly, or refresh the map and select the source again.";
        renderDetail();
        return false;
      }
    }
    function showLinkDeclarationsOnMap() {
      if (state.sessionId !== getSessionId()) { reset(); return false; }
      const scan = state.linkDeclarations, source = state.linkDeclarationsSource;
      if (activeInspectionsBlocked() || state.relationshipKind !== "link" || !visible || !getEventStreamReady() || state.error || state.stale
        || !scan || scan.status !== "scanned" || !htmlGeneratorSourceIsRetained(source)
        || state.evidenceId !== source.evidenceId || state.selectedOrigin !== source.origin
        || !scan.observations.some((item) => item.target_origin !== source.origin)) return false;
      const observations = Object.freeze(scan.observations.map((item) => Object.freeze({ ...item,
        link_value_span: Object.freeze({ ...item.link_value_span }), target_span: Object.freeze({ ...item.target_span }), relation_span: Object.freeze({ ...item.relation_span }) })));
      const layer = Object.freeze({ kind: "link", source: Object.freeze({ ...source }), scan: Object.freeze({
        status: scan.status, complete: scan.complete, reasons: Object.freeze([...scan.reasons]), observations,
        counts: Object.freeze({ ...scan.counts }), retained_header_count: scan.retained_header_count,
      }) });
      if (!addRelationLayer(layer)) return false;
      if (state.view !== "service-map") { state.view = "service-map"; onViewChange?.("service-map"); }
      render();
      return true;
    }
    function htmlGeneratorSourceIsRetained(source, snapshot = state.snapshot) {
      if (!sourceIsRetained(source, snapshot)) return false;
      const origin = snapshot.origins.find((item) => item.origin === source.origin);
      return origin.endpoints.filter((item) => item.evidence.includes(source.evidenceId))
        .every((item) => item.method === source.method && item.path === source.path);
    }
    async function loadHtmlGenerators() {
      const row = state.evidence, sessionId = getSessionId(), generation = state.snapshot?.snapshot.generation;
      if (activeInspectionsBlocked() || !visible || !getEventStreamReady() || state.error || state.stale || state.sessionId !== sessionId || !row
        || state.evidenceId !== row.evidence_id || state.evidenceLoading || state.htmlGeneratorsLoading
        || !validHtmlGeneratorEvidence(row.evidence_id, sessionId, generation)
        || row.evidence_id.split(".")[3] !== row.sequence || row.evidence_id.split(".")[5] !== row.record_id
        || safeOrigin(row.origin) !== row.origin || observationTime(row.started_at) === null
        || !evidenceItems(selectedOrigin()).some((item) => item.id === row.evidence_id)) return false;
      state.packetInspection = "generator";
      const source = Object.freeze({ sessionId, generation, evidenceId: row.evidence_id, origin: row.origin,
        method: row.method, path: safePath(row.path), sequence: row.sequence, startedAt: row.started_at });
      if (!htmlGeneratorSourceIsRetained(source)) return false;
      cancelHtmlGenerators();
      const requestId = ++state.htmlGeneratorsRequestId, selected = state.selectedOrigin;
      const current = () => requestId === state.htmlGeneratorsRequestId && visible && getEventStreamReady() && !state.error && !state.stale
        && sessionId === getSessionId() && sessionId === state.sessionId && selected === state.selectedOrigin
        && row === state.evidence && source.evidenceId === state.evidenceId && htmlGeneratorSourceIsRetained(source);
      state.htmlGeneratorsSource = source;
      state.htmlGeneratorsLoading = true;
      htmlGeneratorsAbort = new AbortController();
      renderDetail();
      let unsupportedServer = false;
      try {
        const params = new URLSearchParams({ session_id: sessionId, evidence_id: source.evidenceId });
        const response = await request(`/api/target/service-map/html-generators?${params}`, { signal: htmlGeneratorsAbort.signal });
        unsupportedServer = response.status === 404;
        if (!response.ok) throw new Error("Retained HTML generators unavailable");
        const payload = await response.json();
        if (!current()) return false;
        state.htmlGenerators = normalizeHtmlGenerators(payload, sessionId, source.evidenceId, row);
        state.htmlGeneratorsLoading = false;
        htmlGeneratorsAbort = null;
        if (!handleSupplementLifetime(state.htmlGenerators, source)) renderDetail();
        return true;
      } catch (_) {
        if (!current()) return false;
        state.htmlGeneratorsLoading = false;
        htmlGeneratorsAbort = null;
        state.htmlGenerators = null;
        state.htmlGeneratorsError = unsupportedServer
          ? "This server does not support retained HTML generator inspection. No generator declarations were inspected."
          : "Could not verify retained HTML generators. Retry explicitly, or refresh the map and select the source again.";
        renderDetail();
        return false;
      }
    }
    function renderStatus() {
      if (destroyed) return;
      // Re-rendered with the status so a filter restored from settings shows.
      if (els.filterSummary) {
        const summary = getFilterSummary();
        els.filterSummary.textContent = summary?.text || "";
        els.filterSummary.title = summary?.detail || "";
      }
      if (!els.status) return;
      const snapshot = state.snapshot?.snapshot;
      let status = "Open a session to view its retained history.";
      if (state.loading && !snapshot) status = "Loading retained HTTP metadata…";
      if (snapshot) {
        status = `${count(snapshot.considered_rows).toLocaleString()} rows considered / ${count(snapshot.retained_rows).toLocaleString()} retained · ${state.snapshot.origins.length.toLocaleString()} origins`;
        status += snapshot.complete === true ? " · Complete retained snapshot" : ` · Incomplete: ${array(snapshot.stopped_by).join(", ") || "projection bounds reached"}`;
        status += ` · ${count(snapshot.included_rows)} included / ${count(snapshot.excluded_rows)} excluded / ${count(snapshot.omitted_rows)} omitted among analyzed`;
        if (count(snapshot.filtered_rows)) status += ` · ${count(snapshot.filtered_rows).toLocaleString()} hidden by the Service Map filter`;
        status += ` · Newest capture-sequence window: ${snapshot.oldest_considered_at || "unknown"} to ${snapshot.latest_considered_at || "unknown"}`;
        if (array(snapshot.stopped_by).includes("technology_token_scan_limit")) status += " · Header technology scan partial: token candidate limit reached";
        if (state.snapshot.legacyCatalog) status += ` · ${LEGACY_CATALOG_NOTICE}`;
        if (state.scopeOnly) status += " · In scope only";
        if (state.stale) status += state.refreshPaused ? " · Stale snapshot: counts have not been revalidated" : " · History changed: counts are from the previous snapshot";
        if (state.snapshot.warningCount) status += ` · ${state.snapshot.warningCount} metadata notice${state.snapshot.warningCount === 1 ? "" : "s"}`;
      }
      // A deletion/gap can clear the retained snapshot while refresh is paused.
      // Derive this suffix now so it never claims cleared data is still shown.
      const error = state.refreshPaused && state.error
        ? `${state.error} Automatic refresh paused. ${snapshot ? "Showing the previous snapshot as stale; use Reload to retry." : "Use Reload to retry."}` : state.error;
      if (activeInspectionsBlocked()) status += ` · ${INACTIVE_SESSION_NOTICE}`;
      els.status.textContent = error ? `${error}${snapshot ? ` ${status}` : ""}` : status;
      // Above the map, only what needs attention: an error, or the first load.
      // Counts, coverage and windows stay under Details.
      if (els.alert) {
        const alert = error || (state.loading && !snapshot ? "Loading retained HTTP metadata…" : "");
        els.alert.textContent = alert;
        els.alert.classList.toggle("hidden", !alert);
        els.alert.classList.toggle("service-map-error", !!state.error);
      }
      els.status.classList.toggle("service-map-error", !!state.error);
      els.refresh.disabled = state.loading;
      // Polling must not resize or dim the toolbar on each check. Keep the
      // request guard, but reserve visible progress for initial/manual loads.
      els.refresh.textContent = "Reload";
      els.refresh.classList.toggle("service-map-background-refresh", state.loading && state.backgroundLoading);
      // An initial or manual load turns the shared progress ring in place of
      // the label, as other buttons do; it always reads a fresh map, so the
      // ring would rarely just flash.
      els.refresh.classList.toggle("is-working", state.loading && !state.backgroundLoading);
      els.refresh.classList.toggle("is-working-shown", state.loading && !state.backgroundLoading);
      els.panel.setAttribute("aria-busy", String(state.loading && !state.backgroundLoading));
    }
    // One toggle per request kind seen in the loaded links, with how many links
    // include it; a hidden kind's links are not drawn or ranked.
    function renderLinkKinds() {
      if (!els.linkKinds) return;
      const hidden = new Set(hiddenLinkKinds());
      const links = new Map(REQUEST_KINDS.map((kind) => [kind, 0]));
      // In Flow they count the flow's requests, which they hide or draw.
      const flow = !!state.flowOrigin;
      if (flow) for (const step of (state.flow?.phases || []).flatMap((phase) => phase.steps)) links.set(step.kind, links.get(step.kind) + step.count);
      for (const origin of flow ? [] : state.snapshot?.origins || []) {
        // One link per source, whichever headers named it; older servers send
        // only the per-header counts.
        for (const link of origin.header_sources?.length ? origin.header_sources : origin.header_links || []) {
          // A page naming its own origin is no link and is never drawn.
          if (link.source_origin === origin.origin) continue;
          for (const [kind] of linkKindCounts(link)) links.set(kind, links.get(kind) + 1);
        }
      }
      const counted = (n) => flow ? `${n} request${n === 1 ? "" : "s"} in this flow` : `${n} Origin/Referer link${n === 1 ? "" : "s"}`;
      const toggles = REQUEST_KINDS.filter((kind) => links.get(kind) > 0).map((kind) => `<button class="service-map-kind kind-${kind}" type="button" data-link-kind="${kind}" data-service-focus="link-kind:${kind}" aria-pressed="${!hidden.has(kind)}" title="${REQUEST_KIND_LABELS[kind]}: ${counted(links.get(kind))}. ${hidden.has(kind) ? "Draw" : "Hide"} them."><span class="service-map-kind-swatch" aria-hidden="true"></span>${REQUEST_KIND_LABELS[kind]} ${links.get(kind)}</button>`).join("");
      replace(els.linkKinds, toggles ? `<span class="service-map-kinds-label">${flow ? "Requests:" : "Links by request:"}</span>${toggles}` : "");
    }
    // Group by site, and every origin or site hidden from the map with a way
    // back for each.
    function renderSiteControls() {
      if (!els.siteControls) return;
      const display = siteDisplay();
      replace(els.siteControls, `<button class="service-map-kind" type="button" data-service-group-sites="toggle" data-service-focus="sites:group" aria-pressed="${display.groupSites}" title="${display.groupSites ? "Show every origin on its own card" : "Gather the origins of one site onto one card"}">Group by site</button>${display.hidden.length ? `<details class="service-map-hidden-list"><summary data-service-focus="sites:hidden">Hidden ${display.hidden.length}</summary>${display.hidden.map((entry) => `<button class="service-map-kind" type="button" data-service-unhide="${escape(entry)}" data-service-focus="unhide:${escape(entry)}" title="Show ${escape(entry)} on the map again">${escape(entry.includes("://") ? entry : `*.${entry}`)} ✕</button>`).join("")}<button class="service-map-kind" type="button" data-service-unhide-all="all" data-service-focus="sites:unhide-all">Show all</button></details>` : ""}`);
    }
    const clientById = (id) => state.snapshot?.clients?.find((client) => clientId(client) === id) || null;
    // Clients lead the map in a column of their own, with an arrow to each card
    // they sent rows to themselves, with no Origin or Referer (a typed address,
    // a bookmark, an app's call). A page's own requests already have the page's
    // arrow. Unselected, a client points only at cards no other card links to,
    // where the map starts; an app's background calls to every card it also
    // reached through a page covered the map. Selected, it points at them all.
    function clientCards(grouped, cardOrder, hidden) {
      const known = new Set(grouped.cards.map((card) => card.origin));
      const shown = new Set(cardOrder.filter((id) => known.has(id)).slice(0, MAX_CARDS));
      const linked = new Set();
      for (const card of grouped.cards.filter((item) => shown.has(item.origin))) {
        for (const redirect of card.redirects) if (redirect.target_origin !== card.origin) linked.add(redirect.target_origin);
        if (card.header_links.some((link) => link.source_origin !== card.origin && shown.has(link.source_origin)
          && linkKindCounts(link).some(([kind]) => !hidden.has(kind)))) linked.add(card.origin);
      }
      const cards = [], links = new Map();
      for (const client of state.snapshot?.clients || []) {
        // A User-Agent no rule names says nothing about who sent the rows.
        if (cards.length >= MAX_CLIENT_CARDS || client.kind === "unknown") continue;
        const id = clientId(client);
        const visits = client.origins.filter((item) => shown.has(grouped.card(item.origin)) && Object.keys(item.entry_kinds).some((kind) => !hidden.has(kind)));
        if (!visits.length) continue;
        cards.push({ ...referenceOrigin(id), client, captured: true, in_scope: true, request_count: client.request_count });
        for (const item of state.selectedClient === id ? visits : visits.filter((visit) => !linked.has(grouped.card(visit.origin)))) {
          const target = grouped.card(item.origin);
          if (!links.has(target)) links.set(target, []);
          links.get(target).push({ source_origin: id, relationship: "client_request", request_kinds: item.entry_kinds, request_count: directRows(item) });
        }
      }
      return { cards, links };
    }
    // A card shows its origin's icon only once the image has loaded, so a
    // failed one keeps the role mark rather than a broken image. Loads redraw
    // the graph once between them.
    const favicons = new Map();
    let faviconRedraw = null;
    function faviconSource(origin) {
      if (!origin.favicon || typeof Image !== "function") return null;
      const token = origin.favicon;
      const source = `/api/target/service-map/favicon?${new URLSearchParams({ session_id: token.split(".")[1], evidence_id: token })}`;
      if (!favicons.has(token)) {
        favicons.set(token, false);
        const image = new Image();
        image.onload = () => {
          if (destroyed) return;
          favicons.set(token, true);
          faviconRedraw ??= setTimeout(() => { faviconRedraw = null; if (!destroyed) renderGraph(); }, 0);
        };
        image.src = source;
      }
      return favicons.get(token) ? source : null;
    }
    function renderGraph() {
      if (destroyed) return;
      syncFlowCopyKinds();
      if (state.flowOrigin) return renderFlow();
      const selected = selectedOrigin();
      const direct = directNeighborhood();
      const query = state.query.trim().toLowerCase();
      const display = siteDisplay();
      // Origins and sites hidden from the map leave it, whatever else shows them.
      // So does an origin whose rows carried no typed response, which names no
      // role, unless it is selected, pinned or searched for; the API list and
      // the inspector keep it.
      const typed = (origin) => origin.captured === false || originRole(origin) !== "unknown" || origin.origin === state.selectedOrigin
        || origin.origin === state.anchorOrigin || !!query && origin.origin.toLowerCase().includes(query);
      const shown = (origin) => origin.endpointNode || typed(origin) && !display.hidden.includes(origin.origin) && !display.hidden.includes(siteKey(origin.origin));
      const candidates = direct ? direct.neighbors : graphOrigins().filter((origin) => !state.scopeOnly || origin.in_scope || !origin.captured);
      const untyped = candidates.filter((origin) => !origin.endpointNode && !typed(origin)).length;
      const stages = originFilterStages(candidates.filter(shown));
      const matchingNeighbors = direct ? stages.matching : [];
      const anchorShown = direct && shown(direct.anchor);
      const origins = direct ? [...(anchorShown ? [direct.anchor] : []), ...matchingNeighbors] : stages.matching;
      const neighborOrder = direct ? stableOrder(state.order, matchingNeighbors) : [];
      const collectionIds = new Set(overlayEdges().flatMap((edge) => [edge.source, edge.target]));
      const allOrder = stableOrder(state.order, origins);
      const sourceIds = new Set(state.relationLayers.map((layer) => layer.source.origin));
      // Overview ordering needs membership only; rescanning every origin for
      // every ID made redraws quadratic even when no address nodes were shown.
      const endpointNodeIds = direct ? null : new Set(origins.filter((item) => item.endpointNode).map((item) => item.origin));
      const order = direct ? [direct.anchor.origin, ...neighborOrder.filter((id) => direct.bodyIds.has(id)), ...neighborOrder.filter((id) => !direct.bodyIds.has(id))]
        : [...allOrder.filter((id) => endpointNodeIds.has(id)), ...allOrder.filter((id) => sourceIds.has(id)), ...allOrder.filter((id) => collectionIds.has(id) && !sourceIds.has(id) && !endpointNodeIds.has(id)), ...allOrder.filter((id) => !collectionIds.has(id))];
      state.siteDisplaySignature = JSON.stringify(display);
      const filterKey = JSON.stringify([query, state.productId, state.productVersion, state.scopeOnly, state.sessionId, state.anchorOrigin, hiddenLinkKinds(), display]);
      if (state.layoutFilter !== filterKey) { state.layoutSlots = new Map(); state.layoutFilter = filterKey; }
      const textSize = doc?.documentElement && typeof root.getComputedStyle === "function"
        ? Number.parseFloat(root.getComputedStyle(doc.documentElement).getPropertyValue("--ui-root-size")) : 12;
      // A site gathers its origins onto one card, except the leading origin's
      // site, a site shown separately, and one holding the pinned origin or an
      // inspection, which need their own cards.
      const leadingSite = siteKey(allOrder.find((id) => siteKey(id)) || "");
      const grouped = groupSites(origins, (site) => !display.groupSites || site === leadingSite || display.expandedSites.includes(site)
        || [state.anchorOrigin, ...collectionIds].some((id) => id && siteKey(id) === site));
      state.siteCards = new Map(grouped.cards.filter((card) => card.site).map((card) => [card.site, card]));
      const selectedCard = state.selectedClient || (state.selectedSite ? `site:${state.selectedSite}` : grouped.card(state.selectedOrigin));
      const cardOrder = [...new Set(order.map(grouped.card))];
      const clients = direct ? { cards: [], links: new Map() } : clientCards(grouped, cardOrder, new Set(hiddenLinkKinds()));
      const linkedCards = grouped.cards.map((card) => clients.links.has(card.origin) ? { ...card, header_links: [...card.header_links, ...clients.links.get(card.origin)] } : card);
      const layout = graphLayout([...clients.cards, ...linkedCards], [...clients.cards.map((card) => card.origin), ...cardOrder], state.layoutSlots, state.anchorOrigin, overlayEdges(), graphGeometry(textSize), hiddenLinkKinds(), clients.cards.length);
      // Status counts origins, not cards: a site card shows all of its own.
      const shownOrigins = layout.nodes.reduce((sum, node) => sum + (node.client ? 0 : node.members?.length || 1), 0);
      // The one count worth seeing without opening Details: cards left out.
      if (els.detailsSummary) els.detailsSummary.textContent = origins.length > shownOrigins ? `Details · ${shownOrigins} / ${origins.length} origins shown` : "Details";
      renderLinkKinds();
      renderSiteControls();
      state.layoutSlots = layout.slots;
      currentLayout = layout.nodes.length ? layout : null;
      applyGraphScale();
      els.boundsDetails?.classList.toggle("hidden", !state.snapshot);
      if (!direct && els.graphDiagnostics) els.graphDiagnostics.textContent = state.snapshot
        ? `${stages.loaded.length} loaded origins · ${stages.queryHidden} query-hidden · ${stages.productHidden} product/version-hidden · ${stages.matching.length} matching · ${shownOrigins} shown · ${Math.max(0, stages.matching.length - shownOrigins)} omitted by ${MAX_CARDS}-card cap. Counts describe only loaded origins and reference cards; server projection omissions and omitted reference declarations are separate. Unloaded products and distinct origins are not counted.` : "";
      els.mapControls?.classList.toggle("hidden", state.view === "apis");
      renderModeButtons(selected);
      if (els.focusSelection) {
        els.focusSelection.classList.toggle("hidden", !state.anchorOrigin);
        els.focusSelection.disabled = !selected || selected.origin === state.anchorOrigin;
        els.focusSelection.title = selected ? `Pin ${selected.origin} without changing its inspector` : "Select an origin to pin it";
      }
      const originSelectionNotice = !selected || layout.nodes.some((node) => node.origin === grouped.card(selected.origin)) ? ""
        : !shown(selected) ? "Selected origin is hidden from the map; inspector retained."
        : direct && !direct.neighbors.some((origin) => origin.origin === selected.origin) ? "Selected origin is outside this direct neighborhood; inspector retained."
        : origins.some((origin) => origin.origin === selected.origin)
        ? `Selected origin is outside the ${MAX_CARDS}-card display; inspector retained.`
        : !direct && !graphOrigins().some((origin) => origin.origin === selected.origin) && (!query || selected.origin.toLowerCase().includes(query))
          ? `Selected origin is outside the ${MAX_REFERENCE_CARDS}-reference-card limit; inspector retained.`
          : "Selected origin is outside this filter; inspector retained.";
      const selectionNotice = state.selectedSite && siteDetails(state.selectedSite) && !layout.nodes.some((node) => node.site === state.selectedSite)
        ? "Selected site has no grouped card in this view; inspector retained." : originSelectionNotice;
      if (!origins.length) {
        if (direct && !anchorShown) {
          replace(els.canvas, '<div class="service-map-empty"><span class="service-map-empty-symbol" aria-hidden="true">◎</span><h3>No visible origins</h3><p>Show hidden origins or change the neighbor filters to see this direct neighborhood.</p></div>');
          els.graphBounds.textContent = [`0 / ${direct.neighbors.length} known direct neighbors shown`, "Pinned anchor is hidden from the map; direct mode retained.", selectionNotice].filter(Boolean).join(" · ");
          if (els.graphDiagnostics) els.graphDiagnostics.textContent = "";
          return;
        }
        replace(els.canvas, `<div class="service-map-empty"><span class="service-map-empty-symbol" aria-hidden="true">◎</span><h3>${state.loading && !state.snapshot ? "Loading service origins…" : state.error && !state.snapshot ? "Service map unavailable" : state.query || state.scopeOnly || state.productId || state.productVersion ? "No matching origins" : "No retained HTTP origins"}</h3><p>${state.query || state.scopeOnly || state.productId || state.productVersion ? "Change the origin search, product/version filters or In scope only." : "This view uses only HTTP history already retained in this session."}</p></div>`);
        els.graphBounds.textContent = ["0 matching origins", untyped ? `${untyped} with no typed response hidden` : "", stages.queryHidden ? `${stages.queryHidden} hidden by query` : "", stages.productHidden ? `${stages.productHidden} hidden by products/versions` : "", state.anchorOrigin ? "Direct relations will resume after a fresh snapshot verifies the pinned origin." : state.modeNotice, selectionNotice].filter(Boolean).join(" · ");
        return;
      }
      // More rows draw a slightly heavier line: 1.5px for one row, 2.5px from 64
      // rows. A real session has hundreds of rows per link, so a steeper scale
      // drew nearly every line at its heaviest.
      const weight = (rows) => rows > 1 ? Math.round(Math.min(2.5, 1.5 + Math.log2(rows) / 6) * 100) / 100 : 0;
      const requests = (edge) => edge.count > 1 || edge.kinds
        ? ` · ${edge.count} request${edge.count === 1 ? "" : "s"}${edge.kinds ? ` (${REQUEST_KINDS.filter((kind) => edge.kinds[kind]).map((kind) => `${REQUEST_KIND_LABELS[kind]} ${edge.kinds[kind]}`).join(", ")})` : ""}${edge.cors?.[0] ? ` · ${corsText(edge.cors)}` : ""}` : "";
      const cardName = (id) => String(id).startsWith("site:") ? `*.${id.slice(5)}` : String(id).startsWith("client:") ? clientName(clientById(id)) : id;
      const title = (edge) => `${escape(cardName(edge.source))} ${edge.undirected ? "—" : "→"} ${escape(edge.undirected ? findOrigin(edge.target)?.address : cardName(edge.target))} · ${escape((edge.labels || [edge.label]).join(" + "))} · ${(edge.relationships || [edge.relationship]).join(", ")}${requests(edge)}${edge.layers ? ` · ${edge.layers.length} inspected source${edge.layers.length === 1 ? "" : "s"}` : ""}`;
      const edges = layout.edges.map((edge) => `<path class="service-map-edge ${edge.undirected ? "peer-observation" : edge.relationship === "body_url_reference" ? "body-reference" : edge.relationship === "link_preconnect" ? "preconnect-hint" : edge.relationship.startsWith("link_") ? "link-declaration" : edge.relationship === "client_request" ? "client-request" : edge.relationship !== "redirect_instruction" ? "header-declaration" : ""}${edge.kind ? ` kind-${edge.kind}` : ""} ${[edge.source, edge.target].includes(selectedCard) ? "selected" : ""}" data-relationship="${edge.relationship}"${weight(edge.count) ? ` style="--edge-weight:${weight(edge.count)}px"` : ""} d="${edge.path}" ${edge.undirected ? "" : `marker-end="url(#service-map-arrow${[edge.source, edge.target].includes(selectedCard) ? "-selected" : edge.kind === "api" ? "-api" : ""})"`}><title>${title(edge)}</title></path>`).join("")
        // Arrows are thin, so a wide transparent stroke over each recorded one
        // takes the pointer: its tooltip, and a click that opens its entry.
        + layout.edges.map((edge, index) => edge.kind ? `<path class="service-map-hit" data-service-edge="${index}" d="${edge.path}"><title>${title(edge)} · Select to list its rows and open a source</title></path>` : "").join("");
      const cards = layout.nodes.map((origin) => {
        if (origin.endpointNode) return `<div class="service-map-card service-map-peer-address" role="group" aria-label="Recorded address match, direct route, ${escape(origin.address)}" style="left:${origin.x}px;top:${origin.y}px"><span class="service-map-card-symbol" aria-hidden="true">◇</span><span class="service-map-card-copy"><strong title="${escape(origin.address)}">${escape(origin.address)}</strong><span class="service-map-card-scheme">Recorded address · direct · ${origin.family.toUpperCase()}</span><span class="service-map-card-meta">Undirected observations only; no shared ownership inferred</span></span></div>`;
        if (origin.client) {
          const selected = selectedCard === origin.origin;
          return `<button class="service-map-card service-map-client ${selected ? "selected" : ""}" type="button" data-service-client="${escape(origin.origin)}" data-service-focus="client:${escape(origin.origin)}" aria-current="${selected}" style="left:${origin.x}px;top:${origin.y}px">
          ${clientRoleMarkup(origin.client)}<span class="service-map-card-copy"><strong title="${escape(clientName(origin.client))}">${escape(clientName(origin.client))}</strong><span class="service-map-card-meta">${origin.client.os ? `${escape(origin.client.os)} · ` : ""}${origin.client.addresses.length === 1 ? `${escape(origin.client.addresses[0])} · ` : origin.client.addresses.length ? `${origin.client.addresses.length} addresses · ` : ""}${rowCount(origin.client.request_count)}</span></span>
        </button>`;
        }
        if (origin.site) {
          const selected = selectedCard === origin.origin;
          return `<button class="service-map-card service-map-site ${!origin.captured ? "referenced" : ""} ${selected ? "selected" : ""}" type="button" data-service-site="${escape(origin.site)}" data-service-focus="site:${escape(origin.site)}" aria-current="${selected}" style="left:${origin.x}px;top:${origin.y}px">
          ${roleMarkup(origin, false, faviconSource(origin))}<span class="service-map-card-copy"><strong title="${escape(origin.members.map((member) => member.origin).join(" · "))}">*.${escape(origin.site)}</strong><span class="service-map-card-meta">${origin.members.length} origins</span><span class="service-map-card-meta">${origin.members.reduce((sum, member) => sum + member.endpoints.length, 0)} API paths · ${origin.request_count.toLocaleString()} sampled rows</span></span>
          <span class="service-map-scope-dot ${!origin.captured ? "hidden" : ""} ${origin.in_scope ? "in-scope" : ""}" title="${origin.in_scope ? "In scope" : "Out of scope"}"></span>
        </button>`;
        }
        const selected = origin.origin === state.selectedOrigin;
        const url = new URL(origin.origin);
        const pinned = origin.origin === state.anchorOrigin;
        return `<button class="service-map-card ${!origin.captured ? "referenced" : ""} ${selected ? "selected" : ""} ${pinned ? "pinned" : ""}" type="button" data-service-origin="${escape(origin.origin)}" data-service-focus="origin:${escape(origin.origin)}" aria-current="${selected}" style="left:${origin.x}px;top:${origin.y}px">
          ${roleMarkup(origin, pinned, faviconSource(origin))}<span class="service-map-card-copy"><strong title="${escape(origin.origin)}">${escape(url.host)}</strong>${productSummaryMarkup(origin)}<span class="service-map-card-meta">${origin.peerInspectionOnly ? "Captured in peer inspection · see evidence" : origin.captured ? `${origin.endpoints.length} API paths · ${origin.request_count.toLocaleString()} sampled rows` : "Referenced only in this snapshot"}</span></span>
          <span class="service-map-scope-dot ${!origin.captured ? "hidden" : ""} ${origin.in_scope ? "in-scope" : ""}" title="${origin.in_scope ? "In scope" : "Out of scope"}"></span>
        </button>`;
      }).join("");
      // An arrowhead takes its line's colour and keeps one size: sized by the
      // stroke, a heavy line grew a large head, and every head was gold.
      const arrowheads = [["service-map-arrow", "--text-dim"], ["service-map-arrow-api", "--service-map-api-edge"], ["service-map-arrow-selected", "--point"]]
        .map(([id, color]) => `<marker id="${id}" viewBox="0 0 8 8" markerUnits="userSpaceOnUse" markerWidth="12" markerHeight="12" refX="7" refY="4" orient="auto" style="color:var(${color})"><path d="M1,1 L7,4 L1,7" fill="none" stroke="currentColor" stroke-width="1.5" /></marker>`).join("");
      replace(els.canvas, `<div class="service-map-scaled"><div class="service-map-layout" style="--service-map-card-width:${layout.geometry.cardWidth}px;--service-map-card-height:${layout.geometry.cardHeight}px;--service-map-line-height:${layout.geometry.lineHeight};width:${layout.width}px;height:${layout.height}px"><svg class="service-map-edges" width="${layout.width}" height="${layout.height}" aria-hidden="true"><defs>${arrowheads}</defs>${edges}</svg>${cards}</div></div>`);
      if (state.relationLayers.some((layer) => layer.kind === "peer")
        || new Set(state.relationLayers.map((layer) => layer.kind)).size > 1) {
        const addressCount = layout.nodes.filter((item) => item.endpointNode).length;
        const originCount = shownOrigins - addressCount;
        const omitted = Math.max(0, origins.length - shownOrigins);
        const spokes = layout.edges.filter((edge) => edge.undirected).length;
        const allEdges = overlayEdges();
        const shownIds = new Set(layout.nodes.map((item) => item.origin));
        const outsideEdges = allEdges.filter((edge) => !shownIds.has(edge.source) || !shownIds.has(edge.target)).length;
        els.graphBounds.textContent = [
          direct ? `${shownOrigins - Number(anchorShown)} / ${direct.neighbors.length} known direct neighbors shown` : `${originCount} origins + ${addressCount} recorded address nodes shown`,
          direct && !anchorShown ? "Pinned anchor is hidden from the map; direct mode retained." : "",
          `${layout.edges.length} / ${layout.edgeCount} links between shown cards · ${spokes} undirected observation spokes`,
          state.relationLayers.length ? `${state.relationLayers.length} / ${MAX_RELATION_LAYERS} shown inspections` : "",
          stages.queryHidden ? `${stages.queryHidden} hidden by query` : "",
          untyped ? `${untyped} with no typed response hidden` : "",
          stages.productHidden ? `${stages.productHidden} hidden by products/versions` : "",
          omitted ? `${omitted} nodes omitted by ${MAX_CARDS}-card cap` : "",
          layout.edgeCount > MAX_EDGES ? `${layout.edgeCount - MAX_EDGES} links omitted by ${MAX_EDGES}-edge cap` : "",
          outsideEdges ? `${outsideEdges} inspected links outside displayed cards` : "",
          anchorShown && query && !direct.anchor.origin.toLowerCase().includes(query) ? "Pinned anchor is outside the search query and remains visible." : "",
          anchorShown && !productMatches(direct.anchor, state.productId, state.productVersion) ? "Pinned anchor remains visible outside product/version filters (context only)." : "",
          state.omittedGraphReferences ? `${state.omittedGraphReferences} metadata reference declarations omitted by ${MAX_REFERENCE_CARDS}-reference-card cap` : "",
          selectionNotice, state.modeNotice,
        ].filter(Boolean).join(" · ");
        if (els.graphDiagnostics) els.graphDiagnostics.textContent = [
          `${stages.loaded.length} loaded nodes · ${stages.queryHidden} query-hidden origins · ${stages.productHidden} product/version-hidden origins · ${origins.length} matching nodes · ${layout.nodes.length} shown · ${omitted} display-cap omitted. Address nodes follow matching observed origins; they have no product metadata.`,
          direct ? `${direct.counts.incoming} incoming / ${direct.counts.outgoing} outgoing declarations and ${direct.counts.recorded_peer_observation || 0} undirected observations. Pinned anchor is context, excluded from matching counts; only direct incident links are included.` : "All loaded metadata and explicitly shown inspections share the same graph.",
          "Graph links deduplicate by source, target and type; per-inspection provenance and coverage remain separate. Counts are not requests or connections. Display and API inspection omissions are separate. Unloaded origins and relationships are not counted.",
          state.relationLayers.some((layer) => layer.kind === "peer") ? PEER_PRIVACY : "",
        ].filter(Boolean).join(" · ");
        return;
      }
      if (direct) {
        const counts = direct.counts;
        const linkOverlay = state.bodyReferenceOverlay?.kind === "link";
        const overlayCount = linkOverlay ? Object.values(LINK_RELATIONS).reduce((sum, item) => sum + (counts[item.type] || 0), 0) : counts.body_url_reference;
        const overlayName = linkOverlay ? "Link declaration" : "Body URL";
        const shownBodyArrows = layout.edges.filter((edge) => edge.relationship === "body_url_reference" || edge.relationship.startsWith("link_")).length;
        const shownMetadataArrows = layout.edges.length - shownBodyArrows;
        const metadataArrows = direct.edgeCount - overlayCount;
        const visibleIds = new Set(layout.nodes.map((origin) => origin.origin));
        const availableBodyArrows = overlayEdges().filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target)).length;
        const availableMetadataArrows = layout.edgeCount - availableBodyArrows;
        const queryHidden = stages.queryHidden, productHidden = stages.productHidden;
        const shownNeighbors = shownOrigins - Number(anchorShown);
        const capOmitted = Math.max(0, matchingNeighbors.length - shownNeighbors);
        const incomplete = state.snapshot.snapshot.complete !== true || array(state.snapshot.snapshot.stopped_by).length > 0;
        const outsideQuery = query && !direct.anchor.origin.toLowerCase().includes(query);
        const summary = [
          `${shownNeighbors} / ${direct.neighbors.length} known direct neighbors shown`,
          !anchorShown ? "Pinned anchor is hidden from the map; direct mode retained." : "",
          `${counts.incoming} incoming / ${counts.outgoing} outgoing links`,
          state.bodyReferenceOverlay ? `${metadataArrows} metadata / ${overlayCount} ${linkOverlay ? "Link" : "body URL"} links` : "",
          state.bodyReferenceOverlay ? `${shownBodyArrows} / ${overlayCount} ${linkOverlay ? "Link" : "body"} arrows shown` : "",
          queryHidden ? `${queryHidden} hidden by query` : "",
          untyped ? `${untyped} with no typed response hidden` : "",
          productHidden ? `${productHidden} hidden by products/versions` : "",
          state.productId || state.productVersion ? `${matchingNeighbors.length} matching neighbors · pinned anchor is context only` : "",
          capOmitted ? `${capOmitted} omitted by ${MAX_CARDS}-card cap` : "",
          layout.edgeCount > MAX_EDGES ? `${layout.edgeCount - MAX_EDGES} arrows omitted by ${MAX_EDGES}-arrow cap` : "",
          anchorShown && outsideQuery ? "Pinned anchor is outside the search query and remains visible." : "",
          anchorShown && !productMatches(direct.anchor, state.productId, state.productVersion) ? "Pinned anchor remains visible outside product/version filters (context only)." : "",
          !direct.anchor.captured ? "Reference-only anchor; no captured rows shown." : "",
          !direct.neighbors.length ? "No direct neighbors appear in loaded metadata; others may exist." : "",
          incomplete ? "Known neighborhood is incomplete; see snapshot bounds above." : "",
          selectionNotice,
        ];
        const diagnostics = [
          `Direct relations · ${direct.neighbors.length} known direct neighbors in loaded metadata${state.bodyReferenceOverlay ? linkOverlay ? " and temporary Link declarations (unique union)" : " and temporary body references (unique union)" : ""}`,
          `${direct.neighbors.length} loaded neighbors · ${queryHidden} query-hidden · ${productHidden} product/version-hidden · ${matchingNeighbors.length} matching · ${shownNeighbors} shown · ${capOmitted} omitted by ${MAX_CARDS}-card cap (anchor ${anchorShown ? "included" : "hidden"}). Pinned anchor is context, excluded from matching counts`,
          `Non-self distinct typed links: ${counts.incoming} incoming / ${counts.outgoing} outgoing · ${counts.redirect_instruction} redirect / ${counts.origin_header} Origin / ${counts.referer_header} Referer${state.bodyReferenceOverlay ? linkOverlay ? Object.values(LINK_RELATIONS).map((item) => ` / ${counts[item.type] || 0} ${item.type}`).join("") : ` / ${counts.body_url_reference} body_url_reference` : ""}`,
          `${layout.edges.length} / ${layout.edgeCount} arrows between displayed cards (cap ${MAX_EDGES}) · ${direct.arrowCount - layout.edgeCount} arrows outside displayed cards`,
          ...(state.bodyReferenceOverlay ? [
            `${overlayName} typed arrows: ${shownBodyArrows} / ${overlayCount} shown · ${overlayCount - availableBodyArrows} outside displayed cards · ${availableBodyArrows - shownBodyArrows} omitted by arrow cap`,
            `Metadata arrows: ${shownMetadataArrows} / ${direct.metadataArrowCount} shown · ${direct.metadataArrowCount - availableMetadataArrows} outside displayed cards · ${availableMetadataArrows - shownMetadataArrows} omitted by arrow cap`,
            `${linkOverlay ? "Link" : "Body"} targets and arrows take priority within the same 24-card and 40-arrow limits.`,
          ] : []),
          "Links count distinct origin pairs and relationship types, not requests, URL occurrences or redirect paths. Incoming and outgoing are relative to the pinned anchor; self-links are excluded.",
          state.bodyReferenceOverlay ? linkOverlay ? "Loaded metadata and explicitly shown retained-header inspections only; no transitive links or confirmed calls." : "Loaded metadata and explicitly shown retained-preview scans only; no transitive links or confirmed calls." : "Loaded metadata only; no transitive links or confirmed calls.",
        ];
        els.graphBounds.textContent = summary.filter(Boolean).join(" · ");
        if (els.graphDiagnostics) els.graphDiagnostics.textContent = diagnostics.join(" · ");
      } else els.graphBounds.textContent = `${shownOrigins} / ${origins.length} matching origins${untyped ? ` · ${untyped} with no typed response hidden` : ""}${stages.queryHidden ? ` · ${stages.queryHidden} hidden by query` : ""}${stages.productHidden ? ` · ${stages.productHidden} hidden by products/versions` : ""}${origins.length > shownOrigins ? ` · ${origins.length - shownOrigins} omitted by ${MAX_CARDS}-card cap` : ""}${state.omittedGraphReferences ? ` · Reference-card cap ${MAX_REFERENCE_CARDS}; ${state.omittedGraphReferences} reference declarations omitted` : ""}${origins.length > MAX_CARDS ? " · Filter to find more" : ""}${layout.edgeCount > MAX_EDGES ? ` · ${MAX_EDGES} / ${layout.edgeCount} arrows shown` : ""}${selectionNotice ? ` · ${selectionNotice}` : ""}${state.modeNotice ? ` · ${state.modeNotice}` : ""}`;
    }
    function endpointMatches(endpoint) {
      return (!state.endpointMethod || endpoint.method === state.endpointMethod) && endpoint.path.includes(state.endpointPath);
    }
    function loadedEndpointEntries(origins = filteredOrigins(), filtered = true) {
      return origins.flatMap((origin) => origin.endpoints.map((endpoint, index) => ({ origin, endpoint, index })))
        .filter((entry) => !filtered || endpointMatches(entry.endpoint));
    }
    // Paths that differ only in an ID (/web/chats/{number}/posts) share one
    // row, opened to list them; a page counts these rows, not every path.
    function endpointUnits(entries) {
      const units = [], templates = new Map();
      for (const entry of entries) {
        const template = entry.endpoint.path_group !== entry.endpoint.path ? entry.endpoint.path_group : null;
        const key = template && JSON.stringify([entry.origin.origin, entry.endpoint.method, template]);
        if (key && templates.has(key)) { templates.get(key).members.push(entry); continue; }
        const unit = { key, template, members: [entry] };
        if (key) templates.set(key, unit);
        units.push(unit);
      }
      return units;
    }
    const endpointIdentity = ({ origin, endpoint }) => ({ origin: origin.origin, method: endpoint.method, path: endpoint.path });
    const sameEndpoint = (entry, identity) => !!identity && entry.origin.origin === identity.origin
      && entry.endpoint.method === identity.method && entry.endpoint.path === identity.path;
    function reconcileEndpointPages() {
      // Selection and pagination use exact retained identities, never old array
      // offsets. Missing anchors clamp the previous page without choosing a row.
      for (const [pageKey, anchorKey, entries] of [
        ["page", "pageAnchor", loadedEndpointEntries()],
        ["detailPage", "detailPageAnchor", loadedEndpointEntries(selectedOrigin() ? [selectedOrigin()] : [])],
      ]) {
        const units = endpointUnits(entries);
        const index = units.findIndex((unit) => unit.members.some((entry) => sameEndpoint(entry, state[anchorKey])));
        state[pageKey] = Math.min(index < 0 ? state[pageKey] : Math.floor(index / API_PAGE_SIZE), Math.max(0, Math.ceil(units.length / API_PAGE_SIZE) - 1));
        // A local origin filter can hide an otherwise retained catalog anchor.
        // Keep it so clearing the filter returns to that exact endpoint; a
        // genuinely removed endpoint still adopts the clamped fallback page.
        const hiddenLoadedAnchor = pageKey === "page" && loadedEndpointEntries((state.snapshot?.origins || []).filter((origin) => !state.scopeOnly || origin.in_scope), false)
          .some((entry) => sameEndpoint(entry, state[anchorKey]));
        if (index < 0 && !hiddenLoadedAnchor) state[anchorKey] = units[state[pageKey] * API_PAGE_SIZE] ? endpointIdentity(units[state[pageKey] * API_PAGE_SIZE].members[0]) : null;
      }
    }
    function setEndpointFilter(kind, value) {
      if (!["method", "path", "clear"].includes(kind)) return;
      replayActionId += 1;
      if (kind === "clear") { state.endpointMethod = ""; state.endpointPath = ""; }
      else state[kind === "method" ? "endpointMethod" : "endpointPath"] = String(value || "");
      state.page = 0;
      state.detailPage = 0;
      state.pageAnchor = null;
      state.detailPageAnchor = null;
      // Local filters never change source identity, cancel pending inspections,
      // alter graph search/zoom, or issue additional retained-data reads.
      renderDetail();
      renderCatalog();
    }
    function endpointFiltersMarkup(place) {
      const methods = new Set(loadedEndpointEntries(state.snapshot?.origins || [], false).map(({ endpoint }) => endpoint.method));
      const missingMethod = !!state.endpointMethod && !methods.has(state.endpointMethod);
      if (state.endpointMethod) methods.add(state.endpointMethod);
      return `<fieldset class="service-map-endpoint-filters"><legend>Loaded endpoint filters</legend><div class="service-map-endpoint-filter-controls"><label>Method (exact)<select data-service-endpoint-filter="method" data-service-focus="${place}:method" title="${escape(state.endpointMethod || "All loaded methods")}"><option value="">All methods</option>${[...methods].sort().map((method) => `<option value="${escape(method)}" ${method === state.endpointMethod ? "selected" : ""}>${escape(method)}</option>`).join("")}</select></label><label>Path contains<input type="search" value="${escape(state.endpointPath)}" data-service-endpoint-filter="path" data-service-focus="${place}:path" placeholder="Path substring" autocomplete="off" spellcheck="false" /></label><button class="secondary-action" type="button" data-service-endpoint-filter-clear="true" data-service-focus="${place}:clear" ${!state.endpointMethod && !state.endpointPath ? "disabled" : ""}>Clear</button></div>${missingMethod ? '<p class="service-map-filter-notice" role="status">Selected method is absent from the loaded snapshot. Filter retained; no loaded endpoints match.</p>' : ""}</fieldset>`;
    }
    function endpointSelectionNotice(origin = selectedOrigin()) {
      if (!origin) return "";
      const selected = state.endpointSelection || (state.evidence?.origin === origin.origin ? state.evidence : null);
      const notices = [];
      if (selected && !endpointMatches(selected)) notices.push("Selected endpoint is outside the loaded endpoint filters. Its inspector selection and evidence are preserved.");
      if (!productMatches(origin, state.productId, state.productVersion)) notices.push("Selected origin is outside the product/version filters. Its inspector and exact evidence remain open.");
      const query = state.query.trim().toLowerCase();
      if (query && !origin.origin.toLowerCase().includes(query)) notices.push("Selected origin is outside the origin search. Its inspector remains open.");
      return notices.length ? `<p class="service-map-filter-notice" role="status">${notices.join(" ")}</p>` : "";
    }
    function endpointCoverageMarkup(matching, loaded, start, hiddenOrigins = 0, hiddenProducts = 0, paths = matching) {
      return `<p class="service-map-muted service-map-endpoint-counts" role="status">${matching ? start + 1 : 0}–${Math.min(start + API_PAGE_SIZE, matching)} / ${matching.toLocaleString()} matching${paths !== matching ? ` (${paths.toLocaleString()} paths)` : ""} · ${loaded.toLocaleString()} loaded · ${(loaded - hiddenOrigins - hiddenProducts - paths).toLocaleString()} hidden by endpoint filters${hiddenProducts ? ` · ${hiddenProducts.toLocaleString()} hidden by origin products/versions` : ""}${hiddenOrigins ? ` · ${hiddenOrigins.toLocaleString()} hidden by origin search` : ""}.</p>`;
    }
    const methodTone = (method) => method.toUpperCase() === "GET" ? "get" : method.toUpperCase() === "POST" ? "post" : "other";
    const apiAuthTag = (kinds) => kinds.length ? `<span class="service-map-api-auth" title="${escape(kinds.map((kind) => AUTH_LABELS[kind][1]).join(", "))}">${LOCK_ICON}${escape(kinds.map((kind) => AUTH_LABELS[kind][0]).join(" · "))}</span>` : "";
    function endpointButton(endpoint, origin, index, catalog = false) {
      const method = endpoint.method;
      return `<button class="service-map-api-row ${state.selectedOrigin === origin.origin && state.endpointIndex === index ? "selected" : ""}" type="button" data-service-endpoint="${index}" data-service-origin="${escape(origin.origin)}" data-service-focus="api:${escape(JSON.stringify([origin.origin, endpoint.method, endpoint.path]))}"><span class="service-map-method ${methodTone(method)}" title="${escape(method)}">${escape(method)}</span><span class="service-map-api-copy">${catalog ? `<small title="${escape(origin.origin)}">${escape(origin.origin)}</small>` : ""}<span title="${escape(endpoint.path)}">${escape(endpoint.path)}</span></span>${apiAuthTag(endpoint.auth || [])}<span class="service-map-api-count">${endpoint.request_count.toLocaleString()}<span class="service-map-chevron" aria-hidden="true">›</span></span></button>`;
    }
    // A template's row: its ID segments marked, how many paths and rows it
    // stands for; open, it lists them. The selected path keeps it open.
    function endpointUnitMarkup(unit, catalog = false) {
      if (unit.members.length === 1) {
        const [{ endpoint, origin, index }] = unit.members;
        return endpointButton(endpoint, origin, index, catalog);
      }
      const { origin, endpoint } = unit.members[0];
      const selected = unit.members.some((entry) => state.selectedOrigin === entry.origin.origin && state.endpointIndex === entry.index);
      const open = selected || state.expandedEndpointGroups.has(unit.key);
      const rows = unit.members.reduce((sum, entry) => sum + entry.endpoint.request_count, 0);
      const kinds = AUTH_KINDS.filter((kind) => unit.members.some((entry) => entry.endpoint.auth?.includes(kind)));
      const template = escape(unit.template).replace(/\{(number|uuid|hex)\}/g, '<span class="service-map-path-id">{$1}</span>');
      return `<button class="service-map-api-row service-map-api-group${selected ? " selected" : ""}" type="button" aria-expanded="${open}" data-service-endpoint-group="${escape(unit.key)}" data-service-focus="api-group:${escape(unit.key)}"><span class="service-map-method ${methodTone(endpoint.method)}" title="${escape(endpoint.method)}">${escape(endpoint.method)}</span><span class="service-map-api-copy">${catalog ? `<small title="${escape(origin.origin)}">${escape(origin.origin)}</small>` : ""}<span title="${escape(unit.template)}">${template}</span><small>${unit.members.length.toLocaleString()} paths</small></span>${apiAuthTag(kinds)}<span class="service-map-api-count">${rows.toLocaleString()}<span class="service-map-chevron" aria-hidden="true">${open ? "⌄" : "›"}</span></span></button>${open ? `<div class="service-map-api-members">${unit.members.map((entry) => endpointButton(entry.endpoint, entry.origin, entry.index)).join("")}</div>` : ""}`;
    }
    function relationshipMarkup(origin) {
      const group = state.relationsByOrigin?.get(origin.origin);
      const inspected = overlayReferences().filter((item) => origin.origin === item.layer.source.origin || item.target_origin === origin.origin);
      if (!group?.items.length && !inspected.length) return "";
      const metadata = (group?.items || []).slice(0, MAX_REFERENCE_SOURCES);
      const shown = inspected.slice(0, Math.max(0, MAX_REFERENCE_SOURCES - metadata.length));
      const omitted = (group?.omitted || 0) + inspected.length - shown.length;
      return `<h4>Shown relationships</h4><div class="service-map-evidence-list">${metadata.map((item) => `<button class="service-map-evidence-button service-map-relation${JSON.stringify([item.sourceOrigin, item.targetOrigin, item.relationship]) === state.highlightedRelation ? " highlighted" : ""}" type="button" data-service-relation-origin="${escape(item.capturedOrigin)}" data-service-relation-evidence="${escape(item.evidence)}" data-service-focus="relation:${escape(JSON.stringify([item.sourceOrigin, item.targetOrigin, item.targetPath || "", item.label]))}"><span><strong>${escape(item.label)}</strong>${escape(item.sourceOrigin)} → ${escape(item.targetOrigin)}${escape(item.targetPath || "")}${item.kinds ? `<br><span class="service-map-relation-kinds">${item.kinds.map(([kind, rows]) => `${escape(REQUEST_KIND_LABELS[kind])} ${rows}`).join(" · ")}${item.cors?.[0] ? ` · ${corsText(item.cors)}` : ""}</span>` : ""}</span><span>View source ›</span></button>`).join("")}${shown.map((item) => `<button class="service-map-evidence-button service-map-relation" type="button" data-service-relation-origin="${escape(item.layer.source.origin)}" data-service-relation-evidence="${escape(item.layer.source.evidenceId)}" data-service-focus="relation:${escape(JSON.stringify([layerKey(item.layer), item.target_origin, item.relation || "body", item.header_index ?? 0, item.relation_span?.start ?? 0]))}"><span><strong>${escape(item.layer.kind === "link" ? LINK_RELATIONS[item.relation].label : "Literal body URL reference")}</strong>${escape(item.layer.source.origin)} → ${escape(item.target_origin)}<br>Source sequence ${escape(item.layer.source.sequence)} · ${item.layer.scan.complete ? "Complete" : "Partial"} inspection${item.layer.kind === "body" ? `<br>${item.occurrences} literal occurrences · Preview byte offsets: ${item.preview_byte_offsets.join(", ")}${item.omitted_offsets ? ` · ${item.omitted_offsets} offsets omitted` : ""}` : `<br>Link header ${item.header_index} · Member bytes ${item.link_value_span.start}–${item.link_value_span.end} · Target ${item.target_span.start}–${item.target_span.end} · Relation ${item.relation_span.start}–${item.relation_span.end}`}</span><span>View source ›</span></button>`).join("")}</div>${omitted ? `<p class="service-map-muted">${omitted} additional relationship declarations omitted from this pane.</p>` : ""}`;
    }
    function bodyReferencesMarkup() {
      const result = state.bodyReferences;
      const scanned = result?.status === "scanned" || result?.status === "partial";
      const hasNeighbors = scanned && result.references.some((item) => item.target_origin !== state.bodyReferencesSource?.origin);
      const showing = state.relationLayers.some((layer) => layer.kind === "body" && layer.source.evidenceId === state.bodyReferencesSource?.evidenceId);
      const showDisabled = activeInspectionsBlocked() || !scanned || !hasNeighbors || !getEventStreamReady() || !!state.error || state.stale || !sourceIsRetained(state.bodyReferencesSource);
      const showHint = !getEventStreamReady() ? "Wait for the session event connection before showing temporary references."
        : state.error || state.stale ? "Wait for a current metadata snapshot, or use Reload, before showing temporary references."
        : scanned && !hasNeighbors ? result.references.length ? "Only the source origin was referenced; self-links are not drawn." : "There are no referenced origins to show on the map."
        : "";
      const buttonLabel = state.bodyReferencesLoading ? "Inspecting retained body references…" : state.bodyReferencesError || result?.status === "unavailable" ? "Retry retained body references" : result ? "Inspect retained body references again" : "Inspect retained body references";
      let summary = "";
      if (result) {
        const scanned = result.status === "scanned" || result.status === "partial";
        const occurrences = result.references.reduce((total, item) => total + item.occurrences, 0);
        const message = result.status === "unsupported" ? "Retained preview is unsupported. No references were inspected."
          : result.status === "unavailable" ? "Retained preview is unavailable. No references were inspected."
          : result.references.length ? `${result.references.length} referenced origin${result.references.length === 1 ? "" : "s"} · ${occurrences.toLocaleString()} literal URL occurrence${occurrences === 1 ? "" : "s"}`
          : "No literal absolute HTTP(S) URL references found in the inspected preview.";
        summary = `<div class="service-map-body-reference-result" role="status"><p>${escape(message)}</p>${result.reasons.length ? `<p class="service-map-muted">${result.reasons.map((reason) => escape(BODY_REFERENCE_REASONS[reason] || reason.replace(/_/g, " "))).join(" · ")}</p>` : ""}</div>
          ${result.references.length ? `<ul class="service-map-body-reference-list" aria-label="Literal URL reference origins">${result.references.map((item) => `<li><span class="service-map-body-reference-origin">${escape(item.target_origin)}</span><span>${item.occurrences.toLocaleString()} occurrence${item.occurrences === 1 ? "" : "s"}</span></li>`).join("")}</ul>` : ""}`;
      }
      return `<div aria-busy="${state.bodyReferencesLoading}">${state.bodyReferencesLoading ? '<p class="service-map-muted" role="status">Inspecting one retained preview locally…</p>' : ""}${state.bodyReferencesError ? `<p class="service-map-error" role="status">${escape(state.bodyReferencesError)}</p>` : ""}${summary}${showDisabled ? "" : `<button class="secondary-action" type="button" data-service-show-body-references="show" data-service-focus="body-references:show" aria-pressed="${showing}"${showHint ? ' aria-describedby="serviceMapBodyShowHint"' : ""} ${showDisabled ? "disabled" : ""}>${showing ? "Update this shown inspection" : "Show references on map"}</button>`}${showHint ? `<p class="service-map-muted" id="serviceMapBodyShowHint">${showHint}</p>` : ""}<details class="service-map-body-reference-limits"><summary data-service-focus="body-references:limits">Coverage</summary>${state.bodyReferencesSource && scanned ? relationshipSourceMarkup(state.bodyReferencesSource, result, "body") : ""}${scanned ? `<p>${result.complete ? "Complete retained-preview scan" : "Partial retained-preview scan"} · ${result.scanned_bytes.toLocaleString()} / ${result.retained_preview_bytes.toLocaleString()} UTF-8 preview bytes inspected${result.omitted_reference_occurrences ? ` · ${result.omitted_reference_occurrences.toLocaleString()} reference occurrence${result.omitted_reference_occurrences === 1 ? "" : "s"} omitted` : ""}</p>` : ""}<p>Literal absolute HTTP(S) URLs only. Origins are text, never fetched. No script execution or relative URL resolution. Only Show references on map adds session-local relationships. Offsets are zero-based bytes relative to the retained UTF-8 preview, not the original response.</p><p>Scan: ${BODY_REFERENCE_LIMITS.scan_bytes.toLocaleString()} bytes · Serialized row read: ${BODY_REFERENCE_LIMITS.serialized_row_bytes.toLocaleString()} bytes · Origins: ${BODY_REFERENCE_LIMITS.origins} · URL candidates: ${BODY_REFERENCE_LIMITS.candidates.toLocaleString()} · Candidate: ${BODY_REFERENCE_LIMITS.candidate_bytes.toLocaleString()} bytes · Offsets per origin: ${BODY_REFERENCE_LIMITS.offsets_per_origin}.</p>${result ? `<p>${result.candidates_scanned.toLocaleString()} candidates inspected · Capture preview truncated: ${result.capture_preview_truncated ? "yes" : "no"} · Scan prefix truncated: ${result.scan_prefix_truncated ? "yes" : "no"}.</p>` : ""}</details></div>`;
    }
    function relationshipSourceMarkup(source, result, kind) {
      return `<p class="service-map-overlay-source">${escape(source.method)} ${escape(source.origin)}${escape(source.path)}</p><p class="service-map-muted">Sequence ${escape(source.sequence)} · Captured ${escape(source.startedAt)} · ${kind === "link" ? "Response Link headers" : "Body URL references"} · ${result.complete ? "Complete" : "Partial"} inspection</p>`;
    }
    function relationshipsMarkup() {
      return `<section class="service-map-body-references service-map-retained-relationships" aria-label="Retained relationships"><h4>Retained relationships</h4><label class="service-map-relationship-kind">Inspect source<select data-service-relationship-kind="select" data-service-focus="relationships:kind" aria-label="Retained relationship source"><option value="body" ${state.relationshipKind === "body" ? "selected" : ""}>Body URL references</option><option value="link" ${state.relationshipKind === "link" ? "selected" : ""}>Response Link headers</option></select></label>${state.relationshipKind === "link" ? linkDeclarationsMarkup() : bodyReferencesMarkup()}</section>`;
    }
    function linkObservationsMarkup(observations) {
      return `<ul class="service-map-body-reference-list" aria-label="Retained Link declarations">${observations.map((item) => `<li><span class="service-map-body-reference-origin">${escape(item.target_origin)}</span><span>${escape(LINK_RELATIONS[item.relation].label)}</span></li>`).join("")}</ul>`;
    }
    function linkDeclarationsMarkup() {
      const result = state.linkDeclarations, source = state.linkDeclarationsSource, scanned = result?.status === "scanned";
      const hasNeighbors = scanned && result.observations.some((item) => item.target_origin !== source?.origin);
      const showing = state.relationLayers.some((layer) => layer.kind === "link" && layer.source.evidenceId === source?.evidenceId);
      const disabled = activeInspectionsBlocked() || state.bodyReferencesLoading || !getEventStreamReady() || !!state.error || state.stale;
      const showDisabled = !scanned || !hasNeighbors || disabled || !htmlGeneratorSourceIsRetained(source);
      const label = state.bodyReferencesLoading ? "Inspecting retained Link headers…" : state.linkDeclarationsError || result?.status === "unavailable"
        ? "Retry retained Link headers" : result ? "Inspect retained Link headers again" : "Inspect retained Link headers";
      const message = !result ? "" : result.status === "unsupported" ? "This retained source is unsupported. No Link declarations were inspected."
        : result.status === "unavailable" ? "Retained response metadata is unavailable. No Link declarations were inspected."
          : result.observations.length ? `${result.observations.length} retained Link declaration${result.observations.length === 1 ? "" : "s"} · ${new Set(result.observations.map((item) => item.target_origin)).size} target origins`
            : result.complete ? "No supported Link declarations found in the inspected retained headers." : "No supported Link declarations are available from the inspected prefix; coverage is partial.";
      return `<div aria-busy="${state.bodyReferencesLoading}">${state.bodyReferencesLoading ? '<p class="service-map-muted" role="status">Inspecting retained response headers locally…</p>' : ""}${state.linkDeclarationsError ? `<p class="service-map-error" role="status">${escape(state.linkDeclarationsError)}</p>` : ""}${result ? `<div class="service-map-body-reference-result" role="status"><p>${escape(message)}</p>${result.reasons.length ? `<p>${result.reasons.map((reason) => escape(LINK_REASONS[reason])).join(" · ")}</p>` : ""}</div>` : ""}${result?.observations.length ? linkObservationsMarkup(result.observations) : ""}${showDisabled ? "" : `<button class="secondary-action" type="button" data-service-show-link-declarations="show" data-service-focus="relationships:show" aria-pressed="${showing}" ${showDisabled ? "disabled" : ""}>${showing ? "Update this shown inspection" : "Show references on map"}</button>`}${scanned && !hasNeighbors ? `<p class="service-map-muted">${result.observations.length ? "Only the source origin was declared; self-links are not drawn." : "There are no declared target origins to show on the map."}</p>` : ""}<details class="service-map-body-reference-limits"><summary data-service-focus="relationships:limits">Coverage</summary>${scanned && source ? relationshipSourceMarkup(source, result, "link") : ""}${scanned ? `<p>${result.complete ? "Complete supported-grammar inspection" : "Partial retained-header inspection"} · ${result.counts.headers_inspected} / ${result.retained_header_count} retained headers inspected · ${result.counts.header_bytes_admitted} name/value bytes admitted</p>` : ""}<p>Literal absolute HTTP(S) targets for service-doc, service-desc, describedby and preconnect only. Complete means this bounded grammar, not every relationship or dependency. Origins are text, never fetched; no URL resolution, DNS, probes or body reads. Source spans refer to retained header value UTF-8 bytes, not original wire offsets.</p><p>Headers: 128 · Name/value bytes: 32,768 · Link field: 4,096 bytes · Target: 4,096 bytes · Candidates: 128 · Parameters and relation tokens per member: 32 each · Observations: 32 · Target origin: 268 bytes.</p>${scanned ? `<p>${result.counts.link_fields_inspected} Link fields · ${result.counts.candidates_inspected} candidates · ${result.counts.members_framed} framed members · ${result.counts.parameters_inspected} parameters · ${result.counts.relation_tokens_inspected} relation tokens · ${result.counts.unknown_relation_tokens_inspected} unknown relation tokens inspected. Counts describe inspected input only; uninspected declarations are not counted.</p>` : ""}</details></div>`;
    }
    function htmlGeneratorsMarkup() {
      const result = state.htmlGenerators, scanned = result?.status === "scanned";
      const disabled = activeInspectionsBlocked() || state.htmlGeneratorsLoading || !getEventStreamReady() || !!state.error || state.stale;
      const buttonLabel = state.htmlGeneratorsLoading ? "Inspecting retained HTML generators…"
        : state.htmlGeneratorsError || result?.status === "unavailable" ? "Retry retained HTML generators"
          : result ? "Inspect retained HTML generators again" : "Inspect retained HTML generators";
      let summary = "";
      if (result) {
        const message = result.status === "unsupported" ? "Retained preview is unsupported. Generator declarations were not inspected."
          : result.status === "unavailable" ? "Retained preview is unavailable. Generator declarations were not inspected."
            : result.observations.length ? `${result.observations.length} reported HTML generator declaration${result.observations.length === 1 ? "" : "s"}`
              : result.complete ? "No supported WordPress or Drupal generator declarations in the inspected head."
                : "No supported generator declarations are available from the inspected prefix; coverage is partial.";
        summary = `<div class="service-map-html-generator-result" role="status"><p>${escape(message)}</p>${result.reasons.length ? `<p class="service-map-muted">${result.reasons.map((reason) => escape(HTML_GENERATOR_REASONS[reason])).join(" · ")}</p>` : ""}</div>`;
      }
      const observations = result?.observations.length ? `<ul class="service-map-references service-map-html-generator-list" aria-label="Reported HTML generator declarations">${result.observations.map((item) => `<li><strong>${escape(productText(item))}</strong> <span class="service-map-muted">meta generator</span></li>`).join("")}</ul>` : "";
      return `<section class="service-map-body-references service-map-html-generators" aria-label="Retained HTML generators" aria-busy="${state.htmlGeneratorsLoading}"><h4>Retained HTML generators</h4>${state.htmlGeneratorsLoading ? '<p class="service-map-muted" role="status">Inspecting one retained HTML preview locally…</p>' : ""}${state.htmlGeneratorsError ? `<p class="service-map-error" role="status">${escape(state.htmlGeneratorsError)}</p>` : ""}${summary}${observations}<details class="service-map-html-generator-limits"><summary data-service-focus="html-generators:limits">Generator coverage and limits</summary>${scanned ? `<p>${result.complete ? "Complete supported-head inspection" : "Partial retained-preview coverage"} · Supported explicit head closed: ${result.head_closed ? "yes" : "no"}. ${result.scan_prefix_bytes.toLocaleString()} / ${result.retained_preview_bytes.toLocaleString()} retained UTF-8 preview bytes offered to the parser. Capture preview truncated: ${result.capture_preview_truncated ? "yes" : "no"} · Scan prefix truncated: ${result.scan_prefix_truncated ? "yes" : "no"}.</p>` : ""}<p>Literal WordPress and Drupal declarations in a supported explicit HTML head only. Numeric or dotted reported versions only. No HTML recovery, entity decoding, script execution, fetching or map aggregation. A closed head can coexist with a truncated, unparsed body; overall coverage remains partial.</p><p>Prefix: ${HTML_GENERATOR_LIMITS.scan_bytes.toLocaleString()} bytes · Serialized row read: ${HTML_GENERATOR_LIMITS.serialized_row_bytes.toLocaleString()} bytes · Tag candidates: ${HTML_GENERATOR_LIMITS.tag_candidates.toLocaleString()} · Tag: ${HTML_GENERATOR_LIMITS.tag_bytes.toLocaleString()} bytes · Attributes per tag: ${HTML_GENERATOR_LIMITS.attributes} · Declarations: ${HTML_GENERATOR_LIMITS.observations} · Version and separator: ${HTML_GENERATOR_LIMITS.version_bytes} bytes each.</p>${scanned ? `<p>${result.tag_candidates_inspected.toLocaleString()} tag candidates inspected · Additional tag candidate encountered: ${result.additional_tag_candidate_encountered ? "yes" : "no"} · Additional supported declaration encountered: ${result.additional_observation_encountered ? "yes" : "no"} · Unrecognized product declarations among inspected candidates: ${result.unknown_product_declarations.toLocaleString()}. Uninspected declarations are not counted.</p>${result.parser_stop ? `<p>Parser stop: ${escape(HTML_GENERATOR_STOP_REASONS[result.parser_stop.reason])} · Raw preview byte cursor: ${result.parser_stop.byte_cursor.toLocaleString()} (not a text-slicing boundary).</p>` : ""}` : ""}</details></section>`;
    }
    function overlayProvenanceMarkup(overlay) {
      if (!overlay) return "";
      const { source, scan } = overlay;
      if (overlay.kind === "peer") return `<p class="service-map-overlay-source" title="${escape(overlay.scan.source.origin)} · Source sequence ${escape(overlay.scan.source.sequence)}">${escape(overlay.scan.source.origin)} · Source sequence ${escape(overlay.scan.source.sequence)}</p><p>${escape(peerAddressNode(overlay).address)} · Recorded ${escape(scan.source.observed_at)} · Inspected ${escape(scan.snapshot.captured_at)}</p><p>${overlay.scan.complete ? "Complete considered window" : "Partial inspection"} · ${overlay.scan.snapshot.considered_rows} / ${overlay.scan.snapshot.retained_rows} retained rows considered · ${overlay.scan.counts.matching_rows} other matching rows</p><details class="service-map-peer-coverage"><summary data-service-focus="peer:coverage">Inspection coverage and privacy</summary>${peerCountsMarkup(overlay.scan)}<p>${PEER_PRIVACY}</p><p>Recorded timestamps do not imply connection counts or continuous endpoint occupancy.</p></details>`;
      if (overlay.kind === "link") return `${relationshipSourceMarkup(source, scan, "link")}${scan.reasons.length ? `<p class="service-map-muted">${scan.reasons.map((reason) => escape(LINK_REASONS[reason])).join(" · ")}</p>` : ""}`;
      return `<p class="service-map-overlay-source" title="${escape(`${source.method} ${source.origin}${source.path}`)}">${escape(source.method)} ${escape(source.origin)}${escape(source.path)}</p><p>Sequence ${escape(source.sequence)} · ${escape(source.startedAt)} · ${scan.complete ? "Complete" : "Partial"} retained-preview scan</p>${!scan.complete ? `<p class="service-map-muted">${scan.reasons.map((reason) => escape(BODY_REFERENCE_REASONS[reason] || reason.replace(/_/g, " "))).join(" · ")}${scan.omitted_reference_occurrences ? ` · ${scan.omitted_reference_occurrences} reference occurrence${scan.omitted_reference_occurrences === 1 ? "" : "s"} omitted` : ""}</p>` : ""}`;
    }
    function renderOverlayStatus() {
      if (!els.overlayStatus) return;
      els.overlayStatus.classList.toggle("hidden", !state.relationLayers.length && !state.bodyOverlayNotice);
      const open = els.overlayStatus.querySelector?.(".service-map-collection")?.open;
      replace(els.overlayStatus, `${state.relationLayers.length ? `<details class="service-map-collection"><summary data-service-focus="relations:collection">Shown inspections · ${state.relationLayers.length} / ${MAX_RELATION_LAYERS}</summary>${state.relationLayers.map((layer) => `<section class="service-map-collection-entry"><strong>${layer.kind === "peer" ? "Recorded address observations" : layer.kind === "link" ? "Response Link declarations" : "Literal body URL references"}</strong>${overlayProvenanceMarkup(layer)}<div class="service-map-overlay-actions"><button class="secondary-action" type="button" ${layer.kind === "peer" ? `data-service-peer-origin="${escape(layer.source.origin)}" data-service-peer-evidence="${escape(layer.source.evidenceId)}"` : `data-service-relation-origin="${escape(layer.source.origin)}" data-service-relation-evidence="${escape(layer.source.evidenceId)}"`} data-service-focus="source:${escape(layerKey(layer))}">View inspected source</button><button class="secondary-action" type="button" data-service-remove-inspection="${escape(layerKey(layer))}" data-service-focus="remove:${escape(layerKey(layer))}">Remove inspection</button></div></section>`).join("")}<button class="secondary-action" type="button" data-service-clear-body-references="clear" data-service-focus="relations:clear">Clear all inspections</button></details>` : ""}${state.bodyOverlayNotice ? `<p role="status">${escape(state.bodyOverlayNotice)}</p>` : ""}`);
      const details = els.overlayStatus.querySelector?.(".service-map-collection");
      if (details && open !== undefined) details.open = open;
    }
    function socketPeerMarkup() {
      const peer = state.socketPeer;
      if (!peer || peer.status === "not_recorded" || peer.status === "unsupported") return "";
      const heading = '<h4>Upstream socket peer</h4>';
      let content;
      if (peer.status === "invalid") content = '<p class="service-map-error">Socket peer details could not be verified for this read.</p>';
      else {
        const route = { direct: "Direct", http_proxy: "HTTP proxy", socks_proxy: "SOCKS proxy", unknown: "Unknown" }[peer.route];
        const address = peer.status === "observed" ? `${peer.ip.includes(":") ? `[${peer.ip}]` : peer.ip}:${peer.port}` : "Unavailable at response headers";
        content = `<dl><dt>Observed socket peer</dt><dd>${escape(address)}</dd><dt>Route used</dt><dd>${escape(route)}</dd><dt>Response headers observed at</dt><dd>${escape(peer.observedAt)}</dd></dl>`;
      }
      return `<section class="service-map-socket-peer" aria-label="Upstream socket peer">${heading}${content}</section>${usableSocketPeer(peer) || state.peerMatches ? peerMatchesMarkup() : ""}`;
    }
    function technologyMarkup(items, origin = null, sourceRow = null) {
      if (!items.length) return "";
      const rows = items.map((item) => {
        const sources = origin ? `<div class="service-map-evidence-list">${item.evidence.map((id, index) => `<button class="service-map-evidence-button" type="button" data-service-relation-origin="${escape(origin.origin)}" data-service-relation-evidence="${escape(id)}" data-service-focus="technology:${escape(JSON.stringify([item.product_id, item.header_name, item.reported_version, item.version_status, id]))}"><span>${escape(productText(item))}</span><span>View source${item.evidence.length > 1 ? ` ${index + 1}` : ""} ›</span></button>`).join("")}</div>` : "";
        return `<li><strong>${escape(productText(item))}</strong><p class="service-map-muted">${escape(TECHNOLOGY_CATEGORIES[item.catalog_category])} · ${escape(item.header_name)} header${origin ? ` · ${rowCount(item.row_count)}` : ""}</p>${sources}</li>`;
      }).join("");
      return `<section class="service-map-technologies" aria-label="Header-reported technologies"><h4>Header-reported technologies</h4><ul class="service-map-references">${rows}</ul></section>`;
    }
    function parametersMarkup(origin, endpoint) {
      const current = state.parametersKey === endpointParametersKey(origin.origin, endpoint);
      const result = current ? state.parameters : null;
      const rows = (n) => `${n} row${n === 1 ? "" : "s"}`;
      // A narrow inspector stacks each parameter: its name and where it was
      // sent, then its values, so long values never squeeze the name.
      const notes = result ? [result.moreRows && `From the newest ${rows(result.rows)}; older rows not read`,
        result.unreadBodies && `${result.unreadBodies} bodies not read (size limit)`, result.omitted && `${result.omitted} more parameters`].filter(Boolean) : [];
      const body = !current && !state.loading ? '<p class="service-map-muted">Reopen this endpoint or reload the map to read current parameters.</p>'
        : !current || state.parametersLoading ? '<p class="service-map-muted">Reading parameters…</p>'
        : state.parametersError ? `<p class="service-map-muted">${escape(state.parametersError)}</p>`
        : !result?.items.length ? `<p class="service-map-muted">No parameters in the newest ${rows(result?.rows || 0)}.</p>`
        : `<ul class="service-map-parameters">${result.items.map((item) => `<li><div><span class="service-map-parameter-name">${escape(item.name)}</span><span class="service-map-muted">${item.location} · ${rows(item.rows)}</span></div>${item.examples.length ? `<div class="service-map-parameter-values">${item.examples.map((value) => `<code>${escape(value)}</code>`).join("")}</div>` : ""}</li>`).join("")}</ul>${notes.length ? `<p class="service-map-muted">${notes.join(" · ")}.</p>` : ""}`;
      return `<section class="service-map-parameters-section" aria-label="Parameters"><h4>Parameters</h4>${body}</section>`;
    }
    // Front-end technologies retained scripts, pages and asset URLs name, each
    // with the rows to open.
    // What the origin's own responses say about its servers, exposures first,
    // each with the rows to open.
    // How the origin's requests authenticate, busiest first, each with a row to
    // open. It leads the APIs tab: it is the first thing a test needs.
    function authMarkup(origin) {
      if (!origin.auth?.length) return "";
      return `<section class="service-map-technologies service-map-auth-methods" aria-label="Authentication"><h4>Authentication</h4><ul class="service-map-references">${origin.auth.map((item) => `<li><strong>${escape(authName(item))}</strong>${item.name && item.kind !== "scheme" ? ` · <code>${escape(item.name)}</code>` : ""}<p class="service-map-muted">${rowCount(item.row_count)}</p>${item.evidence.length ? `<div class="service-map-evidence-list"><button class="service-map-evidence-button" type="button" data-service-relation-origin="${escape(origin.origin)}" data-service-relation-evidence="${escape(item.evidence[0])}" data-service-focus="auth:${escape(JSON.stringify([item.kind, item.name || "", item.evidence[0]]))}"><span>${escape(authName(item))}</span><span>View source ›</span></button></div>` : ""}</li>`).join("")}</ul></section>`;
    }
    function serverTechnologiesMarkup(origin) {
      const items = origin.server_technologies || [];
      const list = (entries) => `<ul class="service-map-references">${entries.map((item) => `<li><strong>${escape(item.name)}</strong>${item.version ? ` · ${escape(item.version)}` : ""}${SERVER_LABELS[item.category] ? ` <span class="service-map-muted">${SERVER_LABELS[item.category]}</span>` : ""}<p class="service-map-muted">${rowCount(item.row_count)} · ${item.signals.join(", ")}</p><div class="service-map-evidence-list">${item.evidence.map((id, index) => `<button class="service-map-evidence-button" type="button" data-service-relation-origin="${escape(origin.origin)}" data-service-relation-evidence="${escape(id)}" data-service-focus="server:${escape(JSON.stringify([item.product_id, item.version, id]))}"><span>${escape(item.name)}</span><span>View source${item.evidence.length > 1 ? ` ${index + 1}` : ""} ›</span></button>`).join("")}</div></li>`).join("")}</ul>`;
      const exposures = items.filter((item) => item.category === "exposure"), servers = items.filter((item) => item.category !== "exposure");
      return `${exposures.length ? `<section class="service-map-technologies service-map-exposures" aria-label="Exposures"><h4>Exposures</h4>${list(exposures)}</section>` : ""}${servers.length ? `<section class="service-map-technologies" aria-label="Server"><h4>Server</h4>${list(servers)}</section>` : ""}`;
    }
    // What the origin's responses carried that no rule names, folded away: a
    // reader, or an agent reading the API, judges these.
    function unnamedMarkup(origin) {
      const groups = [["banners", "Banners"], ["headers", "Headers"], ["cookies", "Cookies"]].filter(([kind]) => origin.unnamed?.[kind]?.length);
      if (!groups.length) return "";
      const total = groups.reduce((sum, [kind]) => sum + origin.unnamed[kind].length, 0);
      return `<details class="service-map-technologies service-map-unnamed"><summary data-service-focus="unnamed:summary">Unnamed signals · ${total}</summary>${groups.map(([kind, title]) => `<h4>${title}</h4><div class="service-map-evidence-list">${origin.unnamed[kind].map((signal) => `<button class="service-map-evidence-button" type="button" data-service-relation-origin="${escape(origin.origin)}" data-service-relation-evidence="${escape(signal.evidence[0] || "")}" data-service-focus="unnamed:${escape(JSON.stringify([kind, signal.value]))}" ${signal.evidence.length ? "" : "disabled"}><span><code>${escape(signal.value)}</code> · ${rowCount(signal.row_count)}</span><span>View source ›</span></button>`).join("")}</div>`).join("")}</details>`;
    }
    function frontTechnologiesMarkup(origin) {
      if (!origin.front_technologies?.length) return "";
      return `<section class="service-map-technologies" aria-label="Front-end"><h4>Front-end</h4><ul class="service-map-references">${origin.front_technologies.map((item) => `<li><strong>${escape(item.name)}</strong>${item.version ? ` · ${escape(item.version)}` : ""}<p class="service-map-muted">${item.row_count} retained row${item.row_count === 1 ? "" : "s"} from ${escape(item.source_origin)}</p><div class="service-map-evidence-list">${item.evidence.map((id, index) => `<button class="service-map-evidence-button" type="button" data-service-relation-origin="${escape(item.source_origin)}" data-service-relation-evidence="${escape(id)}" data-service-focus="library:${escape(JSON.stringify([item.product_id, item.version, id]))}"><span>${escape(item.name)}${item.version ? ` ${escape(item.version)}` : ""}</span><span>View source${item.evidence.length > 1 ? ` ${index + 1}` : ""} ›</span></button>`).join("")}</div></li>`).join("")}</ul></section>`;
    }
    function evidenceMarkup(origin) {
      const items = evidenceItems(origin), row = state.evidence, endpoint = state.endpointIndex === null ? null : origin.endpoints[state.endpointIndex];
      const selected = items.some(item => item.id === state.evidenceId) ? state.evidenceId : null;
      const options = [...items.slice(0, 30)];
      if (row && !options.some(item => item.id === row.evidence_id)) options.unshift({ id: row.evidence_id, label: `${row.method} ${row.path}` });
      const picker = options.length > 1 ? `<select data-service-packet-sample="true" aria-label="Captured sample">${options.map(item => `<option value="${escape(item.id)}" ${item.id === state.evidenceId ? "selected" : ""}>${escape(item.label)}</option>`).join("")}</select>` : "";
      const variants = state.packetOriginals && (state.packetOriginals.request || state.packetOriginals.response)
        ? `<span class="mr-toggle"><button type="button" class="mr-btn ${state.packetVariant === "current" ? "active" : ""}" data-service-packet-variant="current">Captured</button><button type="button" class="mr-btn ${state.packetVariant === "original" ? "active" : ""}" data-service-packet-variant="original">Before changes</button></span>` : "";
      const peer = state.socketPeer;
      const info = row ? `<details class="packet-capture-info"><summary>Capture info</summary><dl><dt>Sequence</dt><dd>${escape(row.sequence)}</dd><dt>Record</dt><dd>${escape(row.record_id)}</dd>${peer?.status === "observed" ? `<dt>Recorded peer</dt><dd>${escape(peer.ip.includes(":") ? `[${peer.ip}]` : peer.ip)}:${escape(peer.port)}</dd><dt>Route</dt><dd>${escape({ direct: "Direct", http_proxy: "HTTP proxy", socks_proxy: "SOCKS proxy", unknown: "Unknown" }[peer.route])}</dd><dt>Response headers observed at</dt><dd>${escape(peer.observedAt)}</dd>` : ""}</dl>${peer?.status === "invalid" ? '<p class="service-map-error">Socket peer details could not be verified for this read.</p>' : peer?.status === "unavailable" ? '<p class="service-map-muted">Unavailable at response headers</p>' : ""}${row.metadata_complete === false ? `<p class="service-map-error">Source metadata is incomplete: ${escape(array(row.omitted).join(", ") || "bounded metadata")}</p>` : ""}${array(row.omitted).includes("technology_token_scan_limit") ? '<p class="service-map-error">Header technology scan is partial: token candidate limit reached. Additional declarations may be omitted.</p>' : ""}${state.evidenceLegacyCatalog ? `<p class="service-map-muted">${LEGACY_CATALOG_NOTICE}</p>` : ""}${usableSocketPeer(peer) ? '<button type="button" class="secondary-action" data-service-packet-peer="true"' + (activeInspectionsBlocked() ? ' disabled' : '') + '>Find matching peer</button>' : ""}</details>` : "";
      const message = state.evidenceLoading || state.packetLoading ? "Loading captured packet…" : state.packetError || state.evidenceError;
      const inactive = activeInspectionsBlocked() ? `<p class="service-map-muted" role="status">${escape(INACTIVE_SESSION_NOTICE)}</p>` : "";
      // The picker and panes are one block sized to the inspector; inspections
      // and peers follow it, so opening one never shrinks the panes.
      return `<div class="packet-block"><div class="packet-source">${picker}${!row && endpoint ? `<span>${escape(endpoint.method)} <strong>${escape(endpoint.path)}</strong></span>` : ""}${row ? `<span>${escape(row.method)} ${escape(row.path)} · ${escape(row.status ?? "No response")} · ${escape(row.started_at)}</span>` : ""}${variants}${info}</div>${inactive}${items.length > 30 ? `<p class="service-map-muted">30 of ${items.length} samples</p>` : ""}
        ${message ? `<p role="status">${escape(message)}</p>${!state.evidenceLoading && !state.packetLoading ? '<button type="button" class="secondary-action" data-service-packet-retry="true">Retry</button>' : ""}` : ""}
        ${state.packet && packetViewerMarkup ? `<div data-service-packet>${packetViewerMarkup(packetInspectOptions())}</div>` : !message && !row ? '<p class="empty-copy">Select a captured sample.</p>' : ""}</div>
        ${selectedInspectionMarkup()}${peerOriginMarkup(origin)}`;
    }
    function replaceDetail(html) {
      const identity = JSON.stringify([state.sessionId, state.selectedOrigin, state.endpointSelection?.method, state.endpointSelection?.path, state.detailTab, state.evidenceId, state.packetVariant]);
      const sameSource = detailRender?.identity === identity && detailRender.evidence === state.evidence;
      // Native disclosures and browser HTML serialization change innerHTML.
      // Compare our generated markup locally so unchanged polls leave the
      // inspector DOM, keyboard focus, and nested scroll positions untouched.
      if (sameSource && detailRender.html === html) return;
      const previousBody = els.detail.querySelector?.(".service-map-detail-body");
      const previousList = els.detail.querySelector?.(".service-map-body-reference-list");
      const previousLimits = els.detail.querySelector?.(".service-map-body-reference-limits");
      const bodyScroll = previousBody?.scrollTop;
      const listScroll = previousList?.scrollTop;
      const limitsOpen = previousLimits?.open;
      const generatorLimitsOpen = els.detail.querySelector?.(".service-map-html-generator-limits")?.open;
      const retainedPacket = sameSource && state.packet && packetViewerElement?.isConnected ? packetViewerElement : null;
      if (!retainedPacket && packetViewer) { packetViewer.destroy(); packetViewer = null; packetViewerElement = null; }
      replace(els.detail, html, !sameSource);
      if (retainedPacket) {
        // Keep the editor/scroll owner, but refresh action eligibility on the
        // retained control when a supplementary read changes session status.
        const nextInspect = els.detail.querySelector?.("[data-service-packet-inspect]");
        const previousInspect = retainedPacket.querySelector?.("[data-service-packet-inspect]");
        if (previousInspect && nextInspect) {
          previousInspect.disabled = nextInspect.disabled;
          if (previousInspect.innerHTML !== nextInspect.innerHTML) previousInspect.innerHTML = nextInspect.innerHTML;
        }
        els.detail.querySelector?.("[data-service-packet]")?.replaceWith(retainedPacket);
      }
      mountDetailsPacket();
      detailRender = { identity, evidence: state.evidence, html };
      if (sameSource) {
        const body = els.detail.querySelector?.(".service-map-detail-body");
        const list = els.detail.querySelector?.(".service-map-body-reference-list");
        const limits = els.detail.querySelector?.(".service-map-body-reference-limits");
        if (limits && limitsOpen !== undefined) limits.open = limitsOpen;
        const generatorLimits = els.detail.querySelector?.(".service-map-html-generator-limits");
        if (generatorLimits && generatorLimitsOpen !== undefined) generatorLimits.open = generatorLimitsOpen;
        if (body && bodyScroll !== undefined) body.scrollTop = bodyScroll;
        if (list && listScroll !== undefined) list.scrollTop = listScroll;
      }
    }
    function clientDetailMarkup(client) {
      return `<header class="service-map-detail-header"><div><h3>${escape(clientName(client))}</h3><p>${[CLIENT_LABELS[client.kind], client.os, client.versions.length ? `Versions ${client.versions.join(", ")}` : ""].filter(Boolean).map(escape).join(" · ")}</p></div></header><div class="service-map-detail-body"><p class="service-map-muted">${rowCount(client.request_count)} named by the User-Agent</p>${client.addresses.length ? `<h4>Connected from</h4><p>${client.addresses.map((address) => `<code>${escape(address)}</code>`).join(" ")}</p>` : ""}<h4>Origins</h4><div class="service-map-evidence-list">${client.origins.map((item) => `<button class="service-map-evidence-button" type="button" data-service-origin="${escape(item.origin)}" data-service-focus="client-origin:${escape(item.origin)}"><span>${escape(item.origin)}<br>${rowCount(item.request_count)}${directRows(item) ? ` · ${directRows(item).toLocaleString()} direct` : ""}</span><span>Inspect ›</span></button>`).join("")}</div></div>`;
    }
    function siteDetailMarkup(site) {
      const inScope = site.members.filter((member) => member.in_scope).length;
      return `<header class="service-map-detail-header"><div><h3 title="${escape(site.site)}">*.${escape(site.site)}</h3><p>${site.members.length} loaded origin${site.members.length === 1 ? "" : "s"} in this site</p></div><span class="detail-chip ${inScope ? "ok" : "none"}">${inScope === site.members.length ? "In scope" : inScope ? "Partly in scope" : "Out of scope"}</span></header><div class="service-map-detail-body"><div class="service-map-overlay-actions"><button class="secondary-action" type="button" data-service-site-expand="${escape(site.site)}" data-service-focus="site:expand">Show origins separately</button><button class="secondary-action" type="button" data-service-hide="${escape(site.site)}" data-service-focus="site:hide">Hide site from map</button></div><h4>Origins</h4><div class="service-map-evidence-list">${site.members.map((member) => `<button class="service-map-evidence-button" type="button" data-service-origin="${escape(member.origin)}" data-service-focus="site-member:${escape(member.origin)}"><span>${escape(member.origin)}<br>${member.captured === false ? "Referenced only in this snapshot" : `${member.endpoints.length} API paths · ${count(member.request_count).toLocaleString()} sampled rows`}</span><span>Inspect ›</span></button>`).join("")}</div></div>`;
    }
    // Hide or show an origin, and group its site again once shown separately.
    function originActionsMarkup(origin) {
      const display = siteDisplay();
      const site = siteKey(origin.origin);
      const hiddenAs = display.hidden.includes(origin.origin) ? origin.origin : site && display.hidden.includes(site) ? site : null;
      const regroup = site && display.groupSites && display.expandedSites.includes(site);
      const openApi = origin.captured && originRoles(origin).some((role) => role === "api" || role === "auth")
        ? `<button class="secondary-action" type="button" data-service-api-docs="${escape(origin.origin)}" data-service-focus="origin:api-docs" title="This origin's API as OpenAPI 3.1, from its retained rows and without their values">API docs</button>` : "";
      return `<div class="service-map-overlay-actions service-map-origin-actions">${openApi}${hiddenAs ? `<button class="secondary-action" type="button" data-service-unhide="${escape(hiddenAs)}" data-service-focus="origin:unhide">${hiddenAs === origin.origin ? "Show on map" : `Show *.${escape(site)} on map`}</button>` : `<button class="secondary-action" type="button" data-service-hide="${escape(origin.origin)}" data-service-focus="origin:hide">Hide from map</button>`}${regroup ? `<button class="secondary-action" type="button" data-service-site-collapse="${escape(site)}" data-service-focus="origin:regroup">Group *.${escape(site)} again</button>` : ""}</div>`;
    }
    function renderDetail() {
      if (destroyed) return;
      const client = state.selectedClient ? clientById(state.selectedClient) : null;
      if (client) { replaceDetail(clientDetailMarkup(client)); return; }
      state.selectedClient = null;
      const site = siteDetails(state.selectedSite);
      if (site) { replaceDetail(siteDetailMarkup(site)); return; }
      // Invalidation drops data before its replacement arrives. Only a current
      // snapshot can establish that the selected site's members disappeared.
      if (state.snapshot) state.selectedSite = null;
      const origin = selectedOrigin();
      if (!origin) { replaceDetail('<div class="service-map-empty"><h3>Select an origin</h3><p>Choose a card to inspect its API paths and retained evidence.</p></div>'); return; }
      if (origin.peerInspectionOnly) {
        replaceDetail(`<header class="service-map-detail-header"><div><h3 title="${escape(origin.origin)}">${escape(new URL(origin.origin).host)}</h3><p>${escape(origin.origin)}</p></div><span class="detail-chip ${origin.in_scope ? "ok" : "none"}">${origin.in_scope ? "In scope" : "Out of scope"}</span></header><div class="service-map-detail-body">${endpointSelectionNotice(origin)}${evidenceMarkup(origin)}</div>`);
        return;
      }
      if (!origin.captured) {
        const bodyReference = overlayReferences().some((item) => item.target_origin === origin.origin);
        replaceDetail(`<header class="service-map-detail-header"><div><h3 title="${escape(new URL(origin.origin).host)}">${escape(new URL(origin.origin).host)}</h3><p title="${escape(origin.origin)}">${escape(origin.origin)}</p></div></header>${originActionsMarkup(origin)}<div class="service-map-detail-body">${endpointSelectionNotice(origin)}<h4>Referenced only in this snapshot</h4><p class="service-map-muted">This origin appears only in loaded declarations${bodyReference ? " or explicitly shown retained references" : ""}. No captured rows are shown for this origin. Scope and projection bounds may omit captured history; no service role or request count is established here.</p>${relationshipMarkup(origin)}<h4>Captured origins</h4><div class="service-map-evidence-list">${origin.references.map((ref) => `<button class="service-map-evidence-button" type="button" data-service-origin="${escape(ref.origin)}" data-service-focus="reference:${escape(ref.origin)}"><span>${escape(ref.label)} ${escape(ref.origin)}</span><span>Inspect source ›</span></button>`).join("")}</div>${origin.referencesOmitted ? `<p class="service-map-muted">${origin.referencesOmitted} additional source references omitted from this pane.</p>` : ""}</div>`);
        return;
      }
      const entries = loadedEndpointEntries([origin]);
      const units = endpointUnits(entries);
      const pageCount = Math.max(1, Math.ceil(units.length / API_PAGE_SIZE));
      state.detailPage = Math.min(state.detailPage, pageCount - 1);
      const start = state.detailPage * API_PAGE_SIZE;
      if (!state.detailPageAnchor && units[start]) state.detailPageAnchor = endpointIdentity(units[start].members[0]);
      replaceDetail(`<header class="service-map-detail-header"><div><h3 title="${escape(new URL(origin.origin).host)}">${escape(new URL(origin.origin).host)}</h3><p title="${escape(origin.origin)}">${escape(origin.origin)}</p></div><span class="detail-chip ${origin.in_scope ? "ok" : "none"}">${origin.in_scope ? "In scope" : "Out of scope"}</span></header>${originActionsMarkup(origin)}
        <div class="service-map-detail-tabs" role="tablist" aria-label="Origin details"><button type="button" role="tab" id="serviceMapDetailApisTab" aria-controls="serviceMapDetailBody" aria-selected="${state.detailTab === "apis"}" tabindex="${state.detailTab === "apis" ? 0 : -1}" data-service-detail-tab="apis" data-service-focus="detail:apis">APIs</button><button type="button" role="tab" id="serviceMapDetailEvidenceTab" aria-controls="serviceMapDetailBody" aria-selected="${state.detailTab === "evidence"}" tabindex="${state.detailTab === "evidence" ? 0 : -1}" data-service-detail-tab="evidence" data-service-focus="detail:evidence">Details</button></div>
        <div class="service-map-detail-body${state.detailTab === "apis" ? "" : " packet-details"}" id="serviceMapDetailBody" role="tabpanel" aria-labelledby="${state.detailTab === "apis" ? "serviceMapDetailApisTab" : "serviceMapDetailEvidenceTab"}">${endpointSelectionNotice(origin)}${state.detailTab === "evidence" ? evidenceMarkup(origin) : `${authMarkup(origin)}${state.endpointIndex === null ? "" : parametersMarkup(origin, origin.endpoints[state.endpointIndex])}${endpointFiltersMarkup("serviceMapDetail")}${endpointCoverageMarkup(units.length, origin.endpoints.length, start, 0, 0, entries.length)}<div class="service-map-api-list">${units.slice(start, start + API_PAGE_SIZE).map((unit) => endpointUnitMarkup(unit)).join("") || '<p class="empty-copy">No loaded endpoints match these filters for this origin.</p>'}</div>${pageCount > 1 ? `<div class="service-map-pagination"><button class="secondary-action" type="button" data-service-detail-page="${state.detailPage - 1}" ${state.detailPage === 0 ? "disabled" : ""}>Previous</button><span>${state.detailPage + 1} / ${pageCount}</span><button class="secondary-action" type="button" data-service-detail-page="${state.detailPage + 1}" ${state.detailPage + 1 >= pageCount ? "disabled" : ""}>Next</button></div>` : ""}${peerOriginMarkup(origin)}${technologyMarkup(origin.technology_observations, origin)}${serverTechnologiesMarkup(origin)}${frontTechnologiesMarkup(origin)}${unnamedMarkup(origin)}${relationshipMarkup(origin)}<div class="service-map-evidence-summary"><h4>Evidence summary</h4><p>${origin.request_count.toLocaleString()} sampled HTTP rows in this snapshot. ${origin.redirects.length} redirect instruction${origin.redirects.length === 1 ? "" : "s"}.</p><button class="secondary-action" type="button" data-service-detail-tab="evidence" data-service-focus="view:evidence">${state.endpointSelection ? "View selected endpoint details" : "View details"}</button></div>`}</div>`);
    }
    function renderCatalog() {
      const loaded = loadedEndpointEntries((state.snapshot?.origins || []).filter((origin) => !state.scopeOnly || origin.in_scope), false);
      const stages = originFilterStages((state.snapshot?.origins || []).filter((origin) => !state.scopeOnly || origin.in_scope));
      const searchedEntries = loadedEndpointEntries(stages.searched, false);
      const originEntries = loadedEndpointEntries(stages.matching, false);
      const entries = originEntries.filter(({ endpoint }) => endpointMatches(endpoint));
      const units = endpointUnits(entries);
      const pages = Math.max(1, Math.ceil(units.length / API_PAGE_SIZE));
      // Invalidation temporarily removes the snapshot. Keep the previous page
      // as the fallback if its identity anchor is absent from the next result.
      if (state.snapshot) state.page = Math.min(state.page, pages - 1);
      const start = state.page * API_PAGE_SIZE;
      if (!state.pageAnchor && units[start]) state.pageAnchor = endpointIdentity(units[start].members[0]);
      replace(els.catalog, `<header class="service-map-catalog-header"><div><h3>Observed API paths</h3></div><span>${entries.length.toLocaleString()} matching loaded combinations</span></header>${endpointFiltersMarkup("serviceMapCatalog")}${endpointSelectionNotice()}${endpointCoverageMarkup(units.length, loaded.length, start, loaded.length - searchedEntries.length, searchedEntries.length - originEntries.length, entries.length)}<div class="service-map-api-list">${units.slice(start, start + API_PAGE_SIZE).map((unit) => endpointUnitMarkup(unit, true)).join("") || `<p class="empty-copy">${state.loading && !state.snapshot ? "Loading retained API paths…" : "No loaded endpoints match these filters, origin search and origin products/versions."}</p>`}</div><div class="service-map-pagination"><button class="secondary-action" type="button" data-service-page="${state.page - 1}" ${!state.snapshot || state.page === 0 ? "disabled" : ""}>Previous</button><span>${units.length ? start + 1 : 0}–${Math.min(start + API_PAGE_SIZE, units.length)} / ${units.length}</span><button class="secondary-action" type="button" data-service-page="${state.page + 1}" ${state.page + 1 >= pages ? "disabled" : ""}>Next</button></div>`);
    }
    function render() {
      if (destroyed) return;
      renderStatus();
      renderProductFilters();
      renderOverlayStatus();
      renderGraph();
      renderDetail();
      renderCatalog();
      els.content.classList.toggle("hidden", state.view === "apis");
      els.catalog.classList.toggle("hidden", state.view !== "apis");
    }
    // A recorded arrow opens the relationship it stands for: the origin that
    // recorded it is selected, and its entry (rows by kind, CORS, View source)
    // is marked and focused in the inspector.
    function selectEdge(edge) {
      if (!edge?.kind) return;
      if (edge.relationship === "client_request") return selectClient(edge.source);
      const recordedBy = edge.relationship === "redirect_instruction" ? edge.source : edge.target;
      // A site card's arrow stands for links of several origins: open the site.
      if (recordedBy.startsWith("site:")) return selectSite(recordedBy.slice(5));
      selectOrigin(recordedBy);
      state.highlightedRelation = JSON.stringify([edge.source, edge.target, edge.relationship]);
      renderDetail();
      const entry = els.detail.querySelector?.(".service-map-relation.highlighted");
      entry?.scrollIntoView?.({ block: "nearest" });
      entry?.focus?.({ preventScroll: true });
    }
    // A site card selects the site; its inspector lists the origins it holds.
    function selectSite(site) {
      if (!state.siteCards?.has(site)) return;
      replayActionId += 1;
      cancelEvidence();
      cancelParameters();
      Object.assign(state, { selectedSite: site, selectedClient: null, selectedOrigin: null, endpointIndex: null, endpointSelection: null, highlightedRelation: null, selectionInitialized: true });
      render();
    }
    // A client card selects the client; its inspector lists where it sent rows.
    function selectClient(id) {
      if (!clientById(id)) return;
      replayActionId += 1;
      cancelEvidence();
      cancelParameters();
      Object.assign(state, { selectedClient: id, selectedSite: null, selectedOrigin: null, endpointIndex: null, endpointSelection: null, highlightedRelation: null, selectionInitialized: true });
      render();
    }
    // Showing a site's origins separately selects the first of them, so the
    // inspector stays on what was being looked at.
    function expandSite(site) {
      const first = siteDetails(site)?.members[0]?.origin;
      if (!first) return;
      saveSiteDisplay({ expandedSites: [...new Set([...siteDisplay().expandedSites, site])] });
      selectOrigin(first);
    }
    function handleClick(event) {
      replayActionId += 1;
      const flowHit = event.target.closest?.("[data-service-flow-record], [data-service-flow-lane]");
      const flowRecord = flowHit?.dataset?.serviceFlowRecord, flowLane = flowHit?.dataset?.serviceFlowLane;
      if ((flowRecord || flowLane) && els.panel.contains(flowHit)) {
        if (!flowIsCurrent()) return;
        if (flowRecord && state.flow.phases.some((phase) => phase.steps.some((step) => step.recordId === flowRecord))) return openInHistory?.(flowRecord);
        if (flowLane && state.flow.lanes.includes(flowLane)) return setFlowMode(flowLane);
        return;
      }
      const hit = event.target.closest?.("[data-service-edge]");
      if (hit?.dataset?.serviceEdge !== undefined && els.panel.contains(hit)) return selectEdge(currentLayout?.edges[Number(hit.dataset.serviceEdge)]);
      const button = event.target.closest("button");
      if (!button || !els.panel.contains(button)) return;
      const data = button.dataset;
      if (data.servicePeerEvidence && data.servicePeerOrigin) loadPeerEvidence(data.servicePeerEvidence, data.servicePeerOrigin);
      else if (data.servicePeerMatches) loadPeerMatches();
      else if (data.serviceShowPeerMatches) showPeerMatchesOnMap();
      else if (data.serviceRelationOrigin) {
        selectOrigin(data.serviceRelationOrigin);
        state.detailTab = "evidence";
        if (data.serviceRelationEvidence) loadEvidence(data.serviceRelationEvidence);
        else renderDetail();
      } else if (data.serviceEndpoint !== undefined) {
        if (state.view === "apis") {
          const origin = findOrigin(data.serviceOrigin), endpoint = origin?.endpoints[Number(data.serviceEndpoint)];
          if (endpoint) state.pageAnchor = endpointIdentity({ origin, endpoint });
        }
        selectOrigin(data.serviceOrigin, Number(data.serviceEndpoint));
        if (state.view === "apis") { state.view = "service-map"; onViewChange?.("service-map"); render(); }
      } else if (data.serviceOrigin) selectOrigin(data.serviceOrigin);
      else if (data.serviceSite) selectSite(data.serviceSite);
      else if (data.serviceClient) selectClient(data.serviceClient);
      else if (data.serviceSiteExpand) expandSite(data.serviceSiteExpand);
      else if (data.serviceSiteCollapse) saveSiteDisplay({ expandedSites: siteDisplay().expandedSites.filter((site) => site !== data.serviceSiteCollapse) });
      else if (data.serviceApiDocs) openApiDocs(data.serviceApiDocs);
      else if (data.serviceHide) {
        if (state.selectedSite === data.serviceHide) state.selectedSite = null;
        saveSiteDisplay({ hidden: [...new Set([...siteDisplay().hidden, data.serviceHide])] });
      } else if (data.serviceUnhide) saveSiteDisplay({ hidden: siteDisplay().hidden.filter((entry) => entry !== data.serviceUnhide) });
      else if (data.serviceUnhideAll) saveSiteDisplay({ hidden: [] });
      else if (data.serviceGroupSites) saveSiteDisplay({ groupSites: !siteDisplay().groupSites });
      else if (data.serviceDetailTab) { if (data.serviceDetailTab === "evidence") selectDetails(); else { state.detailTab = data.serviceDetailTab; packetViewer?.destroy(); packetViewer = null; packetViewerElement = null; renderDetail(); } }
      else if (data.servicePacketVariant) loadPacket(data.servicePacketVariant);
      else if (data.servicePacketRetry) { if (state.evidence) loadPacket(); else if (state.peerEvidenceBinding) loadPeerEvidence(state.evidenceId, state.selectedOrigin); else if (state.evidenceId) loadEvidence(state.evidenceId); }
      else if (data.servicePacketPeer) { state.packetInspection = "peer"; loadPeerMatches(); }
      else if (data.serviceEndpointGroup) {
        const groups = state.expandedEndpointGroups;
        if (groups.has(data.serviceEndpointGroup)) groups.delete(data.serviceEndpointGroup);
        else groups.add(data.serviceEndpointGroup);
        if (state.view === "apis") renderCatalog(); else renderDetail();
      } else if (data.serviceEndpointFilterClear) setEndpointFilter("clear");
      else if (data.serviceProductFilterClear) setProductFilter("clear");
      else if (data.serviceEvidence) loadEvidence(data.serviceEvidence);
      else if (data.serviceBodyReferences) loadBodyReferences();
      else if (data.serviceLinkDeclarations) loadLinkDeclarations();
      else if (data.serviceShowLinkDeclarations) showLinkDeclarationsOnMap();
      else if (data.serviceHtmlGenerators) loadHtmlGenerators();
      else if (data.serviceShowBodyReferences) showBodyReferencesOnMap();
      else if (data.serviceRemoveInspection) { clearOverlay("Inspection removed.", (layer) => layerKey(layer) === data.serviceRemoveInspection); render(); }
      else if (data.serviceClearBodyReferences) clearBodyReferenceOverlay();
      else if (data.servicePage !== undefined) { state.page = Math.max(0, Number(data.servicePage) || 0); state.pageAnchor = null; renderCatalog(); els.catalog.scrollTop = 0; }
      else if (data.serviceDetailPage !== undefined) {
        state.detailPage = Math.max(0, Number(data.serviceDetailPage) || 0);
        state.detailPageAnchor = null;
        renderDetail();
        // Explicit page navigation returns to the endpoint filters/counts. A
        // short last page must not inherit a long page's relationship scroll.
        const body = els.detail.querySelector?.(".service-map-detail-body");
        if (body) body.scrollTop = 0;
      }
    }
    let onViewChange = null;
    listen(els.panel, "click", handleClick);
    listen(els.panel, "change", (event) => {
      if (event.target?.dataset?.serviceProductFilter) setProductFilter(event.target.dataset.serviceProductFilter, event.target.value);
      else if (event.target?.dataset?.servicePacketSample) loadEvidence(event.target.value);
      else if (event.target?.dataset?.servicePacketInspect) {
        if (!visible || state.view !== "service-map" || state.packetVariant !== "current"
          || activeInspectionsBlocked()
          || event.target.isConnected === false || mountPacketViewer && (!state.packet
            || event.target.dataset.servicePacketOwner !== String(state.packetRequestId))) return;
        const kind = event.target.value;
        if (kind !== "body" && (state.stale || state.error || !getEventStreamReady())) return;
        event.target.value = "";
        if (kind === "generator") loadHtmlGenerators();
        else if (kind === "body" || kind === "link") { setRelationshipKind(kind); if (kind === "body") loadBodyReferences(); else loadLinkDeclarations(); }
      }
      else if (event.target?.dataset?.serviceRelationshipKind) setRelationshipKind(event.target.value);
      else if (event.target?.dataset?.serviceEndpointFilter === "method") setEndpointFilter("method", event.target.value);
    });
    listen(els.panel, "input", (event) => {
      if (event.target?.dataset?.serviceEndpointFilter === "path") setEndpointFilter("path", event.target.value);
    });
    listen(els.panel, "keydown", (event) => {
      const flowKey = event.target.closest?.("[data-service-flow-record], [data-service-flow-lane]");
      if ((event.key === "Enter" || event.key === " ") && (flowKey?.dataset?.serviceFlowRecord || flowKey?.dataset?.serviceFlowLane)) {
        event.preventDefault();
        return handleClick(event);
      }
      const tab = event.target.closest('[role="tab"][data-service-detail-tab]');
      if (!tab || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      replayActionId += 1;
      state.detailTab = event.key === "Home" ? "apis" : event.key === "End" ? "evidence" : state.detailTab === "apis" ? "evidence" : "apis";
      if (state.detailTab === "evidence") selectDetails(); else { packetViewer?.destroy(); packetViewer = null; packetViewerElement = null; renderDetail(); }
      const next = [...els.detail.querySelectorAll('[role="tab"][data-service-detail-tab]')].find((button) => button.dataset.serviceDetailTab === state.detailTab);
      next?.focus();
    });
    listen(els.apiDocs, "click", (event) => {
      if (event.target === els.apiDocs) return closeApiDocs();
      const data = event.target.closest?.("button")?.dataset;
      if (!data) return;
      if (data.apiDocsClose !== undefined) closeApiDocs();
      // The text is already read, so the copy runs within the click.
      else if (data.apiDocsCopy !== undefined && state.apiDocs?.document) copyApiDocs("Copied OpenAPI");
      // Swagger Editor cannot fetch the document from this app, so the click
      // copies it to paste there. Nothing is sent to the site.
      else if (data.apiDocsEditor !== undefined && state.apiDocs?.document) {
        if (copyApiDocs("Copied OpenAPI; paste it into Swagger Editor")) openUrl?.(SWAGGER_EDITOR_URL);
      }
      else if (data.apiDocsReplay) sendApiDocsToReplay(data.apiDocsReplay);
    });
    listen(els.apiDocs, "keydown", (event) => {
      if (event.key !== "Escape" || event.defaultPrevented || event.isComposing || !isActiveModal(els.apiDocs)) return;
      event.preventDefault?.();
      closeApiDocs();
    });
    listen(els.zoomOut, "click", () => setZoom(state.zoomScale - ZOOM_LIMITS.step));
    listen(els.zoomReset, "click", fitOrReset);
    listen(els.zoomIn, "click", () => setZoom(state.zoomScale + ZOOM_LIMITS.step));
    listen(els.viewport, "keydown", (event) => {
      if (event.target !== els.viewport || event.ctrlKey || event.metaKey || event.altKey) return;
      const handled = event.key === "+" || event.key === "=" ? setZoom(state.zoomScale + ZOOM_LIMITS.step)
        : event.key === "-" ? setZoom(state.zoomScale - ZOOM_LIMITS.step)
        : event.key === "0" ? setZoom(1) : event.key.toLowerCase() === "f" ? fitGraph() : false;
      if (handled) event.preventDefault();
    });
    // A trackpad pinch arrives as a ctrl+wheel event in Chromium and as WebKit
    // gesture events (the macOS desktop app, Safari) with a scale relative to the
    // start. Either zooms the graph around the fingers instead of zooming the
    // whole page; a plain wheel still scrolls the map. Ctrl+wheel on a mouse
    // zooms the same way.
    let pinchStartScale = null;
    const pinchAnchor = (event) => {
      const rect = els.viewport?.getBoundingClientRect?.();
      return rect && Number.isFinite(event.clientX) && Number.isFinite(event.clientY)
        ? { x: event.clientX - rect.left, y: event.clientY - rect.top } : null;
    };
    listen(els.viewport, "scroll", pinFlowHeads, { passive: true });
    listen(els.viewport, "wheel", (event) => {
      if (!event.ctrlKey || pinchStartScale !== null || !zoomAvailable()) return;
      event.preventDefault();
      // A mouse notch is about 100px against a few px per trackpad frame; the cap
      // keeps one notch near a button step.
      const lines = event.deltaMode === 1 ? 16 : 1;
      const delta = Math.max(-20, Math.min(20, (Number(event.deltaY) || 0) * lines));
      setZoom(state.zoomScale * Math.exp(-delta / 100), { anchor: pinchAnchor(event) });
    }, { passive: false });
    listen(els.viewport, "gesturestart", (event) => {
      if (!zoomAvailable()) return;
      event.preventDefault();
      pinchStartScale = state.zoomScale;
    });
    listen(els.viewport, "gesturechange", (event) => {
      if (pinchStartScale === null) return;
      event.preventDefault();
      if (Number.isFinite(event.scale)) setZoom(pinchStartScale * event.scale, { anchor: pinchAnchor(event) });
    });
    listen(els.viewport, "gestureend", (event) => {
      if (pinchStartScale === null) return;
      event.preventDefault();
      pinchStartScale = null;
    });
    // Resize only refreshes control availability; Fit is an explicit one-shot
    // action, so resizing or polling cannot silently change the user's zoom.
    const resizeObserver = els.viewport && typeof root.ResizeObserver === "function" ? new root.ResizeObserver(updateZoomControls) : null;
    resizeObserver?.observe(els.viewport);
    // Showing or hiding a request kind changes which links count, so the cards
    // are ranked and laid out again for the links that remain.
    listen(els.linkKinds, "click", (event) => {
      const kind = event.target?.closest?.("[data-link-kind]")?.dataset.linkKind;
      if (!REQUEST_KINDS.includes(kind)) return;
      const hidden = new Set(hiddenLinkKinds());
      if (hidden.has(kind)) hidden.delete(kind); else hidden.add(kind);
      saveHiddenLinkKinds(REQUEST_KINDS.filter((item) => hidden.has(item)));
      if (state.snapshot) {
        state.order = relationshipOrder(graphOrigins(), hiddenLinkKinds());
        state.layoutSlots = new Map();
        // Ranked here already; the next read need not rank again.
        state.kindSignature = JSON.stringify(hiddenLinkKinds());
      }
      renderGraph();
    });
    listen(els.refresh, "click", () => {
      // Polling keeps cards where they are; an explicit Reload may move them so
      // relationships captured since the map opened come within the card cap.
      if (state.snapshot) {
        state.order = relationshipOrder(graphOrigins(), hiddenLinkKinds());
        state.layoutSlots = new Map();
      }
      return refresh({ force: true, retry: true });
    });
    listen(els.allOrigins, "click", () => setMapMode(false));
    listen(els.directRelations, "click", () => setMapMode(!state.anchorOrigin));
    listen(els.flow, "click", () => setFlowMode(state.selectedOrigin));
    listen(els.flowMermaid, "click", copyFlow);
    listen(els.focusSelection, "click", focusSelection);
    listen(els.search, "input", () => { replayActionId += 1; state.query = els.search.value; state.page = 0; state.pageAnchor = null; render(); });
    listen(els.scope, "click", () => {
      cancelFlow();
      state.scopeOnly = !state.scopeOnly;
      els.scope.classList.toggle("active", state.scopeOnly);
      els.scope.setAttribute("aria-pressed", String(state.scopeOnly));
      state.refreshPaused = false;
      clearOverlay("Temporary body references cleared because the scope filter changed.");
      state.page = 0;
      state.snapshot = null;
      state.endpointIndex = null;
      cancelEvidence();
      cancelParameters();
      refresh({ force: true });
    });
    render();
    return {
      refresh, reset, selectOrigin, setProductFilter, setZoom, fitGraph, loadEvidence, loadPeerEvidence, loadPeerMatches, showPeerMatchesOnMap, loadBodyReferences, loadLinkDeclarations, loadHtmlGenerators, setRelationshipKind, showBodyReferencesOnMap, showLinkDeclarationsOnMap, clearBodyReferenceOverlay,
      displayChanged() { renderGraph(); },
      // The Service Map filter changes which rows count, as the scope filter
      // does, so it drops inspections the same way; the read re-ranks the cards.
      filterChanged() {
        cancelFlow();
        state.refreshPaused = false;
        clearOverlay("Temporary body references cleared because the Service Map filter changed.");
        state.requestId += 1;
        abort?.abort();
        state.loading = false;
        state.page = 0;
        state.snapshot = null;
        state.endpointIndex = null;
        cancelEvidence();
        cancelParameters();
        return refresh({ force: true });
      },
      scopeChanged(previous, next) {
        const signature = (runtime) => JSON.stringify([array(runtime?.scope_patterns), array(runtime?.excluded_scope_patterns)]);
        if (signature(previous) === signature(next)) return false;
        state.refreshPaused = false;
        return this.invalidate();
      },
      markDirty(event) {
        let recordId = null;
        try {
          const summary = typeof event?.data === "string" ? JSON.parse(event.data) : null;
          if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(summary?.id || "")) recordId = summary.id.toLowerCase();
        } catch (_) { /* Unknown event identity invalidates every inspection. */ }
        const graphChanged = clearOverlay("Affected inspections removed because retained history changed. Inspect and show those sources again when ready.",
          (layer) => !recordId || layer.kind === "peer" || !validTechnologyEvidence(layer.source.evidenceId, layer.source.sessionId, layer.source.generation) || layer.source.evidenceId.split(".")[5].toLowerCase() === recordId);
        state.historyVersion += 1;
        state.stale = true;
        // Open API docs and an open endpoint's parameters stay: this fires for
        // every captured row, so clearing them here would empty the dialog and
        // the panel while traffic flows. A count one row behind is harmless,
        // and Replay reports a row that is gone. Deletion, retention and Clear
        // take their own invalidation paths, which do clear them. The evidence read
        // stays too unless this is its row, or no source could be inspected
        // while traffic flowed; peer matches count other rows, so any row
        // can change them.
        const evidenceRecord = state.peerEvidenceBinding ? null : String(state.evidenceId || "").split(".")[5]?.toLowerCase();
        if (recordId && evidenceRecord && evidenceRecord !== recordId) cancelPeerMatches();
        else cancelEvidence();
        renderHistoryChange(graphChanged);
      },
      setVisible(value, view = state.view) {
        if (destroyed) return;
        if (!value || view !== state.view) closeProductFilters();
        if (!value || view !== state.view) suspendRefresh();
        if (!value || view !== state.view) replayActionId += 1;
        const becameVisible = value && !visible;
        if (!value) cancelParameters();
        if (!value || view !== state.view) cancelPacket();
        if (!value || view !== "service-map") {
          clearOverlay("Temporary body references cleared because the map was hidden.");
          cancelBodyReferences();
          cancelHtmlGenerators();
          cancelPeerMatches();
        }
        if (!value || view !== state.view) closeApiDocs(false);
        visible = value;
        state.view = view;
        if (state.sessionId !== getSessionId()) reset();
        render();
        if (becameVisible && state.detailTab === "evidence") selectDetails();
        historyPresentationPending = false;
        resumeFlow();
        scheduleAutomaticRefresh();
      },
      destroy() {
        if (destroyed) return;
        destroyed = true;
        visible = false;
        closeProductFilters();
        suspendRefresh();
        replayActionId += 1;
        closeApiDocs(false);
        cancelEvidence();
        cancelParameters();
        resizeObserver?.disconnect();
        for (const dispose of eventDisposers) dispose();
        if (faviconRedraw !== null) root.clearTimeout?.(faviconRedraw);
        faviconRedraw = null;
        doc?.removeEventListener?.("visibilitychange", onVisibilityChange);
        root.removeEventListener?.("pagehide", onPageHide);
        root.removeEventListener?.("pageshow", onPageShow);
      },
      setViewChange(callback) { onViewChange = callback; },
      disconnect() {
        replayActionId += 1;
        cancelFlow();
        clearOverlay("Temporary body references cleared because the session event connection was lost.");
        state.requestId += 1;
        state.historyVersion += 1;
        abort?.abort();
        abort = null;
        state.loading = false;
        state.stale = true;
        closeApiDocs();
        cancelEvidence();
        cancelParameters();
        render();
        scheduleAutomaticRefresh();
      },
      retentionChanged() {
        // At the retention cap each capture can remove a row. Canceling and
        // restarting on every removal would starve a slow map forever. Keep
        // its captured window explicitly stale and coalesce one next read;
        // exact inspections cannot retain bindings to possibly removed rows.
        replayActionId += 1;
        state.historyVersion += 1;
        state.stale = true;
        const flowChanged = !!state.flow || state.flowLoading;
        cancelFlow();
        const graphChanged = clearOverlay("Shown inspections cleared because automatic cleanup removed retained history.");
        closeApiDocs();
        cancelEvidence();
        cancelParameters();
        renderHistoryChange(graphChanged || flowChanged);
        scheduleAutomaticRefresh();
      },
      invalidate() {
        replayActionId += 1;
        cancelFlow();
        clearOverlay("Temporary body references cleared because history or scope was invalidated.");
        state.requestId += 1;
        state.historyVersion += 1;
        abort?.abort();
        state.loading = false;
        state.snapshot = null;
        state.endpointIndex = null;
        closeApiDocs();
        cancelEvidence();
        cancelParameters();
        render();
        return refresh();
      },
      getApiDocsModalAction: () => state.apiDocs && visible && els.apiDocs?.getClientRects().length
        ? { modal: els.apiDocs, close: closeApiDocs, apply: null } : null,
      // State access makes offline lifecycle tests use the same real controller.
      loadPacket, selectDetails,
      getState: () => state,
    };
  }
  root.SniperServiceMap = { createController, normalizePacket, technologyLiteral, normalizeFlow, flowLayout, flowMarkup, flowHeadsOffset, flowMermaid, EXPOSURE_LABELS, AUTH_KINDS, relationshipOrder, siteKey, groupSites, originRole, originRoles, reportedProducts, productMatches, productSummaryMarkup, normalizeSnapshot, normalizeRowTechnologies, normalizeBodyReferences, normalizeHtmlGenerators, normalizeLinkDeclarations, normalizeSocketPeer, normalizePeerMatches, usableSocketPeer, peerGraphLayout, PEER_MATCH_LIMITS, LINK_DECLARATION_LIMITS, BODY_REFERENCE_LIMITS, HTML_GENERATOR_LIMITS, MAX_RELATION_LAYERS, stableOrder, graphLayout, graphGeometry, safeOrigin, safePath, MAX_CARDS, MAX_EDGES, MAX_REFERENCE_CARDS, GRAPH_GEOMETRY, ZOOM_LIMITS };
})(typeof window === "undefined" ? globalThis : window);
