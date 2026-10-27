(function (root) {
  "use strict";

  const PAGE_SIZE = 50;
  const SOURCE_NAMES = { crawler: "Static crawler", urlscan: "urlscan.io history", wayback: "Wayback history", urlscan_submit: "New urlscan.io scan" };
  const KIND_NAMES = { live: "Live", observed: "Observed", history: "Historical", candidate: "Candidate" };
  const ACTIVE_STATUSES = new Set(["running", "queued", "stopping"]);

  function parseTarget(value) {
    if (/[\u0000-\u001f\u007f-\u009f]/.test(value)) throw new Error("Remove control characters from the target URL.");
    let target;
    try { target = new URL(value.trim()); } catch (_) { throw new Error("Enter a complete HTTP or HTTPS target URL."); }
    if (!["http:", "https:"].includes(target.protocol) || !target.hostname) {
      throw new Error("Only HTTP and HTTPS targets are supported.");
    }
    if (target.username || target.password) throw new Error("Remove credentials from the target URL.");
    if (target.hostname.includes("*")) throw new Error("Target hostname cannot contain wildcard characters.");
    if (target.port === "0") throw new Error("Use a target port between 1 and 65535.");
    target.hash = "";
    return target;
  }

  function optionalBudget(value, label) {
    const number = Number(value ?? 0);
    if (!Number.isSafeInteger(number) || number < 0) {
      throw new Error(`${label} must be a nonnegative safe integer (0 means unlimited).`);
    }
    return number;
  }

  function buildJobRequest(values, sessionId) {
    if (!sessionId) throw new Error("Wait for the session to finish loading.");
    const target = parseTarget(values.target);
    if (values.includeSubdomains && (target.hostname.startsWith("[") || /^\d+(?:\.\d+){3}$/.test(target.hostname))) {
      throw new Error("Subdomain scope is only available for DNS names.");
    }
    const sources = ["crawler", "urlscan", "wayback", "urlscan_submit"].filter((source) => !!values[source]);
    if (!sources.length) throw new Error("Select at least one discovery source.");
    const history = sources.some((source) => source === "urlscan" || source === "wayback");
    if (history && !values.historyAcknowledged) {
      throw new Error("Allow domain sharing with the selected history services before starting.");
    }
    const submission = sources.includes("urlscan_submit");
    // URL.search/hash are empty for bare delimiters; the server rejects those too.
    if (submission && /[?#]/.test(new URL(values.target.trim()).href)) throw new Error("Remove query strings and fragments before sharing a new scan URL with urlscan.io.");
    if (submission && !values.scanAcknowledged) throw new Error("Allow the new urlscan.io scan and its visibility before starting.");
    if (submission && !["private", "unlisted", "public"].includes(values.scanVisibility)) throw new Error("Choose a valid urlscan.io scan visibility.");
    return {
      session_id: sessionId,
      target_url: target.href,
      include_subdomains: !!values.includeSubdomains,
      sources,
      history_acknowledged: history && !!values.historyAcknowledged,
      scan_acknowledged: submission && !!values.scanAcknowledged,
      scan_visibility: submission ? values.scanVisibility : "private",
      max_requests: optionalBudget(values.maxRequests, "Crawler requests"),
      max_depth: optionalBudget(values.maxDepth, "Crawl depth"),
      max_endpoints: optionalBudget(values.maxEndpoints, "Endpoint budget"),
      max_pages: optionalBudget(values.maxPages, "History pages"),
    };
  }

  function endpointKey(endpoint) { return `${endpoint.method || "UNKNOWN"}\n${endpoint.url || ""}`; }
  function evidenceOf(endpoint) { return Array.isArray(endpoint.evidence) ? endpoint.evidence : []; }
  function kindsOf(endpoint) { return [...new Set(evidenceOf(endpoint).map((item) => item.kind || "candidate"))]; }
  function sourcesOf(endpoint) { return [...new Set(evidenceOf(endpoint).map((item) => item.source || "unknown"))]; }
  function matchesEndpoint(endpoint, term, kind) {
    if (kind && !kindsOf(endpoint).includes(kind)) return false;
    if (!term) return true;
    return [endpoint.url, endpoint.method, ...(endpoint.raw_urls || []), ...evidenceOf(endpoint).flatMap((item) => [item.source, item.kind, item.location])]
      .some((value) => String(value || "").toLowerCase().includes(term));
  }
  function filterEndpoints(endpoints, query, kind) {
    const term = String(query || "").trim().toLowerCase();
    return endpoints.filter((endpoint) => matchesEndpoint(endpoint, term, kind));
  }

  // The text each column shows, which is what it sorts by.
  const SORT_TEXT = {
    method: (endpoint) => endpoint.method || "UNKNOWN",
    url: (endpoint) => endpoint.url || "",
    evidence: (endpoint) => kindsOf(endpoint).map((kind) => KIND_NAMES[kind] || kind).join(", "),
    sources: (endpoint) => sourcesOf(endpoint).map((source) => SOURCE_NAMES[source] || source).join(", "),
  };
  // A copy in the column's order; ties keep the order they came in.
  function sortEndpoints(list, sort) {
    const text = SORT_TEXT[sort?.key];
    if (!text) return list;
    const sign = sort.direction === "desc" ? -1 : 1;
    return list.map((endpoint, index) => [text(endpoint).toLowerCase(), index, endpoint])
      .sort((a, b) => (a[0] < b[0] ? -sign : a[0] > b[0] ? sign : a[1] - b[1]))
      .map(([, , endpoint]) => endpoint);
  }
  // A header click sorts by its column, and a second click reverses it.
  function nextSort(current, key) {
    if (current.key === key) return { key, direction: current.direction === "asc" ? "desc" : "asc" };
    return { key, direction: "asc" };
  }
  function pageEndpoints(endpoints, requestedPage, pageSize = PAGE_SIZE) {
    const pages = Math.max(1, Math.ceil(endpoints.length / pageSize));
    const page = Math.max(0, Math.min(Number.isInteger(requestedPage) ? requestedPage : 0, pages - 1));
    return { page, pages, items: endpoints.slice(page * pageSize, (page + 1) * pageSize) };
  }

  const COPY_JSON_LIMIT = 2 * 1024 * 1024;
  const COPY_LIMIT_ERROR = "Filtered JSON exceeds the 2 MiB copy limit. Narrow the filter or use the full API/CLI.";
  const COPY_DATA_ERROR = "Could not copy this inventory as JSON.";
  const JOB_STATUSES = ["queued", "running", "stopping", "completed", "cancelled", "interrupted", "failed", "unknown"];

  function exportCoverage(jobs, truncated) {
    const counts = (names) => Object.fromEntries(names.map((name) => [name, 0]));
    const coverage = {
      scope: "session", endpoint_job_attribution: "unavailable", raw_job_diagnostics_included: false,
      inventory_truncated: typeof truncated === "boolean" ? truncated : null,
      job_status_counts: counts(JOB_STATUSES), source_counts: counts([...Object.keys(SOURCE_NAMES), "unknown"]),
      source_status_counts: counts(JOB_STATUSES), truncated_source_count: 0, warning_count: 0,
    };
    const increment = (bucket, name) => { bucket[typeof name === "string" && Object.hasOwn(bucket, name) ? name : "unknown"] += 1; };
    for (const job of jobs) {
      if (!job || typeof job !== "object" || Array.isArray(job)) throw new Error(COPY_DATA_ERROR);
      increment(coverage.job_status_counts, job.status);
      if (job.sources !== undefined && !Array.isArray(job.sources)) throw new Error(COPY_DATA_ERROR);
      for (const source of job.sources || []) {
        if (!source || typeof source !== "object" || Array.isArray(source)) throw new Error(COPY_DATA_ERROR);
        increment(coverage.source_counts, source.source);
        increment(coverage.source_status_counts, source.status);
        if (source.truncated !== undefined && typeof source.truncated !== "boolean") throw new Error(COPY_DATA_ERROR);
        if (source.truncated) coverage.truncated_source_count += 1;
        if (source.warnings !== undefined && !Array.isArray(source.warnings)) throw new Error(COPY_DATA_ERROR);
        for (const warning of source.warnings || []) if (typeof warning !== "string") throw new Error(COPY_DATA_ERROR);
        coverage.warning_count += source.warnings?.length || 0;
      }
    }
    return coverage;
  }

  function serializeFilteredExport(input, limit = COPY_JSON_LIMIT) {
    if (!Number.isSafeInteger(limit) || limit < 0 || !Array.isArray(input.endpoints) || !Array.isArray(input.jobs)) throw new Error(COPY_DATA_ERROR);
    // Only finite category counts are built before the original-record preflight.
    // Global job targets and diagnostics can contain URLs unrelated to the filter.
    const coverage = exportCoverage(input.jobs, input.inventoryTruncated);
    let bytes = 0;
    const add = (count) => { if (count > limit - bytes) throw new Error(COPY_LIMIT_ERROR); bytes += count; };
    function countString(value) {
      add(2);
      for (let i = 0; i < value.length; i += 1) {
        const code = value.charCodeAt(i);
        if (code === 34 || code === 92 || code === 8 || code === 9 || code === 10 || code === 12 || code === 13) add(2);
        else if (code < 32) add(6);
        else if (code < 128) add(1);
        else if (code < 2048) add(2);
        else if (code >= 0xd800 && code <= 0xdbff && i + 1 < value.length && value.charCodeAt(i + 1) >= 0xdc00 && value.charCodeAt(i + 1) <= 0xdfff) { add(4); i += 1; }
        else if (code >= 0xd800 && code <= 0xdfff) add(6);
        else add(3);
      }
    }
    // The same fixed traversal measures first, then emits. No mapped endpoint
    // tree or escaped large leaf exists until the complete whitelist fits.
    function walk(raw, string) {
      const text = (value, nullable = false) => {
        if (nullable && value === null) raw("null");
        else { if (typeof value !== "string") throw new Error(COPY_DATA_ERROR); string(value); }
      };
      const number = (value) => {
        if (!Number.isSafeInteger(value) || value < 0) throw new Error(COPY_DATA_ERROR);
        raw(String(value));
      };
      function object(fields) {
        raw("{"); let first = true;
        fields((key, emit) => { if (!first) raw(","); first = false; string(key); raw(":"); emit(); });
        raw("}");
      }
      function array(items, emit) {
        if (!Array.isArray(items)) throw new Error(COPY_DATA_ERROR);
        raw("["); for (let i = 0; i < items.length; i += 1) { if (i) raw(","); emit(items[i]); } raw("]");
      }
      const record = (value) => { if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(COPY_DATA_ERROR); };
      function evidence(value) {
        record(value);
        object((field) => {
          for (const key of ["source", "kind", "location", "timestamp"]) {
            if (value[key] !== undefined) field(key, () => text(value[key], key === "timestamp"));
          }
          if (value.status !== undefined) field("status", () => {
            if (value.status === null) raw("null");
            else { if (value.status > 65535) throw new Error(COPY_DATA_ERROR); number(value.status); }
          });
        });
      }
      function endpoint(value) {
        record(value);
        object((field) => {
          field("url", () => text(value.url)); field("method", () => text(value.method));
          if (value.raw_urls !== undefined) field("raw_urls", () => array(value.raw_urls, (url) => text(url)));
          if (value.evidence !== undefined) field("evidence", () => array(value.evidence, evidence));
          for (const key of ["first_seen", "last_seen"]) if (value[key] !== undefined) field(key, () => text(value[key]));
        });
      }
      object((field) => {
        field("schema_version", () => number(1));
        field("session_id", () => text(input.sessionId));
        field("copied_at", () => text(input.copiedAt));
        field("filters", () => object((f) => { f("query", () => text(input.query)); f("kind", () => text(input.kind)); }));
        field("sort", () => object((f) => { f("key", () => text(input.sort.key)); f("direction", () => text(input.sort.direction)); }));
        field("inventory_count", () => number(input.inventoryCount)); field("matched_count", () => number(input.endpoints.length));
        field("coverage", () => object((f) => {
          for (const key of ["scope", "endpoint_job_attribution"]) f(key, () => text(coverage[key]));
          f("raw_job_diagnostics_included", () => raw("false"));
          f("inventory_truncated", () => raw(coverage.inventory_truncated === null ? "null" : coverage.inventory_truncated ? "true" : "false"));
          for (const key of ["job_status_counts", "source_counts", "source_status_counts"]) f(key, () => object((counter) => {
            for (const [name, count] of Object.entries(coverage[key])) counter(name, () => number(count));
          }));
          for (const key of ["truncated_source_count", "warning_count"]) f(key, () => number(coverage[key]));
        }));
        field("endpoints", () => array(input.endpoints, endpoint));
      });
    }
    walk((token) => add(token.length), countString);
    const expectedBytes = bytes;
    const chunks = [];
    bytes = 0;
    walk((token) => { add(token.length); chunks.push(token); }, (value) => { countString(value); chunks.push(JSON.stringify(value)); });
    const result = chunks.join("");
    if (new TextEncoder().encode(result).length !== expectedBytes || expectedBytes > limit) throw new Error(COPY_DATA_ERROR);
    return result;
  }

  // Match workspace admission, not collection limits. Count before escaping
  // large strings; URL parsing is only authority validation, never target repair.
  function buildReplayDraft(endpoint) {
    const limit = 2 * 1024 * 1024;
    const invalid = () => { throw new Error("This discovery cannot form a safe HTTP Replay draft."); };
    const tooLarge = () => { throw new Error("This discovery exceeds Replay draft limits. The inventory is unchanged."); };
    const url = endpoint?.url, method = endpoint?.method;
    if (typeof url !== "string" || typeof method !== "string") invalid();
    if (url.length > limit || method.length > limit) tooLarge();
    if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(method) || /^(UNKNOWN|CONNECT)$/i.test(method)
      || /[\s\u0000-\u001f\u007f-\u009f\\#]/u.test(url)) invalid();
    const match = url.match(/^(https?):\/\/([^/?#]+)([/?][^#]*)?$/i);
    if (!match) invalid();
    const authority = match[2], scheme = match[1].toLowerCase();
    if (authority.length > 4096) tooLarge();
    if (authority.includes("@") || authority.includes("*")
      || !(authority.startsWith("[") ? /^\[[^\]]+\](?::[0-9]+)?$/.test(authority) : /^[^:]+(?::[0-9]+)?$/.test(authority))) invalid();
    let parsed;
    try { parsed = new URL(`${scheme}://${authority}/`); } catch (_) { invalid(); }
    if (!parsed.hostname || parsed.hostname.includes("*") || parsed.username || parsed.password || parsed.port === "0") invalid();
    const path = !match[3] ? "/" : match[3].startsWith("?") ? `/${match[3]}` : match[3];
    function stringBytes(value, escaped = false) {
      let count = 0;
      for (const char of value) {
        const code = char.codePointAt(0);
        if (code >= 0xd800 && code <= 0xdfff) invalid();
        count += escaped && (char === '"' || char === "\\") ? 2 : code < 128 ? 1 : code < 2048 ? 2 : code < 65536 ? 3 : 4;
        if (count > limit) tooLarge();
      }
      return count;
    }
    const authorityBytes = stringBytes(authority);
    if (authorityBytes > 4096) tooLarge();
    const requestBytes = stringBytes(method) + stringBytes(path) + authorityBytes + "  HTTP/1.1\nHost: ".length;
    // Fixed keys, punctuation, empty body and enums mirror EditableRequest.
    const empty = { scheme: "", host: "", method: "", path: "", headers: [{ name: "Host", value: "" }], body: "", body_encoding: "utf8", preview_truncated: false };
    const serializedBytes = JSON.stringify(empty).length + stringBytes(scheme, true) + stringBytes(authority, true) * 2 + stringBytes(method, true) + stringBytes(path, true);
    if (requestBytes > limit || serializedBytes > limit) tooLarge();
    const request = { ...empty, scheme, host: authority, method, path, headers: [{ name: "Host", value: authority }] };
    if (new TextEncoder().encode(JSON.stringify(request)).length !== serializedBytes) invalid();
    // Replay shows a notice in its response header and body alike, so this one
    // is as short as Replay's own. The evidence stays in Recon.
    return { request, notice: "Draft from Recon. Not sent yet." };
  }

  function createSessionGuard(getSessionId, getGeneration = () => 0) {
    let epoch = 0;
    return {
      capture: () => ({ sessionId: getSessionId(), generation: getGeneration(), epoch }),
      current: (token) => !!token.sessionId && token.sessionId === getSessionId()
        && token.generation === getGeneration() && token.epoch === epoch,
      invalidate: () => { epoch += 1; },
    };
  }

  function createController(options) {
    const shell = options.root;
    const doc = shell.ownerDocument;
    const fetcher = options.fetch || root.fetch.bind(root);
    const schedule = options.setTimeout || root.setTimeout.bind(root);
    const unschedule = options.clearTimeout || root.clearTimeout.bind(root);
    const guard = createSessionGuard(options.getSessionId, options.getSessionGeneration);
    const ids = ["Form", "Target", "Subdomains", "Scope", "Crawler", "Urlscan", "Wayback", "HistoryConsentRow", "HistoryConsent", "HistoryConsentText", "UrlscanSubmit", "ScanOptions", "ScanVisibility", "ScanConsent", "ScanConsentText", "MaxRequests", "MaxDepth", "MaxEndpoints", "MaxPages", "Start", "Refresh", "ActionStatus", "Jobs", "JobsMeta", "Search", "Kind", "InventoryMeta", "LoadStatus", "Head", "Endpoints", "Detail", "PageMeta", "Previous", "Next", "CopyJson"];
    const els = Object.fromEntries(ids.map((id) => [id, shell.querySelector(`#recon${id}`)]));
    let visible = false;
    let sessionId = null;
    let sessionGeneration = null;
    let timer = null;
    let read = null;
    let mutation = null;
    let jobs = [];
    let endpoints = [];
    let loaded = false;
    let loadError = "";
    let actionMessage = "";
    let actionError = false;
    let page = 0;
    let sort = { key: "", direction: "asc" };
    // The endpoints the page shows, which ↑/↓ move through.
    let pageItems = [];
    let selectedKey = null;
    let copyEpoch = 0;
    let copyIntent = 0;
    let bulkContext = 0;
    let inventoryTruncated = false;
    let exportInventoryTruncated = null;
    let disposed = false;
    const listeners = [];

    function on(element, event, callback) {
      element.addEventListener(event, callback);
      listeners.push(() => element.removeEventListener(event, callback));
    }
    function element(tag, className, text) {
      const node = doc.createElement(tag);
      if (className) node.className = className;
      if (text !== undefined) node.textContent = String(text);
      return node;
    }
    function showNotice(node, message, error = false) {
      node.textContent = message;
      node.classList.toggle("hidden", !message);
      node.classList.toggle("recon-error", error);
    }
    function date(value) {
      if (!value) return "—";
      const parsed = new Date(value);
      return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
    }
    function number(value) { return Number.isFinite(Number(value)) ? Number(value).toLocaleString() : "0"; }
    function clearTimer() { if (timer !== null) unschedule(timer); timer = null; }
    function canUse(token) { return !disposed && guard.current(token) && sessionId === token.sessionId; }
    function setAction(message, error = false) {
      actionMessage = message;
      actionError = error;
      showNotice(els.ActionStatus, message, error);
    }
    function matchingEndpoints() { return sortEndpoints(filterEndpoints(endpoints, els.Search.value, els.Kind.value), sort); }
    function canCopyJson() {
      const token = guard.capture();
      const term = String(els.Search.value || "").trim().toLowerCase();
      return visible && !!options.copyText && loaded && !loadError && !read && !mutation
        && canUse(token) && token.generation === sessionGeneration
        && endpoints.some((endpoint) => matchesEndpoint(endpoint, term, els.Kind.value));
    }
    function canOpenReplay() {
      const token = guard.capture();
      return visible && !!options.openInReplay && loaded && !loadError && !read && !mutation
        && canUse(token) && token.generation === sessionGeneration;
    }
    function renderCopyControl() {
      els.CopyJson.disabled = !canCopyJson();
      for (const button of els.Detail.querySelectorAll("[data-open-replay]")) button.disabled = !canOpenReplay();
    }
    function retireBulkCopy() { bulkContext += 1; }
    function renderControls() {
      els.Start.disabled = !canStart();
      els.Start.textContent = mutation?.type === "start" ? "Starting…" : "Start discovery";
      els.Refresh.disabled = !sessionId || !!read || !!mutation;
      showNotice(els.ActionStatus, actionMessage, actionError);
      renderCopyControl();
    }
    function canStart() {
      return !!sessionId && loaded && !loadError && !read && !mutation
        && !jobs.some((job) => ACTIVE_STATUSES.has(job.status));
    }
    function updateScope({ revokeConsent = false } = {}) {
      if (revokeConsent) { els.HistoryConsent.checked = false; els.ScanConsent.checked = false; }
      let target;
      try { target = parseTarget(els.Target.value); } catch (_) { /* Validation is shown on submit. */ }
      const services = [els.Urlscan.checked && "urlscan.io", els.Wayback.checked && "the Internet Archive"].filter(Boolean);
      els.HistoryConsentRow.classList.toggle("hidden", !services.length);
      els.HistoryConsent.required = services.length > 0;
      els.ScanOptions.classList.toggle("hidden", !els.UrlscanSubmit.checked);
      els.ScanConsent.required = els.UrlscanSubmit.checked;
      els.ScanConsentText.textContent = `Allow sharing ${target ? target.href : "the full target URL"} with urlscan.io for a new ${els.ScanVisibility.value} browser scan, including requests outside Sniper's scope.`;
      els.HistoryConsentText.textContent = `Allow sending ${target ? target.hostname : "the target domain"}${els.Subdomains.checked ? " and its subdomain search scope" : ""} to ${services.join(" and ")} for historical lookups.`;
      els.Scope.textContent = target
        ? `Stays on ${target.protocol}//${target.hostname}:${target.port || (target.protocol === "https:" ? "443" : "80")}${els.Subdomains.checked ? " and its subdomains" : ""}; a same-host redirect from HTTP to HTTPS is followed.`
        : "Discovery stays on the URL's scheme, host and port.";
    }
    function renderJobs() {
      const fragment = doc.createDocumentFragment();
      els.JobsMeta.textContent = jobs.length ? `${number(jobs.length)} job${jobs.length === 1 ? "" : "s"}` : "";
      if (!jobs.length) fragment.append(element("p", "recon-empty", loaded ? "No discovery jobs in this session." : "Loading jobs…"));
      for (const job of jobs) {
        const card = element("article", "recon-job");
        const header = element("div", "recon-job-header");
        const title = element("strong", "recon-job-target", job.target_url || "Discovery job");
        const status = element("span", `recon-badge${job.status === "failed" ? " recon-badge-warning" : ""}`, job.status || "unknown");
        header.append(title, status);
        if (ACTIVE_STATUSES.has(job.status)) {
          const stop = element("button", "secondary-action", mutation?.id === job.id ? "Stopping…" : "Stop");
          stop.type = "button";
          stop.dataset.stopJob = job.id;
          stop.disabled = !!mutation || job.status === "stopping";
          stop.setAttribute("aria-label", `Stop discovery for ${job.target_url || job.id}`);
          header.append(stop);
        }
        card.append(header, element("p", "recon-help", `Started ${date(job.started_at)}${job.finished_at ? ` · Finished ${date(job.finished_at)}` : ""}`));
        const sources = element("div", "recon-job-sources");
        for (const source of Array.isArray(job.sources) ? job.sources : []) {
          const row = element("div", "recon-source-status");
          row.append(element("span", "", `${SOURCE_NAMES[source.source] || source.source}: ${source.status || "unknown"} · ${number(source.requests)} requests · ${number(source.discovered)} discovered${source.truncated ? " · LIMIT REACHED / PARTIAL" : ""}`));
          for (const warning of Array.isArray(source.warnings) ? source.warnings : []) row.append(element("p", "recon-warning", warning));
          if (source.error) row.append(element("p", "recon-warning", source.error));
          sources.append(row);
        }
        card.append(sources);
        if (job.error) card.append(element("p", "recon-warning", job.error));
        if (["cancelled", "interrupted", "failed"].includes(job.status)) card.append(element("p", "recon-help", "Partial results are retained in this session's inventory."));
        fragment.append(card);
      }
      els.Jobs.replaceChildren(fragment);
    }
    function addDetailField(list, label, value) {
      list.append(element("dt", "", label), element("dd", "", value || "—"));
    }
    function renderDetail() {
      copyEpoch += 1;
      const selected = endpoints.find((item) => endpointKey(item) === selectedKey);
      const title = element("h3", "", "Endpoint details");
      title.id = "reconDetailTitle";
      const nodes = [title];
      if (!selected) {
        nodes.push(element("p", "recon-help", "Select an endpoint to inspect its raw URLs and provenance."));
      } else {
        if (options.copyText) {
          const copy = element("button", "secondary-action", "Copy URL");
          copy.type = "button";
          copy.dataset.copyEndpoint = selectedKey;
          nodes.push(copy);
        }
        if (options.openInReplay) {
          const open = element("button", "secondary-action", "Open in Replay");
          open.type = "button";
          open.dataset.openReplay = selectedKey;
          open.disabled = !canOpenReplay();
          nodes.push(open);
        }
        const fields = element("dl", "recon-detail-fields");
        addDetailField(fields, "Method", selected.method || "UNKNOWN");
        addDetailField(fields, "Normalized URL", selected.url);
        addDetailField(fields, "First seen", date(selected.first_seen));
        addDetailField(fields, "Last seen", date(selected.last_seen));
        nodes.push(fields, element("h4", "", "Raw URLs"));
        const rawList = element("ul", "recon-raw-urls");
        for (const url of selected.raw_urls || []) rawList.append(element("li", "", url));
        if (!rawList.childNodes.length) rawList.append(element("li", "recon-help", "No raw URLs recorded."));
        nodes.push(rawList, element("h4", "", "Provenance"));
        const evidenceList = element("div", "recon-evidence");
        for (const evidence of evidenceOf(selected)) {
          const item = element("dl", "recon-detail-fields recon-evidence-item");
          addDetailField(item, "Source", SOURCE_NAMES[evidence.source] || evidence.source || "Unknown");
          addDetailField(item, "Evidence", KIND_NAMES[evidence.kind] || evidence.kind || "Candidate");
          addDetailField(item, "Location", evidence.location);
          if (evidence.timestamp) addDetailField(item, "Timestamp", date(evidence.timestamp));
          if (evidence.status !== undefined && evidence.status !== null) addDetailField(item, "HTTP status", String(evidence.status));
          evidenceList.append(item);
        }
        if (!evidenceList.childNodes.length) evidenceList.append(element("p", "recon-help", "No provenance recorded; live status is unknown."));
        nodes.push(evidenceList);
      }
      els.Detail.replaceChildren(...nodes);
    }
    function renderInventory() {
      const filtered = matchingEndpoints();
      const current = pageEndpoints(filtered, page);
      page = current.page;
      pageItems = current.items;
      const fragment = doc.createDocumentFragment();
      for (const endpoint of current.items) {
        const key = endpointKey(endpoint);
        const row = element("tr", key === selectedKey ? "recon-selected" : "");
        row.dataset.endpointKey = key;
        row.setAttribute("aria-selected", String(key === selectedKey));
        const method = element("td", "recon-method", endpoint.method || "UNKNOWN");
        const url = element("td", "recon-url-cell", endpoint.url);
        row.append(method, url,
          element("td", "", kindsOf(endpoint).map((kind) => KIND_NAMES[kind] || kind).join(", ") || "Unknown"),
          element("td", "", sourcesOf(endpoint).map((source) => SOURCE_NAMES[source] || source).join(", ") || "Unknown"));
        fragment.append(row);
      }
      if (!current.items.length) {
        const row = element("tr", "");
        const cell = element("td", "recon-empty", !loaded ? "Loading endpoints…" : endpoints.length ? "No endpoints match these filters." : "No endpoints discovered yet. Choose a target and start discovery.");
        cell.colSpan = 4;
        row.append(cell);
        fragment.append(row);
      }
      els.Endpoints.replaceChildren(fragment);
      const running = jobs.some((job) => ACTIVE_STATUSES.has(job.status));
      els.InventoryMeta.textContent = `${number(endpoints.length)} endpoints in this session${running ? " · Discovery in progress" : ""}${inventoryTruncated ? " · Response truncated; inventory is partial" : ""}`;
      els.PageMeta.textContent = filtered.length ? `${number(page * PAGE_SIZE + 1)}–${number(Math.min((page + 1) * PAGE_SIZE, filtered.length))} of ${number(filtered.length)} matching · Page ${page + 1} / ${current.pages}` : "0 matching endpoints";
      els.Previous.disabled = page === 0;
      els.Next.disabled = page + 1 >= current.pages;
      showNotice(els.LoadStatus, loadError, true);
      renderDetail();
      renderCopyControl();
    }
    function render() { renderControls(); renderJobs(); renderInventory(); }
    function scheduleRefresh() {
      clearTimer();
      if (!visible || !sessionId || disposed) return;
      timer = schedule(() => { timer = null; void refresh(); }, jobs.some((job) => ACTIVE_STATUSES.has(job.status)) ? 2000 : 10000);
    }
    async function jsonResponse(response, fallback) {
      if (!response.ok) {
        const text = (await response.text()).slice(0, 1000);
        let message = text;
        try { const parsed = JSON.parse(text); message = parsed.error || parsed.message || text; } catch (_) { /* Plain text errors are supported too. */ }
        throw new Error(message || `${fallback} (HTTP ${response.status})`);
      }
      return response.json();
    }
    async function refresh() {
      if (!visible || !sessionId || disposed || read || mutation) return;
      clearTimer();
      const token = guard.capture();
      if (!canUse(token)) return;
      const request = { token, controller: new AbortController() };
      read = request;
      renderControls();
      try {
        const response = await fetcher(`/api/recon?session_id=${encodeURIComponent(token.sessionId)}`, { signal: request.controller.signal });
        const snapshot = await jsonResponse(response, "Could not load Recon");
        if (!canUse(token) || read !== request) return;
        if (snapshot.session_id !== token.sessionId || !Array.isArray(snapshot.jobs) || !Array.isArray(snapshot.endpoints)) {
          throw new Error("Recon returned an invalid session snapshot. Refresh to try again.");
        }
        jobs = [...snapshot.jobs].sort((a, b) => String(b.started_at || "").localeCompare(String(a.started_at || "")));
        endpoints = snapshot.endpoints;
        inventoryTruncated = !!snapshot.truncated;
        exportInventoryTruncated = typeof snapshot.truncated === "boolean" ? snapshot.truncated : null;
        loaded = true;
        loadError = "";
        render();
      } catch (error) {
        if (!canUse(token) || read !== request || error.name === "AbortError") return;
        loadError = `${error.message || "Could not load Recon."}${loaded ? " Showing the last loaded results; status may be out of date." : ""}`;
        renderInventory();
      } finally {
        if (canUse(token) && read === request) {
          read = null;
          renderControls();
          scheduleRefresh();
        }
      }
    }
    function formValues() {
      return { target: els.Target.value, includeSubdomains: els.Subdomains.checked, crawler: els.Crawler.checked,
        urlscan: els.Urlscan.checked, wayback: els.Wayback.checked, urlscan_submit: els.UrlscanSubmit.checked, scanAcknowledged: els.ScanConsent.checked, scanVisibility: els.ScanVisibility.value, historyAcknowledged: els.HistoryConsent.checked,
        maxRequests: els.MaxRequests.value, maxDepth: els.MaxDepth.value, maxEndpoints: els.MaxEndpoints.value, maxPages: els.MaxPages.value };
    }
    async function mutate(type, id) {
      if (disposed || mutation || !sessionId || (type === "start" && !canStart())) return;
      const token = guard.capture();
      if (!canUse(token)) return;
      let body;
      try { body = type === "start" ? buildJobRequest(formValues(), token.sessionId) : { session_id: token.sessionId }; }
      catch (error) { setAction(error.message, true); return; }
      const request = { token, type, id, controller: new AbortController() };
      mutation = request;
      retireBulkCopy();
      setAction("");
      renderControls();
      renderJobs();
      // A read begun before a mutation must not overwrite the newly returned job.
      if (read) { read.controller.abort(); read = null; }
      clearTimer();
      try {
        const path = type === "start" ? "/api/recon/jobs" : `/api/recon/jobs/${encodeURIComponent(id)}/stop`;
        const response = await fetcher(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: request.controller.signal });
        const job = await jsonResponse(response, type === "start" ? "Could not start discovery" : "Could not stop discovery");
        if (!canUse(token) || mutation !== request) return;
        if (type === "start") {
          if (!job || typeof job.id !== "string" || typeof job.status !== "string") throw new Error("The job response could not be verified.");
          jobs = [job, ...jobs.filter((item) => item.id !== job.id)];
        } else {
          if (!job || job.stopped !== true || job.session_id !== token.sessionId) throw new Error("The stop response could not be verified.");
          jobs = jobs.map((item) => item.id === id && ACTIVE_STATUSES.has(item.status) ? { ...item, status: "stopping" } : item);
        }
        setAction(type === "start" ? "Discovery started. Progress and any optional budgets appear below." : "Stop requested. Results already discovered are retained.");
      } catch (error) {
        if (!canUse(token) || mutation !== request || error.name === "AbortError") return;
        setAction(`${error.message || "The request failed."} Refresh jobs to confirm the current state before trying again.`, true);
      } finally {
        if (canUse(token) && mutation === request) {
          mutation = null;
          render();
          void refresh();
        }
      }
    }
    function reset() {
      retireBulkCopy();
      guard.invalidate();
      clearTimer();
      if (read) read.controller.abort();
      if (mutation) mutation.controller.abort();
      read = null;
      mutation = null;
      sessionId = null;
      sessionGeneration = null;
      jobs = [];
      endpoints = [];
      loaded = false;
      loadError = "";
      actionMessage = "";
      actionError = false;
      selectedKey = null;
      page = 0;
      inventoryTruncated = false;
      exportInventoryTruncated = null;
      els.Form.reset();
      els.Search.value = "";
      els.Kind.value = "";
      updateScope({ revokeConsent: true });
      render();
    }
    function syncSession() {
      const nextId = options.getSessionId();
      const nextGeneration = options.getSessionGeneration ? options.getSessionGeneration() : 0;
      if (nextId === sessionId && nextGeneration === sessionGeneration) return;
      reset();
      sessionId = nextId;
      sessionGeneration = nextGeneration;
      renderControls();
      if (visible && sessionId) void refresh();
    }
    function setVisible(next) {
      const changed = visible !== !!next;
      visible = !!next;
      syncSession();
      if (!visible) {
        if (changed) { copyEpoch += 1; retireBulkCopy(); }
        clearTimer();
        // Reads belong to this view; pending start/stop requests still own their result.
        if (read) { read.controller.abort(); read = null; }
        renderControls();
      } else if (changed && !read) void refresh();
    }

    on(els.Form, "submit", (event) => { event.preventDefault(); void mutate("start"); });
    on(els.Refresh, "click", () => { void refresh(); });
    on(els.Target, "input", () => updateScope({ revokeConsent: true }));
    for (const field of [els.Subdomains, els.Urlscan, els.Wayback, els.UrlscanSubmit, els.ScanVisibility]) on(field, "change", () => updateScope({ revokeConsent: true }));
    on(els.Search, "input", () => { retireBulkCopy(); page = 0; renderInventory(); });
    on(els.Kind, "change", () => { retireBulkCopy(); page = 0; renderInventory(); });
    on(els.Previous, "click", () => { page -= 1; renderInventory(); });
    on(els.Next, "click", () => { page += 1; renderInventory(); });
    on(els.Endpoints, "click", (event) => {
      const row = event.target.closest("[data-endpoint-key]");
      if (!row) return;
      selectedKey = row.dataset.endpointKey;
      renderInventory();
    });
    on(els.Detail, "click", (event) => {
      const open = event.target.closest("[data-open-replay]");
      if (open) {
        if (open.disabled || !els.Detail.contains(open) || !canOpenReplay() || selectedKey !== open.dataset.openReplay) return;
        const selected = endpoints.find(item => endpointKey(item) === selectedKey);
        if (!selected) return;
        const token = guard.capture(), key = selectedKey;
        const isCurrent = () => canOpenReplay() && canUse(token) && selectedKey === key && els.Detail.contains(open);
        try { options.openInReplay(selected, isCurrent); }
        catch (error) { if (isCurrent()) setAction(error.message || "Could not open Replay draft.", true); }
        return;
      }
      const button = event.target.closest("[data-copy-endpoint]");
      if (!visible || !options.copyText || !button || !els.Detail.contains(button)) return;
      const key = button.dataset.copyEndpoint;
      const selected = endpoints.find((item) => endpointKey(item) === key);
      if (selectedKey !== key || !selected) return;
      const token = guard.capture();
      if (!canUse(token)) return;
      const epoch = ++copyEpoch;
      const intent = ++copyIntent;
      const isCurrent = () => canUse(token) && visible && intent === copyIntent && epoch === copyEpoch && selectedKey === key;
      const failed = () => { if (isCurrent()) setAction("Could not copy URL.", true); };
      try { Promise.resolve(options.copyText(selected.url, "Copied URL", isCurrent)).catch(failed); }
      catch (_) { failed(); }
    });
    on(els.CopyJson, "click", () => {
      if (!canCopyJson()) return;
      const token = guard.capture();
      const intent = ++copyIntent;
      const context = bulkContext;
      const copiedAt = new Date().toISOString();
      const isCurrent = () => canUse(token) && visible && intent === copyIntent && context === bulkContext;
      let text;
      try {
        text = serializeFilteredExport({ sessionId: token.sessionId, copiedAt,
          query: els.Search.value, kind: els.Kind.value, sort, inventoryCount: endpoints.length,
          inventoryTruncated: exportInventoryTruncated, jobs, endpoints: matchingEndpoints() });
      } catch (error) {
        if (isCurrent()) setAction(error.message === COPY_LIMIT_ERROR ? COPY_LIMIT_ERROR : COPY_DATA_ERROR, true);
        return;
      }
      const failed = () => { if (isCurrent()) setAction("Could not copy filtered JSON.", true); };
      try { Promise.resolve(options.copyText(text, "Copied filtered JSON", isCurrent)).catch(failed); }
      catch (_) { failed(); }
    });
    on(els.Head, "click", (event) => {
      if (event.target.closest(".table-col-resize")) return;
      const header = event.target.closest("[data-sort]");
      if (!header) return;
      retireBulkCopy();
      sort = nextSort(sort, header.dataset.sort);
      for (const column of els.Head.querySelectorAll("[data-sort]")) {
        const active = column.dataset.sort === sort.key;
        column.classList.toggle("active", active);
        column.setAttribute("aria-sort", active ? (sort.direction === "asc" ? "ascending" : "descending") : "none");
        const indicator = column.querySelector(".table-sort-indicator");
        if (indicator) indicator.textContent = active ? (sort.direction === "asc" ? "↑" : "↓") : "↕";
      }
      page = 0;
      renderInventory();
    });
    // ↑/↓ move through the page, as in Findings; the app says when they are
    // free, not while a field has focus or a modal is open.
    on(doc, "keydown", (event) => {
      if (!visible || !pageItems.length) return;
      const step = options.arrowStep?.(event) || 0;
      if (!step) return;
      const current = pageItems.findIndex((endpoint) => endpointKey(endpoint) === selectedKey);
      const next = current < 0 ? (step > 0 ? 0 : pageItems.length - 1) : current + step;
      if (next < 0 || next >= pageItems.length) return;
      event.preventDefault();
      selectedKey = endpointKey(pageItems[next]);
      renderInventory();
      Array.from(els.Endpoints.children || []).find((row) => row.dataset.endpointKey === selectedKey)?.scrollIntoView?.({ block: "nearest" });
    });
    on(els.Jobs, "click", (event) => {
      const button = event.target.closest("[data-stop-job]");
      if (button && !button.disabled) void mutate("stop", button.dataset.stopJob);
    });
    reset();
    return { setVisible, syncSession, refresh, reset, dispose() { reset(); disposed = true; listeners.forEach((remove) => remove()); } };
  }

  const api = { COPY_JSON_LIMIT, serializeFilteredExport, buildReplayDraft, createController, buildJobRequest, parseTarget, filterEndpoints, sortEndpoints, pageEndpoints, endpointKey, createSessionGuard };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.SniperRecon = api;
})(typeof window !== "undefined" ? window : globalThis);
