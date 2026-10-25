(function (root) {
  "use strict";

  // Templates come from a public repository: every name, tag, description
  // and YAML line is rendered as text, never as markup, and references are
  // shown, never linked.
  const PAGE_SIZE = 100;
  const BUSY_STATES = new Set(["loading", "downloading", "importing"]);
  const PASSIVE_KINDS = { global: "Judges every captured response", base_url_get: "Judges captured GET responses" };

  function listQuery(filters, page) {
    const params = new URLSearchParams();
    const search = String(filters.search || "").trim();
    if (search) params.set("search", search);
    if (filters.severity) params.set("severity", filters.severity);
    if (filters.support) params.set("support", filters.support);
    if (filters.enabledOnly) params.set("enabled", "true");
    if (filters.sort) {
      params.set("sort", filters.sort);
      params.set("direction", filters.direction === "desc" ? "desc" : "asc");
    }
    params.set("limit", String(PAGE_SIZE));
    params.set("offset", String(Math.max(0, page) * PAGE_SIZE));
    return `/api/templates?${params}`;
  }

  // A header click sorts by its column, and a second click reverses it, as in
  // Findings.
  function nextSort(current, key) {
    if (current.key === key) return { key, direction: current.direction === "asc" ? "desc" : "asc" };
    return { key, direction: "asc" };
  }

  // Turning on what the list shows sends the list's own filter to the passive
  // and the auto scan switches alike; each takes the templates it can run.
  function bulkRequest(filters, enabled) {
    const filter = {};
    const search = String(filters.search || "").trim();
    if (search) filter.search = search;
    if (filters.severity) filter.severity = filters.severity;
    if (filters.support) filter.support = filters.support;
    if (filters.enabledOnly) filter.enabled = true;
    return { filter, enabled: !!enabled };
  }

  // Whether the list shows less than the whole library: only then is turning
  // on all it shows offered.
  function narrowed(filters) {
    return !!(String(filters.search || "").trim() || filters.severity || filters.support || filters.enabledOnly);
  }

  function plural(n, word) { return `${count(n)} ${word}${Number(n) === 1 ? "" : "s"}`; }

  // What is installed, for the library card: its name, a badge saying whether
  // it was checked, and its counts. The rest sits in the tooltip.
  function librarySummary(status) {
    if (!status) return { name: "Loading…", badge: null, detail: "", counts: "", title: "" };
    const library = status.library;
    if (!library) return { name: "No templates", badge: null, detail: "", counts: "Download a release or import an archive.", title: "" };
    const on = Number(status.passive_enabled) || 0;
    const counts = `${plural(status.templates, "template")} · ${count(status.passive_supported)} passive${on ? ` (${count(on)} on)` : ""} · ${count(status.active_supported)} scan`;
    const commit = library.commit ? library.commit.slice(0, 12) : "";
    if (library.source !== "github") return { name: "Imported archive", badge: { text: "not verified", tone: "warn" }, detail: "", counts, title: "" };
    if (library.tag === "main") {
      const date = library.committed_at ? String(library.committed_at).slice(0, 10) : "";
      return {
        name: "main", badge: { text: "unreleased", tone: "warn" }, detail: [commit.slice(0, 7), date].filter(Boolean).join(" · "), counts,
        title: `nuclei-templates main${commit ? ` · commit ${commit}` : ""} · no checksum`,
      };
    }
    return {
      name: library.tag, badge: library.verified ? { text: "verified", tone: "ok" } : { text: "not verified", tone: "warn" }, detail: "", counts,
      title: `nuclei-templates ${library.tag}${commit ? ` · commit ${commit}` : ""}`,
    };
  }

  // ---- YAML ----

  const YAML_KEY = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"[\]{},:][^#]*?)(:)(?=\s|$)/;
  const YAML_BLOCK = /^[|>][+-]?\d*(?=\s|$)/;
  const YAML_QUOTED = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*')/;
  const YAML_CLASSES = {
    key: "token-json-key", punct: "token-punctuation", string: "token-json-string", number: "token-json-number",
    bool: "token-json-boolean", comment: "templates-yaml-comment", expr: "token-url",
  };

  // A part of a line, with each {{expression}} in it set apart.
  function withExpressions(kind, text) {
    const parts = [];
    let last = 0;
    for (const match of String(text).matchAll(/\{\{.*?\}\}/g)) {
      if (match.index > last) parts.push([kind, text.slice(last, match.index)]);
      parts.push(["expr", match[0]]);
      last = match.index + match[0].length;
    }
    if (last < text.length) parts.push([kind, text.slice(last)]);
    return parts;
  }

  // A value after `key:` or `- `: a block marker, a quoted string, a number,
  // a boolean or plain text, then any comment.
  function yamlValue(value) {
    if (!value) return [];
    if (value.startsWith("#")) return [["comment", value]];
    const block = value.match(YAML_BLOCK);
    const quoted = !block && value.match(YAML_QUOTED);
    let body = value;
    let tail = "";
    if (block || quoted) {
      body = (block || quoted)[0];
      tail = value.slice(body.length);
    } else {
      const comment = value.search(/\s#/);
      if (comment >= 0) {
        body = value.slice(0, comment);
        tail = value.slice(comment);
      }
    }
    const parts = block ? [["punct", body]]
      : quoted ? withExpressions("string", body)
        : /^[-+]?(?:\d+(?:\.\d+)?|\.\d+)$/.test(body) ? [["number", body]]
          : /^(?:true|false|null|~)$/i.test(body) ? [["bool", body]]
            : withExpressions("text", body);
    const comment = tail.match(/^(\s*)(#.*)$/);
    if (comment) return [...parts, ["text", comment[1]], ["comment", comment[2]]];
    return tail ? [...parts, ["text", tail]] : parts;
  }

  // A template's YAML as lines of [kind, text]; kinds are key, punct, string,
  // number, bool, comment, expr and text. The lines of a block scalar (`|`,
  // `>`) are its text, so a raw request's `Host:` is not read as a key.
  function yamlLines(text) {
    const lines = [];
    let block = -1;
    for (const line of String(text || "").split(/\r?\n/)) {
      const indent = line.length - line.trimStart().length;
      if (block >= 0 && (!line.trim() || indent > block)) {
        lines.push(withExpressions("text", line));
        continue;
      }
      block = -1;
      const parts = [];
      let rest = line.slice(indent);
      if (indent) parts.push(["text", line.slice(0, indent)]);
      if (rest.startsWith("#") || rest === "---" || rest === "...") {
        parts.push([rest.startsWith("#") ? "comment" : "punct", rest]);
        lines.push(parts);
        continue;
      }
      while (/^-(?:\s|$)/.test(rest)) {
        const space = rest.slice(1).match(/^\s*/)[0];
        parts.push(["punct", "-"]);
        if (space) parts.push(["text", space]);
        rest = rest.slice(1 + space.length);
      }
      const key = rest.match(YAML_KEY);
      if (key) {
        const space = rest.slice(key[0].length).match(/^\s*/)[0];
        parts.push(["key", key[1]], ["punct", ":"]);
        if (space) parts.push(["text", space]);
        rest = rest.slice(key[0].length + space.length);
      }
      if (YAML_BLOCK.test(rest)) block = indent;
      parts.push(...yamlValue(rest));
      // Neighbouring text runs are one.
      lines.push(parts.reduce((merged, part) => {
        const previous = merged[merged.length - 1];
        if (previous && previous[0] === "text" && part[0] === "text") previous[1] += part[1];
        else if (part[1]) merged.push([part[0], part[1]]);
        return merged;
      }, []));
    }
    return lines;
  }

  // What Check for updates found, for the channel the installed library came from.
  function checkLine(result) {
    if (result.channel === "main") {
      const date = result.latest_at ? ` from ${String(result.latest_at).slice(0, 10)}` : "";
      return result.update_available
        ? `Main has a newer commit, ${String(result.latest).slice(0, 12)}${date}. Download main to take it.`
        : "Main is installed and current.";
    }
    return result.update_available
      ? `Release ${result.latest} is available${result.current ? ` (installed: ${result.current})` : ""}.`
      : `Release ${result.latest} is installed and current.`;
  }

  const DOWNLOAD_TITLES = {
    release: "The latest release from github.com/projectdiscovery/nuclei-templates (MIT). GitHub sees this computer's address.",
    main: "The newest commit on main at github.com/projectdiscovery/nuclei-templates (MIT): templates not released yet, with no checksum to verify. GitHub sees this computer's address.",
  };

  // What the library is doing, for the bar under its status: a value out of
  // a total once the total is known.
  function progressOf(status) {
    if (status?.state === "downloading") {
      const label = status.received_bytes ? `Downloading… ${(status.received_bytes / 1048576).toFixed(1)} MiB` : "Contacting GitHub…";
      return { label, value: null, max: null };
    }
    if (status?.state === "importing") {
      const total = Number(status.check_total) || 0;
      if (!total) return { label: "Reading the archive…", value: null, max: null };
      const done = Number(status.checked) || 0;
      return { label: `Checking templates… ${count(done)} of ${count(total)}`, value: done, max: total };
    }
    if (status?.state === "failed" && status.error) return { label: `The last download or import failed: ${status.error}`, error: true };
    return null;
  }

  // The classes Findings badges a severity with.
  function severityClass(severity) {
    return ["critical", "high", "medium", "low"].includes(severity) ? `severity-${severity}` : "severity-info";
  }

  function supportLabel(meta) {
    const ways = [];
    if (meta.passive_supported) ways.push("Passive");
    if (meta.active_supported) ways.push("Scan");
    // A scan sends it only where the session has an Interactsh server.
    if (meta.active_supported && meta.oast) ways.push("OAST");
    if (ways.length) return ways.join(" · ");
    const reason = (meta.reasons || [])[0];
    return reason ? `No: ${reason}` : "No";
  }

  // ---- Manual scan ----

  // Risks a scan leaves out unless each is allowed; dos is never sent.
  const RISKS = ["intrusive", "default-login", "bruteforce", "token-spray", "credential-stuffing", "fuzz", "fuzzing",
    "dast", "osint", "method:put", "method:delete", "method:patch"];

  function parseTargets(text) {
    const targets = String(text || "").split(/[\s,]+/).filter(Boolean);
    if (!targets.length) throw new Error("Name at least one target, such as https://app.example.com.");
    if (targets.length > 20) throw new Error("Name at most 20 targets.");
    for (const target of targets) {
      let url;
      try { url = new URL(target); } catch (_) { throw new Error(`${target} is not a complete http:// or https:// URL.`); }
      if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
        throw new Error(`${target}: a target is an http(s) origin, optionally with a path, without credentials, query or fragment.`);
      }
    }
    return targets;
  }

  function boundedInteger(value, min, max, label) {
    const number = Number(value);
    if (String(value).trim() === "" || !Number.isInteger(number) || number < min || number > max) {
      throw new Error(`${label} must be a whole number from ${min} to ${max}.`);
    }
    return number;
  }

  // The scan the form describes: the templates the list filter shows, or the
  // one selected. A preview counts; a start carries the operator's consent.
  function scanRequest(values, filters, selectedId, sessionId, preview) {
    if (!sessionId) throw new Error("Wait for the session to finish loading.");
    const body = {
      session_id: sessionId,
      targets: parseTargets(values.targets),
      allow_risks: (values.risks || []).filter((risk) => RISKS.includes(risk)),
      rate: boundedInteger(values.rate, 1, 50, "Requests a second"),
      concurrency: boundedInteger(values.concurrency, 1, 8, "Templates at once"),
      max_requests: boundedInteger(values.maxRequests, 1, 50000, "Request limit"),
      apply_match_replace: !!values.applyMatchReplace,
    };
    if (values.selection === "selected") {
      if (!selectedId) throw new Error("Click a template's row in the list first; its On box does not select it.");
      body.ids = [selectedId];
    } else if (values.selection === "on") {
      body.filter = { enabled: true };
    } else {
      const filter = {};
      const search = String(filters.search || "").trim();
      if (search) filter.search = search;
      if (filters.severity) filter.severity = filters.severity;
      body.filter = filter;
    }
    body.history = values.keepAll === false ? "matched" : "all";
    body[preview ? "preview" : "acknowledged"] = true;
    return body;
  }

  function count(value) { return Number(value || 0).toLocaleString(); }

  // ---- Auto scan ----

  // The auto scan's settings as the server takes them; Turn on is the
  // operator's consent.
  function autoRequest(values, sessionId, enabled) {
    if (!sessionId) throw new Error("Wait for the session to finish loading.");
    const hosts = String(values.hosts || "").split(/[\s,]+/).filter(Boolean);
    if (hosts.length > 50) throw new Error("List at most 50 hosts.");
    for (const host of hosts) {
      if (host.includes("/") || host.length > 253) {
        throw new Error(`${host}: list a host as Scope takes it, such as *.example.com or example.com:8443.`);
      }
    }
    const body = { session_id: sessionId, enabled: !!enabled, hosts, rate: boundedInteger(values.rate, 1, 50, "Requests a second") };
    if (enabled) body.acknowledged = true;
    return body;
  }

  // The card's badge says whether it is on.
  function autoLine(auto) {
    if (!auto) return "Loading…";
    const templates = plural(auto.templates, "template");
    if (!auto.enabled) return templates;
    return `${templates} · ${plural(auto.scanned, "host")} scanned · ${count(auto.queued)} waiting`;
  }

  function previewLine(preview) {
    const left = Object.entries(preview.excluded_by_risk || {}).map(([risk, n]) => `${risk} ${count(n)}`);
    if (preview.oast_unavailable) left.push(`${plural(preview.oast_unavailable, "OAST template")} (no Interactsh server)`);
    return `Sends ${plural(preview.requests, "request")} from ${plural(preview.templates, "template")} to ${(preview.targets || []).join(", ")}.${left.length ? ` Left out: ${left.join("; ")}.` : ""}`;
  }

  function jobCounts(job) {
    const parts = [`${count(job.sent)} of ${count(job.planned)} sent`, `${count(job.matched)} matched`];
    if (job.failed) parts.push(`${count(job.failed)} failed`);
    if (job.blocked) parts.push(`${count(job.blocked)} not sent`);
    return parts.join(" · ");
  }

  function jobLine(job) {
    return `${job.status} · ${jobCounts(job)}`;
  }

  // A scan with one target says its origin once; its rows show the path.
  function originOf(job) {
    return (job?.targets || []).length === 1 ? String(job.targets[0]).replace(/^(https?:\/\/[^/]+).*$/, "$1") : null;
  }
  function shortUrl(url, origin) {
    const text = String(url || "");
    if (origin && text === origin) return "/";
    return origin && text.startsWith(`${origin}/`) ? text.slice(origin.length) : text;
  }
  // Stable while the log rolls: the same request keeps its row.
  function resultKey(entry) {
    return [entry.at, entry.template_id, entry.method, entry.url].join("|");
  }
  const RESULT_ORDER = {
    status: (entry) => (entry.error ? 1000 : Number(entry.status) || 0),
    method: (entry) => entry.method || "",
    path: (entry) => entry.url || "",
    template: (entry) => entry.template_id || "",
    ms: (entry) => Number(entry.ms) || 0,
    matched: (entry) => (entry.matched ? 1 : 0),
  };

  function createController(options) {
    const shell = options.root;
    const doc = shell.ownerDocument;
    const fetcher = options.fetch || root.fetch.bind(root);
    const schedule = options.setTimeout || root.setTimeout.bind(root);
    const unschedule = options.clearTimeout || root.clearTimeout.bind(root);
    const ids = ["Version", "Status", "Progress", "ProgressBar", "Download", "Check", "Import", "ImportFile", "Notice", "ScopeNote",
      "More", "Switch", "ImportMenu",
      "Search", "Severity", "Support", "EnableShown", "DisableShown", "Meta", "Head", "Rows", "Detail",
      "Views", "ListControls", "ListActions", "Table", "ResultsTable", "ResultsHead", "ResultsRows", "ResultsTitle",
      "ResultsMatched", "ResultsStop", "Pagination",
      "PageMeta", "Previous", "Next", "ScanTargets", "ScanSelection", "ScanRisks", "ScanRate", "ScanConcurrency",
      "ScanMaxRequests", "ScanMatchReplace", "ScanKeepAll", "ScanPlan", "ScanStart",
      "ScanNotice", "ScanJobs", "AutoSummary", "AutoHosts", "AutoRate", "AutoToggle", "AutoNotice"];
    const els = Object.fromEntries(ids.map((id) => [id, shell.querySelector(`#templates${id}`)]));
    const listeners = [];
    let visible = false;
    let disposed = false;
    let status = null;
    let items = [];
    let total = 0;
    let page = 0;
    let sort = { key: "", direction: "asc" };
    let selected = null;
    // The template being opened, shown as selected before its detail arrives.
    let pendingId = null;
    let openRequest = 0;
    let timer = null;
    let searchTimer = null;
    let busy = false;
    // What the last update check found, for the library it checked.
    let lastCheck = null;
    let listRequest = 0;
    // The list of templates, or the open scan's requests.
    let view = "templates";
    let viewRequest = 0;
    // The box ticked last, where a Shift-click range starts.
    let rangeAnchor = null;

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
    function notice(message, error = false) {
      els.Notice.textContent = message;
      els.Notice.classList.toggle("hidden", !message);
      els.Notice.classList.toggle("recon-error", error);
    }
    // A refusal is `{"error": "…"}` from some endpoints and plain text from
    // others; either way the operator reads the sentence.
    async function json(response, fallback) {
      if (!response.ok) {
        const text = (await response.text()).slice(0, 1000);
        let message = text;
        try {
          const parsed = JSON.parse(text);
          if (typeof parsed?.error === "string") message = parsed.error;
        } catch (_) {}
        throw new Error(message || `${fallback} (HTTP ${response.status})`);
      }
      return response.json();
    }
    // "Turned on" is one of the list's views; the server reads it as
    // `enabled`, apart from what Sniper can run.
    function filters() {
      const show = els.Support.value;
      return {
        search: els.Search.value, severity: els.Severity.value, support: show === "on" ? "" : show, enabledOnly: show === "on",
        sort: sort.key, direction: sort.direction,
      };
    }

    function renderSortHeaders() {
      for (const header of els.Head.querySelectorAll("[data-sort]")) {
        const active = header.dataset.sort === sort.key;
        header.classList.toggle("active", active);
        header.setAttribute("aria-sort", active ? (sort.direction === "asc" ? "ascending" : "descending") : "none");
        const indicator = header.querySelector(".table-sort-indicator");
        if (indicator) indicator.textContent = active ? (sort.direction === "asc" ? "↑" : "↓") : "↕";
      }
    }

    function renderStatus() {
      const working = status && BUSY_STATES.has(status.state);
      const summary = librarySummary(status);
      els.Version.replaceChildren(element("strong", "", summary.name));
      if (summary.badge) els.Version.append(element("span", `detail-chip ${summary.badge.tone}`, summary.badge.text));
      if (summary.detail) els.Version.append(element("span", "recon-help", summary.detail));
      els.Version.title = summary.title;
      els.Status.textContent = summary.counts;
      const progress = progressOf(status);
      els.Progress.textContent = progress?.label || "";
      els.Progress.classList.toggle("hidden", !progress);
      els.Progress.classList.toggle("recon-error", !!progress?.error);
      els.ProgressBar.classList.toggle("hidden", !progress || !!progress.error);
      // Without a value the bar moves without saying how far it got.
      if (progress?.value == null) {
        els.ProgressBar.removeAttribute("value");
      } else {
        els.ProgressBar.max = progress.max;
        els.ProgressBar.value = progress.value;
      }
      // Only what there is to do: with nothing installed, Download or Import;
      // once installed, Update when a check found one. Changing channel and
      // importing wait in the menu.
      const library = status?.library || null;
      if (lastCheck && lastCheck.sha256 !== library?.sha256) lastCheck = null;
      const installed = installedChannel();
      const idle = !working && !busy;
      els.Check.classList.toggle("hidden", !library || !!working);
      els.Check.disabled = !idle;
      els.Download.classList.toggle("hidden", !!working || !(!library || lastCheck?.update_available));
      els.Download.textContent = library ? "Update" : "Download";
      els.Download.title = DOWNLOAD_TITLES[installed];
      els.Download.disabled = !idle;
      els.Import.classList.toggle("hidden", !!library || !!working);
      els.Import.disabled = !idle;
      els.More.classList.toggle("hidden", !!working);
      const other = installed === "main" ? "release" : "main";
      els.Switch.textContent = !library ? "Download main (unreleased)"
        : other === "main" ? "Switch to main (unreleased)" : "Switch to latest release";
      els.Switch.title = DOWNLOAD_TITLES[other];
      els.Switch.disabled = !idle;
      els.ImportMenu.classList.toggle("hidden", !library);
      els.ImportMenu.disabled = !idle;
      const scopeless = (options.getScopeIncludeCount?.() || 0) === 0;
      els.ScopeNote.classList.toggle("hidden", !(scopeless && status?.passive_enabled > 0));
      renderBulk();
      // Start waits for a library, which may arrive after the scan form was
      // first drawn.
      renderScan();
    }

    // Turning on all the list shows is offered once it shows less than all.
    function renderBulk() {
      const bulk = !!status?.library && view === "templates" && narrowed(filters());
      for (const button of [els.EnableShown, els.DisableShown]) {
        button.classList.toggle("hidden", !bulk);
        button.disabled = busy;
      }
    }

    function renderList() {
      els.Rows.replaceChildren();
      if (!items.length) {
        const row = element("tr");
        const cell = element("td", "recon-empty", status?.library ? "No templates match." : "No templates installed.");
        cell.colSpan = 5;
        row.append(cell);
        els.Rows.append(row);
      }
      for (const meta of items) {
        const row = element("tr", meta.id === (pendingId ?? selected?.id) ? "recon-selected" : "");
        row.dataset.templateId = meta.id;
        const toggleCell = element("td");
        if (meta.passive_supported || meta.active_supported) {
          // One that can judge captured traffic does so; one that must send
          // its own requests goes out with the auto scan.
          const toggle = element("input");
          toggle.type = "checkbox";
          toggle.checked = !!meta.enabled;
          toggle.disabled = busy;
          if (meta.passive_supported) {
            toggle.dataset.templateToggle = meta.id;
            toggle.title = "Checks captured traffic while Passive Scan is on";
            toggle.setAttribute("aria-label", `Run ${meta.name || meta.id} on captured traffic`);
          } else {
            toggle.dataset.templateAuto = meta.id;
            toggle.title = "Sent to each new host while the auto scan is on";
            toggle.setAttribute("aria-label", `Send ${meta.name || meta.id} with the auto scan`);
          }
          toggleCell.append(toggle);
        } else {
          const none = element("span", "templates-off", "—");
          none.title = "Sniper cannot run this template";
          toggleCell.append(none);
        }
        const severityCell = element("td");
        severityCell.append(element("span", `severity-badge ${severityClass(meta.severity)}`, meta.severity || "unknown"));
        const nameCell = element("td");
        nameCell.append(element("div", "templates-name", meta.name || meta.id), element("div", "recon-help", meta.id));
        const tagsCell = element("td", "templates-tags");
        for (const tag of (meta.tags || []).slice(0, 6)) tagsCell.append(element("span", "templates-tag", tag));
        tagsCell.title = (meta.tags || []).join(", ");
        row.append(toggleCell, severityCell, nameCell, element("td", "", supportLabel(meta)), tagsCell);
        els.Rows.append(row);
      }
      const first = total ? page * PAGE_SIZE + 1 : 0;
      els.PageMeta.textContent = total ? `${first.toLocaleString()}–${Math.min(total, first + items.length - 1).toLocaleString()} of ${total.toLocaleString()}` : "";
      els.Previous.disabled = page === 0;
      els.Next.disabled = (page + 1) * PAGE_SIZE >= total;
      els.Meta.textContent = status?.library ? `${total.toLocaleString()} ${total === 1 ? "template" : "templates"}` : "";
      renderViews();
    }

    function field(list, label, value) {
      if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) return;
      list.append(element("dt", "", label), element("dd", "", Array.isArray(value) ? value.join(", ") : value));
    }

    // Spans straight in the pre: the app's inline <code> style would box every line.
    function yamlBlock(text) {
      const pre = element("pre", "templates-yaml");
      yamlLines(text).forEach((parts, index) => {
        if (index) pre.append(element("span", "", "\n"));
        for (const [kind, part] of parts) pre.append(element("span", YAML_CLASSES[kind] || "", part));
      });
      return pre;
    }

    function renderDetail() {
      els.Detail.replaceChildren();
      if (view === "results" && openJob) {
        renderResultDetail();
        return;
      }
      if (!selected) {
        els.Detail.append(element("p", "recon-empty", "Select a template."));
        return;
      }
      els.Detail.append(element("h3", "", selected.name || selected.id));
      const badges = element("div", "templates-detail-badges");
      badges.append(element("span", `severity-badge ${severityClass(selected.severity)}`, selected.severity || "unknown"),
        element("span", "templates-detail-id", selected.id));
      els.Detail.append(badges);
      if (selected.description) els.Detail.append(element("p", "templates-description", selected.description));
      const fields = element("dl", "templates-facts");
      field(fields, "Passive", selected.passive_supported ? `${PASSIVE_KINDS[selected.passive] || "Yes"}${selected.enabled ? " · on" : ""}` : "No");
      field(fields, "Scan", selected.active_supported ? `${plural(selected.requests, "request")} per target${selected.oast ? " · waits for an OAST callback" : ""}` : "No");
      field(fields, "Why not", selected.reasons);
      field(fields, "Risk", selected.risks);
      field(fields, "CVE", selected.cve);
      field(fields, "CWE", selected.cwe);
      field(fields, "Authors", selected.authors);
      field(fields, "Path", selected.path);
      if (selected.tags?.length) {
        const tags = element("dd");
        for (const tag of selected.tags) tags.append(element("span", "templates-tag", tag));
        fields.append(element("dt", "", "Tags"), tags);
      }
      els.Detail.append(fields);
      if (selected.references?.length) {
        els.Detail.append(element("h4", "", "References"));
        const list = element("ul", "recon-raw-urls");
        for (const reference of selected.references.slice(0, 20)) list.append(element("li", "", reference));
        els.Detail.append(list);
      }
      els.Detail.append(element("h4", "", "Template"), yamlBlock(selected.yaml || ""));
    }

    function clearTimer() { if (timer !== null) unschedule(timer); timer = null; }

    async function refreshStatus() {
      clearTimer();
      try {
        status = await json(await fetcher("/api/templates/library"), "Could not read the template library");
      } catch (error) {
        notice(error.message, true);
      }
      renderStatus();
      if (status && BUSY_STATES.has(status.state)) {
        if (visible) timer = schedule(refreshStatus, 1000);
        return;
      }
      await loadList();
    }

    async function loadList() {
      const request = ++listRequest;
      if (!status?.library) {
        items = [];
        total = 0;
        renderList();
        renderDetail();
        return;
      }
      try {
        const result = await json(await fetcher(listQuery(filters(), page)), "Could not list templates");
        if (request !== listRequest) return;
        items = Array.isArray(result.items) ? result.items : [];
        total = Number(result.total) || 0;
        renderList();
      } catch (error) {
        if (request === listRequest) notice(error.message, true);
      }
    }

    // Shows the row selected at once and its detail when it arrives; an older
    // request still on its way, as ↑/↓ leave behind, is dropped.
    async function open(id, { reveal = false, navigate = true } = {}) {
      if (navigate) ++viewRequest;
      const request = ++openRequest;
      pendingId = id;
      renderList();
      if (reveal) Array.from(els.Rows.children).find((row) => row.dataset.templateId === id)?.scrollIntoView?.({ block: "nearest" });
      let detail;
      try {
        detail = await json(await fetcher(`/api/templates/${encodeURIComponent(id)}`), "Could not open the template");
      } catch (error) {
        if (request !== openRequest) return;
        pendingId = null;
        notice(error.message, true);
        renderList();
        return;
      }
      if (request !== openRequest) return;
      pendingId = null;
      selected = detail;
      if (els.ScanSelection.value === "selected") schedulePlan();
      renderList();
      renderDetail();
    }

    // ---- Manual scan ----

    let scanSession = null;
    let scanJobs = [];
    let openJob = null;
    let scanBusy = false;
    let scansLoaded = false;
    let scanNoticeSource = null;
    let autoNoticeSource = null;
    let scanGeneration = 0;
    let scanReadRequest = 0;
    let autoReadRequest = 0;
    let resultSort = { key: "", direction: "asc" };
    let openResult = null;
    let matchedOnly = false;
    // The exchange of the open request, read from HTTP history.
    let exchange = null;
    let exchangeRequest = 0;
    let scanTimer = null;
    let planTimer = null;
    let planRequest = 0;

    function scanNotice(message, error = false, source = "action") {
      if (source === "read" && scanNoticeSource === "action" && els.ScanNotice.textContent) return;
      scanNoticeSource = message ? source : null;
      els.ScanNotice.textContent = message;
      els.ScanNotice.classList.toggle("hidden", !message);
      els.ScanNotice.classList.toggle("recon-error", error);
    }
    function scanValues() {
      return {
        targets: els.ScanTargets.value,
        selection: els.ScanSelection.value,
        risks: Array.from(els.ScanRisks.querySelectorAll("input[data-risk]")).filter((box) => box.checked).map((box) => box.dataset.risk),
        rate: els.ScanRate.value,
        concurrency: els.ScanConcurrency.value,
        maxRequests: els.ScanMaxRequests.value,
        applyMatchReplace: els.ScanMatchReplace.checked,
        keepAll: els.ScanKeepAll.checked,
      };
    }
    function startBody() {
      return scanRequest(scanValues(), filters(), selected?.id, options.getSessionId?.(), false);
    }
    function showPlan(text, warning = false) {
      els.ScanPlan.textContent = text;
      els.ScanPlan.classList.toggle("recon-warning", warning);
    }
    // What the form would send, counted by the server a moment after it
    // stops changing; an answer to an older form is dropped.
    async function plan() {
      const request = ++planRequest;
      const owner = scanOwner();
      const current = () => request === planRequest && ownsScan(owner) && visible;
      let body;
      try {
        body = scanRequest(scanValues(), filters(), selected?.id, options.getSessionId?.(), true);
      } catch (error) {
        showPlan(els.ScanTargets.value.trim() ? error.message : "", true);
        return;
      }
      try {
        const preview = await json(await fetcher("/api/templates/scans", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        }), "Could not count the scan");
        if (!current()) return;
        if (preview.templates) showPlan(previewLine(preview));
        else if (preview.oast_unavailable) showPlan("These templates need an Interactsh server: Capture ▸ OAST.", true);
        else showPlan(els.ScanSelection.value === "on" ? "No template is turned on. Tick On in the list." : "No template that can be sent matches.", true);
      } catch (error) {
        if (current()) showPlan(error.message, true);
      }
    }
    function schedulePlan() {
      // The form changed, so the last refusal no longer applies.
      scanNotice("");
      ++planRequest;
      showPlan("");
      if (planTimer !== null) unschedule(planTimer);
      planTimer = schedule(() => { planTimer = null; void plan(); }, 400);
    }
    function clearScanTimer() { if (scanTimer !== null) unschedule(scanTimer); scanTimer = null; }

    function renderScan() {
      const running = scanJobs.some((job) => job.status === "running");
      // The click is the consent; the plan above it says what it sends.
      els.ScanStart.disabled = scanBusy || running || !scansLoaded || !status?.library;
      els.ScanStart.textContent = running ? "A scan is running" : "Start scan";
      const nodes = [];
      for (const job of scanJobs) {
        const open = view === "results" && openJob?.id === job.id;
        const card = element("article", `recon-job templates-job${open ? " recon-selected" : ""}`);
        card.dataset.openScan = job.id;
        card.title = `Started ${new Date(job.started_at).toLocaleString()} · ${plural(job.templates, "template")}`;
        const header = element("div", "recon-job-header");
        header.append(element("strong", "recon-job-target", (job.targets || []).join(", ") || "Manual scan"));
        if (job.auto) header.append(element("span", "detail-chip", "auto"));
        header.append(element("span", `detail-chip ${job.status === "running" ? "info" : job.status === "completed" ? "ok" : "warn"}`, job.status));
        if (job.status === "running") {
          const stop = element("button", "secondary-action", "Stop");
          stop.type = "button";
          stop.dataset.stopScan = job.id;
          stop.disabled = scanBusy;
          header.append(stop);
        }
        card.append(header, element("p", "recon-help", jobCounts(job)));
        for (const warning of (job.warnings || []).slice(0, 3)) card.append(element("p", "recon-warning", warning));
        nodes.push(card);
      }
      els.ScanJobs.replaceChildren(...nodes);
      renderViews();
      renderResults();
    }

    // ---- Results: the open scan's requests ----

    function renderViews() {
      const results = view === "results" && !!openJob;
      els.Views.classList.toggle("hidden", !openJob && !scanJobs.length);
      for (const button of els.Views.querySelectorAll("[data-templates-view]")) {
        const active = button.dataset.templatesView === (results ? "results" : "templates");
        button.classList.toggle("active", active);
        button.setAttribute("aria-selected", active ? "true" : "false");
      }
      for (const node of [els.Table, els.ListControls, els.ListActions, els.Meta]) node.classList.toggle("hidden", results);
      // One page holds the whole list: the count above says it all.
      els.Pagination.classList.toggle("hidden", results || (page === 0 && total <= PAGE_SIZE));
      for (const node of [els.ResultsTable, els.ResultsTitle]) node.classList.toggle("hidden", !results);
    }
    function resultRows() {
      let rows = (openJob?.recent || []).slice().reverse();
      if (matchedOnly) rows = rows.filter((entry) => entry.matched);
      const order = RESULT_ORDER[resultSort.key];
      if (order) {
        const sign = resultSort.direction === "desc" ? -1 : 1;
        rows = rows.map((entry, index) => ({ entry, index })).sort((a, b) => {
          const left = order(a.entry);
          const right = order(b.entry);
          return (left < right ? -1 : left > right ? 1 : a.index - b.index) * sign;
        }).map(({ entry }) => entry);
      }
      return rows;
    }
    function currentResult() {
      return (openJob?.recent || []).find((entry) => resultKey(entry) === openResult) || null;
    }
    function renderResults() {
      const results = view === "results" && !!openJob;
      const job = openJob;
      if (!job?.matched) matchedOnly = false;
      els.ResultsTitle.textContent = job ? `${(job.targets || []).join(", ") || "Manual scan"} · ${jobLine(job)}` : "";
      els.ResultsMatched.classList.toggle("hidden", !results || !job?.matched);
      els.ResultsMatched.classList.toggle("active", matchedOnly);
      els.ResultsMatched.setAttribute("aria-pressed", matchedOnly ? "true" : "false");
      els.ResultsStop.classList.toggle("hidden", !results || job?.status !== "running");
      els.ResultsStop.disabled = scanBusy;
      for (const header of els.ResultsHead.querySelectorAll("[data-result-sort]")) {
        const active = header.dataset.resultSort === resultSort.key;
        header.classList.toggle("active", active);
        header.setAttribute("aria-sort", active ? (resultSort.direction === "asc" ? "ascending" : "descending") : "none");
        const indicator = header.querySelector(".table-sort-indicator");
        if (indicator) indicator.textContent = active ? (resultSort.direction === "asc" ? "↑" : "↓") : "↕";
      }
      const origin = originOf(job);
      const rows = [];
      for (const entry of resultRows()) {
        const key = resultKey(entry);
        const row = element("tr", [entry.matched ? "templates-matched" : "", key === openResult ? "recon-selected" : ""].filter(Boolean).join(" "));
        row.dataset.resultKey = key;
        row.title = `${entry.method} ${entry.url}`;
        row.append(
          element("td", entry.error ? "templates-request-error" : "", entry.error ? "error" : String(entry.status ?? "—")),
          element("td", "", entry.method),
          element("td", "templates-request-url", shortUrl(entry.url, origin)),
          element("td", "", entry.template_id),
          element("td", "", `${count(entry.ms)} ms`),
          element("td", "templates-match-mark", entry.matched ? "✓" : ""),
        );
        rows.push(row);
      }
      if (!rows.length) {
        const row = element("tr");
        const cell = element("td", "recon-empty", job?.status === "running" ? "No requests yet." : "No requests.");
        cell.colSpan = 6;
        row.append(cell);
        rows.push(row);
      }
      els.ResultsRows.replaceChildren(...rows);
    }
    function showResults(job) {
      ++viewRequest;
      if (job && job.id !== openJob?.id) {
        openResult = null;
        exchange = null;
        matchedOnly = false;
      }
      openJob = job || openJob;
      view = openJob ? "results" : "templates";
      renderStatus();
      renderDetail();
    }
    function selectResult(key, reveal = false) {
      openResult = key;
      renderResults();
      if (reveal) Array.from(els.ResultsRows.children).find((row) => row.dataset.resultKey === key)?.scrollIntoView?.({ block: "nearest" });
      const entry = currentResult();
      if (entry?.record_id && exchange?.key !== key) void loadExchange(entry);
      renderDetail();
    }
    async function loadExchange(entry) {
      const request = ++exchangeRequest;
      const owner = scanOwner();
      const key = resultKey(entry);
      exchange = { key, loading: true };
      try {
        const path = options.transactionPath
          ? options.transactionPath(entry.record_id)
          : `/api/transactions/${encodeURIComponent(entry.record_id)}?session_id=${encodeURIComponent(scanSession || "")}`;
        const record = await json(await fetcher(path), "Could not read the exchange");
        if (request !== exchangeRequest || !ownsScan(owner)) return;
        exchange = { key, record };
      } catch (error) {
        if (request !== exchangeRequest || !ownsScan(owner)) return;
        exchange = { key, error: error.message };
      }
      if (openResult === key) renderDetail();
    }
    // The app writes a record the way HTTP history shows it; alone, the
    // request line and the status are enough.
    function rawExchange(record) {
      if (options.rawExchange) return options.rawExchange(record);
      return { request: `${record.method || ""} ${record.path || ""}`.trim(), response: String(record.status ?? "") };
    }
    function renderResultDetail() {
      const entry = currentResult();
      if (!entry) {
        renderJobDetail();
        return;
      }
      els.Detail.append(element("h3", "", `${entry.method} ${shortUrl(entry.url, originOf(openJob))}`));
      els.Detail.append(element("p", "recon-help", [entry.error ? "error" : entry.status ?? "—", `${count(entry.ms)} ms`, entry.template_id,
        entry.matched ? "matched" : ""].filter(Boolean).join(" · ")));
      if (!entry.record_id) {
        els.Detail.append(element("p", "recon-empty", entry.error
          || "Not in HTTP history: this scan kept only the matched exchanges."));
        return;
      }
      if (exchange?.key !== openResult || exchange.loading) {
        els.Detail.append(element("p", "recon-empty", "Loading…"));
        return;
      }
      if (exchange.error) {
        els.Detail.append(element("p", "recon-warning", exchange.error));
        return;
      }
      const history = element("button", "secondary-action", "Open in HTTP history");
      history.type = "button";
      history.dataset.recordId = entry.record_id;
      const raw = rawExchange(exchange.record);
      els.Detail.append(history, element("h4", "", "Request"), element("pre", "templates-exchange", raw.request),
        element("h4", "", "Response"), element("pre", "templates-exchange", raw.response));
    }

    function renderJobDetail() {
      const job = openJob;
      els.Detail.append(element("h3", "", `${job.auto ? "Auto scan" : "Manual scan"} · ${job.status}`));
      const fields = element("dl", "templates-facts");
      field(fields, "Targets", job.targets);
      field(fields, "Library", job.library);
      field(fields, "Progress", jobLine(job));
      field(fields, "Redirects not followed", job.redirects_not_followed ? count(job.redirects_not_followed) : "");
      field(fields, "Not sent to", job.skipped_targets);
      field(fields, "Allowed risks", job.allow_risks);
      field(fields, "Pace", `${count(job.rate)} a second · ${count(job.concurrency)} templates at once · limit ${count(job.max_requests)}`);
      if (job.apply_match_replace) field(fields, "Match & Replace", "Applied");
      field(fields, "History", job.history === "all" ? "Every request" : "Matched requests");
      els.Detail.append(fields);
      for (const warning of job.warnings || []) els.Detail.append(element("p", "recon-warning", warning));
      els.Detail.append(element("p", "recon-empty", "Select a request to see what was sent and what came back."));
    }

    function scanOwner() {
      return { sessionId: scanSession, generation: scanGeneration };
    }
    function ownsScan(owner) {
      return !disposed && owner.generation === scanGeneration && owner.sessionId === scanSession
        && owner.sessionId === (options.getSessionId?.() || null);
    }
    function invalidateScanReads() {
      ++scanReadRequest;
      ++autoReadRequest;
      ++exchangeRequest;
      if (exchange?.loading) exchange = null;
      ++planRequest;
      if (planTimer !== null) unschedule(planTimer);
      planTimer = null;
    }
    function syncScanSession() {
      const sessionId = options.getSessionId?.() || null;
      if (sessionId !== scanSession) {
        scanSession = sessionId;
        ++scanGeneration;
        invalidateScanReads();
        scanBusy = false;
        scansLoaded = false;
        autoBusy = false;
        scanJobs = [];
        openJob = null;
        openResult = null;
        exchange = null;
        view = "templates";
        auto = null;
        autoDraft = false;
        autoQueuedSave = null;
        autoPendingEnabled = null;
        ++autoDraftVersion;
        els.AutoHosts.value = "";
        els.AutoRate.value = "10";
        scanNotice("");
        autoNotice("");
        showPlan("");
        renderScan();
        renderDetail();
        renderAuto();
      }
    }
    async function refreshScans() {
      if (disposed) return;
      clearScanTimer();
      syncScanSession();
      const owner = scanOwner();
      const sessionId = owner.sessionId;
      const request = ++scanReadRequest;
      const current = () => ownsScan(owner) && request === scanReadRequest && visible;
      if (!visible || !sessionId || scanBusy) return;
      let failed = false;
      let listedCurrentJobs = false;
      try {
        const query = `session_id=${encodeURIComponent(sessionId)}`;
        const listed = await json(await fetcher(`/api/templates/scans?${query}`), "Could not list the scans");
        if (!current()) return;
        if (listed?.session_id !== sessionId || !Array.isArray(listed.jobs)) {
          throw new Error("Could not read the scans for this session.");
        }
        scanJobs = listed.jobs;
        scansLoaded = true;
        listedCurrentJobs = true;
        if (scanNoticeSource === "read") scanNotice("");
        if (openJob) {
          const jobId = openJob.id;
          const job = await json(await fetcher(`/api/templates/scans/${encodeURIComponent(jobId)}?${query}`), "Could not read the scan");
          if (!current()) return;
          // A newer selection owns its detail, even within the same refresh.
          if (job?.id === jobId && openJob?.id === jobId) {
            openJob = job;
            if (view === "results") {
              const entry = currentResult();
              if (entry?.record_id && exchange?.key !== openResult) void loadExchange(entry);
              renderDetail();
            }
          }
        }
      } catch (error) {
        if (!current()) return;
        failed = true;
        if (!listedCurrentJobs) scansLoaded = false;
        scanNotice(error.message, true, "read");
      }
      if (!current()) return;
      renderScan();
      const autoRead = await refreshAuto();
      // Retry reads only; a failed start or stop is never sent again here.
      if (current() && (failed || autoRead === false || scanJobs.some((job) => job.status === "running") || auto?.enabled)) {
        scanTimer = schedule(refreshScans, 2000);
      }
    }

    async function scanAct(work) {
      if (disposed) return;
      syncScanSession();
      if (scanBusy) return;
      const owner = scanOwner();
      scanBusy = true;
      scansLoaded = false;
      ++scanReadRequest;
      clearScanTimer();
      renderScan();
      try {
        await work(owner, () => ownsScan(owner));
      } catch (error) {
        if (ownsScan(owner)) scanNotice(error.message || "The request failed.", true);
      } finally {
        if (ownsScan(owner)) {
          scanBusy = false;
          renderScan();
          await refreshScans();
        }
      }
    }

    async function act(work) {
      if (busy) return;
      busy = true;
      renderStatus();
      try {
        await work();
      } catch (error) {
        notice(error.message || "The request failed.", true);
      } finally {
        busy = false;
        await refreshStatus();
      }
    }

    function setPassive(body) {
      return act(async () => {
        const result = await json(await fetcher("/api/templates/passive", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        }), "Could not save the passive templates");
        // The count is in the library summary; what it does not say is that
        // traffic already captured waits for a Rescan.
        notice(body.enabled ? "Checks new traffic. Rescan in Findings checks what is already captured." : "");
        if (selected && Array.isArray(body.ids) && body.ids.includes(selected.id)) await open(selected.id, { navigate: false });
      });
    }

    function setAuto(body) {
      return act(async () => {
        await json(await fetcher("/api/templates/auto/templates", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        }), "Could not save the templates for the auto scan");
        notice("");
        await refreshAuto();
      });
    }

    // On for many at once: each template takes its own kind of On, passive
    // where it can judge captured traffic, the auto scan's where it cannot.
    function setMany(passive, auto) {
      return act(async () => {
        for (const [path, body] of [["/api/templates/passive", passive], ["/api/templates/auto/templates", auto]]) {
          if (!body) continue;
          await json(await fetcher(path, {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
          }), "Could not turn the templates on or off");
        }
        notice("");
        await refreshAuto();
      });
    }

    // ---- Auto scan ----

    let auto = null;
    let autoBusy = false;
    // The operator is editing the host list or pace: a refresh leaves it.
    let autoDraft = false;
    let autoDraftVersion = 0;
    let autoQueuedSave = null;
    let autoPendingEnabled = null;

    function autoNotice(message, error = false, source = "action") {
      if (source === "read" && autoNoticeSource === "action" && els.AutoNotice.textContent) return;
      autoNoticeSource = message ? source : null;
      els.AutoNotice.textContent = message;
      els.AutoNotice.classList.toggle("hidden", !message);
      els.AutoNotice.classList.toggle("recon-error", error);
    }
    function autoValues() {
      return { hosts: els.AutoHosts.value, rate: els.AutoRate.value };
    }
    function renderAuto() {
      const on = !!auto?.enabled;
      // While it is on, say why it would send nothing.
      const warning = !on ? ""
        : !auto.templates ? "Turn on Scan templates in the list."
          : !(auto.hosts || []).length && (options.getScopeIncludeCount?.() || 0) === 0 ? "Scope is empty and no hosts are listed." : "";
      els.AutoSummary.textContent = `${autoLine(auto)}${warning ? `. ${warning}` : ""}`;
      els.AutoSummary.classList.toggle("recon-warning", !!warning);
      if (auto && !autoDraft) {
        els.AutoHosts.value = (auto.hosts || []).join("\n");
        els.AutoRate.value = String(auto.rate || 10);
      }
      els.AutoToggle.setAttribute("aria-checked", on ? "true" : "false");
      els.AutoToggle.disabled = autoBusy || !auto;
    }
    async function refreshAuto() {
      const owner = scanOwner();
      const sessionId = owner.sessionId;
      const request = ++autoReadRequest;
      const current = () => ownsScan(owner) && request === autoReadRequest && visible;
      if (!visible || !sessionId || disposed || autoBusy) return;
      try {
        const read = await json(await fetcher(`/api/templates/auto?session_id=${encodeURIComponent(sessionId)}`), "Could not read the auto scan");
        if (!current()) return;
        if (read?.session_id !== sessionId) throw new Error("Could not read the auto scan for this session.");
        auto = read;
        if (autoNoticeSource === "read") autoNotice("");
      } catch (error) {
        if (!current()) return;
        autoNotice(error.message, true, "read");
        renderAuto();
        return false;
      }
      renderAuto();
      return true;
    }
    async function saveAuto(enabled, draft = null) {
      if (disposed) return;
      syncScanSession();
      const submission = draft || { enabled, values: autoValues(), version: autoDraftVersion };
      if (autoBusy) {
        // Keep the last blur, not whatever may be typed after it.
        autoQueuedSave = submission;
        return;
      }
      const owner = scanOwner();
      // An earlier read cannot put back the setting being changed now.
      ++autoReadRequest;
      autoBusy = true;
      autoPendingEnabled = submission.enabled;
      renderAuto();
      try {
        const body = autoRequest(submission.values, owner.sessionId, submission.enabled);
        const saved = await json(await fetcher("/api/templates/auto", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        }), "Could not save the auto scan");
        if (!ownsScan(owner) || saved.session_id !== owner.sessionId) return;
        auto = saved;
        if (submission.version === autoDraftVersion) autoDraft = false;
        autoNotice("");
      } catch (error) {
        if (ownsScan(owner) && !autoQueuedSave) autoNotice(error.message || "The request failed.", true);
      } finally {
        if (ownsScan(owner)) {
          autoBusy = false;
          const queued = autoQueuedSave;
          autoQueuedSave = null;
          if (queued) {
            await saveAuto(queued.enabled, queued);
          } else {
            autoPendingEnabled = null;
            renderAuto();
            await refreshScans();
          }
        }
      }
    }

    on(els.AutoToggle, "click", () => saveAuto(!auto?.enabled));
    // The hosts and pace save when the field is left.
    for (const control of [els.AutoHosts, els.AutoRate]) {
      on(control, "input", () => { autoDraft = true; ++autoDraftVersion; });
      on(control, "change", () => { if (autoDraft) void saveAuto(autoPendingEnabled ?? !!auto?.enabled); });
    }

    // What the installed library follows: main, or the releases (an imported
    // archive is checked against the latest release).
    function installedChannel() {
      const library = status?.library;
      return library?.source === "github" && library.tag === "main" ? "main" : "release";
    }
    function download(channel) {
      if (els.More) els.More.open = false;
      return act(async () => {
        await json(await fetcher("/api/templates/library/download", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ acknowledged: true, channel }),
        }), "Could not start the download");
        lastCheck = null;
        notice("");
      });
    }

    on(els.Download, "click", () => download(installedChannel()));
    on(els.Switch, "click", () => download(status?.library ? (installedChannel() === "main" ? "release" : "main") : "main"));
    on(els.Check, "click", () => act(async () => {
      const result = await json(await fetcher("/api/templates/library/check", { method: "POST" }), "Could not reach GitHub");
      lastCheck = { ...result, sha256: status?.library?.sha256 };
      notice(checkLine(result));
    }));
    on(els.Import, "click", () => els.ImportFile.click());
    on(els.ImportMenu, "click", () => {
      els.More.open = false;
      els.ImportFile.click();
    });
    // The menu closes when the click lands elsewhere.
    on(doc, "click", (event) => {
      if (els.More?.open && !els.More.contains?.(event.target)) els.More.open = false;
    });
    on(els.ImportFile, "change", () => {
      const file = els.ImportFile.files?.[0];
      els.ImportFile.value = "";
      if (!file) return;
      void act(async () => {
        await json(await fetcher("/api/templates/library/import", {
          method: "POST", headers: { "Content-Type": "application/gzip" }, body: file,
        }), "Could not import the archive");
        notice("");
      });
    });
    on(els.Search, "input", () => {
      renderBulk();
      if (searchTimer !== null) unschedule(searchTimer);
      searchTimer = schedule(() => { searchTimer = null; page = 0; void loadList(); }, 250);
    });
    for (const control of [els.Severity, els.Support]) {
      on(control, "change", () => { page = 0; renderStatus(); void loadList(); });
    }
    on(els.Previous, "click", () => { page = Math.max(0, page - 1); void loadList(); });
    on(els.Next, "click", () => { page += 1; void loadList(); });
    on(els.EnableShown, "click", () => setMany(bulkRequest(filters(), true), bulkRequest(filters(), true)));
    on(els.DisableShown, "click", () => setMany(bulkRequest(filters(), false), bulkRequest(filters(), false)));
    on(els.ScanStart, "click", () => {
      syncScanSession();
      if (!scansLoaded || scanBusy || scanJobs.some((job) => job.status === "running")) return;
      return scanAct(async (_owner, current) => {
        const watching = viewRequest;
        const job = await json(await fetcher("/api/templates/scans", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(startBody()),
        }), "Could not start the scan");
        // A response for a session that was left must not open here.
        if (!current()) return;
        if (watching === viewRequest) showResults(job);
        scanNotice("");
      });
    });
    for (const control of [els.ScanTargets, els.ScanRate, els.ScanConcurrency, els.ScanMaxRequests]) on(control, "input", schedulePlan);
    for (const control of [els.ScanSelection, els.ScanMatchReplace, els.ScanRisks, els.ScanKeepAll]) on(control, "change", schedulePlan);
    // The search and severity choose what a scan sends.
    on(els.Search, "input", () => { if (els.ScanSelection.value === "filter") schedulePlan(); });
    on(els.Severity, "change", () => { if (els.ScanSelection.value === "filter") schedulePlan(); });
    function stopScan(id) {
      return scanAct(async (owner) => {
        await json(await fetcher(`/api/templates/scans/${encodeURIComponent(id)}/stop`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ session_id: owner.sessionId }),
        }), "Could not stop the scan");
      });
    }
    on(els.ScanJobs, "click", (event) => {
      const stop = event.target.closest("[data-stop-scan]");
      if (stop) {
        void stopScan(stop.dataset.stopScan);
        return;
      }
      const card = event.target.closest("[data-open-scan]");
      if (card) {
        showResults(scanJobs.find((job) => job.id === card.dataset.openScan) || null);
        void refreshScans();
      }
    });
    on(els.Views, "click", (event) => {
      const button = event.target.closest("[data-templates-view]");
      if (!button) return;
      if (button.dataset.templatesView === "results") {
        showResults(openJob || scanJobs[0] || null);
        void refreshScans();
      } else {
        ++viewRequest;
        view = "templates";
        renderStatus();
        renderList();
        renderDetail();
      }
    });
    on(els.ResultsRows, "click", (event) => {
      const row = event.target.closest("[data-result-key]");
      if (row) selectResult(row.dataset.resultKey);
    });
    on(els.ResultsHead, "click", (event) => {
      if (event.target.closest(".table-col-resize")) return;
      const header = event.target.closest("[data-result-sort]");
      if (!header) return;
      resultSort = nextSort(resultSort, header.dataset.resultSort);
      renderResults();
    });
    on(els.ResultsMatched, "click", () => {
      matchedOnly = !matchedOnly;
      renderResults();
    });
    on(els.ResultsStop, "click", () => { if (openJob) void stopScan(openJob.id); });
    on(els.Detail, "click", (event) => {
      const record = event.target.closest("[data-record-id]");
      if (record) options.openRecord?.(record.dataset.recordId);
    });
    on(els.Rows, "click", (event) => {
      const box = event.target.closest("[data-template-toggle]") || event.target.closest("[data-template-auto]");
      if (box) {
        const id = box.dataset.templateToggle || box.dataset.templateAuto;
        const from = items.findIndex((meta) => meta.id === rangeAnchor);
        const to = items.findIndex((meta) => meta.id === id);
        rangeAnchor = id;
        if (event.shiftKey && from >= 0 && to >= 0) {
          const range = items.slice(Math.min(from, to), Math.max(from, to) + 1);
          const passive = range.filter((meta) => meta.passive_supported).map((meta) => meta.id);
          const autoIds = range.filter((meta) => !meta.passive_supported && meta.active_supported).map((meta) => meta.id);
          void setMany(passive.length ? { ids: passive, enabled: box.checked } : null,
            autoIds.length ? { ids: autoIds, enabled: box.checked } : null);
          return;
        }
        void (box.dataset.templateToggle
          ? setPassive({ ids: [id], enabled: box.checked })
          : setAuto({ ids: [id], enabled: box.checked }));
        return;
      }
      const row = event.target.closest("[data-template-id]");
      if (row) void open(row.dataset.templateId);
    });
    on(els.Head, "click", (event) => {
      if (event.target.closest(".table-col-resize")) return;
      const header = event.target.closest("[data-sort]");
      if (!header) return;
      sort = nextSort(sort, header.dataset.sort);
      renderSortHeaders();
      page = 0;
      void loadList();
    });
    // ↑/↓ move through the page, as in Findings; the app says when they are
    // free, not while a field has focus or a modal is open.
    on(doc, "keydown", (event) => {
      if (!visible) return;
      const step = options.arrowStep?.(event) || 0;
      if (!step) return;
      if (view === "results" && openJob) {
        const rows = resultRows();
        if (!rows.length) return;
        const current = rows.findIndex((entry) => resultKey(entry) === openResult);
        const next = current < 0 ? (step > 0 ? 0 : rows.length - 1) : current + step;
        if (next < 0 || next >= rows.length) return;
        event.preventDefault();
        selectResult(resultKey(rows[next]), true);
        return;
      }
      if (!items.length) return;
      const current = items.findIndex((meta) => meta.id === (pendingId ?? selected?.id));
      const next = current < 0 ? (step > 0 ? 0 : items.length - 1) : current + step;
      if (next < 0 || next >= items.length) return;
      event.preventDefault();
      void open(items[next].id, { reveal: true });
    });

    function setVisible(next) {
      if (disposed) return;
      const changed = visible !== !!next;
      visible = !!next;
      if (!visible) {
        clearTimer();
        clearScanTimer();
        if (changed) {
          ++scanGeneration;
          invalidateScanReads();
          scanBusy = false;
          scansLoaded = false;
          renderScan();
          autoBusy = false;
          autoQueuedSave = null;
          autoPendingEnabled = null;
        }
      } else if (changed) {
        // The CLI or another window may have changed Scope while Scan was
        // hidden, and the warning about it reads the scope the app holds.
        options.onShow?.();
        void refreshStatus();
        void refreshScans();
      }
    }

    renderStatus();
    renderList();
    renderDetail();
    renderScan();
    return {
      setVisible,
      refresh: refreshStatus,
      // The app calls this when it has reread Scope.
      scopeChanged: renderStatus,
      // Another session's scans are not this one's.
      syncSession() { return refreshScans(); },
      dispose() {
        disposed = true;
        ++scanGeneration;
        invalidateScanReads();
        clearTimer();
        clearScanTimer();
        if (planTimer !== null) unschedule(planTimer);
        listeners.forEach((remove) => remove());
      },
    };
  }

  const api = { createController, listQuery, nextSort, bulkRequest, narrowed, librarySummary, checkLine, progressOf, supportLabel, scanRequest, parseTargets,
    previewLine, jobLine, autoRequest, autoLine, yamlLines, RISKS, PAGE_SIZE };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.SniperTemplates = api;
})(typeof window !== "undefined" ? window : globalThis);
