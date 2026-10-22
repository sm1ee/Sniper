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

  // Turning templates on in bulk follows the list filter, restricted to the
  // ones that can run passively; the server ignores the rest.
  function passiveRequest(filters, enabled) {
    const filter = { support: "passive" };
    const search = String(filters.search || "").trim();
    if (search) filter.search = search;
    if (filters.severity) filter.severity = filters.severity;
    return { filter, enabled: !!enabled };
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
    } else {
      const filter = {};
      const search = String(filters.search || "").trim();
      if (search) filter.search = search;
      if (filters.severity) filter.severity = filters.severity;
      body.filter = filter;
    }
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

  // Turning scan templates on in bulk follows the list filter, as the
  // passive bulk change does.
  function autoTemplatesRequest(filters, enabled) {
    return { ...passiveRequest(filters, enabled), filter: { ...passiveRequest(filters, enabled).filter, support: "active" } };
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

  function createController(options) {
    const shell = options.root;
    const doc = shell.ownerDocument;
    const fetcher = options.fetch || root.fetch.bind(root);
    const schedule = options.setTimeout || root.setTimeout.bind(root);
    const unschedule = options.clearTimeout || root.clearTimeout.bind(root);
    const ids = ["Version", "Status", "Progress", "ProgressBar", "Channel", "Download", "Check", "Import", "ImportFile", "Notice", "ScopeNote",
      "Search", "Severity", "Support", "EnabledOnly", "EnableShown", "DisableShown", "Meta", "Head", "Rows", "Detail",
      "PageMeta", "Previous", "Next", "ScanTargets", "ScanSelection", "ScanRisks", "ScanRate", "ScanConcurrency",
      "ScanMaxRequests", "ScanMatchReplace", "ScanPlan", "ScanStart",
      "ScanNotice", "ScanJobs", "AutoSummary", "AutoHosts", "AutoRate", "AutoToggle", "AutoNotice"];
    const els = Object.fromEntries(ids.map((id) => [id, shell.querySelector(`#templates${id}`)]));
    const listeners = [];
    let visible = false;
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
    // Until one is picked, Download follows the installed library, so updating
    // a library taken from main does not fall back to the release.
    let channelPicked = false;
    let listRequest = 0;

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
    function filters() {
      return {
        search: els.Search.value, severity: els.Severity.value, support: els.Support.value, enabledOnly: els.EnabledOnly.checked,
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
      if (!channelPicked && status?.library) els.Channel.value = status.library.tag === "main" ? "main" : "release";
      els.Download.title = DOWNLOAD_TITLES[channel()];
      els.Channel.disabled = !!working || busy;
      els.Download.disabled = !!working || busy;
      els.Import.disabled = !!working || busy;
      els.Check.disabled = !!working || busy;
      const scopeless = (options.getScopeIncludeCount?.() || 0) === 0;
      els.ScopeNote.classList.toggle("hidden", !(scopeless && status?.passive_enabled > 0));
      // Bulk changes act on passive-capable templates only, so they are offered
      // only while the list shows exactly those.
      const bulk = !!status?.library && (els.Support.value === "passive" || els.Support.value === "active");
      for (const button of [els.EnableShown, els.DisableShown]) {
        button.classList.toggle("hidden", !bulk);
        button.disabled = busy;
      }
      // Start waits for a library, which may arrive after the scan form was
      // first drawn.
      renderScan();
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
      if (showingJob && openJob) {
        renderJobDetail();
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
    async function open(id, { reveal = false } = {}) {
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
      showingJob = false;
      if (els.ScanSelection.value === "selected") schedulePlan();
      renderList();
      renderDetail();
    }

    // ---- Manual scan ----

    let scanSession = null;
    let scanJobs = [];
    let openJob = null;
    let showingJob = false;
    let scanBusy = false;
    let scanTimer = null;
    let planTimer = null;
    let planRequest = 0;

    function scanNotice(message, error = false) {
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
        if (request !== planRequest) return;
        if (preview.templates) showPlan(previewLine(preview));
        else showPlan(preview.oast_unavailable ? "These templates need an Interactsh server: Capture ▸ OAST." : "No template that can be sent matches.", true);
      } catch (error) {
        if (request === planRequest) showPlan(error.message, true);
      }
    }
    function schedulePlan() {
      // The form changed, so the last refusal no longer applies.
      scanNotice("");
      if (planTimer !== null) unschedule(planTimer);
      planTimer = schedule(() => { planTimer = null; void plan(); }, 400);
    }
    function clearScanTimer() { if (scanTimer !== null) unschedule(scanTimer); scanTimer = null; }

    function renderScan() {
      const running = scanJobs.some((job) => job.status === "running");
      // The click is the consent; the plan above it says what it sends.
      els.ScanStart.disabled = scanBusy || running || !status?.library;
      els.ScanStart.textContent = running ? "A scan is running" : "Start scan";
      const nodes = [];
      for (const job of scanJobs) {
        const card = element("article", "recon-job");
        card.title = `Started ${new Date(job.started_at).toLocaleString()} · ${plural(job.templates, "template")}`;
        const header = element("div", "recon-job-header");
        header.append(element("strong", "recon-job-target", (job.targets || []).join(", ") || "Manual scan"));
        if (job.auto) header.append(element("span", "detail-chip", "auto"));
        header.append(element("span", `detail-chip ${job.status === "running" ? "info" : job.status === "completed" ? "ok" : "warn"}`, job.status));
        const results = element("button", "secondary-action", "Results");
        results.type = "button";
        results.dataset.openScan = job.id;
        header.append(results);
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
      els.Detail.append(fields);
      for (const warning of job.warnings || []) els.Detail.append(element("p", "recon-warning", warning));
      els.Detail.append(element("h4", "", `Matches (${count(job.matched)})`));
      const results = element("ul", "templates-matches");
      for (const result of job.results || []) {
        const item = element("li");
        const open = element("button", "templates-match-open");
        open.type = "button";
        open.dataset.recordId = result.record_id;
        open.setAttribute("aria-label", `Open the matched exchange for ${result.template_id} in HTTP history`);
        open.append(element("span", `severity-badge ${severityClass(result.severity)}`, result.severity || "unknown"),
          element("span", "", `${result.name || result.template_id}${result.matcher ? ` [${result.matcher}]` : ""}`));
        item.append(open, element("div", "templates-match-where", `${result.method} ${result.url}${result.evidence ? ` — ${result.evidence}` : ""}`));
        results.append(item);
      }
      if (!results.children.length) results.append(element("li", "recon-help", job.status === "running" ? "Nothing matched yet." : "Nothing matched."));
      els.Detail.append(results);
      const recent = (job.recent || []).slice(-50).reverse();
      els.Detail.append(element("h4", "", "Latest requests"));
      const log = element("ul", "templates-requests");
      // With one target the origin says nothing; the path is what differs.
      const origin = (job.targets || []).length === 1 ? String(job.targets[0]).replace(/^(https?:\/\/[^/]+).*$/, "$1") : null;
      for (const entry of recent) {
        const item = element("li", entry.matched ? "templates-matched" : "");
        const url = origin && String(entry.url).startsWith(`${origin}/`) ? String(entry.url).slice(origin.length) : entry.url;
        item.title = `${entry.method} ${entry.url}`;
        item.append(element("span", `templates-request-status${entry.error ? " templates-request-error" : ""}`, entry.error ? "error" : String(entry.status ?? "—")),
          element("span", "templates-request-url", `${entry.method} ${url}`),
          element("span", "recon-help", `${entry.error || `${count(entry.ms)} ms`} · ${entry.template_id}`));
        log.append(item);
      }
      if (!log.children.length) log.append(element("li", "recon-help", "No requests yet."));
      els.Detail.append(log);
    }

    async function refreshScans() {
      clearScanTimer();
      const sessionId = options.getSessionId?.() || null;
      if (sessionId !== scanSession) {
        scanSession = sessionId;
        scanJobs = [];
        openJob = null;
        showingJob = false;
        auto = null;
        autoDraft = false;
        showPlan("");
        renderScan();
        renderDetail();
        renderAuto();
      }
      if (!visible || !sessionId) return;
      try {
        const query = `session_id=${encodeURIComponent(sessionId)}`;
        const listed = await json(await fetcher(`/api/templates/scans?${query}`), "Could not list the scans");
        if (sessionId !== scanSession || listed.session_id !== sessionId) return;
        scanJobs = Array.isArray(listed.jobs) ? listed.jobs : [];
        if (openJob) {
          const job = await json(await fetcher(`/api/templates/scans/${encodeURIComponent(openJob.id)}?${query}`), "Could not read the scan");
          if (sessionId !== scanSession) return;
          openJob = job;
          if (showingJob) renderDetail();
        }
      } catch (error) {
        scanNotice(error.message, true);
      }
      renderScan();
      await refreshAuto();
      // An auto job can start at any moment while the auto scan is on.
      if (visible && (scanJobs.some((job) => job.status === "running") || auto?.enabled)) scanTimer = schedule(refreshScans, 2000);
    }

    async function scanAct(work) {
      if (scanBusy) return;
      scanBusy = true;
      renderScan();
      try {
        await work();
      } catch (error) {
        scanNotice(error.message || "The request failed.", true);
      } finally {
        scanBusy = false;
        renderScan();
        await refreshScans();
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
        if (selected && Array.isArray(body.ids) && body.ids.includes(selected.id)) await open(selected.id);
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

    // ---- Auto scan ----

    let auto = null;
    let autoBusy = false;
    // The operator is editing the host list or pace: a refresh leaves it.
    let autoDraft = false;

    function autoNotice(message, error = false) {
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
      els.AutoToggle.textContent = on ? "On" : "Off";
      els.AutoToggle.classList.toggle("online", on);
      els.AutoToggle.setAttribute("aria-pressed", on ? "true" : "false");
      els.AutoToggle.disabled = autoBusy || !auto;
    }
    async function refreshAuto() {
      const sessionId = options.getSessionId?.() || null;
      if (!visible || !sessionId) return;
      try {
        const read = await json(await fetcher(`/api/templates/auto?session_id=${encodeURIComponent(sessionId)}`), "Could not read the auto scan");
        if (read.session_id !== (options.getSessionId?.() || null)) return;
        auto = read;
      } catch (error) {
        autoNotice(error.message, true);
      }
      renderAuto();
    }
    async function saveAuto(enabled) {
      if (autoBusy) return;
      autoBusy = true;
      renderAuto();
      try {
        const body = autoRequest(autoValues(), options.getSessionId?.(), enabled);
        auto = await json(await fetcher("/api/templates/auto", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        }), "Could not save the auto scan");
        autoDraft = false;
        autoNotice("");
      } catch (error) {
        autoNotice(error.message || "The request failed.", true);
      } finally {
        autoBusy = false;
        renderAuto();
        await refreshScans();
      }
    }

    on(els.AutoToggle, "click", () => saveAuto(!auto?.enabled));
    // The hosts and pace save when the field is left.
    for (const control of [els.AutoHosts, els.AutoRate]) {
      on(control, "input", () => { autoDraft = true; });
      on(control, "change", () => { if (autoDraft) void saveAuto(!!auto?.enabled); });
    }

    function channel() {
      return els.Channel.value === "main" ? "main" : "release";
    }

    on(els.Channel, "change", () => { channelPicked = true; renderStatus(); });
    on(els.Download, "click", () => act(async () => {
      await json(await fetcher("/api/templates/library/download", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ acknowledged: true, channel: channel() }),
      }), "Could not start the download");
      notice("");
    }));
    on(els.Check, "click", () => act(async () => {
      const result = await json(await fetcher("/api/templates/library/check", { method: "POST" }), "Could not reach GitHub");
      notice(checkLine(result));
    }));
    on(els.Import, "click", () => els.ImportFile.click());
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
      if (searchTimer !== null) unschedule(searchTimer);
      searchTimer = schedule(() => { searchTimer = null; page = 0; void loadList(); }, 250);
    });
    for (const control of [els.Severity, els.Support, els.EnabledOnly]) {
      on(control, "change", () => { page = 0; renderStatus(); void loadList(); });
    }
    on(els.Previous, "click", () => { page = Math.max(0, page - 1); void loadList(); });
    on(els.Next, "click", () => { page += 1; void loadList(); });
    on(els.EnableShown, "click", () => (els.Support.value === "active"
      ? setAuto(autoTemplatesRequest(filters(), true))
      : setPassive(passiveRequest(filters(), true))));
    on(els.DisableShown, "click", () => (els.Support.value === "active"
      ? setAuto(autoTemplatesRequest(filters(), false))
      : setPassive(passiveRequest(filters(), false))));
    on(els.ScanStart, "click", () => scanAct(async () => {
      const job = await json(await fetcher("/api/templates/scans", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(startBody()),
      }), "Could not start the scan");
      openJob = job;
      showingJob = true;
      renderDetail();
      scanNotice("");
    }));
    for (const control of [els.ScanTargets, els.ScanRate, els.ScanConcurrency, els.ScanMaxRequests]) on(control, "input", schedulePlan);
    for (const control of [els.ScanSelection, els.ScanMatchReplace, els.ScanRisks]) on(control, "change", schedulePlan);
    // The search and severity choose what a scan sends.
    on(els.Search, "input", () => { if (els.ScanSelection.value === "filter") schedulePlan(); });
    on(els.Severity, "change", () => { if (els.ScanSelection.value === "filter") schedulePlan(); });
    on(els.ScanJobs, "click", (event) => {
      const stop = event.target.closest("[data-stop-scan]");
      if (stop) {
        void scanAct(async () => {
          await json(await fetcher(`/api/templates/scans/${encodeURIComponent(stop.dataset.stopScan)}/stop`, {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ session_id: scanSession }),
          }), "Could not stop the scan");
          scanNotice("Stopped. Matches found so far are kept.");
        });
        return;
      }
      const results = event.target.closest("[data-open-scan]");
      if (results) {
        openJob = scanJobs.find((job) => job.id === results.dataset.openScan) || null;
        showingJob = !!openJob;
        renderDetail();
        void refreshScans();
      }
    });
    on(els.Detail, "click", (event) => {
      const record = event.target.closest("[data-record-id]");
      if (record) options.openRecord?.(record.dataset.recordId);
    });
    on(els.Rows, "click", (event) => {
      const toggle = event.target.closest("[data-template-toggle]");
      if (toggle) {
        void setPassive({ ids: [toggle.dataset.templateToggle], enabled: toggle.checked });
        return;
      }
      const autoBox = event.target.closest("[data-template-auto]");
      if (autoBox) {
        void setAuto({ ids: [autoBox.dataset.templateAuto], enabled: autoBox.checked });
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
      if (!visible || !items.length) return;
      const step = options.arrowStep?.(event) || 0;
      if (!step) return;
      const current = items.findIndex((meta) => meta.id === (pendingId ?? selected?.id));
      const next = current < 0 ? (step > 0 ? 0 : items.length - 1) : current + step;
      if (next < 0 || next >= items.length) return;
      event.preventDefault();
      void open(items[next].id, { reveal: true });
    });

    function setVisible(next) {
      const changed = visible !== !!next;
      visible = !!next;
      if (!visible) {
        clearTimer();
        clearScanTimer();
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
      syncSession() { void refreshScans(); },
      dispose() {
        clearTimer();
        clearScanTimer();
        if (planTimer !== null) unschedule(planTimer);
        listeners.forEach((remove) => remove());
      },
    };
  }

  const api = { createController, listQuery, nextSort, passiveRequest, librarySummary, checkLine, progressOf, supportLabel, scanRequest, parseTargets,
    previewLine, jobLine, autoRequest, autoLine, yamlLines, RISKS, PAGE_SIZE };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.SniperTemplates = api;
})(typeof window !== "undefined" ? window : globalThis);
