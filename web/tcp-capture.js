(function (root) {
  "use strict";
  const LIVE = new Set(["connecting", "open"]);
  const STATUS_LABELS = new Map([
    ["connecting", "Connecting"], ["open", "Open"], ["closed", "Closed"],
    ["failed", "Failed"], ["stopped", "Stopped"], ["interrupted", "Interrupted"]
  ]);
  const FAILURE_LABELS = new Map([
    ["resolution_timeout", "Name lookup timed out"], ["resolution_failed", "Name lookup failed"],
    ["connect_timeout", "Connection timed out"], ["connection_refused", "Connection refused"],
    ["connect_failed", "Connection failed"], ["self_target", "Target is this listener"],
    ["relay_failed", "Stream interrupted"], ["storage_failed", "History storage failed"]
  ]);
  const DIRECTIONS = ["client_to_server", "server_to_client"];
  const MAX_DISPLAY_BYTES = 256 * 1024;
  const GAP = "Missing bytes in this capture.";
  const MALFORMED = "This capture is malformed.";
  const TOO_LARGE = "This capture is too large to show.";
  function statusLabel(record) {
    const label = STATUS_LABELS.get(record.status) || String(record.status || "");
    const reason = record.status === "failed" ? FAILURE_LABELS.get(record.failure) : null;
    return reason ? label + " · " + reason : label;
  }
  function validateSettings(localPort, host, targetPort) {
    const port = value => /^\d+$/.test(String(value)) && Number(value) >= 1 && Number(value) <= 65535;
    if (!port(localPort) || !port(targetPort)) throw new Error("Ports must be whole numbers from 1 to 65535.");
    host = String(host).trim();
    if (!host || host.length > 253 || /[\s\x00-\x1f\x7f/?#@]/.test(host)) throw new Error("Enter a hostname or IP address, without a URL or path.");
    if (/[:\[\]]/.test(host)) {
      const address = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
      try {
        // URL's IPv6 parser is syntax-only: no DNS lookup or connection.
        if (/[\[\]]/.test(address)) throw new Error();
        host = new URL("http://[" + address + "]/").hostname.slice(1, -1);
      } catch (_) { throw new Error("Enter a hostname or IP address without a port; use Target port separately."); }
    }
    return { local_port: Number(localPort), target_host: host, target_port: Number(targetPort) };
  }
  async function requestError(response) {
    const fallback = "TCP request failed (" + response.status + "). Refresh and try again.";
    // Only display known, bounded configuration messages, never arbitrary server
    // output (which could be HTML or contain captured traffic).
    if (![400, 500, 503].includes(response.status) || typeof response.text !== "function") return fallback;
    try {
      const message = await response.text();
      if (message.length > 240) return fallback;
      if (response.status === 500 && /^TCP capture stopped, but [0-9]{1,8} connection record\(s\) are not saved\. Keep Sniper open, restore storage, then retry saving\.$/.test(message)) return message;
      if (response.status === 503 && message === "TCP capture cannot start while Sniper is shutting down") return message;
      if (response.status === 404 && message === "unknown TCP listener") return "This listener was removed. Refresh and try again.";
      if (response.status !== 400) return fallback;
      if (/^Local port [0-9]{1,5} is already in use\. Choose another Local port or stop the listener using it\.$/.test(message)
        || /^Another listener already uses local port [0-9]{1,5}\.$/.test(message)
        || /^A session keeps at most [0-9]{1,3} TCP listeners\.$/.test(message)
        || message === "TCP history requires recovery before capture can start"
        || message === "TCP history is full; use a new session"
        || /^Could not bind local port [0-9]{1,5}\. Check the port and local permissions\.$/.test(message)
        || message === "Enter a hostname or IP address without a port; use Target port separately."
        || message === "invalid target host" || message === "ports must be 1–65535") return message;
    } catch (_) {}
    return fallback;
  }
  // The capture in the order it was read, each chunk with its bytes. Each
  // direction's chunks must join end to end, or none of it is shown: a gap
  // would put bytes at the wrong offset.
  function conversation(record, direction = "both") {
    if (record.chunks == null) return [];
    if (!Array.isArray(record.chunks) || record.chunks.some(chunk => !chunk || typeof chunk !== "object"
      || !DIRECTIONS.includes(chunk.direction) || typeof chunk.data_base64 !== "string")) throw new Error(MALFORMED);
    const lengths = { client_to_server: 0, server_to_client: 0 };
    const parts = [];
    // A direction not shown is neither decoded nor checked.
    for (const chunk of [...record.chunks].sort((a, b) => a.sequence - b.sequence)) {
      if (direction !== "both" && chunk.direction !== direction) continue;
      if (chunk.offset !== lengths[chunk.direction]) throw new Error(GAP);
      let raw;
      try { raw = atob(chunk.data_base64); } catch (_) { throw new Error(MALFORMED); }
      lengths[chunk.direction] += raw.length;
      if (lengths[chunk.direction] > MAX_DISPLAY_BYTES) throw new Error(TOO_LARGE);
      if (raw.length) parts.push({ direction: chunk.direction, at: chunk.at, offset: chunk.offset, bytes: Uint8Array.from(raw, char => char.charCodeAt(0)) });
    }
    return parts;
  }
  // One direction's bytes, joined: what an export or a copy would take.
  function streamBytes(record, direction) {
    const parts = conversation(record, direction);
    const bytes = new Uint8Array(parts.reduce((total, part) => total + part.bytes.length, 0));
    let offset = 0;
    for (const part of parts) { bytes.set(part.bytes, offset); offset += part.bytes.length; }
    return bytes;
  }
  const MAX_CACHED_CHUNKS = 1024, MAX_CACHED_BASE64 = 512 * 1024;
  function sameChunks(a, b) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((chunk, i) => chunk.sequence === b[i]?.sequence
      && chunk.direction === b[i]?.direction && chunk.offset === b[i]?.offset && chunk.data_base64 === b[i]?.data_base64);
  }
  function formatHex(bytes, start = 0) {
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const row = Array.from(bytes.subarray(i, i + 16));
      lines.push((start + i).toString(16).padStart(8, "0") + "  " + row.map(b => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ") + "  " + row.map(b => b >= 32 && b <= 126 ? String.fromCharCode(b) : ".").join(""));
    }
    return lines.join("\n");
  }
  function formatText(bytes) {
    // A projection only: replacement glyphs and escaped controls are never writable.
    return new TextDecoder("utf-8").decode(bytes).replace(/[\x00-\x08\x0b-\x1f\x7f]/g, c => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0"));
  }
  function clock(value) {
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return "";
    return date.toLocaleTimeString("en-GB", { hour12: false }) + "." + String(date.getMilliseconds()).padStart(3, "0");
  }
  function durationMs(record) {
    // Interrupted records have no known end time. Only live streams age with now.
    if (!record.ended_at && !LIVE.has(record.status)) return -1;
    const start = Date.parse(record.started_at), end = record.ended_at ? Date.parse(record.ended_at) : Date.now();
    return Number.isFinite(start) && Number.isFinite(end) ? Math.max(0, end - start) : -1;
  }
  function duration(record) {
    const ms = durationMs(record);
    return ms < 0 ? "—" : (ms / 1000).toFixed(1) + " s";
  }
  function byteSize(value) {
    const bytes = Number(value) || 0;
    if (bytes < 1024) return bytes + " B";
    const units = ["KB", "MB", "GB"];
    let size = bytes / 1024, unit = 0;
    while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++; }
    return size.toFixed(size >= 10 ? 0 : 1) + " " + units[unit];
  }
  function pausedDuration(value) {
    // A missing timestamp must not become epoch time; future server clocks do
    // not establish a real elapsed duration on this client.
    const start = typeof value === "string" && value.trim() ? Date.parse(value) : NaN;
    const elapsed = Date.now() - start;
    if (!Number.isFinite(elapsed) || elapsed < 0) return "—";
    const seconds = Math.floor(elapsed / 1000);
    return seconds < 60 ? seconds + "s" : seconds < 3600 ? Math.floor(seconds / 60) + "m" : Math.floor(seconds / 3600) + "h " + Math.floor(seconds % 3600 / 60) + "m";
  }
  const MAX_LISTENERS = 16;
  function targetLabel(settings) {
    const host = String(settings?.target_host || "");
    return (host.includes(":") ? "[" + host + "]" : host) + ":" + settings?.target_port;
  }
  function listenerRoute(listener) {
    return "127.0.0.1:" + listener.settings.local_port + " → " + targetLabel(listener.settings);
  }
  function listenerState(listener) {
    return listener.running ? "Listening" : !listener.enabled ? "Off" : String(listener.error || "Not running");
  }
  function createController({ document, sessionId, readPath, writePath, request, openSettings, intercept = false, arrowStep = () => 0, formatTime = clock, formatSize = byteSize }) {
    const interceptController = intercept ? createInterceptController({ document, sessionId, readPath, writePath, request, formatSize, onChanged: () => refresh() }) : null;
    const el = id => document.getElementById(id);
    let epoch = 0, selection = 0, detailRequest = 0, selectedId = null, detail = null, records = [], status = null;
    let reading = null, writing = false, mode = "hex", listKey = "", actionError = null, streamView = null;
    // The listener being edited: null, "new", or a listener's id.
    let editing = null, listenerSort = { key: "local_port", direction: "asc" }, shownListeners = [];
    let liveOnly = false, sort = { key: "index", direction: "desc" }, shown = [], indexById = new Map();
    const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
    const text = (id, value) => { if (el(id).textContent !== value) el(id).textContent = value; };
    const snapshot = () => ({ epoch, session: sessionId() });
    const current = stamp => stamp.epoch === epoch && stamp.session === sessionId();
    const visible = () => { const panel = el("tcpPanel"); return Boolean(panel) && !panel.closest?.(".hidden"); };
    async function json(path, options) {
      const response = await request(path, options);
      if (!response.ok) throw new Error(await requestError(response));
      return response.json();
    }
    const listeners = () => Array.isArray(status?.listeners) ? status.listeners : [];
    function renderStatus() {
      const all = listeners(), running = all.filter(listener => listener.running);
      const unavailable = !status || writing;
      // Status and rows are separate snapshots. History only grows within a
      // session, so a newer list at the cap must not still look accepting.
      const count = Math.max(status?.history_count || 0, records.length);
      const full = Boolean(status && status.history_limit > 0 && count >= status.history_limit);
      const storageError = Boolean(status?.load_error || status?.persistence_error);
      const atLimit = running.length > 0 && status.active_limit > 0 && status.active_count >= status.active_limit;
      const blocked = storageError ? "History storage unavailable"
        : full ? "History full (" + count + "/" + status.history_limit + ")"
        : atLimit ? status.active_count + " of " + status.active_limit + " connections; new ones wait" : "";
      text("tcpListenerStatus", !status ? "Unavailable"
        : blocked || (running.length ? running.length + " listening" : all.length ? "Off" : "No listeners"));
      el("tcpAddListener").disabled = unavailable || all.length >= MAX_LISTENERS;
      text("tcpOpenSettings", running.length === 1 ? listenerRoute(running[0])
        : running.length ? running.length + " listeners" : "Listener off");
      const warning = status?.persistence_error ? "TCP history is not saved. Restore storage, then stop and retry saving."
        : storageError ? "TCP history storage is unavailable."
        : full ? "History is full. Start a new session to capture more." : "";
      text("tcpSettingsError", actionError?.message || warning);
      el("tcpRetrySaving").hidden = !status?.persistence_error;
      el("tcpRetrySaving").disabled = unavailable;
      renderListeners(all, unavailable);
      el("tcpListenerForm").hidden = editing === null;
      el("tcpRemoveListener").hidden = editing === null || editing === "new";
      for (const id of ["tcpLocalPort", "tcpTargetHost", "tcpTargetPort", "tcpSaveListener", "tcpCancelListener", "tcpRemoveListener"]) el(id).disabled = unavailable;
      // Paused bytes are counted beside the Intercept switch, not here too.
      const live = records.filter(record => LIVE.has(record.status)).length;
      text("tcpHistoryStatus", [
        records.length === 1 ? "1 connection" : records.length + " connections",
        live ? live + " live" : "", blocked
      ].filter(Boolean).join(" · "));
    }
    const LISTENER_SORT = {
      local_port: listener => Number(listener.settings?.local_port) || 0,
      target: listener => targetLabel(listener.settings), status: listenerState
    };
    function renderListeners(all, unavailable) {
      const value = LISTENER_SORT[listenerSort.key] || LISTENER_SORT.local_port, factor = listenerSort.direction === "asc" ? 1 : -1;
      shownListeners = [...all].sort((a, b) => {
        const x = value(a), y = value(b);
        return (typeof x === "number" && typeof y === "number" ? x - y : collator.compare(String(x), String(y))) * factor;
      });
      const body = el("tcpListenerRows");
      body.replaceChildren();
      for (const listener of shownListeners) {
        const row = document.createElement("tr"), selected = listener.id === editing;
        row.dataset.listenerId = listener.id;
        row.classList.toggle("selected", selected);
        row.setAttribute("aria-selected", String(selected));
        const toggle = document.createElement("button");
        toggle.className = "switch"; toggle.type = "button"; toggle.disabled = unavailable;
        toggle.dataset.listenerToggle = listener.id;
        toggle.setAttribute("role", "switch");
        toggle.setAttribute("aria-checked", String(Boolean(listener.enabled)));
        toggle.setAttribute("aria-label", "Listener on port " + listener.settings.local_port);
        const on = document.createElement("td");
        on.className = "tcp-col-on"; on.append(toggle); row.append(on);
        const state = listenerState(listener);
        for (const [content, className] of [["127.0.0.1:" + listener.settings.local_port, ""], [targetLabel(listener.settings), ""],
          [state, listener.enabled && !listener.running ? "tcp-listener-error" : ""]]) {
          const cell = document.createElement("td");
          cell.textContent = content; cell.title = content;
          if (className) cell.className = className;
          row.append(cell);
        }
        body.append(row);
      }
      if (!shownListeners.length) {
        const row = document.createElement("tr"), cell = document.createElement("td");
        cell.colSpan = 4; cell.className = "tcp-empty"; cell.textContent = "No listeners";
        row.append(cell); body.append(row);
      }
    }
    function nextPort() {
      const used = new Set(listeners().map(listener => listener.settings?.local_port));
      let port = 9000;
      while (used.has(port)) port++;
      return port;
    }
    function openForm(target) {
      const listener = listeners().find(item => item.id === target);
      if (target !== "new" && !listener) return;
      editing = target; actionError = null;
      el("tcpLocalPort").value = String(listener ? listener.settings.local_port : nextPort());
      el("tcpTargetHost").value = listener ? listener.settings.target_host : "";
      el("tcpTargetPort").value = listener ? String(listener.settings.target_port) : "";
      renderStatus();
      el("tcpTargetHost").focus?.();
    }
    function closeForm() { editing = null; actionError = null; renderStatus(); }
    function statusText(record) {
      return [
        statusLabel(record),
        record.pending_count ? record.pending_count + " paused" : "",
        record.capture_truncated || record.intercept_truncated ? "partial" : "",
        !LIVE.has(record.status) && !record.durable ? "not saved" : ""
      ].filter(Boolean).join(" · ");
    }
    const SORT_VALUES = {
      index: record => indexById.get(record.id) || 0,
      local_port: record => Number(record.local_port) || 0,
      target: record => record.target, peer: record => record.peer, status: record => statusLabel(record),
      client_bytes: record => Number(record.client_bytes) || 0, server_bytes: record => Number(record.server_bytes) || 0,
      duration: durationMs, started_at: record => Date.parse(record.started_at) || 0
    };
    function sortedRecords() {
      const value = SORT_VALUES[sort.key] || SORT_VALUES.index, factor = sort.direction === "asc" ? 1 : -1;
      return [...records].sort((a, b) => {
        const x = value(a), y = value(b);
        const order = typeof x === "number" && typeof y === "number" ? x - y : collator.compare(String(x), String(y));
        return order * factor || (indexById.get(b.id) || 0) - (indexById.get(a.id) || 0);
      });
    }
    function renderList() {
      // The list comes newest first; # counts from the oldest, as in HTTP history.
      indexById = new Map(records.map((record, position) => [record.id, records.length - position]));
      shown = sortedRecords().filter(record => !liveOnly || LIVE.has(record.status));
      const key = JSON.stringify([shown, selectedId, sort, liveOnly, shown.some(r => LIVE.has(r.status)) ? Math.floor(Date.now() / 1000) : 0]);
      if (key === listKey) return;
      listKey = key;
      const body = el("tcpHistoryRows");
      body.replaceChildren();
      for (const record of shown) {
        const row = document.createElement("tr");
        row.dataset.tcpId = record.id;
        row.classList.toggle("selected", record.id === selectedId);
        row.setAttribute("aria-selected", String(record.id === selectedId));
        const values = [indexById.get(record.id), record.local_port ? record.local_port : "—", record.target, record.peer, statusText(record), formatSize(record.client_bytes), formatSize(record.server_bytes), duration(record), formatTime(record.started_at)];
        values.forEach((value, column) => {
          const cell = document.createElement("td");
          if (column === 4) cell.className = "tcp-status tcp-status-" + record.status;
          cell.textContent = String(value);
          row.append(cell);
        });
        body.append(row);
      }
      if (!shown.length) {
        const row = document.createElement("tr"), cell = document.createElement("td");
        cell.colSpan = 9; cell.className = "tcp-empty";
        cell.textContent = records.length ? "No live connections" : "No TCP connections";
        row.append(cell); body.append(row);
      }
    }
    function chunkBlock(part) {
      const outbound = part.direction === "client_to_server";
      const block = document.createElement("div"), head = document.createElement("div"), bytes = document.createElement("pre");
      block.className = "tcp-chunk " + (outbound ? "tcp-chunk-out" : "tcp-chunk-in");
      head.className = "tcp-chunk-head";
      head.textContent = (outbound ? "→ " : "← ") + formatSize(part.bytes.length) + (part.at ? " · " + clock(part.at) : "");
      bytes.textContent = mode === "hex" ? formatHex(part.bytes, part.offset) : formatText(part.bytes);
      block.append(head, bytes);
      return block;
    }
    function streamMeta(record, error) {
      if (error) return error;
      return [
        formatSize(record.client_bytes) + " sent", formatSize(record.server_bytes) + " received",
        record.capture_truncated ? "Partial capture" : "",
        !LIVE.has(record.status) && !record.durable ? "Not saved" : ""
      ].filter(Boolean).join(" · ");
    }
    function renderDetail() {
      interceptController?.setConnection(detail);
      text("tcpStreamTitle", detail ? detail.target : "");
      const surface = el("tcpStreamBytes");
      if (!detail) {
        streamView = null;
        surface.replaceChildren();
        surface.textContent = selectedId ? "Loading…" : "Select a connection.";
        text("tcpStreamMeta", "");
        return;
      }
      const direction = el("tcpDirection").value;
      const view = { session: sessionId(), id: selectedId, direction, mode };
      const same = streamView && Object.keys(view).every(name => streamView[name] === view[name]);
      // Counters change on every poll of a live connection, and a capped capture
      // keeps relaying without new chunks: redraw only when the shown chunks did.
      const shownChunks = Array.isArray(detail.chunks) ? detail.chunks.filter(chunk => direction === "both" || chunk?.direction === direction) : null;
      if (same && streamView.chunks && sameChunks(streamView.chunks, shownChunks)) {
        text("tcpStreamMeta", streamMeta(detail, streamView.error));
        return;
      }
      // A live stream grows at its end: one that was scrolled to the end follows it.
      const atEnd = same && surface.scrollTop + surface.clientHeight >= surface.scrollHeight - 4;
      const scrollTop = surface.scrollTop;
      let parts = [], error = "";
      try { parts = conversation(detail, direction); } catch (failure) { error = failure.message; }
      surface.replaceChildren();
      surface.textContent = !error && !parts.length ? "No bytes captured" : "";
      for (const part of parts) surface.append(chunkBlock(part));
      if (same) surface.scrollTop = atEnd ? surface.scrollHeight : scrollTop;
      // Only a bounded copy is kept to compare with; a larger capture redraws.
      const cacheable = shownChunks && shownChunks.length <= MAX_CACHED_CHUNKS
        && shownChunks.reduce((sum, chunk) => sum + (typeof chunk?.data_base64 === "string" ? chunk.data_base64.length : Infinity), 0) <= MAX_CACHED_BASE64;
      streamView = { ...view, error, chunks: cacheable ? shownChunks.map(({ sequence, direction, offset, data_base64 }) => ({ sequence, direction, offset, data_base64 })) : null };
      text("tcpStreamMeta", streamMeta(detail, error));
    }
    async function loadDetail(stamp) {
      const id = selectedId, intent = selection;
      if (!id) return;
      const version = ++detailRequest;
      const owns = () => current(stamp) && selection === intent && id === selectedId && version === detailRequest;
      try {
        const result = await json(readPath("/api/tcp/connections/" + encodeURIComponent(id), stamp.session));
        if (owns()) {
          text("tcpHistoryError", "");
          const changed = JSON.stringify(detail) !== JSON.stringify(result);
          detail = result; if (changed) renderDetail();
        }
      } catch (error) { if (owns()) text("tcpHistoryError", error.message); }
    }
    async function select(id) {
      selectedId = id; selection++; detail = null; renderList(); renderDetail();
      const stamp = snapshot();
      try { await loadDetail(stamp); } catch (error) { if (current(stamp) && selectedId === id) text("tcpHistoryError", error.message); }
    }
    async function refresh() {
      if (writing) return;
      if (reading) return reading;
      void interceptController?.refresh();
      const stamp = snapshot();
      const pending = (async () => {
        try {
          const [nextStatus, nextRecords] = await Promise.all([json(readPath("/api/tcp/status", stamp.session)), json(readPath("/api/tcp/connections", stamp.session))]);
          if (!current(stamp)) return;
          status = nextStatus; records = nextRecords;
          interceptController?.reconcileConnections(records);
          // Saving may be recovered from another window; other errors stay.
          if (actionError?.action === "stop" && status.persistence_error === false) actionError = null;
          if (editing !== null && editing !== "new" && !listeners().some(listener => listener.id === editing)) editing = null;
          if (selectedId && !records.some(r => r.id === selectedId)) { selectedId = null; selection++; detail = null; renderDetail(); }
          renderStatus(); renderList(); text("tcpHistoryError", "");
          await loadDetail(stamp);
        } catch (error) {
          if (current(stamp)) { status = null; renderStatus(); text("tcpHistoryError", error.message); text("tcpSettingsError", error.message); }
        }
      })();
      reading = pending;
      try { await pending; } finally { if (reading === pending) reading = null; }
    }
    async function write(action, path, method, body) {
      if (writing || !status) return false;
      // Invalidate reads already in flight, and do not poll until the write settles.
      epoch++; reading = null; actionError = null; writing = true;
      const stamp = snapshot();
      renderStatus();
      let done = false;
      try {
        await json(writePath(path, stamp.session), { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body ?? {}) });
        done = true;
      } catch (error) {
        if (current(stamp)) actionError = { message: error.message, action };
      } finally {
        if (current(stamp)) { writing = false; await refresh(); renderStatus(); }
      }
      return done;
    }
    async function saveListener() {
      if (editing === null) return;
      let settings;
      try { settings = validateSettings(el("tcpLocalPort").value, el("tcpTargetHost").value, el("tcpTargetPort").value); }
      catch (error) { actionError = { message: error.message }; renderStatus(); return; }
      const existing = listeners().find(listener => listener.id === editing);
      const saved = editing === "new"
        ? await write("add", "/api/tcp/listeners", "POST", { enabled: true, settings })
        : await write("update", "/api/tcp/listeners/" + encodeURIComponent(editing), "PUT", { enabled: existing ? Boolean(existing.enabled) : true, settings });
      if (saved) closeForm();
    }
    async function toggleListener(id) {
      const listener = listeners().find(item => item.id === id);
      if (listener) await write("toggle", "/api/tcp/listeners/" + encodeURIComponent(id), "PUT", { enabled: !listener.enabled, settings: listener.settings });
    }
    async function removeListener() {
      if (editing === null || editing === "new") return;
      if (await write("remove", "/api/tcp/listeners/" + encodeURIComponent(editing), "DELETE")) closeForm();
    }
    function reset() {
      interceptController?.reset();
      epoch++; selection++; reading = null; writing = false; actionError = null; selectedId = null; detail = null; records = []; status = null; listKey = ""; editing = null;
      renderStatus(); renderList(); renderDetail(); text("tcpHistoryError", "");
    }
    function sortListenersBy(key) {
      listenerSort = listenerSort.key === key ? { key, direction: listenerSort.direction === "asc" ? "desc" : "asc" } : { key, direction: "asc" };
      for (const header of el("tcpListenerHead")?.querySelectorAll?.("[data-sort]") || []) {
        const active = header.dataset.sort === listenerSort.key;
        header.classList.toggle("active", active);
        header.setAttribute("aria-sort", active ? (listenerSort.direction === "asc" ? "ascending" : "descending") : "none");
        const indicator = header.querySelector(".table-sort-indicator");
        if (indicator) indicator.textContent = active ? (listenerSort.direction === "asc" ? "↑" : "↓") : "↕";
      }
      renderStatus();
    }
    function sortBy(key) {
      sort = sort.key === key ? { key, direction: sort.direction === "asc" ? "desc" : "asc" } : { key, direction: key === "index" || key === "started_at" ? "desc" : "asc" };
      for (const header of el("tcpHistoryHead")?.querySelectorAll?.("[data-sort]") || []) {
        const active = header.dataset.sort === sort.key;
        header.classList.toggle("active", active);
        header.setAttribute("aria-sort", active ? (sort.direction === "asc" ? "ascending" : "descending") : "none");
        const indicator = header.querySelector(".table-sort-indicator");
        if (indicator) indicator.textContent = active ? (sort.direction === "asc" ? "↑" : "↓") : "↕";
      }
      renderList();
    }
    function bindStackResizer() {
      const handle = el("tcpStackResizer"), workbench = el("tcpWorkbench");
      const list = workbench?.querySelector?.(".tcp-history");
      if (!handle?.addEventListener || !list) return;
      handle.addEventListener("dblclick", () => workbench.style.removeProperty("--tcp-list-height"));
      handle.addEventListener("mousedown", event => {
        event.preventDefault();
        const startY = event.clientY, start = list.getBoundingClientRect().height, room = workbench.getBoundingClientRect().height - 180;
        const onMove = move => workbench.style.setProperty("--tcp-list-height", Math.round(Math.max(120, Math.min(room, start + move.clientY - startY))) + "px");
        const onUp = () => {
          document.body.classList.remove("pane-resizing-y"); handle.classList.remove("active");
          document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp);
        };
        document.body.classList.add("pane-resizing-y"); handle.classList.add("active");
        document.addEventListener("mousemove", onMove); document.addEventListener("mouseup", onUp);
      });
    }
    el("tcpListenerForm").addEventListener("submit", event => { event.preventDefault(); void saveListener(); });
    el("tcpAddListener").addEventListener("click", () => openForm("new"));
    el("tcpCancelListener").addEventListener("click", closeForm);
    el("tcpRemoveListener").addEventListener("click", () => void removeListener());
    el("tcpRetrySaving").addEventListener("click", () => void write("stop", "/api/tcp/stop", "POST", {}));
    el("tcpListenerRows").addEventListener("click", event => {
      const toggle = event.target.closest?.("[data-listener-toggle]");
      if (toggle) { void toggleListener(toggle.dataset.listenerToggle); return; }
      const row = event.target.closest?.("tr[data-listener-id]");
      if (row) openForm(row.dataset.listenerId);
    });
    el("tcpListenerHead")?.addEventListener("click", event => {
      if (event.target.closest?.(".table-col-resize")) return;
      const header = event.target.closest?.("[data-sort]");
      if (header) sortListenersBy(header.dataset.sort);
    });
    // ↑/↓ move through the listeners while their list has focus.
    el("tcpListenerShell")?.addEventListener("keydown", event => {
      const step = arrowStep(event);
      if (!step || !shownListeners.length) return;
      const at = shownListeners.findIndex(listener => listener.id === editing);
      const next = at < 0 ? (step > 0 ? 0 : shownListeners.length - 1) : at + step;
      if (next < 0 || next >= shownListeners.length) return;
      event.preventDefault();
      openForm(shownListeners[next].id);
      el("tcpListenerShell").focus?.();
    });
    el("tcpOpenSettings").addEventListener("click", openSettings);
    el("tcpLiveOnly")?.addEventListener("click", () => {
      liveOnly = !liveOnly;
      el("tcpLiveOnly").classList.toggle("active", liveOnly);
      el("tcpLiveOnly").setAttribute("aria-pressed", String(liveOnly));
      renderList();
    });
    el("tcpHistoryRows").addEventListener("click", event => {
      const row = event.target.closest?.("tr[data-tcp-id]");
      if (row && row.dataset.tcpId !== selectedId) select(row.dataset.tcpId);
    });
    el("tcpHistoryHead")?.addEventListener("click", event => {
      if (event.target.closest?.(".table-col-resize")) return;
      const header = event.target.closest?.("[data-sort]");
      if (header) sortBy(header.dataset.sort);
    });
    // ↑/↓ move through the list, as in HTTP history; the app says when they
    // are free, not while a field has focus or a modal is open.
    document.addEventListener?.("keydown", event => {
      if (!visible() || !shown.length) return;
      const step = arrowStep(event);
      if (!step) return;
      const at = shown.findIndex(record => record.id === selectedId);
      const next = at < 0 ? (step > 0 ? 0 : shown.length - 1) : at + step;
      if (next < 0 || next >= shown.length) return;
      event.preventDefault();
      const id = shown[next].id;
      void select(id);
      Array.from(el("tcpHistoryRows").children).find(row => row.dataset.tcpId === id)?.scrollIntoView?.({ block: "nearest" });
    });
    el("tcpDirection").addEventListener("change", renderDetail);
    for (const view of ["hex", "text"]) el(view === "hex" ? "tcpHexView" : "tcpTextView").addEventListener("click", () => {
      mode = view;
      for (const [id, value] of [["tcpHexView", "hex"], ["tcpTextView", "text"]]) {
        el(id).classList.toggle("active", mode === value); el(id).setAttribute("aria-pressed", String(mode === value));
      }
      renderDetail();
    });
    bindStackResizer();
    return { refresh, reset, select };
  }
  function parseHex(value) {
    const compact = String(value).replace(/\s/g, "");
    if (!compact || !/^(?:[0-9a-fA-F]{2})+$/.test(compact)) throw new Error("Enter whole hex byte pairs. Drop removes the bytes.");
    if (compact.length > 32768) throw new Error("Pending bytes are limited to 16 KiB.");
    return Uint8Array.from(compact.match(/../g), pair => parseInt(pair, 16));
  }
  function rawHex(base64) { return Array.from(atob(base64), c => c.charCodeAt(0).toString(16).padStart(2, "0")).join(" "); }
  function createInterceptController({ document, sessionId, readPath, writePath, request, formatSize = byteSize, onChanged = () => {} }) {
    const el = id => document.getElementById(id), text = (id, value) => { el(id).textContent = value; };
    let generation = 0, version = 0, connection = null, policy = null, items = [], selected = null;
    let fresh = false, busy = false, tab = "stream", reading = null, historyKey = "", historyOwner = "", pickerKey = "", autoSelect = true;
    let actionFocus = null, originalOwner = "";
    // Store only operator edits, never original previews or resolved ranges. The
    // backend permits at most 32 live connections with two pending directions.
    // Keep headroom for unobserved external resolutions, but never evict an edit.
    const drafts = new Map(), maxDrafts = 128, maxDraftText = 64 * 1024;
    const EDIT_NOT_KEPT = "Edit not kept:";
    const draftKey = (id, pendingId) => JSON.stringify([id, pendingId]);
    const originalText = item => typeof item?.original_base64 === "string" ? rawHex(item.original_base64) : "";
    function selectedText(item) {
      if (typeof item.selected_base64 === "string") return rawHex(item.selected_base64);
      // Unchanged forwarding has no replacement payload. Only reuse complete,
      // explicitly unedited originals; missing evidence must not look accepted.
      return item.edited === false && item.preview_truncated === false && item.original_length > 0
        && item.original_length === item.selected_length && typeof item.original_base64 === "string"
        && atob(item.original_base64).length === item.original_length ? originalText(item) : "";
    }
    const editorText = item => !item ? "" : item.state === "pending"
      ? drafts.get(draftKey(connection?.id, item.pending_id))?.text ?? originalText(item)
      : item.state === "forwarding" ? selectedText(item) : "";
    function forgetConnection(id) {
      for (const [key, draft] of drafts) if (draft.connectionId === id) drafts.delete(key);
    }
    function reconcileConnections(records) {
      // Terminal status is monotonic. A zero pending count is not: an older list
      // response may have raced a new pending range, so it must not clear edits.
      for (const record of records) if (["closed", "stopped", "failed", "interrupted"].includes(record.status)) forgetConnection(record.id);
    }
    function saveDraft() {
      const item = chosen(), editor = el("tcpPendingHex");
      if (!fresh || busy || !LIVE.has(connection?.status) || item?.state !== "pending") return;
      const key = draftKey(connection.id, item.pending_id), value = editor.value;
      if (value === originalText(item)) { drafts.delete(key); if (actionError.startsWith(EDIT_NOT_KEPT)) showError(""); return; }
      if (value.length > maxDraftText || (!drafts.has(key) && drafts.size >= maxDrafts)) {
        editor.value = editorText(item);
        showError(value.length > maxDraftText
          ? EDIT_NOT_KEPT + " at most 16 KiB of bytes."
          : EDIT_NOT_KEPT + " too many unsent edits. Forward, drop or reset one first.");
        return;
      }
      drafts.set(key, {connectionId: connection.id, pendingId: item.pending_id, text: value});
      if (actionError.startsWith(EDIT_NOT_KEPT)) showError("");
    }
    let readError = "", actionError = "", closeWait = null, connectionEpoch = 0;
    function showError(message, kind = "action") {
      if (kind === "read") readError = message; else actionError = message;
      text("tcpInterceptError", actionError || readError);
    }
    function clearErrors() { readError = ""; showError(""); }
    const direction = value => value === "client_to_server" ? "Client → Server" : "Server → Client";
    const chosen = () => items.find(item => item.pending_id === selected);
    const stamp = () => ({ generation, session: sessionId() });
    const current = value => value.generation === generation && value.session === sessionId();
    // Disabling a focused native control moves focus to the document. Restore
    // only while this operation still owns it; any later navigation wins.
    const cancelActionFocus = () => { actionFocus = null; };
    for (const event of ["keydown", "pointerdown"]) document.addEventListener?.(event, cancelActionFocus, true);
    document.addEventListener?.("focusin", event => {
      if (actionFocus && event.target !== actionFocus.element) cancelActionFocus();
    }, true);
    function restoreActionFocus() {
      if (!actionFocus) return;
      const saved = actionFocus;
      if (!current(saved.token) || saved.owner !== connectionEpoch || saved.id !== connection?.id) { cancelActionFocus(); return; }
      if (busy || !fresh) return;
      let target = saved.element;
      // A resolved range must not leave focus on a now-unusable decision. The
      // picker is only a navigation target: new bytes remain unselected.
      if (target.disabled && ["forward", "drop"].includes(saved.action) && tab === "pending" &&
          (selected !== saved.pendingId || chosen()?.state !== "pending")) {
        target = selected === saved.pendingId && !el("tcpPendingHex").disabled ? el("tcpPendingHex")
          : el("tcpPendingPicker").disabled ? el("tcpPendingTab") : el("tcpPendingPicker");
      } else if (target.disabled && saved.action === "close" && !LIVE.has(connection?.status)) {
        target = el(tab === "pending" ? "tcpPendingTab" : "tcpStreamTab");
      }
      const active = document.activeElement;
      if (target.disabled || target.isConnected === false || target.closest?.("[hidden]") ||
          (document.hasFocus && !document.hasFocus()) ||
          (active !== saved.element && active !== document.body && active !== document.documentElement)) { cancelActionFocus(); return; }
      // Close acceptance can precede its terminal detail by several polls. Keep
      // ownership while waiting so that disabling Close later has a safe target.
      if (saved.action !== "close" || !closeWait || !LIVE.has(connection?.status)) cancelActionFocus();
      if (active !== target) target.focus({preventScroll: true});
    }
    async function json(path, options) {
      const response = await request(path, options);
      if (!response.ok) throw Object.assign(new Error(response.status === 409 ? "The bytes changed. Review them, then try again." : "TCP request failed (" + response.status + ")."), { status: response.status });
      return response.status === 204 ? null : response.json();
    }
    function render() {
      // Only the connection detail can settle a Close request. An empty pending
      // list or an accepted POST is not evidence that the connection ended.
      if (closeWait && closeWait.session === sessionId() && closeWait.id === connection?.id &&
          ["closed", "stopped", "failed", "interrupted"].includes(connection.status)) {
        closeWait = null;
        text("tcpInterceptNotice", "");
      }
      const item = chosen(), live = connection && LIVE.has(connection.status);
      el("tcpInterceptToggle").disabled = busy || !policy;
      el("tcpInterceptToggle").setAttribute("aria-checked", String(Boolean(policy?.enabled)));
      // Which direction to hold matters only while holding.
      el("tcpInterceptDirection").hidden = !policy?.enabled;
      el("tcpInterceptDirection").disabled = busy || !policy;
      el("tcpInterceptDirection").value = policy?.direction || "both";
      // The legacy pending total includes already-approved writes. Do not infer
      // global state from this connection's separately fetched pending items.
      const split = policy && Number.isInteger(policy.paused_count) && Number.isInteger(policy.forwarding_count) && policy.paused_count >= 0 && policy.forwarding_count >= 0 && policy.paused_count + policy.forwarding_count <= policy.pending_count;
      const unresolved = split ? policy.pending_count - policy.paused_count - policy.forwarding_count : 0;
      const state = !policy ? "" : !split ? (policy.pending_count ? policy.pending_count + " unresolved" : "")
        : [policy.paused_count ? policy.paused_count + " paused" : "", policy.forwarding_count ? policy.forwarding_count + " forwarding" : "", unresolved ? unresolved + " unresolved" : ""].filter(Boolean).join(" · ");
      text("tcpInterceptStatus", state);
      // Pending has a use only while holding, or while held bytes remain.
      el("tcpPendingTab").hidden = !(policy?.enabled || items.length);
      if (el("tcpPendingTab").hidden && tab === "pending") tab = "stream";
      text("tcpPendingTab", "Pending" + (items.length ? " " + items.length : ""));
      el("tcpStreamSurface").hidden = tab !== "stream";
      el("tcpPendingSurface").hidden = tab !== "pending";
      for (const [id, active] of [["tcpStreamTab", tab === "stream"], ["tcpPendingTab", tab === "pending"]]) {
        el(id).classList.toggle("active", active); el(id).setAttribute("aria-pressed", String(active));
      }
      for (const id of ["tcpDirection", "tcpHexView", "tcpTextView"]) el(id).hidden = tab !== "stream";
      const picker = el("tcpPendingPicker");
      const nextPickerKey = JSON.stringify([items.map(entry => [entry.pending_id, entry.sequence, entry.direction, entry.original_length, entry.state]), Boolean(selected)]);
      // Do not rebuild an unchanged native select while the operator is using it.
      if (pickerKey !== nextPickerKey) {
        pickerKey = nextPickerKey;
        picker.replaceChildren();
        if (!selected) { const option = document.createElement("option"); option.value = ""; option.textContent = items.length ? "Choose bytes" : "No pending bytes"; picker.append(option); }
        for (const entry of items) {
          const option = document.createElement("option"); option.value = entry.pending_id;
          option.textContent = "#" + entry.sequence + " · " + direction(entry.direction) + " · " + formatSize(entry.original_length) + (entry.state === "pending" ? "" : " · " + entry.state);
          picker.append(option);
        }
      }
      // A choice of one is no choice: the picker shows once a second range waits.
      picker.hidden = items.length < 2 && Boolean(selected || !items.length);
      picker.value = selected || ""; picker.disabled = picker.hidden || busy || !fresh || !items.length;
      const editable = Boolean(fresh && live && item?.state === "pending" && typeof item.original_base64 === "string" && !busy);
      const forwarding = item?.state === "forwarding", dropped = item?.state === "dropped";
      const editor = el("tcpPendingHex"), original = el("tcpPendingOriginal"), draft = editorText(item);
      const previewFocused = document.activeElement === editor || original.contains?.(document.activeElement);
      if (editor.value !== draft) editor.value = draft;
      editor.readOnly = !editable;
      editor.disabled = !editable && !(fresh && live && forwarding && draft && !busy);
      editor.setAttribute("aria-label", forwarding ? "Bytes being forwarded, as hex" : "Pending bytes as hex");
      editor.placeholder = !connection ? "Select a connection" : !fresh ? "Pending bytes unavailable"
        : forwarding ? "Preview unavailable" : dropped ? "Dropped"
        : item && item.state !== "pending" ? "Preview unavailable"
        : !item && items.length ? "Choose bytes" : "No pending bytes";
      const owner = item ? JSON.stringify([sessionId(), connection?.id, item.pending_id]) : "";
      original.hidden = !fresh || !live || !(forwarding || dropped);
      if (owner !== originalOwner || original.hidden) original.open = false;
      originalOwner = owner;
      const originalHex = el("tcpPendingOriginalHex"), originalValue = original.hidden ? "" : typeof item.original_base64 === "string" ? originalText(item) : "Preview unavailable";
      if (originalHex.textContent !== originalValue) originalHex.textContent = originalValue;
      for (const id of ["tcpForward", "tcpDrop", "tcpPendingReset"]) el(id).disabled = !editable;
      text("tcpForward", item?.direction === "server_to_client" ? "Forward to client" : "Forward to server");
      // Direction and size are in the picker once there is a choice; alone,
      // the range says them here.
      const range = item && picker.hidden ? direction(item.direction) + " · " + formatSize(item.original_length) + " · " : "";
      text("tcpPendingMeta", !connection || !fresh ? "" : !live ? "Connection ended" : item ? range + (item.state === "pending" ? "paused " + pausedDuration(item.received_at)
        : forwarding ? "forwarding" + (Number.isInteger(item.selected_length) ? " " + formatSize(item.selected_length) : "")
        : dropped ? "dropping" : "state unavailable") : "");
      el("tcpCloseConnection").disabled = busy || !live || !fresh;
      el("tcpPendingSurface").setAttribute("aria-busy", String(busy));
      if (previewFocused && !busy && editor.disabled && original.hidden && tab === "pending" &&
          (!document.hasFocus || document.hasFocus()) && !el("tcpPendingSurface").closest?.("[hidden]")) {
        (picker.disabled || !live ? el("tcpPendingTab") : picker).focus({preventScroll: true});
      }
      restoreActionFocus();
    }
    function renderHistory() {
      const events = [...(connection?.intercept_events || [])].sort((a, b) => a.sequence - b.sequence);
      const owner = JSON.stringify([sessionId(), connection?.id]);
      const key = JSON.stringify([owner, events, connection?.intercept_truncated]);
      if (key === historyKey) return;
      historyKey = key;
      const host = el("tcpInterceptHistory");
      const previous = owner === historyOwner ? Array.from(host.querySelectorAll("details")) : [];
      const opened = new Set(previous.filter(n => n.open).map(n => n.dataset.pendingId));
      const focused = previous.find(n => n.children[0] === document.activeElement)?.dataset.pendingId;
      const scrollTop = host.scrollTop, scrollLeft = host.scrollLeft;
      const sameOwner = owner === historyOwner;
      historyOwner = owner;
      let focusTarget = null;
      host.replaceChildren();
      const updateExpansion = () => host.classList.toggle("expanded", Array.from(host.children).some(row => row.open));
      for (const event of events) {
        const row = document.createElement("details"), summary = document.createElement("summary"), bytes = document.createElement("div");
        row.dataset.pendingId = event.pending_id; row.open = opened.has(event.pending_id);
        if (focused && event.pending_id === focused) focusTarget = summary;
        // Sizes say what changed: the edited size, and what reached the socket
        // when that fell short of it.
        summary.textContent = "Intercepted #" + event.sequence + " · " + direction(event.direction) + " · " + event.state + " · " + formatSize(event.original_length)
          + (event.edited || event.selected_length !== event.original_length ? " → " + formatSize(event.selected_length) : "")
          + (event.state === "forwarded" && event.written_bytes !== event.selected_length ? " · " + formatSize(event.written_bytes) + " written" : "");
        bytes.className = "tcp-event-bytes";
        const original = document.createElement("pre"), selected = document.createElement("pre");
        original.textContent = "Original\n" + (typeof event.original_base64 === "string" ? rawHex(event.original_base64) : "Preview unavailable");
        const unchanged = event.state === "forwarded" && event.edited === false && event.preview_truncated === false
          && typeof event.original_base64 === "string" && event.original_length > 0
          && event.original_length === event.selected_length && event.written_bytes === event.selected_length
          && atob(event.original_base64).length === event.original_length;
        const selectedPreview = typeof event.selected_base64 === "string" ? rawHex(event.selected_base64)
          : unchanged ? "Unchanged"
          : event.state === "dropped" && event.selected_length === 0 ? "Dropped"
          : "Preview unavailable";
        selected.textContent = "Sent\n" + selectedPreview;
        bytes.append(original); bytes.append(selected);
        row.addEventListener("toggle", updateExpansion);
        row.append(summary); row.append(bytes); host.append(row);
      }
      updateExpansion();
      if (connection?.intercept_truncated) { const note = document.createElement("p"); note.className = "tcp-event-note"; note.textContent = "Some intercepted bytes are missing."; host.append(note); }
      focusTarget?.focus({preventScroll: true});
      if (sameOwner) { host.scrollTop = scrollTop; host.scrollLeft = scrollLeft; }
    }
    async function refresh() {
      if (busy) return;
      if (reading) return reading;
      const token = stamp(), id = connection?.id, revision = ++version;
      const owns = () => current(token) && revision === version && id === connection?.id;
      const operation = (async () => {
        try {
          const [nextPolicy, pending] = await Promise.all([
            json(readPath("/api/tcp/intercept", token.session)),
            id ? json(readPath("/api/tcp/connections/" + encodeURIComponent(id) + "/pending", token.session)) : Promise.resolve({items: []})
          ]);
          if (!owns()) return;
          policy = nextPolicy; items = pending.items; fresh = true; showError("", "read");
          if (!items.some(item => item.pending_id === selected)) selected = autoSelect ? items[0]?.pending_id || null : null;
          // Once bytes have been presented, a replacement must be chosen explicitly,
          // including when another client resolved the previous pending item.
          if (selected) autoSelect = false;
          // Only this connection's successful, current response can retire its
          // drafts. Failed/stale reads and activity elsewhere preserve them.
          const pendingIds = new Set(items.filter(item => item.state === "pending").map(item => item.pending_id));
          for (const [key, draft] of drafts) if (draft.connectionId === id && !pendingIds.has(draft.pendingId)) drafts.delete(key);
          render();
        } catch (error) {
          if (owns()) { fresh = false; policy = null; showError(error.message, "read"); render(); }
        }
      })();
      reading = operation;
      try { await operation; } finally { if (reading === operation) reading = null; }
    }
    function setConnection(record) {
      const changed = connection?.id !== record?.id;
      connection = record;
      if (record) reconcileConnections([record]);
      if (changed) { connectionEpoch++; cancelActionFocus(); closeWait = null; autoSelect = true; version++; reading = null; fresh = false; items = []; selected = null; text("tcpInterceptNotice", ""); clearErrors(); }
      render(); renderHistory();
      if (changed) void refresh();
    }
    async function mutate(action) {
      if (busy || !policy) return;
      const item = chosen(), id = connection?.id;
      let path = "/api/tcp/intercept", method = "PUT", body;
      if (action === "policy" || action === "toggle") {
        body = { enabled: action === "toggle" ? !policy.enabled : policy.enabled, direction: el("tcpInterceptDirection").value, expected_revision: policy.revision };
      } else {
        if (!fresh || !connection || !LIVE.has(connection.status)) return;
        path = "/api/tcp/connections/" + encodeURIComponent(id);
        method = "POST";
        if (action === "close") path += "/close";
        else {
          if (!item || item.state !== "pending") return;
          path += "/pending/" + encodeURIComponent(item.pending_id) + "/decision";
          body = {action, expected_revision: item.revision};
          if (action === "forward") {
            try {
              const bytes = parseHex(el("tcpPendingHex").value);
              const encoded = btoa(String.fromCharCode(...bytes));
              if (encoded !== item.original_base64) body.replacement_base64 = encoded;
            } catch (error) { showError(error.message); return; }
          }
        }
      }
      if (action === "forward" || action === "drop") autoSelect = false;
      generation++; version++; reading = null; busy = true; fresh = false;
      const token = stamp(), owner = connectionEpoch;
      const trigger = el({toggle: "tcpInterceptToggle", policy: "tcpInterceptDirection", forward: "tcpForward", drop: "tcpDrop", close: "tcpCloseConnection"}[action]);
      actionFocus = document.activeElement === trigger ? {element: trigger, action, token, owner, id, pendingId: item?.pending_id} : null;
      closeWait = null; showError(""); text("tcpInterceptNotice", ""); render();
      try {
        await json(writePath(path, token.session), {method, headers:{"content-type":"application/json"}, ...(body ? {body:JSON.stringify(body)} : {})});
        if (current(token) && (action === "forward" || action === "drop")) {
          drafts.delete(draftKey(id, item.pending_id));
          if (action === "drop" && id === connection?.id && selected === item.pending_id) selected = null;
        }
        if (current(token) && owner === connectionEpoch && id === connection?.id) {
          closeWait = action === "close" ? {session: token.session, id} : null;
          text("tcpInterceptNotice", action === "close" ? "Closing…" : "");
        }
      } catch (error) {
        // Only a conflict says the decision was refused; any other failure may
        // have reached the socket, and the bytes are not sent again.
        if (current(token) && owner === connectionEpoch && id === connection?.id) showError(error.status === 409 ? error.message : error.message + " Outcome unknown; not retried.");
      } finally {
        if (current(token)) { busy = false; render(); await refresh(); onChanged(); }
      }
    }
    function reset() {
      generation++; version++; connectionEpoch++; cancelActionFocus(); closeWait = null; connection = null; policy = null; items = []; selected = null; fresh = false; busy = false; reading = null; historyKey = ""; historyOwner = ""; pickerKey = ""; drafts.clear(); tab = "stream"; autoSelect = true;
      clearErrors(); text("tcpInterceptNotice", ""); render(); renderHistory();
    }
    el("tcpInterceptToggle").addEventListener("click", () => mutate("toggle"));
    el("tcpInterceptDirection").addEventListener("change", () => mutate("policy"));
    el("tcpPendingPicker").addEventListener("change", () => { selected = el("tcpPendingPicker").value; autoSelect = false; showError(""); render(); });
    el("tcpPendingHex").addEventListener("input", saveDraft);
    el("tcpPendingReset").addEventListener("click", () => { const item = chosen(); if (item && !busy && fresh) { drafts.delete(draftKey(connection.id, item.pending_id)); showError(""); render(); } });
    for (const [id, action] of [["tcpForward", "forward"], ["tcpDrop", "drop"], ["tcpCloseConnection", "close"]]) el(id).addEventListener("click", () => mutate(action));
    for (const [id, next] of [["tcpStreamTab", "stream"], ["tcpPendingTab", "pending"]]) el(id).addEventListener("click", () => { tab = next; render(); });
    reset();
    return {refresh, reset, setConnection, reconcileConnections};
  }

  const api = { statusLabel, requestError, validateSettings, conversation, streamBytes, formatHex, formatText, parseHex, createInterceptController, createController };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.SniperTcpCapture = api;
})(typeof window === "undefined" ? globalThis : window);
