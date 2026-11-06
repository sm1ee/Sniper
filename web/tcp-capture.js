(function (root) {
  "use strict";
  const LIVE = new Set(["connecting", "open"]);
  const FAILURE_LABELS = new Map([
    ["resolution_timeout", "Name lookup timed out"], ["resolution_failed", "Name lookup failed"],
    ["connect_timeout", "Connection timed out"], ["connection_refused", "Connection refused"],
    ["connect_failed", "Connection failed"], ["self_target", "Target is this listener"],
    ["relay_failed", "Stream interrupted"], ["storage_failed", "History storage failed"]
  ]);
  function statusLabel(record) {
    const reason = record.status === "failed" ? FAILURE_LABELS.get(record.failure) : null;
    return reason ? "failed · " + reason : record.status;
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
      if (response.status !== 400) return fallback;
      if (/^Local port [0-9]{1,5} is already in use\. Choose another Local port or stop the listener using it\.$/.test(message)
        || /^Could not bind local port [0-9]{1,5}\. Check the port and local permissions\.$/.test(message)
        || message === "Enter a hostname or IP address without a port; use Target port separately."
        || message === "invalid target host" || message === "ports must be 1–65535") return message;
    } catch (_) {}
    return fallback;
  }
  function streamBytes(record, direction) {
    const chunks = (record.chunks || []).filter(chunk => chunk.direction === direction);
    let length = 0;
    const parts = chunks.map(chunk => {
      if (chunk.offset !== length) throw new Error("Captured stream has a gap. Complete bytes are unavailable.");
      const raw = atob(chunk.data_base64);
      length += raw.length;
      if (length > 256 * 1024) throw new Error("Captured stream exceeds the display limit.");
      return Uint8Array.from(raw, char => char.charCodeAt(0));
    });
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.length; }
    return bytes;
  }
  function formatHex(bytes) {
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const row = Array.from(bytes.subarray(i, i + 16));
      lines.push(i.toString(16).padStart(8, "0") + "  " + row.map(b => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ") + "  " + row.map(b => b >= 32 && b <= 126 ? String.fromCharCode(b) : ".").join(""));
    }
    return lines.join("\n");
  }
  function formatText(bytes) {
    // A projection only: replacement glyphs and escaped controls are never writable.
    return new TextDecoder("utf-8").decode(bytes).replace(/[\x00-\x08\x0b-\x1f\x7f]/g, c => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0"));
  }
  function timestamp(value) {
    const date = new Date(value);
    return Number.isFinite(date.getTime()) ? date.toLocaleTimeString([], { hour12: false }) : "—";
  }
  function duration(record) {
    // Interrupted records have no known end time. Only live streams age with now.
    if (!record.ended_at && !LIVE.has(record.status)) return "—";
    const start = Date.parse(record.started_at), end = record.ended_at ? Date.parse(record.ended_at) : Date.now();
    return Number.isFinite(start) && Number.isFinite(end) ? (Math.max(0, end - start) / 1000).toFixed(1) + " s" : "—";
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
  function createController({ document, sessionId, readPath, writePath, request, openSettings, intercept = false }) {
    const interceptController = intercept ? createInterceptController({ document, sessionId, readPath, writePath, request, onChanged: () => refresh() }) : null;
    const el = id => document.getElementById(id);
    let epoch = 0, selection = 0, detailRequest = 0, selectedId = null, detail = null, records = [], status = null;
    let reading = null, writing = false, mode = "hex", listKey = "", actionError = null, streamView = null;
    const text = (id, value) => { if (el(id).textContent !== value) el(id).textContent = value; };
    const snapshot = () => ({ epoch, session: sessionId() });
    const current = stamp => stamp.epoch === epoch && stamp.session === sessionId();
    async function json(path, options) {
      const response = await request(path, options);
      if (!response.ok) throw new Error(await requestError(response));
      return response.json();
    }
    function matchesSettings(actual, expected) {
      if (!actual || typeof actual.target_host !== "string" || actual.local_port !== expected.local_port || actual.target_port !== expected.target_port) return false;
      // Rust and URL spell IPv4-mapped IPv6 addresses differently. Compare
      // both hosts using the same syntax-only parser used for the request.
      try { return validateSettings(actual.local_port, actual.target_host, actual.target_port).target_host === expected.target_host; }
      catch (_) { return false; }
    }
    function renderStatus() {
      const enabled = Boolean(status?.enabled);
      const unavailable = !status || writing;
      // Status and rows are separate snapshots. History only grows within a
      // session, so a newer list at the cap must not still look accepting.
      const count = Math.max(status?.history_count || 0, records.length);
      const full = Boolean(status && status.history_limit > 0 && count >= status.history_limit);
      const storageError = Boolean(status?.load_error || status?.persistence_error);
      const blocked = storageError ? "New connections blocked (storage unavailable)"
        : full ? "New connections blocked (" + count + "/" + status.history_limit + ")"
        : enabled && status.active_limit > 0 && status.active_count >= status.active_limit
          ? "At connection limit (" + status.active_count + "/" + status.active_limit + ") · New connections wait. Close an unneeded connection to free a slot." : "";
      const listener = status ? (enabled ? "Listener on" : "Listener off") + (blocked ? " · " + blocked : "") : "Listener unavailable";
      for (const id of ["tcpLocalPort", "tcpTargetHost", "tcpTargetPort"]) el(id).disabled = unavailable || enabled;
      el("tcpStart").disabled = unavailable || enabled || storageError || full;
      el("tcpStop").disabled = unavailable || (!enabled && !status?.persistence_error);
      text("tcpStop", !enabled && status?.persistence_error ? "Retry saving" : "Stop");
      text("tcpListenerStatus", status ? blocked ? listener : enabled ? "Listening on 127.0.0.1:" + status.settings?.local_port : "Stopped" : "Unavailable");
      if (enabled && status.settings) {
        el("tcpLocalPort").value = status.settings.local_port;
        el("tcpTargetHost").value = status.settings.target_host;
        el("tcpTargetPort").value = status.settings.target_port;
      }
      const warning = status?.persistence_error
        ? "TCP history is not saved. Keep Sniper open, restore storage, then choose " + (enabled ? "Stop" : "Retry saving") + ". New connections are blocked."
        : storageError ? "TCP history storage is unavailable. New connections are blocked."
        : full ? "History full. Session → New session, then start TCP in Capture Settings. Switching sessions closes existing TCP connections; pending bytes are not forwarded. History is retained." : "";
      text("tcpSettingsError", actionError?.message || warning);
      const pending = records.reduce((total, record) => total + (record.pending_count || 0), 0);
      text("tcpHistoryStatus", records.length + " connections" + (pending ? " · " + pending + " active intercepts" : "") + " · " + listener + (warning ? " · " + warning : ""));
    }
    function renderList() {
      const filter = el("tcpStateFilter").value;
      const shown = records.filter(r => filter === "all" || (filter === "live" ? LIVE.has(r.status) : !LIVE.has(r.status)));
      const key = JSON.stringify([shown, records.length, filter, selectedId, shown.some(r => LIVE.has(r.status)) ? Math.floor(Date.now() / 1000) : 0]);
      if (key === listKey) return;
      listKey = key;
      const body = el("tcpHistoryRows");
      const focused = document.activeElement?.dataset?.tcpId;
      body.replaceChildren();
      for (const record of shown) {
        const row = document.createElement("tr");
        row.classList.toggle("selected", record.id === selectedId);
        for (const value of [record.target, record.peer, statusLabel(record) + (record.pending_count ? " · " + record.pending_count + " active intercepts (" + (record.pending_directions || []).map(d => d === "client_to_server" ? "C→S" : "S→C").join(", ") + ")" : ""), record.client_bytes + " B", record.server_bytes + " B", duration(record), timestamp(record.started_at), ((record.capture_truncated || record.intercept_truncated) ? "Partial · " : "") + (LIVE.has(record.status) ? "Live · memory" : record.durable ? "Saved" : "Not saved")]) {
          const cell = document.createElement("td");
          if (!row.children.length) {
            const button = document.createElement("button");
            button.type = "button"; button.className = "tcp-row-target"; button.textContent = value;
            button.dataset.tcpId = record.id;
            button.setAttribute("aria-pressed", String(record.id === selectedId));
            button.setAttribute("aria-label", "Open TCP stream to " + record.target);
            button.addEventListener("click", () => select(record.id));
            cell.append(button);
          } else cell.textContent = value;
          row.append(cell);
        }
        body.append(row);
      }
      if (!shown.length) {
        const row = document.createElement("tr"), cell = document.createElement("td");
        cell.colSpan = 8; cell.textContent = records.length
          ? "No " + (filter === "live" ? "live" : "closed") + " TCP connections. Choose All states to view history."
          : "No TCP connections. Configure a listener in Capture Settings.";
        row.append(cell); body.append(row);
      }
      if (focused) Array.from(body.querySelectorAll("button")).find(button => button.dataset.tcpId === focused)?.focus({preventScroll: true});
    }
    function renderDetail() {
      interceptController?.setConnection(detail);
      text("tcpStreamTitle", detail ? detail.target + " · " + statusLabel(detail) : "Stream");
      if (!detail) { streamView = null; text("tcpStreamBytes", selectedId ? "Loading stream…" : "Select a connection."); text("tcpStreamMeta", "Read-only capture. TCP chunks are not protocol messages."); return; }
      const direction = el("tcpDirection").value, session = sessionId();
      let chunks;
      try { chunks = (detail.chunks || []).filter(chunk => chunk.direction === direction); }
      catch (error) {
        streamView = null; text("tcpStreamBytes", ""); text("tcpStreamMeta", "Captured stream is malformed. Complete bytes are unavailable."); return;
      }
      // Compare exact source fields, not counters or a lossy hash. A capped stream
      // can keep receiving traffic without its captured bytes changing.
      const same = streamView?.cacheable && streamView.session === session && streamView.id === selectedId && streamView.direction === direction && streamView.mode === mode &&
        streamView.chunks.length === chunks.length && chunks.every((chunk, i) => chunk.offset === streamView.chunks[i].offset && chunk.data_base64 === streamView.chunks[i].data_base64);
      if (!same) {
        let length = 0, error = "", display;
        try {
          const bytes = streamBytes(detail, direction);
          length = bytes.length;
          display = length ? mode === "hex" ? formatHex(bytes) : formatText(bytes) : "No captured bytes in this direction.";
        } catch (failure) { error = failure.message; display = ""; }
        // Keep one bounded snapshot only, including offsets so a new gap cannot
        // reuse a valid display. Never retain prior connections or rendered text.
        const cacheable = chunks.length <= 1024 && chunks.reduce((sum, chunk) => sum + (typeof chunk.data_base64 === "string" ? chunk.data_base64.length : 512 * 1024 + 1), 0) <= 512 * 1024;
        streamView = { session, id: selectedId, direction, mode, length, error, cacheable, chunks: cacheable ? chunks.map(chunk => ({ offset: chunk.offset, data_base64: chunk.data_base64 })) : [] };
        el("tcpStreamBytes").textContent = display;
      }
      text("tcpStreamMeta", streamView.error || streamView.length + " captured bytes in this direction" + (detail.capture_truncated ? " · Partial capture; later bytes are unavailable" : "") + (LIVE.has(detail.status) ? " · Live bytes are not saved until close" : !detail.durable ? " · Not durably saved" : " · Saved") + (mode === "text" ? " · UTF-8 display only; invalid bytes use replacement characters" : "") + " · Read-only");
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
          // A different window may recover this operation. Match the failed
          // request, not the editable form or just any running listener, and
          // retain validation, session-conflict and unrelated request errors.
          const attempted = actionError?.action === "start" ? actionError.settings : null;
          const recoveredBind = attempted && status.enabled === true &&
            matchesSettings(status.settings, attempted) &&
            (actionError.message === "Local port " + attempted.local_port + " is already in use. Choose another Local port or stop the listener using it." ||
              actionError.message === "Could not bind local port " + attempted.local_port + ". Check the port and local permissions.");
          const recoveredPersistence = actionError?.action === "stop" && status.persistence_error === false &&
            /^TCP capture stopped, but [0-9]{1,8} connection record\(s\) are not saved\. Keep Sniper open, restore storage, then retry saving\.$/.test(actionError.message);
          if (recoveredBind || recoveredPersistence) actionError = null;
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
    async function mutate(action) {
      if (writing || !status) return;
      let body = {};
      try { if (action === "start") body = validateSettings(el("tcpLocalPort").value, el("tcpTargetHost").value, el("tcpTargetPort").value); }
      catch (error) { actionError = { message: error.message }; renderStatus(); return; }
      // Invalidate reads already in flight, and do not poll until the write settles.
      epoch++; reading = null; actionError = null; writing = true;
      const stamp = snapshot();
      renderStatus();
      try {
        await json(writePath("/api/tcp/" + action, stamp.session), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      } catch (error) {
        if (current(stamp)) actionError = { message: error.message, action, settings: body };
      } finally {
        if (current(stamp)) { writing = false; await refresh(); renderStatus(); }
      }
    }
    function reset() {
      interceptController?.reset();
      epoch++; selection++; reading = null; writing = false; actionError = null; selectedId = null; detail = null; records = []; status = null; listKey = "";
      el("tcpTargetHost").value = ""; el("tcpTargetPort").value = ""; el("tcpLocalPort").value = "9000";
      renderStatus(); renderList(); renderDetail(); text("tcpHistoryError", "");
    }
    el("tcpListenerForm").addEventListener("submit", event => { event.preventDefault(); mutate("start"); });
    el("tcpStop").addEventListener("click", () => mutate("stop"));
    el("tcpOpenSettings").addEventListener("click", openSettings);
    el("tcpStateFilter").addEventListener("change", renderList);
    el("tcpDirection").addEventListener("change", renderDetail);
    for (const view of ["hex", "text"]) el(view === "hex" ? "tcpHexView" : "tcpTextView").addEventListener("click", () => {
      mode = view;
      for (const [id, value] of [["tcpHexView", "hex"], ["tcpTextView", "text"]]) {
        el(id).classList.toggle("active", mode === value); el(id).setAttribute("aria-pressed", String(mode === value));
      }
      renderDetail();
    });
    return { refresh, reset, select };
  }
  function parseHex(value) {
    const compact = String(value).replace(/\s/g, "");
    if (!compact || !/^(?:[0-9a-fA-F]{2})+$/.test(compact)) throw new Error("Enter complete hexadecimal byte pairs. Use Drop bytes to remove this chunk.");
    if (compact.length > 32768) throw new Error("Pending bytes are limited to 16 KiB.");
    return Uint8Array.from(compact.match(/../g), pair => parseInt(pair, 16));
  }
  function rawHex(base64) { return Array.from(atob(base64), c => c.charCodeAt(0).toString(16).padStart(2, "0")).join(" "); }
  function createInterceptController({ document, sessionId, readPath, writePath, request, onChanged = () => {} }) {
    const el = id => document.getElementById(id), text = (id, value) => { el(id).textContent = value; };
    let generation = 0, version = 0, connection = null, policy = null, items = [], selected = null;
    let fresh = false, busy = false, tab = "stream", reading = null, historyKey = "", historyOwner = "", pickerKey = "", autoSelect = true;
    let actionFocus = null, originalOwner = "";
    // Store only operator edits, never original previews or resolved ranges. The
    // backend permits at most 32 live connections with two pending directions.
    // Keep headroom for unobserved external resolutions, but never evict an edit.
    const drafts = new Map(), maxDrafts = 128, maxDraftText = 64 * 1024;
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
      if (value === originalText(item)) { drafts.delete(key); if (actionError.startsWith("This edit was not saved:")) showError(""); return; }
      if (value.length > maxDraftText || (!drafts.has(key) && drafts.size >= maxDrafts)) {
        editor.value = editorText(item);
        showError(value.length > maxDraftText
          ? "This edit was not saved: hexadecimal text is limited to 64 KiB (16 KiB of bytes). The previous draft is unchanged."
          : "This edit was not saved: the pending draft limit was reached. Resolve or reset another draft, then try again. Existing drafts are unchanged.");
        return;
      }
      drafts.set(key, {connectionId: connection.id, pendingId: item.pending_id, text: value});
      if (actionError.startsWith("This edit was not saved:")) showError("");
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
      if (!response.ok) throw new Error(response.status === 409 ? "TCP state changed. Review the refreshed bytes before retrying." : "TCP request failed (" + response.status + "). Refresh before retrying.");
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
      text("tcpInterceptToggle", "Intercept " + (policy?.enabled ? "on" : "off"));
      el("tcpInterceptToggle").setAttribute("aria-pressed", String(Boolean(policy?.enabled)));
      el("tcpInterceptDirection").disabled = busy || !policy;
      el("tcpInterceptDirection").value = policy?.direction || "both";
      // The legacy pending total includes already-approved writes. Do not infer
      // global state from this connection's separately fetched pending items.
      const split = policy && Number.isInteger(policy.paused_count) && Number.isInteger(policy.forwarding_count) && policy.paused_count >= 0 && policy.forwarding_count >= 0 && policy.paused_count + policy.forwarding_count <= policy.pending_count;
      const unresolved = split ? policy.pending_count - policy.paused_count - policy.forwarding_count : 0;
      const state = !policy ? "Intercept unavailable" : !split ? policy.pending_count + " unresolved"
        : [policy.paused_count ? policy.paused_count + " paused" : "", policy.forwarding_count ? policy.forwarding_count + " forwarding" : "", unresolved ? unresolved + " unresolved" : ""].filter(Boolean).join(" · ") || "0 pending";
      text("tcpInterceptStatus", state);
      text("tcpPendingTab", "Pending" + (items.length ? " (" + items.length + ")" : ""));
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
        if (!selected) { const option = document.createElement("option"); option.value = ""; option.textContent = items.length ? "Choose pending bytes" : "No pending bytes"; picker.append(option); }
        for (const entry of items) {
          const option = document.createElement("option"); option.value = entry.pending_id;
          option.textContent = "#" + entry.sequence + " · " + direction(entry.direction) + " · " + entry.original_length + " B · " + entry.state;
          picker.append(option);
        }
      }
      picker.value = selected || ""; picker.disabled = busy || !fresh || !items.length;
      const editable = Boolean(fresh && live && item?.state === "pending" && typeof item.original_base64 === "string" && !busy);
      const forwarding = item?.state === "forwarding", dropped = item?.state === "dropped";
      const editor = el("tcpPendingHex"), original = el("tcpPendingOriginal"), draft = editorText(item);
      const previewFocused = document.activeElement === editor || original.contains?.(document.activeElement);
      if (editor.value !== draft) editor.value = draft;
      editor.readOnly = !editable;
      editor.disabled = !editable && !(fresh && live && forwarding && draft && !busy);
      editor.setAttribute("aria-label", forwarding ? "Selected raw hexadecimal bytes, delivery not confirmed" : "Pending raw hexadecimal bytes");
      editor.placeholder = !connection ? "Select a connection." : !fresh ? "Pending state unavailable."
        : forwarding ? "Selected byte preview unavailable." : dropped ? "Dropped; no bytes selected."
        : item && item.state !== "pending" ? "Byte preview unavailable."
        : !item && items.length ? "Choose pending bytes." : "No pending bytes.";
      const owner = item ? JSON.stringify([sessionId(), connection?.id, item.pending_id]) : "";
      original.hidden = !fresh || !live || !(forwarding || dropped);
      if (owner !== originalOwner || original.hidden) original.open = false;
      originalOwner = owner;
      const originalHex = el("tcpPendingOriginalHex"), originalValue = original.hidden ? "" : typeof item.original_base64 === "string" ? originalText(item) : "Original byte preview unavailable.";
      if (originalHex.textContent !== originalValue) originalHex.textContent = originalValue;
      for (const id of ["tcpForward", "tcpDrop", "tcpPendingReset"]) el(id).disabled = !editable;
      text("tcpForward", item?.direction === "server_to_client" ? "Forward to client" : "Forward to server");
      text("tcpPendingMeta", !connection ? "Select a connection." : !fresh ? "Pending state unavailable." : !live ? "Connection ended. No bytes can be forwarded." : item ? item.original_length + " original bytes · " + (item.state === "pending" ? "Paused " + pausedDuration(item.received_at) + " · Not sent"
        : forwarding ? item.selected_length + " selected · Forwarding; delivery not confirmed"
        : dropped ? "Drop accepted; waiting for final state" : "State unavailable; delivery not confirmed") : items.length ? "Choose pending bytes to review before forwarding." : "No pending bytes.");
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
        summary.textContent = "#" + event.sequence + " " + direction(event.direction) + " · " + event.state + " · " + event.original_length + " original → " + event.selected_length + " selected · " + event.written_bytes + " B written";
        bytes.className = "tcp-event-bytes";
        const original = document.createElement("pre"), selected = document.createElement("pre"), note = document.createElement("p");
        original.textContent = "Original · received offset " + event.original_offset + "\n" + (typeof event.original_base64 === "string" ? rawHex(event.original_base64) : "Preview unavailable");
        const unchanged = event.state === "forwarded" && event.edited === false && event.preview_truncated === false
          && typeof event.original_base64 === "string" && event.original_length > 0
          && event.original_length === event.selected_length && event.written_bytes === event.selected_length
          && atob(event.original_base64).length === event.original_length;
        const selectedPreview = typeof event.selected_base64 === "string" ? rawHex(event.selected_base64)
          : unchanged ? "Unchanged\n" + rawHex(event.original_base64)
          : event.state === "dropped" && event.selected_length === 0 ? "Dropped; no bytes selected."
          : "Selected byte preview unavailable.";
        selected.textContent = "Selected · destination offset " + event.destination_offset + "\n" + selectedPreview;
        note.className = "tcp-event-note";
        note.textContent = "Written = socket accepted, not peer application acknowledged.";
        bytes.append(original); bytes.append(selected);
        row.addEventListener("toggle", updateExpansion);
        row.append(summary); row.append(bytes); row.append(note); host.append(row);
      }
      updateExpansion();
      if (connection?.intercept_truncated) { const note = document.createElement("p"); note.textContent = "Partial intercept history; some events or byte previews are unavailable."; host.append(note); }
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
          text("tcpInterceptNotice", action === "close" ? "Close requested. Waiting for final state." : action === "forward" ? "Forward accepted; delivery not confirmed. Check Stream for written bytes." : action === "drop" ? "Drop accepted. Check Stream for final state." : "");
        }
      } catch (error) {
        if (current(token) && owner === connectionEpoch && id === connection?.id) showError(error.message + " The outcome may be uncertain; no automatic retry was sent.");
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

  const api = { statusLabel, requestError, validateSettings, streamBytes, formatHex, formatText, parseHex, createInterceptController, createController };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.SniperTcpCapture = api;
})(typeof window === "undefined" ? globalThis : window);
