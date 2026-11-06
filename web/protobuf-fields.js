/* Explicit, read-only body inspection. This view does not own Replay drafts. */
(function (root) {
  "use strict";
  const MAX_BYTES = 1024 * 1024, PAGE = 200;
  function inspectMessage(message, decoder = root.SniperProtobufWire, format = "protobuf", messageIndex = 0) {
    if (!message) return { note: "No body available." };
    if (message.preview_truncated) return { note: "Body preview is truncated. Open the complete body before inspecting fields." };
    const body = String(message.body ?? message.body_preview ?? "");
    let bytes;
    if (message.body_encoding === "base64") {
      if (body.length > Math.ceil(MAX_BYTES / 3) * 4) return { note: "Fields inspection is limited to 1 MiB." };
      try {
        const raw = atob(body);
        bytes = Uint8Array.from(raw, ch => ch.charCodeAt(0));
      } catch (_) { return { note: "Invalid Base64 body. Use Raw to correct it." }; }
    } else {
      if (body.length > MAX_BYTES) return { note: "Fields inspection is limited to 1 MiB." };
      bytes = new TextEncoder().encode(body);
    }
    if (bytes.length > MAX_BYTES) return { note: "Fields inspection is limited to 1 MiB." };
    if (!decoder) return { note: "Selected inspector unavailable." };
    if (format === "grpc") {
      const contentTypes = (message.headers || []).filter(h => String(h.name).toLowerCase() === "content-type").map(h => String(h.value).split(";")[0].trim().toLowerCase());
      if (contentTypes.some(type => type.startsWith("application/grpc-web"))) return {note: "gRPC-Web is not supported by the native gRPC inspector. Use Raw or Hex."};
      const result = decoder.parse(bytes);
      if (!result.ok) return {note: `Cannot read gRPC envelope: ${result.error.code} at byte ${result.error.offset}. Raw and Hex are unchanged.`};
      const count = result.messages.length;
      const index = Number.isInteger(messageIndex) && messageIndex >= 0 && messageIndex < count ? messageIndex : 0;
      const envelope = result.messages[index];
      const model = {rows: [], bytes, size: bytes.length, messageCount: count, messageIndex: index};
      if (!envelope) return model;
      const payload = result.messageBytes(index);
      const types = (message.headers || []).filter(h => String(h.name).toLowerCase() === "content-type");
      const encoding = types.length === 1 ? decoder.classifyContentType(types[0].value) : null;
      if (!envelope.compressed && encoding === "proto") {
        let binary = ""; for (const byte of payload) binary += String.fromCharCode(byte);
        const inner = inspectMessage({body: btoa(binary), body_encoding: "base64"}, root.SniperProtobufWire);
        if (inner.note) model.payloadNote = inner.note;
        else model.rows = inner.rows.map(row => ({...row, offset: String(Number(row.offset) + envelope.payloadOffset)}));
      } else {
        const preview = Array.from(payload.subarray(0,24), b => b.toString(16).padStart(2,"0")).join(" ");
        model.rows = [{field: `Message ${index + 1}`, depth:0, wire: envelope.compressed ? "Compressed" : encoding === "json" ? "JSON" : "Bytes", value: `${preview}${payload.length>24?" …":""} (${payload.length} bytes) · opaque`, offset:String(envelope.payloadOffset), path:[index]}];
      }
      return model;
    }
    const result = decoder.inspect(bytes);
    if (!result.ok) return { note: `Cannot read ${format === "cbor" ? "CBOR" : format === "msgpack" ? "MessagePack" : "Protobuf wire"} fields: ${result.error.code} at byte ${result.error.offset}. Raw and Hex are unchanged.` };
    const rows = [];
    if (format === "cbor") {
      function walk(node, path, depth, editPath = [], blocked = false) {
        let value;
        if (node.type === "array" || node.type === "map") value = `${node.children.length / (node.type === "map" ? 2 : 1)} ${node.type === "map" ? "entries" : "items"}${node.indefinite ? " · indefinite" : ""}`;
        else if (node.type === "tag") value = `tag ${node.tag} · opaque`;
        else if (node.chunks) value = `${node.chunks.length} chunks · indefinite`;
        else if (node.type === "text") value = JSON.stringify(node.value.slice(0,160)) + (node.value.length > 160 ? " …" : "");
        else if (node.type === "bytes") {
          value = Array.from(bytes.subarray(node.dataOffset,node.dataOffset+Math.min(24,node.length)),b=>b.toString(16).padStart(2,"0")).join(" ") + (node.length>24?" …":"") + ` (${node.length} bytes)`;
        } else value = String(node.value);
        rows.push({path:[rows.length],editPath,keyBranch:blocked,scalarType:node.type,scalarValue:node.value,additionalInfo:node.additionalInfo,indefinite:Boolean(node.indefinite),valueOffset:node.dataOffset,valueLength:node.length ?? 0,field:path.length>200?`…${path.slice(-199)}`:path,fullPath:path,depth,wire:node.type,value,offset:String(node.offset)});
        if(node.children) node.children.forEach((child,i)=>walk(child,node.type==="map" ? `${path}[${Math.floor(i/2)}].${i%2?"value":"key"}` : `${path}[${i}]`,depth+1, [...editPath, {kind:node.type==="map"?"value":"item",index:node.type==="map"?Math.floor(i/2):i}], blocked || (node.type==="map" && i%2===0)));
        if(node.chunks) node.chunks.forEach((child,i)=>walk(child,`${path}.chunk[${i}]`,depth+1,[],true));
        if(node.child) walk(node.child,`${path}.tagged`,depth+1,[],true);
      }
      walk(result.value,"$",0);
      return {rows,size:bytes.length,bytes};
    }
    if (format === "msgpack") {
      function walk(node, path, depth, editPath = [], keyBranch = false) {
        let value;
        if (node.type === "array" || node.type === "map") value = `${node.length} ${node.type === "map" ? "entries" : "items"}`;
        else if (node.type === "string" && node.validUtf8) value = JSON.stringify(node.value.slice(0, 160)) + (node.value.length > 160 ? " …" : "");
        else if (node.dataOffset !== undefined) {
          const preview = Array.from(bytes.subarray(node.dataOffset, node.dataOffset + Math.min(24, node.byteLength)), b => b.toString(16).padStart(2,"0")).join(" ");
          value = `${node.type === "extension" ? `type ${node.extensionType} · opaque · ` : node.type === "string" ? "Invalid UTF-8 · " : ""}${preview}${node.byteLength > 24 ? " …" : ""} (${node.byteLength} bytes)`;
        } else value = String(node.value);
        rows.push({path: [rows.length], editPath, scalarType: node.type, scalarValue: node.value, marker: node.marker, keyBranch, valueOffset: node.dataOffset, valueLength: node.byteLength ?? 0, field: path.length > 200 ? `…${path.slice(-199)}` : path, fullPath: path, depth, wire: node.type, value, offset: String(node.offset)});
        if (node.items) node.items.forEach((child, i) => walk(child, `${path}[${i}]`, depth+1, [...editPath, {kind:"item",index:i}], keyBranch));
        if (node.entries) node.entries.forEach((entry, i) => { walk(entry.key, `${path}[${i}].key`, depth+1, [], true); walk(entry.value, `${path}[${i}].value`, depth+1, [...editPath, {kind:"value",index:i}], keyBranch); });
      }
      walk(result.root, "$", 0);
      return {rows, size:bytes.length, bytes};
    }
    function visit(fields, depth, prefix = []) {
      for (const [index, field] of fields.entries()) {
        const path = [...prefix, index];
        const value = field.value;
        const preview = Array.from(bytes.subarray(value.offset, value.offset + Math.min(24, value.length)), b => b.toString(16).padStart(2, "0")).join(" ");
        rows.push({ path, wireType: field.wireType, unsigned: field.unsigned, valueOffset: value.offset, valueLength: value.length, field: `#${field.number}`, depth, wire: ["VARINT", "FIXED64", "LEN", "GROUP", "END", "FIXED32"][field.wireType],
          value: field.wireType === 0 ? `${field.unsigned} (unsigned interpretation)` : `${preview}${value.length > 24 ? " …" : ""} (${value.length} bytes)`, offset: String(field.offset) });
        if (field.children) visit(field.children, depth + 1, path);
      }
    }
    visit(result.fields, 0);
    return { rows, size: bytes.length, bytes };
  }
  function formatFromMime(message) {
    const headers = message?.headers || [];
    const types = headers.filter(h => String(h.name).toLowerCase() === "content-type").map(h => String(h.value).split(";")[0].trim().toLowerCase());
    if (types.length !== 1) return "";
    if (["application/grpc", "application/grpc+proto", "application/grpc+json"].includes(types[0])) return "grpc";
    if (types[0] === "application/cbor") return "cbor";
    if (["application/msgpack", "application/x-msgpack"].includes(types[0])) return "msgpack";
    if (["application/protobuf", "application/x-protobuf"].includes(types[0])) return "protobuf";
    return "";
  }
  // Hex opens the way to Fields only for a body whose type does not say what
  // it is; a PDF, an image or JSON says, and Fields offered for one was noise.
  function untypedBody(message) {
    if (!(message?.body ?? message?.body_preview)) return false;
    const types = (message.headers || []).filter(h => String(h.name).toLowerCase() === "content-type")
      .map(h => String(h.value).split(";")[0].trim().toLowerCase());
    return types.every(type => ["", "application/octet-stream", "binary/octet-stream"].includes(type));
  }
  function showFieldsButton(source, target, message, open = false) {
    if (!source.owner || source.owner.type === "websocket") return false;
    return Boolean(open || formatFromMime(message) || (source.views?.[target] === "hex" && untypedBody(message)));
  }
  function editBlockReason(message, format = "protobuf") {
    if (!message || message.preview_truncated) return "A complete body is required.";
    const headers = message.headers || [];
    const values = name => headers.filter(h => String(h.name).toLowerCase() === name).map(h => String(h.value).trim().toLowerCase());
    if (values("content-encoding").some(v => v !== "identity")) return "Compressed bodies are read only.";
    const types = values("content-type");
    if (types.length !== 1 || formatFromMime(message) !== format || !["protobuf", "msgpack", "cbor"].includes(format)) return "Editing requires the matching explicit Protobuf, MessagePack or CBOR MIME. gRPC is not supported.";
    if (message.body_encoding !== "base64") return "Editing currently requires a Base64 body.";
    return "";
  }
  function editHint(row, msgpack, cbor = false) {
    if (cbor) {
      if(row.scalarType === "bool") return "true / false";
      const ai=row.additionalInfo, max=ai<24?23n:(1n<<BigInt(8*2**(ai-24)))-1n;
      if(row.scalarType === "uint") return `Decimal · 0–${max}`;
      if(row.scalarType === "negative") return `Decimal · ${-1n-max}–−1`;
      return `Hex · up to ${max>65536n?65536:max} bytes${row.scalarType === "text"?" · UTF-8":""}`;
    }
    if (!msgpack) return row.wireType === 0 ? "Unsigned decimal · 0–18446744073709551615" : row.wireType === 1 ? "Hex · 8 bytes" : row.wireType === 5 ? "Hex · 4 bytes" : "Hex · up to 65536 bytes";
    const m = row.marker;
    if (row.scalarType === "bool") return "true / false";
    if (["int", "uint"].includes(row.scalarType)) {
      if (m <= 127) return "Decimal · 0–127";
      if (m >= 224) return "Decimal · −32–−1";
      const signed = m >= 208, width = [1,2,4,8][m - (signed ? 208 : 204)], bits = BigInt(width * 8);
      const min = signed ? -(1n << (bits - 1n)) : 0n, max = signed ? (1n << (bits - 1n)) - 1n : (1n << bits) - 1n;
      return `Decimal · ${min}–${max}`;
    }
    const cap = m >= 160 && m <= 191 ? 31 : [196,217].includes(m) ? 255 : [197,218].includes(m) ? 65535 : 65536;
    return `Hex · up to ${cap} bytes${row.scalarType === "string" ? " · UTF-8" : ""}`;
  }
  function parseHex(value) {
    const text = value.replace(/\s/g, "");
    if (text.length > 65536 * 2 || text.length % 2 || !/^[0-9a-f]*$/i.test(text)) throw new Error("invalid-hex");
    return Uint8Array.from(text.match(/../g) || [], pair => parseInt(pair, 16));
  }
  // Scroll only this body pane: never move the page or opposite editor.
  // Instant positioning also respects reduced-motion preferences.
  function revealEditor(view, form, input) {
    input.focus?.({preventScroll:true});
    if (!view.getBoundingClientRect || !form.getBoundingClientRect) return;
    const viewport = view.getBoundingClientRect(), rect = form.getBoundingClientRect();
    const top = viewport.top + (view.clientTop || 0), height = view.clientHeight;
    if (!height) return;
    if (rect.height > height - 8 || rect.top < top + 4) view.scrollTop += rect.top - top - 4;
    else if (rect.bottom > top + height - 4) view.scrollTop += rect.bottom - top - height + 4;
  }
  let getSource = null, owner = null;
  const panes = {};
  function close(target) {
    const p = panes[target];
    if (!p) return;
    p.open = false;
    p.card.classList.remove("protobuf-fields-open");
    p.view.hidden = true;
    p.button.classList.remove("active");
    p.button.setAttribute("aria-pressed", "false");
  }
  function sync(restore = null) {
    if (!getSource) return;
    const source = getSource();
    if (owner !== source.owner) {
      Object.keys(panes).forEach(close);
      owner = source.owner;
      Object.values(panes).forEach(p => { p.format = ""; p.formatChosen = false; p.sourceKey = null; p.messageIndex = 0; });
    }
    for (const [target, p] of Object.entries(panes)) {
      let message, sourceError = false;
      try { message = source[target](); } catch (_) { sourceError = true; }
      p.button.hidden = !showFieldsButton(source, target, message, p.open);
      if (!p.open) continue;
      p.card.querySelectorAll(".replay-view-tab").forEach(b => b.classList.remove("active"));
      if (!p.formatChosen) p.format = formatFromMime(message);
      // Other pane redraws must not reset this inspector's page or scroll.
      const key = [source.owner, sourceError, message?.body ?? message?.body_preview ?? "",
        message?.body_encoding, Boolean(message?.preview_truncated), Boolean(message), source.revision, source.editable, source.requestText, p.format, p.messageIndex,
        JSON.stringify((message?.headers || []).map(h => [String(h.name).toLowerCase(), String(h.value)]))];
      if (p.sourceKey && key.every((value, index) => value === p.sourceKey[index])) continue;
      p.sourceKey = key;
      p.view.replaceChildren();
      const el = (tag, text) => { const node = document.createElement(tag); node.textContent = text; return node; };
      const summary = el("div", ""); summary.className = "protobuf-fields-summary";
      const editable = target === "request" && source.editable && source.applyFields && !editBlockReason(message, p.format) && (p.format === "cbor" ? root.SniperCborEditor : p.format === "msgpack" ? root.SniperMessagePackEditor : root.SniperProtobufEdit);
      const label = el("span", p.format === "protobuf" ? (editable ? "No schema" : "No schema · Read only") : p.format && !editable ? "Read only" : "");
      label.hidden = !label.textContent;
      label.title = editable ? "Wire types, not schema types. Unsigned varint and raw bytes only." : `Wire types, not schema types. ${target === "request" ? (editBlockReason(message) || "Select Raw, then Fields to enable explicit edits.") : "Responses are read only."}`;
      summary.append(label); p.view.append(summary);
      const select = el("select", ""); select.setAttribute("aria-label", "Body format");
      for (const [value, name] of [["", "Select format…"], ["protobuf", "Protobuf"], ["msgpack", "MessagePack"], ["cbor", "CBOR"], ["grpc", "gRPC"]]) { const option = el("option", name); option.value = value; select.append(option); }
      select.value = p.format;
      select.addEventListener("change", () => { p.format = ["msgpack", "protobuf", "cbor", "grpc"].includes(select.value) ? select.value : ""; p.formatChosen = true; p.messageIndex = 0; p.sourceKey = null; sync(); });
      
      if (p.format === "msgpack") label.title = "Ordered map entries. Extensions are opaque bytes, not decoded timestamps.";
      if (p.format === "cbor") label.title = "Tags are opaque. Duplicate keys and canonical encoding are not validated.";
      let model;
      if (sourceError) model = { note: "Cannot inspect this request draft. Check Raw; no fields were read from an older request." };
      else if (!p.format) { summary.append(select); continue; }
      else model = inspectMessage(message, p.format === "grpc" ? root.SniperGrpcEnvelope : p.format === "cbor" ? root.SniperCbor : p.format === "msgpack" ? root.SniperMessagePack : root.SniperProtobufWire, p.format, p.messageIndex);
      if (model.note) { summary.append(select); p.view.append(el("p", model.note)); continue; }
      if (p.format === "grpc") {
        label.textContent = "Read only · Envelope only";
        label.title = "No transport, streaming or trailer support is implied. Compressed payloads are opaque.";
        if (model.messageCount) {
          const pickerLabel = el("label", `Message / ${model.messageCount} `);
          const picker = el("input", ""); picker.type = "number"; picker.className = "grpc-message-picker"; picker.min = "1"; picker.max = String(model.messageCount); picker.step = "1"; picker.value = String(model.messageIndex + 1);
          picker.setAttribute("aria-label", "gRPC message"); picker.style.width = "6em";
          picker.addEventListener("change", () => {
            const n = Number(picker.value);
            if (!Number.isInteger(n) || n < 1 || n > model.messageCount) { picker.value = String(model.messageIndex + 1); return; }
            p.messageIndex = n - 1; p.sourceKey = null; sync();
          });
          pickerLabel.append(picker); summary.append(pickerLabel);
        }
        if (model.payloadNote) p.view.append(el("p", model.payloadNote));
      }
      const status = el("span", "");
      summary.append(status, select);
      const table = document.createElement("table"), head = document.createElement("thead"), hr = document.createElement("tr");
      for (const label of (p.format !== "protobuf" ? ["Path", "Type", "Value", "Offset"] : ["Field", "Wire", "Value", "Offset"])) hr.append(el("th", label));
      head.append(hr); table.append(head);
      const tbody = document.createElement("tbody"); table.append(tbody); p.view.append(table);
      const restoreIndex = restore?.target === target && restore.owner === source.owner
        ? model.rows.findIndex(row => row.path.length === restore.path.length && row.path.every((value, index) => value === restore.path[index])) : -1;
      let page = restoreIndex < 0 ? 0 : Math.floor(restoreIndex / PAGE);
      let restoredControl = null;
      const nav = document.createElement("div"), prev = el("button", "Previous"), next = el("button", "Next");
      prev.type = next.type = "button";
      function showPage() {
        tbody.replaceChildren();
        for (const row of model.rows.slice(page * PAGE, (page + 1) * PAGE)) {
          const tr = document.createElement("tr"), field = el("td", row.field);
          if (row.fullPath) { field.title = row.fullPath; field.setAttribute("aria-label", row.fullPath); }
          field.style.paddingLeft = `${8 + row.depth * 12}px`;
          const valueCell = el("td", row.value);
          if (editable && (p.format === "cbor" ? !row.keyBranch && !row.indefinite && ["uint","negative","bool","text","bytes"].includes(row.scalarType) : p.format === "msgpack" ? !row.keyBranch && ["uint","int","bool","string","binary"].includes(row.scalarType) : [0,1,2,5].includes(row.wireType)) && row.valueLength <= 65536) {
            const edit = el("button", "Edit"); edit.type = "button";
            edit.setAttribute("aria-label", `Edit ${row.field} as ${p.format !== "protobuf" ? row.scalarType : row.wireType === 0 ? "unsigned varint" : "raw hex"}`);
            valueCell.append(edit);
            if (restoreIndex >= 0 && row === model.rows[restoreIndex]) restoredControl = edit;
            edit.addEventListener("click", () => {
              const previousScroll = p.view.scrollTop;
              const format = p.format;
              const snapshot = {owner: source.owner, revision: source.revision, requestText: source.requestText, format};
              const msgpack = format === "msgpack", cbor = format === "cbor", scalar = msgpack || cbor, numeric = scalar ? ["int","uint","negative"].includes(row.scalarType) : row.wireType === 0, boolean = scalar && row.scalarType === "bool";
              const session = cbor ? root.SniperCborEditor.session(model.bytes) : msgpack ? root.SniperMessagePackEditor.session(model.bytes) : root.SniperProtobufEdit.createSession(model.bytes);
              const form = el("div", ""); form.className = "protobuf-field-edit";
              const hint = el("label", editHint(row, msgpack, cbor));
              const input = el("input", ""); input.type = "text";
              input.maxLength = numeric ? 21 : boolean ? 5 : 131072;
              input.value = scalar && (numeric || boolean) ? String(row.scalarValue) : row.wireType === 0 ? row.unsigned : Array.from(model.bytes.subarray(row.valueOffset, row.valueOffset + row.valueLength), b => b.toString(16).padStart(2, "0")).join("");
              input.setAttribute("aria-label", hint.textContent); hint.append(input);
              const apply = el("button", "Apply"), cancel = el("button", "Cancel"), error = el("span", "");
              apply.type = cancel.type = "button"; error.setAttribute("role", "alert");
              form.append(hint, apply, cancel, error); valueCell.replaceChildren(form);
              function dismiss() {
                valueCell.replaceChildren();
                valueCell.textContent = row.value;
                valueCell.append(edit);
                p.view.scrollTop = previousScroll;
                edit.focus?.({preventScroll:true});
              }
              cancel.addEventListener("click", dismiss);
              form.addEventListener("keydown", event => {
                if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); dismiss(); }
              });
              revealEditor(p.view, form, input);
              apply.addEventListener("click", () => {
                try {
                  const now = getSource();
                  if (now.owner !== snapshot.owner || now.revision !== snapshot.revision || now.requestText !== snapshot.requestText || !now.editable) throw new Error("stale-source");
                  const current = now.request();
                  if (p.format !== format || editBlockReason(current, format)) throw new Error("editing-blocked");
                  const currentModel = inspectMessage(current, cbor ? root.SniperCbor : msgpack ? root.SniperMessagePack : root.SniperProtobufWire, format);
                  if (!currentModel.bytes) throw new Error("invalid-source");
                  if (boolean && !["true","false"].includes(input.value)) throw new Error("invalid-boolean");
                  const operation = scalar ? (numeric ? {kind:"integer",value:input.value} : boolean ? {kind:"boolean",value:input.value === "true"} : {kind:"bytes",value:parseHex(input.value)}) : row.wireType === 0 ? {kind:"unsigned-varint", value:input.value} : {kind:"bytes", value:parseHex(input.value)};
                  const bytes = session.apply(currentModel.bytes, scalar ? row.editPath : row.path, operation);
                  now.applyFields(snapshot, bytes);
                  p.sourceKey = null;
                  sync({target, owner: snapshot.owner, path: row.path, scrollTop: previousScroll});
                } catch (e) { error.textContent = `Not applied: ${e.code || e.message || "invalid-value"}. Cancel and reopen to retry.`; }
              });
            });
          }
          tr.append(field, el("td", row.wire), valueCell, el("td", row.offset)); tbody.append(tr);
        }
        prev.disabled = page === 0; next.disabled = (page + 1) * PAGE >= model.rows.length;
        status.textContent = `${model.rows.length} ${model.rows.length === 1 ? "field" : "fields"} · ${model.size} bytes${model.rows.length > PAGE ? ` · ${page * PAGE + 1}–${Math.min((page + 1) * PAGE, model.rows.length)} shown` : ""}`;
      }
      prev.addEventListener("click", () => { if (page) { page--; showPage(); } });
      next.addEventListener("click", () => { if ((page + 1) * PAGE < model.rows.length) { page++; showPage(); } });
      nav.append(prev, next); if (model.rows.length > PAGE) p.view.append(nav);
      showPage();
      if (restoredControl) {
        p.view.scrollTop = restore.scrollTop;
        revealEditor(p.view, restoredControl, restoredControl);
      }
    }
  }
  function init(provider) {
    getSource = provider;
    document.querySelectorAll(".replay-fields-tab").forEach(button => {
      const target = button.dataset.fieldsTarget, card = button.closest(".panel-card");
      const view = document.createElement("div"); view.className = "protobuf-fields-view"; view.hidden = true;
      view.setAttribute("aria-label", `Replay ${target} binary fields`);
      card.append(view); panes[target] = { card, view, button, open: false, format: "", formatChosen: false };
      button.setAttribute("aria-pressed", "false");
      button.addEventListener("click", () => {
        const source = getSource();
        if (owner !== source.owner) { Object.keys(panes).forEach(close); owner = source.owner; Object.values(panes).forEach(p => { p.format = ""; p.formatChosen = false; p.sourceKey = null; p.messageIndex = 0; }); }
        if (!source.owner || source.owner.type === "websocket") return;
        const p = panes[target]; p.open = true;
        card.classList.add("protobuf-fields-open"); view.hidden = false;
        button.classList.add("active"); button.setAttribute("aria-pressed", "true"); sync();
      });
    });
    sync();
  }
  const api = { editHint, showFieldsButton, formatFromMime, inspectMessage, editBlockReason, parseHex, revealEditor, init, sync, close };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.SniperProtobufFields = api;
})(typeof globalThis !== "undefined" ? globalThis : window);
