/* Schema-less, explicit single-field edits; no IO or automatic type inference. */
(function(root) {
  "use strict";
  const wire = typeof module === "object" && module.exports ? require("./protobuf-wire.js") : root.SniperProtobufWire;
  function error(code) { const e = new Error(code); e.code = code; throw e; }
  function equal(a,b) { return a.length === b.length && a.every((v,i) => v === b[i]); }
  function encode(n) {
    const a = [];
    do { let b = Number(n & 127n); n >>= 7n; a.push(b | (n ? 128 : 0)); } while(n);
    return Uint8Array.from(a);
  }
  function join(...parts) {
    const n = parts.reduce((s,p) => s + p.length, 0);
    if(n > wire.limits.bytes) error("byte-limit");
    const out = new Uint8Array(n); let pos = 0;
    for(const p of parts) { out.set(p,pos); pos += p.length; }
    return out;
  }
  function parse(bytes) {
    const result = wire.inspect(bytes);
    if(!result.ok) error(result.error.code);
    return result.fields;
  }
  function createSession(input) {
    if(!(input instanceof Uint8Array)) error("invalid-input");
    if(input.length > wire.limits.bytes) error("byte-limit");
    const snapshot = Uint8Array.from(input); parse(snapshot);
    let consumed = false;
    function apply(current, path, operation) {
      if(consumed) error("session-consumed");
      if(!(current instanceof Uint8Array) || !equal(current,snapshot)) error("stale-source");
      if(!Array.isArray(path) || !path.length || path.length > wire.limits.depth ||
        path.some(i => !Number.isSafeInteger(i) || i < 0)) error("invalid-path");
      if(!operation || typeof operation !== "object") error("invalid-operation");
      // Parse fresh from private bytes. Never trust UI-owned field offsets/types.
      function change(bytes, level) {
        const fields = parse(bytes), field = fields[path[level]];
        if(!field) error("field-not-found");
        const start = field.value.offset, end = start + field.value.length;
        const old = bytes.slice(start,end);
        let next;
        if(level < path.length - 1) {
          // A LEN descent is an explicit user's message interpretation, not inference.
          if(field.wireType !== 2 && field.wireType !== 3) error("not-message");
          next = change(old,level + 1);
        } else if(operation.kind === "unsigned-varint") {
          if(field.wireType !== 0) error("wire-mismatch");
          if(typeof operation.value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(operation.value)) error("invalid-uint64");
          const n = BigInt(operation.value);
          if(n > 18446744073709551615n) error("invalid-uint64");
          if(n.toString() === field.unsigned) return bytes; // Preserve overlong encoding on no-op.
          next = encode(n);
        } else if(operation.kind === "bytes") {
          if(![1,2,5].includes(field.wireType)) error("wire-mismatch");
          if(!(operation.value instanceof Uint8Array)) error("invalid-bytes");
          if(operation.value.length > wire.limits.bytes) error("byte-limit");
          next = Uint8Array.from(operation.value);
          if(field.wireType !== 2 && next.length !== old.length) error("fixed-width");
        } else error("unsupported-operation");
        if(equal(old,next)) return bytes;
        let prefix = bytes.slice(field.offset,start);
        if(field.wireType === 2 && old.length !== next.length) {
          prefix = join(bytes.slice(field.offset,field.offset + field.tagLength), encode(BigInt(next.length)));
        }
        return join(bytes.slice(0,field.offset),prefix,next,bytes.slice(end));
      }
      const output = change(snapshot,0); parse(output);
      consumed = true;
      return Uint8Array.from(output);
    }
    return Object.freeze({ apply, originalBytes: () => Uint8Array.from(snapshot) });
  }
  const api = Object.freeze({ createSession });
  if(typeof module === "object" && module.exports) module.exports = api;
  else root.SniperProtobufEdit = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
