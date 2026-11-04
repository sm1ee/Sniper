/* Read-only wire inspection. No schema/type guesses, traffic IO or re-encoding. */
(function (root) {
  "use strict";
  const limits = Object.freeze({ bytes: 1024 * 1024, fields: 10000, depth: 64 });
  function inspect(input) {
    if (!(input instanceof Uint8Array)) throw new TypeError("Expected Uint8Array");
    if (input.byteLength > limits.bytes) return { ok: false, fields: [], error: { code: "byte-limit", offset: 0 } };
    // Never retain the caller's mutable buffer or expose our original snapshot.
    const bytes = Uint8Array.from(input);
    let position = 0, count = 0;
    const fail = (code, offset = position) => { throw { code, offset }; };
    function varint() {
      const start = position;
      let value = 0n;
      for (let i = 0; i < 10; i++) {
        if (position >= bytes.length) fail("truncated-varint", start);
        const byte = bytes[position++];
        if (i === 9 && byte > 1) fail("varint-overflow", start);
        value |= BigInt(byte & 127) << BigInt(i * 7);
        if (!(byte & 128)) return value;
      }
      fail("varint-overflow", start);
    }
    function take(length) {
      if (length > bytes.length - position) fail("truncated-value");
      const offset = position;
      position += length;
      return { offset, length };
    }
    function message(depth, endGroup = null) {
      if (depth > limits.depth) fail("depth-limit");
      const fields = [];
      while (position < bytes.length) {
        const offset = position, key = varint();
        if (key > 0xffffffffn || key >> 3n === 0n) fail("invalid-field-number", offset);
        const number = Number(key >> 3n), wireType = Number(key & 7n);
        if (wireType === 4) {
          if (number !== endGroup) fail("unexpected-end-group", offset);
          return { fields, endTagOffset: offset };
        }
        if (++count > limits.fields) fail("field-limit", offset);
        const field = { number, wireType, offset, tagLength: position - offset };
        switch (wireType) {
          case 0: {
            const valueOffset = position;
            field.unsigned = varint().toString();
            field.value = { offset: valueOffset, length: position - valueOffset };
            break;
          }
          case 1: field.value = take(8); break;
          case 2: {
            const sizeOffset = position, length = varint();
            if (length > BigInt(bytes.length - position)) fail("truncated-value", sizeOffset);
            field.lengthPrefix = { offset: sizeOffset, length: position - sizeOffset };
            field.value = take(Number(length));
            break;
          }
          case 3: {
            const valueOffset = position, nested = message(depth + 1, number);
            field.children = nested.fields;
            field.value = { offset: valueOffset, length: nested.endTagOffset - valueOffset };
            break;
          }
          case 5: field.value = take(4); break;
          default: fail("invalid-wire-type", offset);
        }
        field.length = position - offset;
        fields.push(field);
      }
      if (endGroup !== null) fail("unclosed-group");
      return { fields };
    }
    let result;
    try { result = { ok: true, fields: message(0).fields }; }
    catch (error) {
      if (!error || typeof error.code !== "string") throw error;
      // Do not offer a partially decoded body as a valid message.
      result = { ok: false, fields: [], error };
    }
    return { ...result, byteLength: bytes.length, originalBytes: () => Uint8Array.from(bytes) };
  }
  const api = Object.freeze({ inspect, limits });
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.SniperProtobufWire = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
