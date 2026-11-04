/* Read-only MessagePack inspection. No IO, encoding, or object-key coercion. */
(function (root) {
  'use strict';
  const limits = Object.freeze({ bytes: 1048576, nodes: 10000, depth: 64 });
  function inspect(input) {
    if (!(input instanceof Uint8Array)) throw new TypeError('Expected Uint8Array');
    if (input.length > limits.bytes) return { ok: false, error: { code: 'byte-limit', offset: 0 } };
    const bytes = Uint8Array.from(input), view = new DataView(bytes.buffer);
    let position = 0, count = 0;
    const fail = (code, offset = position) => { throw { code, offset }; };
    function take(n) {
      if (n > bytes.length - position) fail('truncated-value');
      const start = position; position += n; return start;
    }
    function uint(n) {
      const p = take(n);
      if (n === 1) return view.getUint8(p);
      if (n === 2) return view.getUint16(p);
      return view.getUint32(p);
    }
    function parse(depth) {
      const offset = position;
      if (depth > limits.depth) fail('depth-limit', offset);
      if (++count > limits.nodes) fail('node-limit', offset);
      const marker = uint(1), node = { offset, marker };
      function integer(n, signed) {
        node.type = signed ? 'int' : 'uint';
        if (!n) { node.value = String(signed ? marker - 256 : marker); return; }
        const p = take(n);
        const value = n === 8 ? (signed ? view.getBigInt64(p) : view.getBigUint64(p)) :
          n === 4 ? (signed ? view.getInt32(p) : view.getUint32(p)) :
          n === 2 ? (signed ? view.getInt16(p) : view.getUint16(p)) :
          signed ? view.getInt8(p) : view.getUint8(p);
        node.value = value.toString();
      }
      function payload(type, length, extension) {
        node.type = type;
        if (extension) node.extensionType = view.getInt8(take(1));
        node.dataOffset = take(length); node.byteLength = length;
        if (type === 'string') {
          try { node.value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(node.dataOffset, position)); node.validUtf8 = true; }
          catch { node.validUtf8 = false; } // Invalid UTF-8 remains a string wire type with bytes, never replacement text.
        }
      }
      function container(type, length) {
        node.type = type; node.length = length;
        const needed = type === 'map' ? length * 2 : length;
        if (needed > limits.nodes - count) fail('node-limit', offset);
        if (needed > bytes.length - position) fail('truncated-value');
        if (type === 'array') {
          node.items = [];
          for (let i = 0; i < length; i++) node.items.push(parse(depth + 1));
        } else {
          node.entries = [];
          for (let i = 0; i < length; i++) node.entries.push({ key: parse(depth + 1), value: parse(depth + 1) });
        }
      }
      if (marker <= 0x7f) integer(0, false);
      else if (marker >= 0xe0) integer(0, true);
      else if (marker >= 0xa0 && marker <= 0xbf) payload('string', marker & 31);
      else if (marker >= 0x90 && marker <= 0x9f) container('array', marker & 15);
      else if (marker >= 0x80 && marker <= 0x8f) container('map', marker & 15);
      else if (marker === 0xc0) { node.type = 'nil'; node.value = null; }
      else if (marker === 0xc1) fail('reserved-marker', offset);
      else if (marker === 0xc2 || marker === 0xc3) { node.type = 'bool'; node.value = marker === 0xc3; }
      else if (marker >= 0xc4 && marker <= 0xc6) payload('binary', uint([1,2,4][marker - 0xc4]));
      else if (marker >= 0xc7 && marker <= 0xc9) payload('extension', uint([1,2,4][marker - 0xc7]), true);
      else if (marker === 0xca || marker === 0xcb) {
        const width = marker === 0xca ? 4 : 8, p = take(width);
        node.type = width === 4 ? 'float32' : 'float64';
        const v = width === 4 ? view.getFloat32(p) : view.getFloat64(p);
        node.value = Object.is(v, -0) ? '-0' : String(v);
      }
      else if (marker >= 0xcc && marker <= 0xcf) integer([1,2,4,8][marker - 0xcc], false);
      else if (marker >= 0xd0 && marker <= 0xd3) integer([1,2,4,8][marker - 0xd0], true);
      else if (marker >= 0xd4 && marker <= 0xd8) payload('extension', [1,2,4,8,16][marker - 0xd4], true);
      else if (marker >= 0xd9 && marker <= 0xdb) payload('string', uint([1,2,4][marker - 0xd9]));
      else if (marker === 0xdc || marker === 0xdd) container('array', uint(marker === 0xdc ? 2 : 4));
      else if (marker === 0xde || marker === 0xdf) container('map', uint(marker === 0xde ? 2 : 4));
      node.end = position;
      return node;
    }
    try {
      const value = parse(0);
      if (position !== bytes.length) fail('trailing-data');
      return { ok: true, root: value, nodeCount: count, byteLength: bytes.length, originalBytes: () => bytes.slice() };
    } catch (error) {
      if (!error || typeof error.code !== 'string') throw error;
      return { ok: false, error, originalBytes: () => bytes.slice() };
    }
  }
  const api = Object.freeze({ inspect, limits });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.SniperMessagePack = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
