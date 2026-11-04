const test = require("node:test"), assert = require("node:assert/strict");
const { createSession } = require("../web/protobuf-edit.js");
const b = (...xs) => Uint8Array.from(xs);
const edit = (source,path,op) => createSession(source).apply(source,path,op);
const uint = value => ({kind:"unsigned-varint",value});
const raw = value => ({kind:"bytes",value});
test("order and duplicate occurrence stay exact", () => {
 const src=b(0x88,0,0x81,0,8,2,0x12,1,65,8,3);
 assert.deepEqual(edit(src,[1],uint("128")),b(0x88,0,0x81,0,8,0x80,1,0x12,1,65,8,3));
});
test("no-op preserves noncanonical key/value/length", () => {
 for(const [src,op] of [[b(0x88,0,0x81,0),uint("1")],[b(0x92,0,0x81,0,65),raw(b(65))]])
 assert.deepEqual(edit(src,[0],op),src);
});
test("same-length edit preserves overlong length and tag", () =>
 assert.deepEqual(edit(b(0x92,0,0x81,0,65),[0],raw(b(66))),b(0x92,0,0x81,0,66)));
test("different length rewrites length only, preserving overlong tag", () =>
 assert.deepEqual(edit(b(0x92,0,0x81,0,65),[0],raw(b(66,67))),b(0x92,0,2,66,67)));
test("nested LEN propagates length up chain", () =>
 assert.deepEqual(edit(b(10,4,18,2,8,1,24,4),[0,0,0],uint("128")),b(10,5,18,3,8,128,1,24,4)));
test("group tags and other fields preserved", () =>
 assert.deepEqual(edit(b(11,8,1,12,16,5),[0,0],uint("128")),b(11,8,128,1,12,16,5)));
test("fixed32/64 are exact byte operations", () => {
 for(const [key,size] of [[13,4],[9,8]]) {
 const src=b(key,...Array(size).fill(0));
 assert.deepEqual(edit(src,[0],raw(b(...Array(size).fill(255)))),b(key,...Array(size).fill(255)));
 assert.throws(()=>edit(src,[0],raw(b(1))),/fixed-width/);
 }
});
test("uint64 maximal exact decimal", () =>
 assert.deepEqual(edit(b(8,1),[0],uint("18446744073709551615")),b(8,...Array(9).fill(255),1)));
test("reject ambiguous or invalid numbers", () => {
 for(const value of ["-1","1.5","01","1e2","","18446744073709551616",2,1n])
 assert.throws(()=>edit(b(8,1),[0],uint(value)),/invalid-uint64/);
});
test("reject wire mismatch and unsupported guesses", () => {
 assert.throws(()=>edit(b(10,0),[0],uint("1")),/wire-mismatch/);
 assert.throws(()=>edit(b(8,1),[0],raw(b(2))),/wire-mismatch/);
 assert.throws(()=>edit(b(10,0),[0],{kind:"string",value:"abc"}),/unsupported-operation/);
});
test("bad path and explicit LEN traversal errors", () => {
 for(const p of [[],[-1],[0.5],[NaN],Array(65).fill(0)]) assert.throws(()=>edit(b(8,1),p,uint("1")),/invalid-path/);
 assert.throws(()=>edit(b(8,1),[2],uint("1")),/field-not-found/);
 assert.throws(()=>edit(b(8,1),[0,0],uint("1")),/not-message/);
 assert.throws(()=>edit(b(10,1,255),[0,0],uint("1")),/truncated-varint/);
});
test("stale input cannot overwrite raw edits; no session consume on failure", () => {
 const src=b(8,1), session=createSession(src);
 assert.throws(()=>session.apply(b(8,2),[0],uint("3")),/stale-source/);
 assert.deepEqual(session.apply(src,[0],uint("3")),b(8,3));
 assert.throws(()=>session.apply(src,[0],uint("4")),/session-consumed/);
});
test("snapshots and output do not alias source", () => {
 const src=b(8,1), session=createSession(src), snap=session.originalBytes();
 snap[1]=5; src[1]=6;
 assert.deepEqual(session.originalBytes(),b(8,1));
 const out=session.apply(b(8,1),[0],uint("2")); out[1]=9;
 assert.deepEqual(session.originalBytes(),b(8,1));
});
test("malformed source and oversized edits fail atomically", () => {
 assert.throws(()=>createSession(b(8)),/truncated-varint/);
 assert.throws(()=>createSession(new Uint8Array(1048577)),/byte-limit/);
 const src=b(10,0), s=createSession(src);
 assert.throws(()=>s.apply(src,[0],raw(new Uint8Array(1048576))),/byte-limit/);
 assert.deepEqual(s.apply(src,[0],raw(b(1))),b(10,1,1));
});
test("arbitrary LEN payload remains opaque unless explicitly traversed", () =>
 assert.deepEqual(edit(b(10,2,255,255),[0],raw(b(255,0,255))),b(10,3,255,0,255)));
test("1000 value transitions preserve duplicate neighbors", () => {
 for(let i=0;i<1000;i++) {
 const source=b(8,7,16,1,8,9);
 const out=edit(source,[1],uint(String(i)));
 const parsed=require("../web/protobuf-wire.js").inspect(out);
 assert.equal(parsed.fields[1].unsigned,String(i));
 assert.deepEqual(out.slice(0,2),b(8,7)); assert.deepEqual(out.slice(-2),b(8,9));
 }
});
