const test = require('node:test');
const assert = require('node:assert/strict');
const { inspect, limits } = require('../web/protobuf-wire.js');
const decode = values => inspect(Uint8Array.from(values));
const vint = value => { let n = BigInt(value), out = []; do { let b = Number(n & 127n); n >>= 7n; out.push(b | (n ? 128 : 0)); } while(n); return out; };
test('empty message', () => assert.equal(decode([]).ok, true));
test('types and offsets without schema guesses', () => {
  const d = decode([8,150,1,17,0,0,0,0,0,0,0,0,26,2,8,1,37,0,0,0,0]);
  assert.equal(d.ok,true);
  assert.deepEqual(d.fields.map(f=>f.wireType),[0,1,2,5]);
  assert.equal(d.fields[0].unsigned,'150');
  assert.deepEqual(d.fields[2].value,{offset:14,length:2});
  assert.equal(d.fields[2].children,undefined);
  assert.equal(d.fields[2].text,undefined);
});
test('uint64 is exact decimal, not JS number', () => assert.equal(decode([8,...vint(2n**64n-1n)]).fields[0].unsigned,'18446744073709551615'));
test('duplicate fields, order, zero lengths and noncanonical varints preserved', () => {
  const b=[16,1,8,128,0,8,0,26,0]; const d=decode(b);
  assert.equal(d.ok,true); assert.deepEqual(d.fields.map(f=>f.number),[2,1,1,3]);
  assert.deepEqual([...d.originalBytes()],b);
});
test('no alias with source or returned original copy', () => {
  const src=Uint8Array.from([8,1]);const d=inspect(src);src.fill(0);d.originalBytes().fill(0);
  assert.deepEqual([...d.originalBytes()],[8,1]);
});
test('respects typed-array subview',()=>assert.deepEqual([...inspect(Uint8Array.from([0,8,1,0]).subarray(1,3)).originalBytes()],[8,1]));
test('maximum legal field number',()=>assert.equal(decode([...vint(0xfffffff8n),1]).fields[0].number,536870911));
test('deprecated groups retain children and closing tag',()=>{
  const d=decode([11,16,1,12]);assert.equal(d.ok,true);assert.equal(d.fields[0].length,4);
  assert.equal(d.fields[0].children[0].unsigned,'1');
});
for(const [bytes, code] of [
 [[0],'invalid-field-number'],[[7],'invalid-field-number'],[[14],'invalid-wire-type'],
 [[15],'invalid-wire-type'],[[8,128],'truncated-varint'],[[128],'truncated-varint'],
 [[8,...Array(9).fill(255),2],'varint-overflow'],
 [[8,...Array(10).fill(128)],'varint-overflow'],
 [[...vint(2n**32n),0],'invalid-field-number'],
 [[10,3,1],'truncated-value'],[[9,1],'truncated-value'],[[13,1],'truncated-value'],
 [[12],'unexpected-end-group'],[[11,20],'unexpected-end-group'],[[11],'unclosed-group'],
 [[10,...vint(2n**64n-1n)],'truncated-value'],
]) test(`reject ${code} ${bytes.join(',')}`,()=>{
 const d=decode(bytes);assert.equal(d.ok,false);assert.equal(d.error.code,code);assert.deepEqual(d.fields,[]);
 assert.deepEqual([...d.originalBytes()],bytes);
});
test('byte resource bound before copy',()=>assert.equal(inspect(new Uint8Array(limits.bytes+1)).error.code,'byte-limit'));
test('field resource bound',()=>assert.equal(decode(Array(limits.fields+1).fill([8,0]).flat()).error.code,'field-limit'));
test('group depth bound',()=>assert.equal(decode([...Array(limits.depth+1).fill(11),...Array(limits.depth+1).fill(12)]).error.code,'depth-limit'));
test('valid group depth boundary',()=>assert.equal(decode([...Array(limits.depth).fill(11),...Array(limits.depth).fill(12)]).ok,true));
test('input contract',()=>assert.throws(()=>inspect([8,1]),TypeError));
test('deterministic arbitrary input: total, non-mutating, bounded spans',()=>{
 let seed=17; const rand=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed>>>24};
 for(let i=0;i<10000;i++){
  const bytes=Uint8Array.from({length:rand()},rand), before=Uint8Array.from(bytes), d=inspect(bytes);
  assert.deepEqual(bytes,before);assert.deepEqual(d.originalBytes(),before);
  if(d.ok) for(const f of d.fields){assert.ok(f.offset+f.length<=bytes.length);assert.ok(f.value.offset+f.value.length<=bytes.length)}
  else assert.ok(d.error.offset>=0 && d.error.offset<=bytes.length);
 }
});
