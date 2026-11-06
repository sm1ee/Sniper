const {test} = require('node:test');
const a = require('node:assert/strict');
const {inspect,limits} = require('../web/msgpack-reader.js');
const read = hex => inspect(Uint8Array.from(Buffer.from(hex.replace(/ /g,''),'hex')));
function value(hex) { const r = read(hex); a.equal(r.ok,true); return r.root; }
test('integer families exact',()=>{
 const cases={ '00':'0','7f':'127','e0':'-32','ff':'-1','ccff':'255','cdffff':'65535','ceffffffff':'4294967295','cfffffffffffffffff':'18446744073709551615','d080':'-128','d18000':'-32768','d280000000':'-2147483648','d38000000000000000':'-9223372036854775808','d37fffffffffffffff':'9223372036854775807'};
 for(const [h,v] of Object.entries(cases)) a.equal(value(h).value,v);
});
test('nil and booleans',()=>{a.equal(value('c0').value,null);a.equal(value('c2').value,false);a.equal(value('c3').value,true);});
test('float special values preserved',()=>{a.equal(value('ca80000000').value,'-0');a.equal(value('ca7fc00000').value,'NaN');a.equal(value('cb7ff0000000000000').value,'Infinity');a.equal(value('cbfff0000000000000').value,'-Infinity');});
test('all string families, UTF8 and BOM',()=>{for(const h of ['a161','d90161','da000161','db0000000161']) a.equal(value(h).value,'a');a.equal(value('a3efbbbf').value,'\ufeff');a.equal(value('a1ff').validUtf8,false);a.equal(value('a1ff').value,undefined);});
test('binary families',()=>{for(const h of ['c401ff','c50001ff','c600000001ff']){const n=value(h);a.equal(n.type,'binary');a.equal(n.byteLength,1);a.equal(n.end,h.length/2);}});
test('extensions remain opaque including timestamp',()=>{for(const h of ['d4ff00','d5000000','d60000000000','d7000000000000000000','d800'+'00'.repeat(16),'c701feab','c80001feab','c900000001feab']){const n=value(h);a.equal(n.type,'extension');a.equal(n.end,h.length/2);}a.equal(value('d4ff00').extensionType,-1);});
test('array families',()=>{for(const h of ['9100','dc000100','dd0000000100']) {const n=value(h);a.equal(n.type,'array');a.equal(n.items[0].value,'0');}});
test('map keys are ordered nodes, duplicate/non-string safe',()=>{
 const n=value('8301a16101a16291c3c0');a.equal(n.entries.length,3);a.equal(n.entries[0].key.value,'1');a.equal(n.entries[1].key.value,'1');a.equal(n.entries[2].key.type,'array');
 for(const h of ['de00010102','df000000010102']) a.equal(value(h).entries[0].value.value,'2');
});
test('trailing and reserved not accepted as success',()=>{a.equal(read('0001').error.code,'trailing-data');a.equal(read('c1').error.code,'reserved-marker');a.equal(read('').ok,false);});
test('all truncations of representative nodes rejected',()=>{for(const h of ['cfffffffffffffffff','a3eab080','82a161ca3f800000a162d4ff00','c600000003aabbcc','dd00000002c0c3']) {const b=Buffer.from(h,'hex');a.equal(inspect(b).ok,true);for(let i=0;i<b.length;i++) a.equal(inspect(b.subarray(0,i)).ok,false);}});
test('byte, depth and node limits',()=>{
 a.equal(inspect(new Uint8Array(limits.bytes+1)).error.code,'byte-limit');
 a.equal(read('91'.repeat(64)+'00').ok,true);a.equal(read('91'.repeat(65)+'00').error.code,'depth-limit');
 a.equal(read('ddffffffff').error.code,'node-limit');a.equal(read('dfffffffff').error.code,'node-limit');
 const b=Buffer.concat([Buffer.from('dc270f','hex'),Buffer.alloc(9999)]);a.equal(inspect(b).nodeCount,10000);
 a.equal(inspect(Buffer.concat([Buffer.from('dc2710','hex'),Buffer.alloc(10000)])).error.code,'node-limit');
});
test('source and exposed snapshot mutations isolated',()=>{const b=Buffer.from('9101','hex');const r=inspect(b);b[1]=7;r.originalBytes()[1]=9;a.equal(r.root.items[0].value,'1');a.deepEqual([...r.originalBytes()],[0x91,1]);});
test('all marker bytes covered, never unexpected exceptions',()=>{for(let i=0;i<256;i++){const r=inspect(Uint8Array.of(i));a.equal(typeof r.ok,'boolean');}});
test('deterministic arbitrary input 10000',()=>{let seed=17;for(let j=0;j<10000;j++){const b=new Uint8Array(j%97);for(let i=0;i<b.length;i++){seed=(Math.imul(seed,1664525)+1013904223)>>>0;b[i]=seed>>>24;}const before=b.slice();const r=inspect(b);a.deepEqual(b,before);if(r.ok){a.equal(r.root.end,b.length);a.deepEqual(r.originalBytes(),b);a.ok(r.nodeCount<=10000);}else a.ok(r.error.offset>=0&&r.error.offset<=b.length);}});
test('input contract',()=>{a.throws(()=>inspect([0]),TypeError);});
