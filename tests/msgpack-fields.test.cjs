const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const decoder=require('../web/msgpack-reader.js'),fields=require('../web/protobuf-fields.js');
const inspect=bytes=>fields.inspectMessage({body:Buffer.from(bytes).toString('base64'),body_encoding:'base64'},decoder,'msgpack');
test('ordered duplicate non-string map keys remain distinct rows',()=>{
 const r=inspect([0x82,1,2,1,3]);
 assert.deepEqual(r.rows.map(x=>x.field),['$','$[0].key','$[0].value','$[1].key','$[1].value']);
 assert.deepEqual(r.rows.map(x=>x.value),['2 entries','1','2','1','3']);
 assert.equal(r.rows[4].offset,'4');
});
test('typed previews bounded, exact integer, invalid utf8 and opaque extensions',()=>{
 assert.equal(inspect([0xcf,...Array(8).fill(255)]).rows[0].value,'18446744073709551615');
 assert.match(inspect([0xd4,255,0]).rows[0].value,/type -1 · opaque/);
 assert.match(inspect([0xa1,255]).rows[0].value,/Invalid UTF-8/);
 const r=inspect([0xda,1,0,...Array(256).fill(97)]); assert.ok(r.rows[0].value.length<170);
 assert.match(inspect([1,2]).note,/MessagePack.*trailing-data/);
});
test('messagepack asset is registered and read-only guard precedes editing',()=>{
 const api=fs.readFileSync('src/api.rs','utf8'),html=fs.readFileSync('web/index.html','utf8'),ui=fs.readFileSync('web/protobuf-fields.js','utf8');
 assert.match(api,/route\("\/msgpack-reader.js", get\(msgpack_reader_js\)\)/);
 assert.match(api,/include_str!\("..\/web\/msgpack-reader.js"\)/);
 assert.match(html,/script src="\/msgpack-reader.js" defer/);
 assert.match(ui,/const editable = target === "request"/);
 assert.match(ui,/Read only/);
});
function node(tag='div'){const listeners={},classes=new Set();return {tag,children:[],style:{},dataset:{},attrs:{},textContent:'',classList:{add:x=>classes.add(x),remove:x=>classes.delete(x)},append(...n){this.children.push(...n)},replaceChildren(...n){this.children=n},setAttribute(k,v){this.attrs[k]=v},addEventListener(k,f){listeners[k]=f},fire(k){listeners[k]?.()},querySelectorAll(){return []},closest(){return this.card}}}
test('format is explicit, messagepack paginates read-only and switching never changes draft',()=>{
 global.SniperProtobufWire=require('../web/protobuf-wire.js');global.SniperMessagePack=decoder;
 const card=node(),button=node('button');button.card=card;button.dataset.fieldsTarget='request';
 global.document={querySelectorAll:()=>[button],createElement:node};
 const m={body_encoding:'base64',body:Buffer.from([0xdc,0,205,...Array(205).fill(1)]).toString('base64')},before=JSON.stringify(m),owner={id:2};
 fields.init(()=>({owner,request:()=>m,editable:true,applyFields(){throw Error('must not edit')}}));button.fire('click');
 let view=card.children[0],summary=view.children[0];
 // Protobuf rejects this sample; selector still remains accessible on errors.
 const select=summary.children.find(x=>x.tag==='select'); assert.ok(select);select.value='msgpack';select.fire('change');
 summary=view.children[0];assert.equal(summary.children[0].textContent,'Read only');
 const table=view.children[1];assert.equal(table.children[1].children.length,200);
 assert.equal(table.children[1].children[0].children[2].children.length,0);
 view.children[2].children[1].fire('click');assert.equal(table.children[1].children.length,6);
 assert.equal(JSON.stringify(m),before);
});

test('nested occurrence paths retain ancestors and bounded display',()=>{
 const r=inspect([0x92,0x91,1,0x91,2]);
 assert.deepEqual(r.rows.map(x=>x.field),['$','$[0]','$[0][0]','$[1]','$[1][0]']);
 const nested=inspect([...Array(64).fill([0x81,1]).flat(),2]);
 assert.equal(nested.note,undefined);
 const last=nested.rows.at(-1);assert.ok(last.fullPath.length>200);assert.equal(last.field.length,200);
 assert.equal(last.fullPath,'$'+ '[0].value'.repeat(64));
});
test('exact unique MIME is used without byte sniffing',()=>{
 const mime=value=>fields.formatFromMime({headers:[{name:'CONTENT-TYPE',value}]});
 for(const t of ['application/msgpack','Application/X-Msgpack; charset=binary'])assert.equal(mime(t),'msgpack');
 for(const t of ['application/protobuf','application/x-protobuf'])assert.equal(mime(t),'protobuf');
 for(const t of ['application/grpc-web+proto','text/plain','application/json','application/msgpack-evil','application/msgpack, application/protobuf'])assert.equal(mime(t),'');
 assert.equal(fields.formatFromMime({body:'CAE=',body_encoding:'base64'}),'');
 assert.equal(fields.formatFromMime({headers:[{name:'Content-Type',value:'application/msgpack'},{name:'Content-Type',value:'application/msgpack'}]}),'');
});
test('MIME initial selection, explicit override retained until owner changes',()=>{
 global.SniperProtobufWire=require('../web/protobuf-wire.js');global.SniperMessagePack=decoder;
 const card=node(),button=node('button');button.card=card;button.dataset.fieldsTarget='request';global.document={querySelectorAll:()=>[button],createElement:node};
 let owner={id:'mime'},m={headers:[{name:'Content-Type',value:'application/msgpack'}],body:'AQ==',body_encoding:'base64'};
 fields.init(()=>({owner,request:()=>m}));button.fire('click');let view=card.children[0];
 assert.equal(view.children[0].children[0].textContent,'Read only');
 let select=view.children[0].children.find(n=>n.tag==='select');select.value='protobuf';select.fire('change');
 fields.close('request');button.fire('click');assert.match(view.children[0].children[0].textContent,/No schema/);
 m={...m,headers:[{name:'Content-Type',value:'application/x-msgpack'}]};fields.sync();assert.match(view.children[0].children[0].textContent,/No schema/);
 owner={id:'new'};button.fire('click');assert.equal(view.children[0].children[0].textContent,'Read only');
 owner={id:'ambiguous'};m={...m,headers:[]};button.fire('click');assert.equal(view.children[0].children[0].textContent,'');
 assert.equal(view.children.length,1);assert.equal(view.children[0].children.find(n=>n.tag==='select').value,'');
});
