const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const decoder=require('../web/cbor-reader.js'),fields=require('../web/protobuf-fields.js');
const inspect=bytes=>fields.inspectMessage({body:Buffer.from(bytes).toString('base64'),body_encoding:'base64'},decoder,'cbor');
test('cbor ordered duplicate map keys and paths',()=>{
 const r=inspect([0xa2,1,2,1,3]);
 assert.deepEqual(r.rows.map(x=>x.field),['$','$[0].key','$[0].value','$[1].key','$[1].value']);
 assert.deepEqual(r.rows.map(x=>x.value),['2 entries','1','2','1','3']);
});
test('cbor indefinite chunks and opaque tags',()=>{
 const r=inspect([0x9f,0xc1,1,0x7f,0x61,97,0x61,98,0xff,0xff]);
 assert.deepEqual(r.rows.map(x=>x.field),['$','$[0]','$[0].tagged','$[1]','$[1].chunk[0]','$[1].chunk[1]']);
 assert.match(r.rows[1].value,/opaque/);assert.equal(r.rows[4].value,'"a"');
 assert.match(inspect([0xff]).note,/CBOR.*unexpected-break/);
});
test('cbor exact integers, previews bounded, original unchanged',()=>{
 const bytes=[0x1b,...Array(8).fill(255)];const before=[...bytes];
 assert.equal(inspect(bytes).rows[0].value,'18446744073709551615');assert.deepEqual(bytes,before);
 assert.ok(inspect([0x79,1,0,...Array(256).fill(97)]).rows[0].value.length<170);
});
test('cbor MIME contextual read only and assets',()=>{
 const m={headers:[{name:'Content-Type',value:'Application/CBOR; charset=binary'}],body_encoding:'base64'};
 assert.equal(fields.formatFromMime(m),'cbor');
 assert.equal(fields.showFieldsButton({owner:{},views:{request:'raw'}},'request',m),true);
 assert.equal(fields.editBlockReason(m,'cbor'),'');
 assert.equal(fields.formatFromMime({headers:[{name:'Content-Type',value:'application/cbor-seq'}]}),'');
 const api=fs.readFileSync('src/api.rs','utf8'),html=fs.readFileSync('web/index.html','utf8');
 assert.match(api,/route\("\/cbor-reader.js", get\(cbor_reader_js\)\)/);assert.match(api,/include_str!\("..\/web\/cbor-reader.js"\)/);
 assert.match(html,/script src="\/cbor-reader.js" defer/);
});

function node(tag='div'){const listeners={},classes=new Set();return {tag,children:[],style:{},dataset:{},attrs:{},textContent:'',classList:{add:x=>classes.add(x),remove:x=>classes.delete(x)},append(...n){this.children.push(...n)},replaceChildren(...n){this.children=n},setAttribute(k,v){this.attrs[k]=v},addEventListener(k,f){listeners[k]=f},fire(k){listeners[k]?.()},querySelectorAll(){return []},closest(){return this.card}}}
test('cbor selector and pagination are read only',()=>{
 global.SniperCbor=decoder;global.SniperProtobufWire=require('../web/protobuf-wire.js');
 const card=node(),button=node('button');button.card=card;button.dataset.fieldsTarget='request';
 global.document={querySelectorAll:()=>[button],createElement:node};
 const m={headers:[{name:'Content-Type',value:'application/cbor'}],body_encoding:'base64',body:Buffer.from([0x98,205,...Array(205).fill(1)]).toString('base64')},before=JSON.stringify(m);
 const owner={id:1};fields.init(()=>({owner,request:()=>m,editable:true,applyFields(){throw Error('must not edit')}}));button.fire('click');
 const view=card.children[0],summary=view.children[0];
 assert.equal(summary.children[0].textContent,'Read only');
 assert.equal(summary.children.find(x=>x.tag==='select').value,'cbor');
 const table=view.children[1];assert.equal(table.children[1].children.length,200);
 assert.equal(table.children[1].children[0].children[2].children.length,0);
 view.children[2].children[1].fire('click');assert.equal(table.children[1].children.length,6);
 assert.equal(JSON.stringify(m),before);
});
test('both Fields tooltips include CBOR',()=>{
 const html=fs.readFileSync('web/index.html','utf8');
 assert.equal((html.match(/title="Inspect Protobuf, MessagePack, CBOR or gRPC fields"/g)||[]).length,2);
});

test('CBOR scalar UI edits only values, blocks tag/key/chunk branches',()=>{
 global.SniperCbor=decoder;global.SniperCborEditor=require('../web/cbor-editor.js');
 const card=node(),button=node('button');button.card=card;button.dataset.fieldsTarget='request';global.document={querySelectorAll:()=>[button],createElement:node};
 let m={headers:[{name:'Content-Type',value:'application/cbor'}],body_encoding:'base64',body:Buffer.from([0xa2,1,2,1,3]).toString('base64')};
 const owner={}, source={owner,revision:1,requestText:'original',editable:true,request:()=>m,applyFields(snapshot,bytes){assert.equal(snapshot.owner,owner);m={...m,body:Buffer.from(bytes).toString('base64')};source.revision++;}};
 fields.init(()=>source);button.fire('click');const view=card.children[0];
 let rows=view.children[1].children[1].children;
 assert.equal(rows[1].children[2].children.length,0);assert.equal(rows[3].children[2].children.length,0);
 rows[4].children[2].children[0].fire('click');const form=rows[4].children[2].children[0];
 assert.equal(form.children[0].textContent,'Decimal · 0–23');form.children[0].children[0].value='7';form.children[1].fire('click');
 assert.deepEqual([...Buffer.from(m.body,'base64')],[0xa2,1,2,1,7]);
 const blocked=inspect([0x83,0xc1,1,0x7f,0x61,97,0xff,0xa1,0x81,1,2]);
 assert.ok(blocked.rows.find(x=>x.field==='$[0].tagged').keyBranch);
 assert.ok(blocked.rows.find(x=>x.field==='$[1].chunk[0]').keyBranch);
 assert.ok(blocked.rows.find(x=>x.field==='$[2][0].key[0]').keyBranch);
 const api=fs.readFileSync('src/api.rs','utf8'),html=fs.readFileSync('web/index.html','utf8');
 assert.match(api,/route\("\/cbor-editor.js", get\(cbor_editor_js\)\)/);assert.match(api,/include_str!\("..\/web\/cbor-editor.js"\)/);assert.match(html,/script src="\/cbor-editor.js" defer/);
});
