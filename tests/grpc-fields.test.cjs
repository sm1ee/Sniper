const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const decoder=require('../web/grpc-envelope.js');
global.SniperGrpcEnvelope=decoder;global.SniperProtobufWire=require('../web/protobuf-wire.js');
const fields=require('../web/protobuf-fields.js');
const msg=(bytes,mime='application/grpc')=>({headers:[{name:'Content-Type',value:mime}],body_encoding:'base64',body:Buffer.from(bytes).toString('base64')});
const inspect=(m,i=0)=>fields.inspectMessage(m,decoder,'grpc',i);
test('native MIME exact contextual selection excludes web and ambiguous headers',()=>{
 for(const mime of ['application/grpc','application/grpc+proto','application/grpc+json']) {
 const m=msg([],mime);assert.equal(fields.formatFromMime(m),'grpc');assert.equal(fields.showFieldsButton({owner:{},views:{request:'raw'}},'request',m),true);assert.ok(fields.editBlockReason(m,'grpc'));
 }
 for(const mime of ['application/grpc-web','application/grpc-web+proto','application/grpc-web-text','application/grpc+xml']) assert.equal(fields.formatFromMime(msg([],mime)),'');
 const m=msg([]);m.headers.push(m.headers[0]);assert.equal(fields.formatFromMime(m),'');
});
test('message selection and absolute offsets, no source mutation',()=>{
 const m=msg([0,0,0,0,2,8,1,0,0,0,0,2,8,2]),before=JSON.stringify(m);
 assert.equal(inspect(m).messageCount,2);assert.equal(inspect(m).rows[0].offset,'5');
 assert.equal(inspect(m,1).rows[0].value,'2 (unsigned interpretation)');assert.equal(inspect(m,1).rows[0].offset,'12');
 assert.equal(JSON.stringify(m),before);
});
test('compressed, JSON, untyped manual input stay opaque; complete preview required',()=>{
 assert.equal(inspect(msg([1,0,0,0,2,8,1])).rows[0].wire,'Compressed');
 assert.equal(inspect(msg([0,0,0,0,2,8,1],'application/grpc+json')).rows[0].wire,'JSON');
 assert.equal(inspect(msg([0,0,0,0,2,8,1],'application/octet-stream')).rows[0].wire,'Bytes');
 assert.match(inspect({...msg([]),preview_truncated:true}).note,/truncated/);
 assert.match(inspect(msg([0])).note,/truncated-header/);
 assert.match(inspect(msg([0,0,0,0,1,0])).payloadNote,/invalid-field/);
 assert.equal(inspect(msg([])).messageCount,0);
});
function node(tag='div'){const listeners={},classes=new Set();return {tag,children:[],style:{},dataset:{},attrs:{},textContent:'',classList:{add:x=>classes.add(x),remove:x=>classes.delete(x)},append(...n){this.children.push(...n)},replaceChildren(...n){this.children=n},setAttribute(k,v){this.attrs[k]=v},addEventListener(k,f){listeners[k]=f},fire(k){listeners[k]?.()},querySelectorAll(){return []},closest(){return this.card}}}
test('read-only message picker selects frames and rejects invalid index',()=>{
 const card=node(),button=node('button');button.card=card;button.dataset.fieldsTarget='request';
 global.document={querySelectorAll:()=>[button],createElement:node};
 const m=msg([0,0,0,0,2,8,1,0,0,0,0,2,8,2]);
 fields.init(()=>({owner:card,request:()=>m,editable:true,applyFields(){throw Error('no edit')}}));button.fire('click');
 const view=card.children[0];
 function picker(){return view.children[0].children.find(n=>n.tag==='label').children[0]}
 assert.match(view.children[0].children[0].textContent,/Envelope only/);
 picker().value='2';picker().fire('change');
 assert.equal(picker().value,'2');
 const table=view.children.find(n=>n.tag==='table');assert.equal(table.children[1].children[0].children[2].textContent,'2 (unsigned interpretation)');
 assert.equal(table.children[1].children[0].children[2].children.length,0);
 picker().value='999';picker().fire('change');assert.equal(picker().value,'2');
});
test('native assets loaded before fields',()=>{
 const api=fs.readFileSync('src/api.rs','utf8'),html=fs.readFileSync('web/index.html','utf8');
 assert.match(api,/route\("\/grpc-envelope.js", get\(grpc_envelope_js\)\)/);
 assert.match(api,/include_str!\("..\/web\/grpc-envelope.js"\)/);
 assert.ok(html.indexOf('src="/grpc-envelope.js"')<html.indexOf('src="/protobuf-fields.js"'));
});

test('manual native inspector rejects gRPC-Web even with valid native-shaped bytes',()=>{
 for(const mime of ['application/grpc-web','application/grpc-web+proto','application/grpc-web-text','Application/Grpc-Web+Json; charset=utf-8']) assert.match(inspect(msg([0,0,0,0,2,8,1],mime)).note,/gRPC-Web is not supported/);
 const m=msg([]);m.headers.push({name:'Content-Type',value:'application/grpc-web'});assert.match(inspect(m).note,/gRPC-Web is not supported/);
});
test('message picker uses themed control and keyboard focus styling',()=>{
 const css=fs.readFileSync('web/styles.css','utf8'),js=fs.readFileSync('web/protobuf-fields.js','utf8');
 assert.match(js,/picker.className = "grpc-message-picker"/);
 assert.match(css,/\.protobuf-fields-summary \.grpc-message-picker \{[^}]*color: var\(--text\)[^}]*background: var\(--panel\)/);
 assert.match(css,/\.grpc-message-picker:focus-visible \{[^}]*outline: 2px solid var\(--accent\)/);
});

test('same-owner same-body header changes invalidate rendered interpretation',()=>{
 const card=node(),button=node('button');button.card=card;button.dataset.fieldsTarget='request';
 global.document={querySelectorAll:()=>[button],createElement:node};
 const m=msg([0,0,0,0,2,8,1]);const source={owner:card,request:()=>m,editable:true,revision:1};
 fields.init(()=>source);button.fire('click');const view=card.children[0];
 const table=()=>view.children.find(n=>n.tag==='table');
 const wire=()=>table().children[1].children[0].children[1].textContent;
 assert.equal(wire(),'VARINT');
 const original=table();fields.sync();assert.equal(table(),original,'unchanged header content retains DOM');
 m.headers[0].value='application/grpc+json';fields.sync();
 assert.equal(wire(),'JSON');assert.notEqual(table(),original);
 m.headers[0].value='application/grpc+proto';fields.sync();assert.equal(wire(),'VARINT');
 // Keep an explicit manual selection so web exclusion is re-evaluated.
 const select=view.children[0].children.find(n=>n.tag==='select');select.value='grpc';select.fire('change');
 m.headers[0].value='application/grpc-web';fields.sync();
 assert.match(view.children.find(n=>n.tag==='p').textContent,/gRPC-Web is not supported/);
 assert.equal(table(),undefined);
});
test('content-encoding-only change invalidates editing eligibility without body/revision changes',()=>{
 global.SniperProtobufEdit=require('../web/protobuf-edit.js');
 const card=node(),button=node('button');button.card=card;button.dataset.fieldsTarget='request';
 global.document={querySelectorAll:()=>[button],createElement:node};
 const m=msg([8,1],'application/protobuf');
 const source={owner:card,request:()=>m,editable:true,revision:1,applyFields(){throw Error('not used')}};
 fields.init(()=>source);button.fire('click');const view=card.children[0];
 const edits=()=>view.children.find(n=>n.tag==='table').children[1].children[0].children[2].children.length;
 assert.equal(edits(),1);
 m.headers.push({name:'Content-Encoding',value:'gzip'});fields.sync();assert.equal(edits(),0);
 m.headers.pop();fields.sync();assert.equal(edits(),1);
 m.headers.push({name:'Content-Type',value:'application/protobuf'});fields.sync();
 assert.equal(view.children.some(n=>n.tag==='table'),false,'duplicate MIME clears automatic interpretation');
});
