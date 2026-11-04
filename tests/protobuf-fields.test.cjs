const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const wire = require('../web/protobuf-wire.js');
global.SniperProtobufWire = wire;
const fields = require('../web/protobuf-fields.js');
const inspect = m => fields.inspectMessage(m, wire);
test('explicit binary inspection preserves input and exposes wire rather than schema', () => {
  const m = {body:'CJYBEgNhYmM=', body_encoding:'base64'};
  const before = JSON.stringify(m), r = inspect(m);
  assert.equal(r.rows.length, 2); assert.equal(r.rows[0].value, '150 (unsigned interpretation)');
  assert.equal(r.rows[1].wire, 'LEN'); assert.match(r.rows[1].value, /61 62 63/);
  assert.equal(JSON.stringify(m), before);
});
test('preview, missing, malformed and oversized input fail without stale fallback', () => {
  assert.match(inspect(null).note, /No body/);
  assert.match(inspect({preview_truncated:true}).note, /truncated/);
  assert.match(inspect({body:'@',body_encoding:'base64'}).note, /Invalid Base64/);
  assert.match(inspect({body:'AA==',body_encoding:'base64'}).note, /invalid-field-number/);
  assert.match(inspect({body:'a'.repeat(1048577)}).note, /1 MiB/);
  assert.match(inspect({body:'é'.repeat(600000)}).note, /1 MiB/);
});
test('response preview bytes and empty protobuf', () => {
  assert.equal(inspect({body_preview:'CAE=',body_encoding:'base64'}).rows[0].value, '1 (unsigned interpretation)');
  assert.equal(inspect({body:''}).rows.length,0);
});
function node(tag='div') {
  const classes = new Set(), listeners = {};
  return {tag, children:[], hidden:false, style:{}, dataset:{}, attrs:{}, textContent:'',
    classList:{add:k=>classes.add(k),remove:k=>classes.delete(k),contains:k=>classes.has(k)},
    append(...n){this.children.push(...n)},replaceChildren(...n){this.children=n},
    setAttribute(k,v){this.attrs[k]=v},addEventListener(k,f){listeners[k]=f},click(){listeners.click?.()},
    querySelectorAll(){return this.tabs || []}, closest(){return this.card}
  };
}
test('UI paginates, closes without editing source, drops old owner, handles parse failures', () => {
  const card=node(), button=node('button'); button.dataset.fieldsTarget='request'; button.card=card;
  const raw=node('button'); raw.classList.add('active'); card.tabs=[raw];
  global.document={querySelectorAll:()=>[button],createElement:node};
  let message={headers:[{name:'Content-Type',value:'application/protobuf'}],body_encoding:'base64',body:Buffer.from(Array(601).fill([8,1]).flat()).toString('base64')};
  let owner={id:'a'}, fail=false;
  fields.init(()=>({owner,request:()=>{if(fail) throw Error('secret raw traffic');return message;}}));
  const before=JSON.stringify(message); button.click();
  const view=card.children[0], table=view.children[1], tbody=table.children[1];
  assert.equal(view.children[0].children[0].textContent, 'No schema · Read only');
  assert.match(view.children[0].children[0].title, /Wire types, not schema types/);
  assert.equal(tbody.children.length,200); assert.equal(raw.classList.contains('active'),false);
  const nav=view.children[2]; nav.children[1].click(); assert.equal(tbody.children.length,200);
  const secondPageStatus = view.children[0].children[1].textContent;
  fields.sync(); assert.equal(view.children[0].children[1].textContent, secondPageStatus);
  assert.equal(view.children[1], table, 'unchanged source preserves DOM and scroll');
  nav.children[1].click();nav.children[1].click(); assert.equal(tbody.children.length,1);
  assert.equal(JSON.stringify(message),before);
  fields.close('request'); assert.equal(view.hidden,true); assert.equal(JSON.stringify(message),before);
  button.click(); assert.equal(view.children[1], table, 'reopening keeps page for unchanged source');
  message={...message, body:'CAE='}; fields.sync();
  assert.equal(view.children[0].children[1].textContent, '1 field · 2 bytes');
  assert.notEqual(view.children[1], table, 'changed body refreshes rows');
  owner={id:'b'}; fields.sync(); assert.equal(view.hidden,true);
  fail=true;button.click();assert.match(view.children[1].textContent,/Cannot inspect/);
  assert.doesNotMatch(view.children[1].textContent,/secret/);
  delete global.document;
});
test('integration loads codec first and does not add persistent mode', () => {
  const html=fs.readFileSync(path.join(__dirname,'../web/index.html'),'utf8');
  assert.ok(html.indexOf('/protobuf-wire.js')<html.indexOf('/protobuf-fields.js'));
  assert.ok(html.indexOf('/protobuf-fields.js')<html.indexOf('/app.js'));
  assert.equal((html.match(/data-fields-target=/g)||[]).length,2);
  const app=fs.readFileSync(path.join(__dirname,'../web/app.js'),'utf8');
  assert.match(app,/SniperProtobufFields\?\.close\(target\)/);
  assert.match(app,/SniperProtobufFields\?\.sync\(\)/);
  assert.doesNotMatch(app,/replayMessageViews\[target\] = "fields"/);
});
test('native asset router serves both inspector scripts as JavaScript', () => {
  const api=fs.readFileSync(path.join(__dirname,'../src/api.rs'),'utf8');
  for (const name of ['wire','fields']) {
    assert.ok(api.includes(`.route("/protobuf-${name}.js", get(protobuf_${name}_js))`));
    const handler=api.match(new RegExp(`async fn protobuf_${name}_js\\(\\) -> Response \\{([^]*?)\\n\\}`));
    assert.ok(handler); assert.ok(handler[1].includes('"application/javascript; charset=utf-8"'));
    assert.ok(handler[1].includes(`include_str!("../web/protobuf-${name}.js")`));
  }
});

test('compact Fields spacing is scoped and header wraps', () => {
  const css=fs.readFileSync(path.join(__dirname,'../web/styles.css'),'utf8');
  assert.match(css,/\.protobuf-fields-summary \{[^}]*flex-wrap: wrap/);
  assert.match(css,/\.protobuf-fields-view th, \.protobuf-fields-view td \{[^}]*padding: 4px 8px/);
});

test('editing rejects ambiguous MIME, compression and UTF8, strict raw hex', () => {
 const base={body_encoding:'base64',headers:[{name:'Content-Type',value:'application/protobuf'}]};
 assert.equal(fields.editBlockReason(base),'');
 for(const m of [ {...base,body_encoding:'utf8'}, {...base,preview_truncated:true}, {...base,headers:[{name:'Content-Type',value:'application/grpc+proto'}]}, {...base,headers:[...base.headers,{name:'content-encoding',value:'gzip'}]}, {...base,headers:[...base.headers,...base.headers]}]) assert.ok(fields.editBlockReason(m));
 assert.deepEqual([...fields.parseHex('00 ff 12')],[0,255,18]);
 for(const bad of ['0','zz','0x12','aa!']) assert.throws(()=>fields.parseHex(bad));
});
test('request apply explicitly edits one occurrence; stale revision and response deny editing', () => {
 global.SniperProtobufEdit=require('../web/protobuf-edit.js');
 const card=node(), button=node('button'); button.dataset.fieldsTarget='request';button.card=card;
 global.document={querySelectorAll:()=>[button],createElement:node};
 let owner={id:'ed'}, revision=0, text='draft', applied=0;
 let message={body:'CAE=',body_encoding:'base64',headers:[{name:'Content-Type',value:'application/protobuf'}]};
 fields.init(()=>({owner,revision,requestText:text,editable:true,request:()=>message,applyFields(snapshot,bytes){assert.equal(snapshot.revision,revision);message={...message,body:Buffer.from(bytes).toString('base64')};revision++;text='changed';applied++;}}));
 button.click();const view=card.children[0];
 const cell=()=>view.children[1].children[1].children[0].children[2];
 cell().children[0].click(); let form=cell().children[0];form.children[0].children[0].value='128';form.children[1].click();
 assert.equal(applied,1);assert.equal(message.body,'CIAB');
 cell().children[0].click();form=cell().children[0];form.children[0].children[0].value='9';revision++;form.children[1].click();
 assert.equal(applied,1);assert.match(form.children[3].textContent,/stale-source/);
 const responseCard=node(), responseButton=node('button');responseButton.dataset.fieldsTarget='response';responseButton.card=responseCard;
 global.document.querySelectorAll=()=>[responseButton];
 fields.init(()=>({owner,revision,requestText:text,editable:true,response:()=>message,applyFields(){throw Error('must not run')}}));
 responseButton.click();const responseCell=responseCard.children[0].children[1].children[1].children[0].children[2];
 assert.equal(responseCell.children.length,0);
 delete global.document;
});
test('edit asset and app source guard ownership revision and framing before applying',()=>{
 const app=fs.readFileSync(path.join(__dirname,'../web/app.js'),'utf8');
 assert.match(app,/current !== snapshot.owner/);assert.match(app,/current.protobufEditRevision/);assert.match(app,/current.requestText !== snapshot.requestText/);
 assert.match(app,/const updated = parseEditableRawRequest\(next, current.baseRequest\)/);
 const html=fs.readFileSync(path.join(__dirname,'../web/index.html'),'utf8'); assert.ok(html.includes('/protobuf-edit.js')); assert.ok(html.indexOf('/protobuf-wire.js') < html.indexOf('/protobuf-edit.js')); assert.ok(html.indexOf('/protobuf-edit.js') < html.indexOf('/protobuf-fields.js'));
 const api=fs.readFileSync(path.join(__dirname,'../src/api.rs'),'utf8');assert.ok(api.includes('.route("/protobuf-edit.js", get(protobuf_edit_js))'));assert.ok(api.includes('include_str!("../web/protobuf-edit.js")'));
});

test('deep groups do not materialize repeated full raw hex strings',()=>{
 const len=900000, n=len, varint=[];let v=n; do {let b=v&127;v=Math.floor(v/128);varint.push(b|(v?128:0));} while(v);
 const bytes=Buffer.concat([Buffer.from(Array(60).fill(11)),Buffer.from([18,...varint]),Buffer.alloc(len),Buffer.from(Array(60).fill(12))]);
 const model=inspect({body:bytes.toString('base64'),body_encoding:'base64'});
 assert.equal(model.rows.length,61);assert.ok(model.rows.every(row=>!('rawHex' in row)));
 assert.ok(model.rows.every(row=>row.value.length<150));
 assert.throws(()=>fields.parseHex('00'.repeat(65537)));
 const src=fs.readFileSync(path.join(__dirname,'../web/protobuf-fields.js'),'utf8');
 assert.match(src,/row.valueLength <= 65536/);
});

test('inline edit controls avoid pager margin and retain usable targets', () => {
  const css=fs.readFileSync(path.join(__dirname,'../web/styles.css'),'utf8');
  const row=css.match(/\.protobuf-fields-view td > button \{([^}]+)\}/)[1];
  assert.match(row,/margin: 0 0 0 8px/);
  assert.match(row,/min-height: 24px/);
  assert.doesNotMatch(row,/(?:^|;)\s*height:/);
  assert.match(css,/\.protobuf-field-edit button \{[^}]*margin: 0/);
  assert.match(css,/\.protobuf-fields-view button:focus-visible/);
});

test('opening an editor reveals it only inside its body pane without animation', () => {
  let focused;
  const view={scrollTop:0,clientHeight:180,clientTop:0,getBoundingClientRect:()=>({top:100})};
  const input={focus:options=>focused=options};
  fields.revealEditor(view,{getBoundingClientRect:()=>({top:240,bottom:340,height:100})},input);
  assert.deepEqual(focused,{preventScroll:true}); assert.equal(view.scrollTop,64);
  view.scrollTop=50;
  fields.revealEditor(view,{getBoundingClientRect:()=>({top:120,bottom:170,height:50})},input);
  assert.equal(view.scrollTop,50,'already visible stays put');
  fields.revealEditor(view,{getBoundingClientRect:()=>({top:240,bottom:600,height:360})},input);
  assert.equal(view.scrollTop,186,'oversize form begins at viewport top');
});

test('cancel restores originating edit button focus and pane scroll without rebuilding rows', () => {
  global.SniperProtobufEdit=require('../web/protobuf-edit.js');
  const card=node(),button=node('button');button.dataset.fieldsTarget='request';button.card=card;
  global.document={querySelectorAll:()=>[button],createElement:node};
  const owner={},message={body:'CAE=',body_encoding:'base64',headers:[{name:'Content-Type',value:'application/protobuf'}]};
  fields.init(()=>({owner,revision:0,requestText:'draft',editable:true,request:()=>message,applyFields(){throw Error('not applied')}}));
  button.click();
  const view=card.children[0],table=view.children[1],cell=table.children[1].children[0].children[2],edit=cell.children[0];
  let focus;edit.focus=options=>focus=options;
  view.scrollTop=17;edit.click();
  const form=cell.children[0];view.scrollTop=100;form.children[2].click();
  assert.equal(view.scrollTop,17);assert.equal(cell.children[0],edit);
  assert.equal(view.children[1],table);assert.deepEqual(focus,{preventScroll:true});
  delete global.document;
});

test('successful apply restores occurrence page and edit focus, including duplicate field numbers', () => {
  global.SniperProtobufEdit=require('../web/protobuf-edit.js');
  const card=node(),button=node('button');button.dataset.fieldsTarget='request';button.card=card;
  let focused;
  global.document={querySelectorAll:()=>[button],createElement:tag=>{
    const n=node(tag);n.focus=options=>{focused={node:n,options}};return n;
  }};
  const owner={};let revision=0,text='draft';
  let message={body:Buffer.from(Array(601).fill([8,1]).flat()).toString('base64'),body_encoding:'base64',headers:[{name:'Content-Type',value:'application/protobuf'}]};
  fields.init(()=>({owner,revision,requestText:text,editable:true,request:()=>message,applyFields(snapshot,bytes){
    message={...message,body:Buffer.from(bytes).toString('base64')};revision++;text='updated';
    fields.sync(); // Real apply may synchronously rerender.
  }}));
  button.click();const view=card.children[0];
  view.children[2].children[1].click();view.children[2].children[1].click();
  view.scrollTop=72;
  const cell=view.children[1].children[1].children[5].children[2];
  cell.children[0].click();const form=cell.children[0];
  form.children[0].children[0].value='128';form.children[1].click();
  assert.match(view.children[0].children[1].textContent,/401–600 shown/);
  const updated=view.children[1].children[1].children[5].children[2];
  assert.match(updated.textContent,/128/);
  assert.equal(focused.node,updated.children[0]);assert.deepEqual(focused.options,{preventScroll:true});
  assert.equal(view.scrollTop,72);
  const decoded=inspect(message);assert.equal(decoded.rows[405].unsigned,'128');
  assert.equal(decoded.rows[404].unsigned,'1');assert.equal(decoded.rows[406].unsigned,'1');
  delete global.document;
});

test('MessagePack duplicate occurrence edit, width refusal, stale guard and key exclusion',()=>{
 global.SniperMessagePack=require('../web/msgpack-reader.js');global.SniperMessagePackEditor=require('../web/msgpack-editor.js');
 const card=node(),button=node('button');button.dataset.fieldsTarget='request';button.card=card;
 global.document={querySelectorAll:()=>[button],createElement:node};
 let owner={},revision=0,text='m',applied=0;
 let message={body:Buffer.from([0x82,0xa1,97,1,0xa1,97,2]).toString('base64'),body_encoding:'base64',headers:[{name:'Content-Type',value:'application/msgpack'}]};
 fields.init(()=>({owner,revision,requestText:text,editable:true,request:()=>message,applyFields(snapshot,bytes){assert.equal(snapshot.format,'msgpack');message={...message,body:Buffer.from(bytes).toString('base64')};revision++;text+='x';applied++;}}));
 button.click();const view=card.children[0],rows=()=>view.children[1].children[1].children;
 assert.equal(rows()[1].children[2].children.length,0);
 rows()[4].children[2].children[0].click();let form=rows()[4].children[2].children[0];
 assert.match(form.children[0].textContent,/Decimal · 0–127/);
 form.children[0].children[0].value='128';form.children[1].click();assert.equal(applied,0);assert.match(form.children[3].textContent,/width-range/);
 form.children[0].children[0].value='9';form.children[1].click();assert.equal(applied,1);assert.deepEqual([...Buffer.from(message.body,'base64')],[0x82,0xa1,97,1,0xa1,97,9]);
 rows()[4].children[2].children[0].click();form=rows()[4].children[2].children[0];revision++;form.children[1].click();assert.equal(applied,1);assert.match(form.children[3].textContent,/stale-source/);
 assert.ok(fields.editBlockReason(message,'protobuf'));assert.equal(fields.editBlockReason(message,'msgpack'),'');
 delete global.document;
});

test('MessagePack editor script is served and loaded after reader',()=>{
 const api=fs.readFileSync('src/api.rs','utf8'), html=fs.readFileSync('web/index.html','utf8');
 assert.ok(api.includes('.route("/msgpack-editor.js", get(msgpack_editor_js))'));
 assert.ok(api.includes('asset_response("application/javascript", include_str!("../web/msgpack-editor.js"))'));
 assert.ok(html.indexOf('/msgpack-reader.js')<html.indexOf('/msgpack-editor.js'));
 assert.ok(html.indexOf('/msgpack-editor.js')<html.indexOf('/protobuf-fields.js'));
});
test('Fields visibility follows each pane MIME, with keyboard-native Hex fallback and owner reset', () => {
  const reqCard=node(), resCard=node(), req=node('button'), res=node('button');
  req.dataset.fieldsTarget='request'; req.card=reqCard;
  res.dataset.fieldsTarget='response'; res.card=resCard;
  global.document={querySelectorAll:()=>[req,res],createElement:node};
  const msg = type => ({headers:type ? [{name:'Content-Type',value:type}] : [],body_encoding:'base64',body:'CAE='});
  let request=msg('application/json'), response=msg('application/msgpack'), owner={id:'a'};
  const views={request:'raw',response:'pretty'};
  fields.init(()=>({owner,views,request:()=>request,response:()=>response}));
  assert.equal(req.hidden,true); assert.equal(res.hidden,false);
  views.request='hex';fields.sync();assert.equal(req.hidden,false);
  req.click();assert.equal(reqCard.children[0].hidden,false);assert.equal(req.hidden,false);
  // Raw/Pretty handlers close first, then sync with the new view.
  fields.close('request');views.request='raw';fields.sync();assert.equal(req.hidden,true);
  request=msg('Application/X-Protobuf; charset=binary');fields.sync();assert.equal(req.hidden,false);
  request.headers.push({name:'content-type',value:'application/protobuf'});fields.sync();assert.equal(req.hidden,true);
  request=msg('');fields.sync();assert.equal(req.hidden,true);
  views.request='hex';fields.sync();assert.equal(req.hidden,false);
  req.click();owner={id:'b'};views.request='pretty';response=msg('application/json');fields.sync();
  assert.equal(req.hidden,true);assert.equal(res.hidden,true);assert.equal(reqCard.children[0].hidden,true);
  owner={type:'websocket'};views.request='hex';fields.sync();assert.equal(req.hidden,true);
  owner=null;fields.sync();assert.equal(req.hidden,true);
  delete global.document;
});
test('Fields controls are hidden before hydration and remain native keyboard accessible', () => {
  const html=fs.readFileSync(path.join(__dirname,'../web/index.html'),'utf8');
  const css=fs.readFileSync(path.join(__dirname,'../web/styles.css'),'utf8');
  const app=fs.readFileSync(path.join(__dirname,'../web/app.js'),'utf8');
  assert.equal((html.match(/class="replay-fields-tab" hidden/g)||[]).length,2);
  assert.match(css,/\.replay-fields-tab\[hidden\]\s*\{\s*display:\s*none;/);
  assert.match(app,/views: state\.replayMessageViews/);
  assert.doesNotMatch(html,/class="replay-fields-tab"[^>]*tabindex="-1"/);
});

test('minimal edit hints expose exact safe ranges without generic prose',()=>{
 assert.equal(fields.editHint({wireType:0},false),'Unsigned decimal · 0–18446744073709551615');
 assert.equal(fields.editHint({wireType:1},false),'Hex · 8 bytes');
 assert.equal(fields.editHint({wireType:5},false),'Hex · 4 bytes');
 assert.equal(fields.editHint({scalarType:'int',marker:0xd3},true),'Decimal · -9223372036854775808–9223372036854775807');
 assert.equal(fields.editHint({scalarType:'uint',marker:0xcf},true),'Decimal · 0–18446744073709551615');
 assert.equal(fields.editHint({scalarType:'string',marker:0xa3},true),'Hex · up to 31 bytes · UTF-8');
 assert.equal(fields.editHint({scalarType:'binary',marker:0xc6},true),'Hex · up to 65536 bytes');
 assert.equal(fields.editHint({scalarType:'bool'},true),'true / false');
});
