(function(root){
'use strict';
const reader=typeof module!=='undefined'&&module.exports?require('./cbor-reader.js'):root.SniperCbor;
const fail=code=>{throw Object.assign(new Error(code),{code});};
function session(input){
 const parsed=reader.inspect(input);if(!parsed.ok)fail(parsed.error.code);
 const original=parsed.originalBytes();let used=false;
 function apply(current,path,edit){
  if(used)fail('session-used');
  if(!(current instanceof Uint8Array)||current.length!==original.length||current.some((v,i)=>v!==original[i]))fail('stale-source');
  if(!Array.isArray(path)||path.length>64)fail('invalid-path');
  let n=reader.inspect(original).value;
  for(const s of path){
   if(!s)fail('invalid-path');
   if(n.type==='tag'&&s.kind==='tagged'){n=n.child;continue;}
   if(!Number.isSafeInteger(s.index)||s.index<0)fail('invalid-path');
   if(n.type==='array'&&s.kind==='item'&&s.index<n.children.length)n=n.children[s.index];
   else if(n.type==='map'&&s.kind==='value'&&s.index<n.children.length/2)n=n.children[s.index*2+1];
   else fail('invalid-path');
  }
  if(!edit||typeof edit!=='object')fail('invalid-edit');
  const ai=n.additionalInfo;
  function header(major,v){
   const width=ai<24?0:2**(ai-24),max=width===0?23n:(1n<<BigInt(width*8))-1n;
   if(v<0n||v>max)fail('width-range');
   const b=new Uint8Array(1+width);b[0]=(major<<5)|(width===0?Number(v):ai);
   for(let i=width;i>0;i--){b[i]=Number(v&255n);v>>=8n;}return b;
  }
  let replacement;
  if((n.type==='uint'||n.type==='negative')&&edit.kind==='integer'){
   if(typeof edit.value!=='string'||edit.value.length>21||!/^(-?(0|[1-9][0-9]*))$/.test(edit.value))fail('invalid-integer');
   const v=BigInt(edit.value);
   if(n.type==='uint'&&v<0n||n.type==='negative'&&v>=0n)fail('type-range');
   replacement=header(n.major,n.major===0?v:-1n-v);
  }else if(n.type==='bool'&&edit.kind==='boolean'&&typeof edit.value==='boolean')replacement=Uint8Array.of(edit.value?245:244);
  else if((n.type==='bytes'||n.type==='text')&&!n.indefinite&&edit.kind==='bytes'){
   if(!(edit.value instanceof Uint8Array)||edit.value.length>65536)fail('byte-limit');
   if(n.type==='text'){try{new TextDecoder('utf-8',{fatal:true}).decode(edit.value);}catch{fail('invalid-utf8');}}
   const h=header(n.major,BigInt(edit.value.length));replacement=new Uint8Array(h.length+edit.value.length);replacement.set(h);replacement.set(edit.value,h.length);
  }else fail('unsupported-edit');
  const length=original.length-(n.end-n.offset)+replacement.length;if(length>reader.limits.bytes)fail('byte-limit');
  const out=new Uint8Array(length);out.set(original.subarray(0,n.offset));out.set(replacement,n.offset);out.set(original.subarray(n.end),n.offset+replacement.length);
  const check=reader.inspect(out);if(!check.ok)fail(check.error.code);used=true;return out;
 }
 return Object.freeze({apply});
}
const api=Object.freeze({session});if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.SniperCborEditor=api;
})(globalThis);
