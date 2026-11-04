(function(root){
'use strict';
const reader=typeof module!=='undefined'&&module.exports?require('./msgpack-reader.js'):root.SniperMessagePack;
const fail=code=>{throw Object.assign(new Error(code),{code});};
function session(input){
 const parsed=reader.inspect(input); if(!parsed.ok) fail(parsed.error.code);
 const original=parsed.originalBytes(); let used=false;
 function apply(current,path,edit){
  if(used) fail('session-used');
  if(!(current instanceof Uint8Array)||current.length!==original.length||current.some((v,i)=>v!==original[i])) fail('stale-source');
  if(!Array.isArray(path)||path.length>64) fail('invalid-path');
  // Reparse private bytes, never trust caller-visible metadata.
  let n=reader.inspect(original).root;
  for(const step of path){
   if(!step||!Number.isSafeInteger(step.index)||step.index<0) fail('invalid-path');
   if(n.type==='array'&&step.kind==='item'&&step.index<n.items.length)n=n.items[step.index];
   else if(n.type==='map'&&step.kind==='value'&&step.index<n.entries.length)n=n.entries[step.index].value;
   else fail('invalid-path');
  }
  if(!edit||typeof edit!=='object')fail('invalid-edit');
  let replacement;
  if((n.type==='uint'||n.type==='int')&&edit.kind==='integer'){
   if(typeof edit.value!=='string'||edit.value.length>21||!/^(-?(0|[1-9][0-9]*))$/.test(edit.value))fail('invalid-integer');
   const v=BigInt(edit.value),m=n.marker;
   replacement=original.slice(n.offset,n.end); const dv=new DataView(replacement.buffer);
   if(m<=127){if(v<0n||v>127n)fail('width-range');replacement[0]=Number(v);}
   else if(m>=224){if(v< -32n||v> -1n)fail('width-range');replacement[0]=Number(v+256n);}
   else {
    const signed=m>=208, width=n.end-n.offset-1,bits=BigInt(width*8),min=signed?-(1n<<(bits-1n)):0n,max=signed?(1n<<(bits-1n))-1n:(1n<<bits)-1n;
    if(v<min||v>max)fail('width-range');
    if(width===8)(signed?dv.setBigInt64.bind(dv):dv.setBigUint64.bind(dv))(1,v);
    else {let u=v<0n?v+(1n<<bits):v;for(let i=width;i>0;i--){replacement[i]=Number(u&255n);u>>=8n;}}
   }
  } else if(n.type==='bool'&&edit.kind==='boolean'&&typeof edit.value==='boolean')replacement=Uint8Array.of(edit.value?195:194);
  else if((n.type==='string'||n.type==='binary')&&edit.kind==='bytes'){
   if(!(edit.value instanceof Uint8Array)||edit.value.length>65536)fail('byte-limit');
   // Preserve original marker width. String wire values require valid UTF-8.
   if(n.type==='string'){try{new TextDecoder('utf-8',{fatal:true}).decode(edit.value);}catch{fail('invalid-utf8');}}
   const header=n.dataOffset-n.offset,m=n.marker,len=edit.value.length;
   const capacity=m>=160&&m<=191?31:header===2?255:header===3?65535:4294967295;
   if(len>capacity)fail('width-range');
   replacement=new Uint8Array(header+len);replacement.set(original.subarray(n.offset,n.dataOffset));
   if(header===1)replacement[0]=160+len;else {let l=len;for(let i=header-1;i>0;i--){replacement[i]=l&255;l=Math.floor(l/256);}}
   replacement.set(edit.value,header);
  } else fail('unsupported-edit');
  const length=original.length-(n.end-n.offset)+replacement.length;if(length>reader.limits.bytes)fail('byte-limit');
  const out=new Uint8Array(length);out.set(original.subarray(0,n.offset));out.set(replacement,n.offset);out.set(original.subarray(n.end),n.offset+replacement.length);
  const check=reader.inspect(out);if(!check.ok)fail(check.error.code);
  used=true;return out;
 }
 return Object.freeze({apply});
}
const api=Object.freeze({session});if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.SniperMessagePackEditor=api;
})(globalThis);
