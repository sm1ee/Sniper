/* Read-only CBOR wire inspection, RFC 8949. No tag interpretation or re-encoding. */
(function(root) {
'use strict';
const limits=Object.freeze({bytes:1048576,nodes:10000,depth:64});
function inspect(input) {
 if (!(input instanceof Uint8Array)) throw new TypeError('Expected Uint8Array');
 if(input.length>limits.bytes) return {ok:false,error:{code:'byte-limit',offset:0}};
 const bytes=Uint8Array.from(input), view=new DataView(bytes.buffer); let p=0,count=0;
 const fail=(code,offset=p)=>{throw {code,offset};};
 const take=n=>{if(n>bytes.length-p)fail('truncated-value');const s=p;p+=n;return s;};
 function arg(ai){if(ai<24)return BigInt(ai); if(ai>27)fail('reserved-additional-info',p-1);let n=2**(ai-24),s=take(n),v=0n;for(let i=0;i<n;i++)v=(v<<8n)|BigInt(bytes[s+i]);return v;}
 function size(v){if(v>BigInt(bytes.length-p))fail('truncated-value');return Number(v);}
 function item(depth,chunkMajor) {
  if(depth>limits.depth)fail('depth-limit'); if(++count>limits.nodes)fail('node-limit');
  const offset=p, h=bytes[take(1)],major=h>>5, ai=h&31;
  if(h===255)fail('unexpected-break',offset);
  if(chunkMajor!==undefined && (major!==chunkMajor || ai===31))fail('invalid-string-chunk',offset);
  const n={offset,major,additionalInfo:ai};
  if(ai>=28&&ai<=30)fail('reserved-additional-info',offset);
  const indefinite=ai===31;
  if(indefinite && (major<2||major>5))fail('invalid-indefinite',offset);
  if(major===7){
   if(ai<24){n.type=ai===20||ai===21?'bool':ai===22?'null':ai===23?'undefined':'simple';n.value=ai===20?false:ai===21?true:ai===22?null:ai===23?undefined:ai;}
   else if(ai===24){n.type='simple';n.value=bytes[take(1)];if(n.value<32)fail('invalid-simple',offset);}
   else {n.type='float';n.width=2**(ai-24);const s=take(n.width);let value;
    if(ai===25){const x=view.getUint16(s),sign=x&32768?-1:1,e=(x>>10)&31,f=x&1023;value=e===31?(f?NaN:sign*Infinity):sign*(e===0?2**-24*f:2**(e-15)*(1+f/1024));}
    else value=ai===26?view.getFloat32(s):view.getFloat64(s);
    n.value=Number.isNaN(value)?'NaN':Object.is(value,-0)?'-0':String(value);
   }
  }else {
   const a=indefinite?null:arg(ai); n.indefinite=indefinite;
   if(major<2){n.type=major===0?'uint':'negative';n.value=(major===0?a:-1n-a).toString();}
   else if(major===2||major===3){n.type=major===2?'bytes':'text';
    if(indefinite){n.chunks=[];while(true){if(p===bytes.length)fail('missing-break');if(bytes[p]===255){p++;break;}n.chunks.push(item(depth+1,major));}}
    else {const length=size(a);n.dataOffset=take(length);n.length=length;if(major===3){try{n.value=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes.subarray(n.dataOffset,p));}catch{fail('invalid-utf8',n.dataOffset);}}}
   }else if(major===4||major===5){n.type=major===4?'array':'map';n.children=[];const total=indefinite?null:a*BigInt(major===5?2:1);
    if(total!==null&&total>BigInt(limits.nodes-count))fail('node-limit');
    if(total!==null&&total>BigInt(bytes.length-p))fail('truncated-value');
    while(total===null||BigInt(n.children.length)<total){if(p===bytes.length){if(total===null)fail('missing-break');fail('truncated-value');}if(total===null&&bytes[p]===255){if(major===5&&n.children.length%2)fail('odd-map');p++;break;}n.children.push(item(depth+1));}
   }else {n.type='tag';n.tag=a.toString();n.child=item(depth+1);}
  }
  n.end=p;return n;
 }
 try{const value=item(0);if(p!==bytes.length)fail('trailing-data');return {ok:true,value,nodeCount:count,byteLength:bytes.length,originalBytes:()=>Uint8Array.from(bytes)};}catch(e){if(e&&typeof e.code==='string')return {ok:false,error:e,originalBytes:()=>Uint8Array.from(bytes)};throw e;}
}
const api=Object.freeze({inspect,limits});if(typeof module==='object'&&module.exports)module.exports=api;else root.SniperCbor=api;
})(typeof globalThis==='object'?globalThis:this);
