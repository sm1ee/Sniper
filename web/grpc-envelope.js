(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.SniperGrpcEnvelope=api;})(globalThis,()=>{
'use strict';
const MAX_BYTES=1048576, MAX_MESSAGES=10000;
function classifyContentType(value){
 if(typeof value!=='string')return null;
 const mime=value.split(';',1)[0].trim().toLowerCase();
 if(mime==='application/grpc'||mime==='application/grpc+proto')return 'proto';
 if(mime==='application/grpc+json')return 'json';
 return null; // gRPC-Web is deliberately separate.
}
function parse(input){
 if(!(input instanceof Uint8Array))return {ok:false,error:{code:'invalid-input',offset:0}};
 if(input.byteLength>MAX_BYTES)return {ok:false,error:{code:'input-limit',offset:0}};
 const bytes=Uint8Array.from(input), messages=[];
 const fail=(code,offset)=>({ok:false,error:{code,offset},originalBytes:()=>bytes.slice()});
 let offset=0;
 while(offset<bytes.length){
  if(messages.length>=MAX_MESSAGES)return fail('message-limit',offset);
  if(bytes.length-offset<5)return fail('truncated-header',offset);
  const start=offset, flag=bytes[offset];
  if(flag!==0&&flag!==1)return fail('invalid-flag',offset);
  const length=bytes[offset+1]*16777216+bytes[offset+2]*65536+bytes[offset+3]*256+bytes[offset+4];
  offset+=5;
  if(length>MAX_BYTES)return fail('message-size-limit',start+1);
  if(length>bytes.length-offset)return fail('truncated-message',offset);
  messages.push(Object.freeze({index:messages.length,offset:start,payloadOffset:offset,length,compressed:flag===1,end:offset+length}));
  offset+=length;
 }
 const spans=messages.map(m=>[m.payloadOffset,m.end]);
 return {ok:true,messages:Object.freeze(messages),byteLength:bytes.length,originalBytes:()=>bytes.slice(),messageBytes(index){if(!Number.isInteger(index)||index<0||index>=spans.length)throw new RangeError('message index');return bytes.slice(...spans[index]);}};
}
return Object.freeze({parse,classifyContentType,MAX_BYTES,MAX_MESSAGES});
});
