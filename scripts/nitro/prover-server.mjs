#!/usr/bin/env node
// Untrusted parent transport: public proof material only, CPU proving, no Ethereum RPC.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateConfig, proveCandidate } from './prove-mint.mjs';

const MAX_BODY=512*1024, MAX_DOCUMENT=65536;
function reply(res,status,value) {
  if(res.destroyed || res.writableEnded) return;
  res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});
  res.end(JSON.stringify(value));
}
async function body(req) {
  if(req.headers['content-type']?.split(';')[0]!=='application/json') throw Error('invalid_request');
  let length=0; const chunks=[];
  for await(const chunk of req) {
    length+=chunk.length;
    if(length>MAX_BODY) throw Error('invalid_request');
    chunks.push(chunk);
  }
  const value=JSON.parse(Buffer.concat(chunks));
  if(!value || Array.isArray(value) || Object.keys(value).sort().join()!=='document,request'
      || typeof value.document!=='string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.document)) throw Error('invalid_request');
  const document=Buffer.from(value.document,'base64');
  if(!document.length || document.length>MAX_DOCUMENT || document.toString('base64')!==value.document) throw Error('invalid_request');
  return {request:value.request,document};
}
export function createProverServer(config,{prover=proveCandidate,deadlineMs=550000}={}) {
  validateConfig(config,{candidate:true});
  if(!Number.isInteger(deadlineMs) || deadlineMs<1 || deadlineMs>550000) throw Error('Invalid server deadline');
  let busy=false;
  const server=createServer(async(req,res)=>{
    if(req.method!=='POST' || req.url!=='/prove') { reply(res,404,{error:'not_found'}); req.resume(); return; }
    if(busy) { reply(res,503,{error:'prover_busy'}); req.resume(); return; }
    busy=true;
    const controller=new AbortController();
    const timer=setTimeout(()=>{
      controller.abort(); reply(res,504,{error:'prover_timeout'});
      if(!req.complete) req.destroy();
    },deadlineMs);
    res.once('close',()=>{ if(!res.writableEnded) controller.abort(); });
    try {
      let input;
      try { input=await body(req); }
      catch { reply(res,400,{error:'invalid_request'}); return; }
      const candidate=await prover(config,input.request,input.document,{signal:controller.signal});
      if(!controller.signal.aborted) reply(res,200,candidate);
    } catch { reply(res,502,{error:'prover_failed'}); }
    finally { clearTimeout(timer); busy=false; }
  });
  server.requestTimeout=550000; server.headersTimeout=10000;
  server.keepAliveTimeout=1000; server.maxRequestsPerSocket=1;
  return server;
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if(process.argv.length!==3) throw Error('Usage: prover-server.mjs CPU_CONFIG');
    const bytes=await readFile(process.argv[2]);
    if(bytes.length>65536) throw Error('Config too large');
    const server=createProverServer(JSON.parse(bytes));
    server.on('error',()=>{ console.error('Prover listener failed'); process.exitCode=1; });
    server.listen(8789,'127.0.0.1',()=>console.log('Unverified CPU proof candidates on 127.0.0.1:8789; no Ethereum RPC'));
  } catch(e) { console.error(e.message); process.exitCode=1; }
}
