import {createServer} from 'node:http';
import {once} from 'node:events';

// Redirected requests are not reliably intercepted by Playwright route handlers.
// Use an actual disposable loopback receiver; never log or retain its URLs.
export async function startCallbackReceiver(receive) {
  let redirectUri;
  const server=createServer((request,response)=>{
    let url;
    try{url=new URL(request.url,redirectUri);}catch{}
    const expected=new URL(redirectUri);
    const accepted=request.method==='GET'&&request.headers.host===expected.host&&
      url?.origin+url?.pathname===redirectUri&&!url.hash;
    response.writeHead(accepted?200:404,{'Content-Type':'text/html','Cache-Control':'no-store','Connection':'close'});
    if(accepted)receive(url.href);
    response.end('<!doctype html><title>Synthetic callback</title>');
  });
  server.headersTimeout=5000;server.requestTimeout=10000;
  server.listen(0,'127.0.0.1');
  await once(server,'listening');
  redirectUri='http://127.0.0.1:'+server.address().port+'/passkey-qualification';
  return {redirectUri,close:()=>new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()))};
}
