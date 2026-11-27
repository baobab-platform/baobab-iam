import {createServer} from 'node:http';

// A real redirect destination is required: Playwright route handlers only
// intercept the first request in a redirect chain. This page supplies an RP
// origin, never identity, credentials, session state or a provider response.
export async function startBrowserUI(port = 4455) {
  const server = createServer((request, response) => {
    const path = new URL(request.url, 'http://127.0.0.1').pathname;
    const allowed = request.method === 'GET' &&
      ['/', '/login', '/settings', '/error'].includes(path);
    response.writeHead(allowed ? 200 : 404, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    });
    response.end(allowed
      ? '<!doctype html><html><meta charset="utf-8"><body>Disposable IAM WebAuthn browser</body></html>'
      : 'Not found');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return server;
}

export async function stopBrowserUI(server) {
  if (!server) return;
  await new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
    server.closeAllConnections();
  });
}
