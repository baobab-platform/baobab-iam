import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {startBrowserUI, stopBrowserUI} from './n06-browser-ui.mjs';

test('provider redirect reaches a real private RP page and teardown closes it', async () => {
  const ui = await startBrowserUI(0);
  const {address, port} = ui.address();
  assert.equal(address, '127.0.0.1');
  const target = `http://${address}:${port}/login?flow=private-flow`;
  const provider = createServer((_request, response) => {
    response.writeHead(303, {Location: target});
    response.end();
  });
  try {
    await new Promise(resolve => provider.listen(0, '127.0.0.1', resolve));
    const result = await fetch(`http://127.0.0.1:${provider.address().port}/browser`);
    assert.equal(result.status, 200);
    assert.equal(result.url, target);
    assert.equal(result.headers.get('cache-control'), 'no-store');
    assert.equal(result.headers.get('set-cookie'), null);
    assert.ok(!(await result.text()).includes('private-flow'));
    assert.equal((await fetch(target, {method: 'POST', body: 'secret'})).status, 404);
    assert.equal((await fetch(`http://${address}:${port}/sessions/whoami`)).status, 404);
    await assert.rejects(startBrowserUI(port), {code: 'EADDRINUSE'});
  } finally {
    await stopBrowserUI(provider);
    await stopBrowserUI(ui);
  }
  assert.equal(ui.listening, false);
  await assert.rejects(fetch(target));
});
