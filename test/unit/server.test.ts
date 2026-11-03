import { strict as assert } from 'node:assert';
import test from 'node:test';

import { serverName } from '../../src/server.js';

test('exposes the server name', () => {
  assert.equal(serverName, 'ssh-mcp-server');
});
