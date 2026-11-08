import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

const source = readFileSync(join(process.cwd(), 'native', 'windows_trust.cc'), 'utf8');

function nativeFunction(name: string, endMarker: string): string {
  const start = source.indexOf(`napi_value ${name}`);
  const end = source.indexOf(endMarker, start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  return source.slice(start, end);
}

test('shares the non-secret credential-blob structural gate between read and availability probes', () => {
  assert.match(source, /bool HasUsableCredentialBlob\(const CREDENTIALW\* credential\)/u);
  assert.match(source, /CredentialBlobSize == 0/u);
  assert.match(source, /CredentialBlobSize > 4096/u);
  assert.match(source, /CredentialBlobSize % sizeof\(wchar_t\)\) != 0/u);
  assert.match(source, /units\[index\] == L'\\0'/u);

  const readCredential = nativeFunction('ReadCredential', 'napi_value CredentialAvailable');
  const credentialAvailable = nativeFunction('CredentialAvailable', '#ifdef SSH_MCP_NATIVE_TEST');
  assert.match(readCredential, /HasUsableCredentialBlob\(credential\)/u);
  assert.match(credentialAvailable, /HasUsableCredentialBlob\(credential\)/u);
  assert.equal(credentialAvailable.includes('napi_create_string_utf16'), false);
  assert.equal(credentialAvailable.includes('std::wstring password'), false);
});
