import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import test from 'node:test';

import ssh2, { type SFTPWrapper } from 'ssh2';

import type { ExecutionAuditJournal } from '../../src/execution/execution-audit-journal.js';
import { createExecutionAuthorization } from '../../src/execution/remote-command-execution.js';
import { RemoteFileUploadProvider, Ssh2RemoteFileUploadTransport } from '../../src/execution/remote-file-upload.js';

const { Server, utils } = ssh2;

const username = 'test-user';
const password = 'test-password';
const destination = '/srv/application/config.json';
const payload = Buffer.from('{"enabled":true}\n');

interface TestSftpServer {
  readonly port: number;
  readonly fingerprint: string;
  readonly files: Map<string, Buffer>;
  close(): Promise<void>;
}

function fingerprint(key: Buffer): string {
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/u, '')}`;
}

async function startSftpServer(corruptReadback = false): Promise<TestSftpServer> {
  const hostKey = utils.generateKeyPairSync('ed25519');
  const parsedKey = utils.parseKey(hostKey.private);
  if (parsedKey instanceof Error) throw parsedKey;
  const files = new Map<string, Buffer>();
  const server = new Server({ hostKeys: [hostKey.private] }, (client) => {
    client
      .on('error', () => undefined)
      .on('authentication', (context) => {
        if (context.method === 'password' && context.username === username && context.password === password) context.accept();
        else context.reject();
      })
      .on('ready', () => {
        client.on('session', (accept) => {
          const session = accept();
          session.on('sftp', (acceptSftp) => configureSftp(acceptSftp(), files, corruptReadback));
        });
      });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  return {
    port: address.port,
    fingerprint: fingerprint(parsedKey.getPublicSSH()),
    files,
    close: () => new Promise((resolve, reject) => server.close((error) => (error === undefined ? resolve() : reject(error)))),
  };
}

function configureSftp(transport: SFTPWrapper, files: Map<string, Buffer>, corruptReadback: boolean): void {
  const handles = new Map<number, { readonly path: string; readonly readable: boolean }>();
  let nextHandle = 0;
  const handle = (): Buffer => {
    const value = Buffer.alloc(4);
    value.writeUInt32BE(nextHandle++, 0);
    return value;
  };
  const get = (value: Buffer) => handles.get(value.readUInt32BE(0));
  transport
    .on('OPEN', (requestId: number, path: string, flags: number) => {
      const readable = (flags & utils.sftp.OPEN_MODE.READ) !== 0;
      if (readable && !files.has(path)) return transport.status(requestId, utils.sftp.STATUS_CODE.NO_SUCH_FILE);
      if (!readable) files.set(path, Buffer.alloc(0));
      const value = handle();
      handles.set(value.readUInt32BE(0), { path, readable });
      transport.handle(requestId, value);
    })
    .on('WRITE', (requestId: number, value: Buffer, offset: number, data: Buffer) => {
      const file = get(value);
      if (file === undefined || file.readable) return transport.status(requestId, utils.sftp.STATUS_CODE.FAILURE);
      const current = files.get(file.path) ?? Buffer.alloc(0);
      const next = Buffer.alloc(Math.max(current.length, offset + data.length));
      current.copy(next);
      data.copy(next, offset);
      files.set(file.path, next);
      transport.status(requestId, utils.sftp.STATUS_CODE.OK);
    })
    .on('READ', (requestId: number, value: Buffer, offset: number, length: number) => {
      const file = get(value);
      const contents = file === undefined || !file.readable ? undefined : files.get(file.path);
      if (contents === undefined) return transport.status(requestId, utils.sftp.STATUS_CODE.FAILURE);
      if (offset >= contents.length) return transport.status(requestId, utils.sftp.STATUS_CODE.EOF);
      const returned = corruptReadback ? Buffer.from('corrupt') : contents.subarray(offset, offset + length);
      transport.data(requestId, returned);
    })
    .on('CLOSE', (requestId: number, value: Buffer) => {
      if (get(value) === undefined) return transport.status(requestId, utils.sftp.STATUS_CODE.FAILURE);
      handles.delete(value.readUInt32BE(0));
      transport.status(requestId, utils.sftp.STATUS_CODE.OK);
    })
    .on('RENAME', (requestId: number, from: string, to: string) => {
      const contents = files.get(from);
      if (contents === undefined) return transport.status(requestId, utils.sftp.STATUS_CODE.NO_SUCH_FILE);
      files.delete(from);
      files.set(to, contents);
      transport.status(requestId, utils.sftp.STATUS_CODE.OK);
    })
    .on('REMOVE', (requestId: number, path: string) => {
      files.delete(path);
      transport.status(requestId, utils.sftp.STATUS_CODE.OK);
    });
}

function auditJournal(): ExecutionAuditJournal {
  return {
    digestArguments: async () => 'a'.repeat(64),
    begin: async (intent) => ({ operationId: intent.operationId, finish: async () => undefined, handoff: async () => undefined }),
  };
}

function uploadProvider(port: number, expectedHostFingerprint: string): RemoteFileUploadProvider {
  const profile = {
    profileId: 'sftp-test',
    host: '127.0.0.1',
    port,
    user: username,
    expectedHostFingerprint,
    authMode: 'password' as const,
    approvedKnownHostsReference: 'known-hosts://sftp-test',
    credentialReference: 'os://ssh/sftp-test',
  };
  return new RemoteFileUploadProvider({
    connectionValidation: { validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }) },
    authorizationProvider: { authorize: async () => createExecutionAuthorization(profile, Date.now() + 60_000) },
    transport: new Ssh2RemoteFileUploadTransport({ getPassword: async () => ({ password }) }),
    auditJournal: auditJournal(),
  });
}

test('uploads and independently verifies an SFTP temporary file before rename', async () => {
  const server = await startSftpServer();
  try {
    const provider = uploadProvider(server.port, server.fingerprint);
    const contentBase64 = payload.toString('base64');
    const approval = await provider.requestActionApproval({ profileId: 'sftp-test', remotePath: destination, contentBase64 });
    assert.equal(approval.approved, true);
    const result = await provider.upload({ profileId: 'sftp-test', remotePath: destination, contentBase64, approvalCapability: approval.capability });

    assert.equal(result.outcome, 'success');
    assert.equal(result.integrity, 'verified');
    assert.deepEqual(server.files.get(destination), payload);
    assert.equal(
      [...server.files.keys()].some((path) => path.startsWith(`${destination}.ssh-mcp-upload-`)),
      false,
    );
  } finally {
    await server.close();
  }
});

test('rejects an unapproved SFTP host key before uploading', async () => {
  const server = await startSftpServer();
  try {
    const provider = uploadProvider(server.port, 'SHA256:1111111111111111111111111111111111111111111');
    const contentBase64 = payload.toString('base64');
    const approval = await provider.requestActionApproval({ profileId: 'sftp-test', remotePath: destination, contentBase64 });
    const result = await provider.upload({ profileId: 'sftp-test', remotePath: destination, contentBase64, approvalCapability: approval.capability });

    assert.equal(result.outcome, 'failure');
    assert.equal(result.code, 'host-key-failure');
    assert.equal(server.files.size, 0);
  } finally {
    await server.close();
  }
});

test('fails without renaming when SFTP readback does not match the requested digest', async () => {
  const server = await startSftpServer(true);
  try {
    const provider = uploadProvider(server.port, server.fingerprint);
    const contentBase64 = payload.toString('base64');
    const approval = await provider.requestActionApproval({ profileId: 'sftp-test', remotePath: destination, contentBase64 });
    const result = await provider.upload({ profileId: 'sftp-test', remotePath: destination, contentBase64, approvalCapability: approval.capability });

    assert.equal(result.outcome, 'failure');
    assert.equal(result.code, 'integrity-failure');
    assert.equal(server.files.has(destination), false);
  } finally {
    await server.close();
  }
});
