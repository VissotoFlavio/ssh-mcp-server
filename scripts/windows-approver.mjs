import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'win32') throw new Error('The Windows approver is available only on Windows.');

const root = join(fileURLToPath(new URL('..', import.meta.url)), 'build', 'Release');
const executable = join(root, 'ssh-mcp-approver.exe');
if (!existsSync(executable)) throw new Error('Build the native boundary first with npm run build:native.');

const environment = { ...process.env };
environment.SSH_MCP_APPROVER_PIPE ??= '\\\\.\\pipe\\ssh-mcp-approver';
environment.SSH_MCP_APPROVER_SECRET ??= randomBytes(32).toString('hex');
console.error(`SSH_MCP_APPROVER_PIPE=${environment.SSH_MCP_APPROVER_PIPE}`);
console.error('Use the same SSH_MCP_APPROVER_PIPE and SSH_MCP_APPROVER_SECRET values when starting ssh-mcp-server.');

const child = spawn(executable, [], { env: environment, stdio: 'inherit', windowsHide: false });
child.on('exit', (code, signal) => {
  if (signal !== null) process.kill(process.pid, signal);
  else process.exitCode = code ?? 1;
});
