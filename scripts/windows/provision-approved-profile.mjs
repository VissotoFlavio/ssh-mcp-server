import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const addon = require(join(here, '..', '..', 'build', 'Release', 'windows_trust.node'));
const input = await readFile(0, 'utf8');
const request = JSON.parse(input);
if (Object.getPrototypeOf(request) !== Object.prototype) throw new Error('Invalid provisioning request');
addon.provisionApprovedProfile(request);
