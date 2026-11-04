import { release } from 'node:os';

/** The single supported runtime envelope for the per-user Windows alpha. */
export function supportsWindowsAlphaRuntime(): boolean {
  if (process.platform !== 'win32' || process.arch !== 'x64') return false;
  const nodeMajor = Number.parseInt(process.versions.node.split('.')[0] ?? '', 10);
  const windowsBuild = Number.parseInt(release().split('.')[2] ?? '', 10);
  return Number.isSafeInteger(nodeMajor) && nodeMajor >= 22 && Number.isSafeInteger(windowsBuild) && windowsBuild >= 20_348;
}
