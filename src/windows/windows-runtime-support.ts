import { release } from 'node:os';

export interface WindowsRuntimeFacts {
  readonly platform: string;
  readonly architecture: string;
  readonly nodeVersion: string;
  readonly osRelease: string;
}

/** The single supported runtime envelope for the per-user Windows alpha. */
export function supportsWindowsAlphaRuntime(
  facts: WindowsRuntimeFacts = { platform: process.platform, architecture: process.arch, nodeVersion: process.versions.node, osRelease: release() },
): boolean {
  if (facts.platform !== 'win32' || facts.architecture !== 'x64') return false;
  const node = /^(\d+)\.\d+\.\d+$/u.exec(facts.nodeVersion);
  const windows = /^(\d+)\.(\d+)\.(\d+)$/u.exec(facts.osRelease);
  if (node === null || windows === null) return false;
  const nodeMajor = Number(node[1]);
  const windowsBuild = Number(windows[3]);
  const supportedBuild = windowsBuild === 20_348 || windowsBuild >= 22_631;
  return Number.isSafeInteger(nodeMajor) && nodeMajor >= 22 && Number.isSafeInteger(windowsBuild) && supportedBuild;
}
