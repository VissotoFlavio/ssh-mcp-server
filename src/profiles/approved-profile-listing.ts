import { LocalConnectionProfileRegistry, type LocalProfileRegistry, type LocalProfileRegistryOptions } from './local-profile-registry.js';

/** The only classification disclosed for a locally approved profile. */
export const APPROVED_PROFILE_CLASSIFICATION = 'operator-approved' as const;
export const SSH_MCP_STATE_ROOT_ENV = 'SSH_MCP_STATE_ROOT';

export interface ApprovedProfileSummary {
  readonly profileId: string;
  readonly classification: typeof APPROVED_PROFILE_CLASSIFICATION;
}

/**
 * Trusted boundary used by the MCP server. Implementations return already
 * minimized profile summaries rather than connection profiles or state files.
 */
export interface ApprovedProfileListingProvider {
  listApprovedProfiles(): Promise<readonly ApprovedProfileSummary[]>;
}

export type RuntimeProfileRegistryFactory = (options: LocalProfileRegistryOptions) => LocalProfileRegistry;

const createLocalProfileRegistry: RuntimeProfileRegistryFactory = (options) => new LocalConnectionProfileRegistry(options);

function invalidRuntimeConfiguration(): never {
  throw new TypeError('Approved profile discovery configuration is invalid');
}

/**
 * Adapt the operator-owned registry into the discovery boundary. The adapter
 * deliberately projects only the public profile identifier into a fixed,
 * non-sensitive classification.
 */
export function createLocalApprovedProfileListingProvider(registry: LocalProfileRegistry): ApprovedProfileListingProvider {
  if (!registry || typeof registry.listProfiles !== 'function') {
    throw new TypeError('A trusted local profile registry is required');
  }

  return {
    async listApprovedProfiles(): Promise<readonly ApprovedProfileSummary[]> {
      const profiles = await registry.listProfiles();
      const summaries: ApprovedProfileSummary[] = [];
      for (const { profileId } of profiles) {
        summaries.push({ profileId, classification: APPROVED_PROFILE_CLASSIFICATION });
      }
      return summaries;
    },
  };
}

/**
 * Production composition: only the operator-configured state root may create
 * the local profile registry. Configuration errors remain deliberately generic.
 */
export function createRuntimeApprovedProfileListingProvider(
  environment: Readonly<Record<string, string | undefined>> = process.env,
  registryFactory: RuntimeProfileRegistryFactory = createLocalProfileRegistry,
): ApprovedProfileListingProvider {
  const stateRoot = environment[SSH_MCP_STATE_ROOT_ENV];
  if (typeof stateRoot !== 'string' || stateRoot.trim() === '') {
    return invalidRuntimeConfiguration();
  }

  try {
    return createLocalApprovedProfileListingProvider(registryFactory({ stateRoot }));
  } catch {
    return invalidRuntimeConfiguration();
  }
}
