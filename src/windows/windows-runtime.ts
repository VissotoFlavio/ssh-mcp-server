import { APPROVED_PROFILE_CLASSIFICATION, type ApprovedProfileListingProvider } from '../profiles/approved-profile-listing.js';
import type { ConnectionValidationProvider } from '../validation/trusted-connection-validation.js';

import { WindowsSecureStorage } from './windows-secure-storage.js';

export interface WindowsRuntimeProviders {
  readonly approvedProfileListingProvider: ApprovedProfileListingProvider;
  readonly connectionValidationProvider?: ConnectionValidationProvider;
}

/**
 * Discovery is available through the native storage boundary. Validation is
 * deliberately not advertised until the addon supplies a cancellable async
 * agent-key readiness operation and all per-profile prerequisites can be
 * proven before MCP tool registration.
 */
export function createWindowsRuntimeProviders(
  storage: Pick<WindowsSecureStorage, 'listProfiles'> = new WindowsSecureStorage(),
): WindowsRuntimeProviders {
  return {
    approvedProfileListingProvider: {
      async listApprovedProfiles() {
        return storage.listProfiles().map(({ profileId }) => ({ profileId, classification: APPROVED_PROFILE_CLASSIFICATION }));
      },
    },
  };
}
