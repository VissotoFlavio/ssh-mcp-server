import { APPROVED_PROFILE_CLASSIFICATION, type ApprovedProfileListingProvider } from '../profiles/approved-profile-listing.js';
import type { ConnectionValidationProvider } from '../validation/trusted-connection-validation.js';

import { WindowsSecureStorage } from './windows-secure-storage.js';

export interface WindowsRuntimeProviders {
  readonly approvedProfileListingProvider: ApprovedProfileListingProvider;
  readonly connectionValidationProvider?: ConnectionValidationProvider;
}

/**
 * The native storage boundary is sufficient for discovery. Validation remains
 * unavailable until a native known-hosts snapshot can be composed with every
 * authentication boundary without exposing a mutable filesystem path.
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
