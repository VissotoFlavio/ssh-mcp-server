import { APPROVED_PROFILE_CLASSIFICATION, type ApprovedProfileListingProvider } from '../profiles/approved-profile-listing.js';
import type { ConnectionValidationProvider } from '../validation/trusted-connection-validation.js';

import { WindowsSecureStorage } from './windows-secure-storage.js';

export interface WindowsRuntimeProviders {
  readonly approvedProfileListingProvider: ApprovedProfileListingProvider;
  readonly connectionValidationProvider?: ConnectionValidationProvider;
}

/**
 * The native storage boundary is sufficient for discovery. Password readiness
 * has an internal in-memory session, but validation remains unavailable at
 * the MCP boundary until agent-key readiness can consume an opaque native
 * known-hosts snapshot without exposing a mutable filesystem path.
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
