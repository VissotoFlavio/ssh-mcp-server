import { APPROVED_PROFILE_CLASSIFICATION, type ApprovedProfileListingProvider } from '../profiles/approved-profile-listing.js';
import { validateProfileSelection } from '../profiles/connection-profile.js';
import type { ConnectionValidationProvider } from '../validation/trusted-connection-validation.js';

import { WindowsSecureStorage } from './windows-secure-storage.js';
import { createWindowsValidationSession, WindowsValidationSession } from './windows-validation-session.js';

export interface WindowsRuntimeProviders {
  readonly approvedProfileListingProvider: ApprovedProfileListingProvider;
  readonly connectionValidationProvider?: ConnectionValidationProvider;
}

/**
 * Native construction is fail-closed when any required Windows boundary is unavailable.
 */
export function createWindowsRuntimeProviders(
  storage: Pick<WindowsSecureStorage, 'listProfiles'> &
    Partial<Pick<WindowsSecureStorage, 'getProfile' | 'readKnownHosts' | 'withKnownHostsSnapshot'>> = new WindowsSecureStorage(),
  validationSession: Pick<WindowsValidationSession, 'validate'> | undefined = (() => {
    try {
      const profiles = storage.listProfiles();
      if (typeof storage.getProfile !== 'function' || typeof storage.withKnownHostsSnapshot !== 'function') return undefined;
      const readKnownHosts = storage.readKnownHosts;
      if (profiles.some((profile) => profile.authMode === 'password') && typeof readKnownHosts !== 'function') return undefined;
      return createWindowsValidationSession({
        getProfile: storage.getProfile.bind(storage),
        readKnownHosts:
          typeof readKnownHosts === 'function'
            ? readKnownHosts.bind(storage)
            : () => {
                throw new TypeError('Windows known-hosts storage is unavailable');
              },
        withKnownHostsSnapshot: storage.withKnownHostsSnapshot.bind(storage),
      });
    } catch {
      return undefined;
    }
  })(),
): WindowsRuntimeProviders {
  return {
    approvedProfileListingProvider: {
      async listApprovedProfiles() {
        return storage.listProfiles().map(({ profileId }) => ({ profileId, classification: APPROVED_PROFILE_CLASSIFICATION }));
      },
    },
    ...(validationSession === undefined
      ? {}
      : {
          connectionValidationProvider: {
            async validateConnection(input: unknown, signal?: AbortSignal) {
              const selection = validateProfileSelection(input);
              await validationSession.validate(selection, signal);
              return { profileId: selection.profileId, ready: true as const };
            },
          },
        }),
  };
}
