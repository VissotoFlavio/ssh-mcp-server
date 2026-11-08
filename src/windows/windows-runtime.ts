import { APPROVED_PROFILE_CLASSIFICATION, type ApprovedProfileListingProvider } from '../profiles/approved-profile-listing.js';
import { validateProfileSelection } from '../profiles/connection-profile.js';
import type { ConnectionValidationProvider } from '../validation/trusted-connection-validation.js';

import { createWindowsReadinessStatusProvider, type WindowsReadinessStatusProvider } from './windows-readiness-status.js';
import { WindowsSecureStorage } from './windows-secure-storage.js';
import { createWindowsValidationSession, WindowsValidationSession } from './windows-validation-session.js';

export interface WindowsRuntimeProviders {
  readonly approvedProfileListingProvider: ApprovedProfileListingProvider;
  readonly connectionValidationProvider?: ConnectionValidationProvider;
  readonly windowsReadinessStatusProvider: WindowsReadinessStatusProvider;
}

/**
 * Native construction is fail-closed when any required Windows boundary is unavailable.
 */
export function createWindowsRuntimeProviders(
  storage: Pick<WindowsSecureStorage, 'listProfiles'> &
    Partial<
      Pick<WindowsSecureStorage, 'credentialAvailable' | 'getProfile' | 'inspectReadiness' | 'readKnownHosts' | 'withKnownHostsSnapshot'>
    > = new WindowsSecureStorage(),
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
  const validationProvider =
    validationSession === undefined
      ? undefined
      : {
          async validateConnection(input: unknown, signal?: AbortSignal) {
            const selection = validateProfileSelection(input);
            await validationSession.validate(selection, signal);
            return { profileId: selection.profileId, ready: true as const };
          },
        };
  const readinessStorage =
    typeof storage.inspectReadiness === 'function' &&
    typeof storage.readKnownHosts === 'function' &&
    typeof storage.credentialAvailable === 'function'
      ? {
          credentialAvailable: storage.credentialAvailable.bind(storage),
          inspectReadiness: storage.inspectReadiness.bind(storage),
          listProfiles: storage.listProfiles.bind(storage),
          readKnownHosts: storage.readKnownHosts.bind(storage),
        }
      : undefined;
  return {
    approvedProfileListingProvider: {
      async listApprovedProfiles() {
        return storage.listProfiles().map(({ profileId }) => ({ profileId, classification: APPROVED_PROFILE_CLASSIFICATION }));
      },
    },
    ...(validationProvider === undefined ? {} : { connectionValidationProvider: validationProvider }),
    windowsReadinessStatusProvider: createWindowsReadinessStatusProvider(true, readinessStorage, validationProvider !== undefined),
  };
}
