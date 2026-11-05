import { APPROVED_PROFILE_CLASSIFICATION, type ApprovedProfileListingProvider } from '../profiles/approved-profile-listing.js';
import { validateProfileSelection } from '../profiles/connection-profile.js';
import type { ConnectionValidationProvider } from '../validation/trusted-connection-validation.js';

import { supportsWindowsAlphaRuntime } from './windows-runtime-support.js';
import { WindowsSecureStorage } from './windows-secure-storage.js';
import { WindowsValidationSession } from './windows-validation-session.js';

export interface WindowsRuntimeProviders {
  readonly approvedProfileListingProvider: ApprovedProfileListingProvider;
  readonly connectionValidationProvider?: ConnectionValidationProvider;
}

function nativeValidationSession(): Pick<WindowsValidationSession, 'validate'> | undefined {
  if (!supportsWindowsAlphaRuntime()) return undefined;
  try {
    return new WindowsValidationSession();
  } catch {
    return undefined;
  }
}

/**
 * Discovery and validation are composed only on the supported Windows alpha.
 * Agent-key readiness remains wholly native after policy authorization, so a
 * snapshot pathname and OpenSSH command line never cross into TypeScript.
 */
export function createWindowsRuntimeProviders(
  storage: Pick<WindowsSecureStorage, 'listProfiles'> = new WindowsSecureStorage(),
  validationSession: Pick<WindowsValidationSession, 'validate'> | undefined = nativeValidationSession(),
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
            async validateConnection(input: unknown) {
              const selection = validateProfileSelection(input);
              await validationSession.validate(selection);
              return { profileId: selection.profileId, ready: true as const };
            },
          },
        }),
  };
}
