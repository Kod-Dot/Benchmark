/** The licence Microsoft said an area needs, when it refused for want of one.
 * Mirrors `licence_needed` in dca-core's entra module. */
export function licenceNeeded(message: string | undefined): string | null {
  if (!message) return null;
  if (message.includes('Request not applicable to target tenant')) return 'a Microsoft Intune licence';
  if (message.includes('AadPremiumLicenseRequired') || message.includes('does not have access to any of the reviews'))
    return 'Microsoft Entra ID P2 or ID Governance';
  return null;
}
