import type { OrganizationLegalIdentifier } from '../organization-admission-verifier.js'

/** Correlates organization NIF and Spanish VAT representation without rewriting foreign identifiers. */
export function normalizeSpanishOrganizationIdentifier(
  identifier: OrganizationLegalIdentifier,
): OrganizationLegalIdentifier | undefined {
  const scheme = identifier.scheme.trim().toUpperCase()
  if (scheme !== 'NIF' && scheme !== 'VAT') return undefined
  const value = identifier.value.trim().toUpperCase().replace(/^(?:VATES-|ES)/u, '')
  if (!/^[A-Z][0-9]{7}[0-9A-Z]$/u.test(value)) return undefined
  return { scheme: 'NIF', value }
}
