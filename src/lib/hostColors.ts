/** Per-host accent colours.
 *
 *  This is a safety feature, not decoration: with several firewalls open, a
 *  coloured frame around the active session is the difference between a config
 *  change landing on the lab box and landing on City Hall's production edge.
 *  Red for prod, green for lab, whatever the operator decides — the point is
 *  that the wrong window looks wrong before a command is typed.
 *
 *  Stored as a stable key rather than a hex string so the actual shades can be
 *  tuned in one place, and so the set stays small and colourblind-separable
 *  (these differ in lightness as well as hue). `none` is the default and paints
 *  nothing.
 */
export type HostColor = 'none' | 'red' | 'amber' | 'green' | 'blue' | 'violet'

export const HOST_COLORS: { key: HostColor; label: string; hex: string }[] = [
  { key: 'none', label: 'None', hex: 'transparent' },
  { key: 'red', label: 'Production', hex: '#e5484d' },
  { key: 'amber', label: 'Staging', hex: '#f2b25c' },
  { key: 'green', label: 'Lab', hex: '#4ec9a8' },
  { key: 'blue', label: 'Default', hex: '#4f9cf9' },
  { key: 'violet', label: 'Special', hex: '#b98bfa' },
]

const BY_KEY = new Map(HOST_COLORS.map((c) => [c.key, c.hex]))

/** Hex for a host colour key, or null for `none`/unset — callers skip painting
 *  on null rather than drawing a transparent rule. */
export function hostColorHex(key: HostColor | undefined): string | null {
  if (!key || key === 'none') return null
  return BY_KEY.get(key) ?? null
}
