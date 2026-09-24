/** Heuristic detection of destructive commands, for the pre-send guard.
 *
 *  Best-effort, like the AI secret scanner: it catches the well-known
 *  foot-guns across Linux and network gear so a paste, snippet, or broadcast of
 *  one pauses for a confirm. It is not a sandbox and cannot catch everything —
 *  a creative rewrite slips it — so it errs toward the obvious shapes and lets
 *  the human decide.
 */
const RULES: { re: RegExp; reason: string }[] = [
  { re: /\brm\s+-[a-z]*[rf]/i, reason: 'rm -rf (recursive/forced delete)' },
  { re: /\bmkfs(\.\w+)?\b/i, reason: 'mkfs (format a filesystem)' },
  { re: /\bdd\b[^\n]*\bof=\/dev\//i, reason: 'dd writing to a device' },
  { re: />\s*\/dev\/(sd|nvme|vd|hd)/i, reason: 'redirect over a raw disk' },
  { re: /\b(shutdown|poweroff|halt|reboot)\b/i, reason: 'power/reboot command' },
  { re: /:\s*\(\s*\)\s*\{/, reason: 'shell fork bomb' },
  // Network gear
  { re: /\breload\b/i, reason: 'reload (device restart)' },
  { re: /\bwrite\s+erase\b/i, reason: 'write erase (wipe config)' },
  { re: /\berase\s+(startup-config|flash|nvram)/i, reason: 'erase config/flash' },
  { re: /\bdelete\s+\/force\b/i, reason: 'delete /force' },
  { re: /\bformat\s+(flash|disk\d)/i, reason: 'format flash/disk' },
  { re: /\brequest\s+system\s+(shutdown|reboot|zeroize)/i, reason: 'PAN-OS/Junos system shutdown' },
  { re: /\bfactory-default\b/i, reason: 'factory-default reset' },
]

/** Returns a short reason if the text looks destructive, else null. */
export function isDangerousCommand(text: string): string | null {
  for (const { re, reason } of RULES) {
    if (re.test(text)) return reason
  }
  return null
}
