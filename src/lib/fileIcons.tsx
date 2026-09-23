import {
  Archive, Braces, Database, FileCode2, FileImage, FileSpreadsheet, FileText,
  File as FileIcon, FileTerminal, Folder, KeyRound, Link2, Lock, Settings2,
} from 'lucide-react'
import type { FileEntry } from '../types'

/** Extension -> icon. Kept as one table rather than a chain of regexes so the
 *  mapping is greppable and a new type is a one-line change.
 *
 *  Tints are muted on purpose: a file grid where every row is a different
 *  saturated colour reads as noise. Only two categories get real colour —
 *  directories (structure) and credentials (danger of touching them) — and
 *  everything else varies by glyph shape alone. */
const BY_EXT: Record<string, { Icon: typeof FileIcon; tint: string }> = {}

const register = (exts: string[], Icon: typeof FileIcon, tint = 'text-ink-faint') => {
  for (const e of exts) BY_EXT[e] = { Icon, tint }
}

register(['md', 'markdown', 'txt', 'rst', 'log'], FileText)
register(['json', 'jsonc', 'json5'], Braces)
register(['yaml', 'yml', 'toml', 'ini', 'conf', 'cfg', 'properties'], Settings2)
register(['xml', 'html', 'htm', 'css', 'scss'], FileCode2)
register(['ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs', 'rs', 'go', 'py', 'rb', 'java', 'c', 'h', 'cpp', 'cs', 'php'], FileCode2)
register(['sh', 'bash', 'zsh', 'ps1', 'bat', 'cmd'], FileTerminal)
register(['csv', 'tsv', 'xlsx', 'xls'], FileSpreadsheet)
register(['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'bmp', 'ico'], FileImage)
register(['zip', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'zst', '7z', 'rar'], Archive)
register(['db', 'sqlite', 'sqlite3', 'sql', 'dump'], Database)
register(['pem', 'key', 'crt', 'cer', 'pfx', 'p12', 'pub'], KeyRound, 'text-alert')

/** Filenames that are credentials regardless of extension. */
const SENSITIVE = new Set([
  'id_rsa', 'id_ed25519', 'id_ecdsa', 'authorized_keys', 'known_hosts',
  '.env', 'shadow', 'passwd', '.htpasswd', 'credentials',
])

export function iconFor(entry: FileEntry): {
  Icon: typeof FileIcon
  tint: string
  label: string
} {
  if (entry.kind === 'directory') {
    return { Icon: Folder, tint: 'text-warn', label: 'folder' }
  }
  if (entry.kind === 'symlink') {
    return { Icon: Link2, tint: 'text-accent', label: 'symlink' }
  }

  const lower = entry.name.toLowerCase()
  if (SENSITIVE.has(lower)) {
    return { Icon: Lock, tint: 'text-alert', label: 'sensitive file' }
  }

  const dot = lower.lastIndexOf('.')
  const ext = dot > 0 ? lower.slice(dot + 1) : ''
  const hit = BY_EXT[ext]
  return hit
    ? { Icon: hit.Icon, tint: hit.tint, label: `${ext} file` }
    : { Icon: FileIcon, tint: 'text-ink-faint', label: 'file' }
}
