import type { DirListing, PaneSide } from '../types'
import { safeInvoke, inTauri } from './tauri'
import { mockLocalListing, mockRemoteListing } from '../data/mockHosts'

/* ---------------------------------------------------------------------------
   The only module that knows command names. Everything above it works in terms
   of "list this directory", so renaming a Rust command is a one-file change and
   the browser-fallback path lives in exactly one place.
--------------------------------------------------------------------------- */

export async function listDirectory(
  side: PaneSide,
  sessionId: string,
  path: string,
): Promise<DirListing> {
  if (!inTauri()) {
    // Layout work in a plain browser: serve the fixtures, ignore the path.
    return side === 'local' ? mockLocalListing : mockRemoteListing
  }

  const cmd = side === 'local' ? 'local_list' : 'sftp_list'
  const res = await safeInvoke<DirListing>(cmd, { sessionId, path })
  if (!res) throw new Error(`${cmd} returned nothing`)
  return res
}

export async function transfer(
  direction: 'upload' | 'download',
  sessionId: string,
  localPath: string,
  remotePath: string,
): Promise<void> {
  const cmd = direction === 'upload' ? 'sftp_put' : 'sftp_get'
  await safeInvoke(cmd, { sessionId, localPath, remotePath })
}

/* --------------------------------------------------------------- path utils */

/** Join for display and navigation. Local paths are Windows-flavoured, remote
 *  paths are always POSIX — mixing the two separators is the most common source
 *  of "file not found" in a dual-pane client. */
export function joinPath(side: PaneSide, base: string, name: string): string {
  if (side === 'remote') {
    return base === '/' ? `/${name}` : `${base.replace(/\/+$/, '')}/${name}`
  }
  return base.endsWith('\\') ? `${base}${name}` : `${base}\\${name}`
}

export function parentPath(side: PaneSide, path: string): string {
  if (side === 'remote') {
    const trimmed = path.replace(/\/+$/, '')
    const cut = trimmed.lastIndexOf('/')
    return cut <= 0 ? '/' : trimmed.slice(0, cut)
  }
  const trimmed = path.replace(/\\+$/, '')
  const cut = trimmed.lastIndexOf('\\')
  // "C:" alone is not a valid path; keep the trailing separator on a drive root.
  return cut <= 2 ? `${trimmed.slice(0, 3)}` : trimmed.slice(0, cut)
}

export function basename(side: PaneSide, path: string): string {
  const sep = side === 'remote' ? '/' : '\\'
  const parts = path.split(sep).filter(Boolean)
  return parts[parts.length - 1] ?? path
}
