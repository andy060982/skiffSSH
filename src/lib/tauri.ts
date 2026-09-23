/** Tauri runtime helpers that degrade gracefully in a plain browser.
 *
 *  `npm run dev` serves the UI at localhost:1420 with no Tauri host attached,
 *  which is by far the fastest way to iterate on layout. Everything here must
 *  therefore no-op rather than throw when the IPC bridge is absent. */

export const inTauri = (): boolean =>
  typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window

type WindowAction = 'minimize' | 'toggleMaximize' | 'close'

export async function windowAction(action: WindowAction): Promise<void> {
  if (!inTauri()) return
  const { getCurrentWindow } = await import('@tauri-apps/api/window')
  const w = getCurrentWindow()
  if (action === 'minimize') await w.minimize()
  else if (action === 'toggleMaximize') await w.toggleMaximize()
  else await w.close()
}

/** invoke() that degrades to a no-op outside Tauri, so the UI can be driven in
 *  a plain browser during layout work. Returns undefined when there is no host.
 *  Errors are surfaced rather than swallowed — a failed ssh_write is a real bug. */
export async function safeInvoke<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T | undefined> {
  if (!inTauri()) return undefined
  const { invoke } = await import('@tauri-apps/api/core')
  return invoke<T>(cmd, args)
}

/** listen() that resolves to a no-op unsubscriber outside Tauri. */
export async function safeListen<T>(
  event: string,
  handler: (payload: T) => void,
): Promise<() => void> {
  if (!inTauri()) return () => {}
  const { listen } = await import('@tauri-apps/api/event')
  const un = await listen<T>(event, (e) => handler(e.payload))
  return un
}

/** Native file drops from Explorer, with paths. Browser drag events only carry
 *  File objects with no filesystem path, so this MUST come from Tauri's webview
 *  API; in a plain browser it is a no-op. Returns an unsubscribe. */
export async function onFileDrop(
  handler: (paths: string[]) => void,
): Promise<() => void> {
  if (!inTauri()) return () => {}
  const { getCurrentWebview } = await import('@tauri-apps/api/webview')
  const un = await getCurrentWebview().onDragDropEvent((event) => {
    if (event.payload.type === 'drop' && event.payload.paths.length > 0) {
      handler(event.payload.paths)
    }
  })
  return un
}
