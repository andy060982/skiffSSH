import type { Terminal } from '@xterm/xterm'
import type { SearchAddon } from '@xterm/addon-search'

/** Live xterm instances by session id.
 *
 *  Exists so shell-level features (find bar, snippet paste) can reach the
 *  focused pane's Terminal without threading refs through five components.
 *  A module-level map rather than context because the terminals live outside
 *  React's render cycle anyway — they are imperative objects that mount once
 *  and survive re-renders by design. */
const terms = new Map<string, { term: Terminal; search: SearchAddon }>()

export function registerTerm(sessionId: string, term: Terminal, search: SearchAddon): void {
  terms.set(sessionId, { term, search })
}

export function unregisterTerm(sessionId: string): void {
  terms.delete(sessionId)
}

export function getTerm(sessionId: string): { term: Terminal; search: SearchAddon } | undefined {
  return terms.get(sessionId)
}
