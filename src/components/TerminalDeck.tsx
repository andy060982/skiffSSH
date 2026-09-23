import { useRef } from 'react'
import type { Session } from '../types'
import { TerminalPane } from './TerminalPane'
import { ResizeHandle } from './ResizeHandle'

export type SplitOrientation = 'columns' | 'rows'

/** Holds one live TerminalPane per open session, showing only the active group.
 *
 *  Panes are unmounted only when their session is actually closed — hiding them
 *  with `hidden` keeps the xterm instance and its scrollback alive across tab
 *  switches, which is the whole reason this component exists.
 *
 *  That constraint drives an otherwise odd structure: the divider for a pane is
 *  rendered *inside* that pane's wrapper rather than as a sibling between
 *  wrappers. Interleaving separate handle elements would mean the visible panes
 *  sit at shifting positions in the child list, and React unmounts a component
 *  whose position changes — taking the terminal buffer with it. Keeping each
 *  wrapper at a fixed index makes the tree stable no matter which panes are
 *  visible or how they are ordered.
 */
export function TerminalDeck({
  sessions,
  visibleIds,
  focusedId,
  orientation,
  sizes,
  broadcast,
  onResize,
  onResetSizes,
  onFocus,
  onSize,
}: {
  sessions: Session[]
  /** Sessions to show, in order. */
  visibleIds: string[]
  focusedId: string | null
  orientation: SplitOrientation
  /** flex-grow per session id; absent means 1. */
  sizes: Record<string, number>
  /** When true, input to the focused pane is mirrored to its siblings. */
  broadcast: boolean
  /** Drag delta in px for the divider before `sessionId`. */
  onResize: (sessionId: string, deltaPx: number, containerPx: number) => void
  onResetSizes: () => void
  onFocus: (sessionId: string) => void
  onSize?: (sessionId: string, cols: number, rows: number) => void
}) {
  const boxRef = useRef<HTMLDivElement>(null)
  const columns = orientation === 'columns'
  const split = visibleIds.length > 1

  return (
    <div
      ref={boxRef}
      className={`flex h-full w-full ${columns ? 'flex-row' : 'flex-col'}`}
    >
      {sessions.map((s) => {
        const visible = visibleIds.includes(s.id)
        // A divider goes before every visible pane except the first one.
        const showHandle = visible && split && visibleIds.indexOf(s.id) > 0

        return (
          <div
            key={s.id}
            hidden={!visible}
            onMouseDown={() => onFocus(s.id)}
            style={{ flexGrow: sizes[s.id] ?? 1, flexBasis: 0 }}
            className={`flex min-h-0 min-w-0 ${columns ? 'flex-row' : 'flex-col'} ${
              split && focusedId === s.id ? 'ring-1 ring-accent/40 ring-inset' : ''
            }`}
          >
            {showHandle && (
              <ResizeHandle
                axis={columns ? 'x' : 'y'}
                aria-label="Resize panes"
                onReset={onResetSizes}
                onResize={(delta) => {
                  const box = boxRef.current
                  if (!box) return
                  onResize(
                    s.id,
                    delta,
                    columns ? box.clientWidth : box.clientHeight,
                  )
                }}
              />
            )}
            <div className="relative min-h-0 min-w-0 flex-1">
              <TerminalPane
                session={s}
                visible={visible}
                onSize={onSize}
                broadcastTo={
                  // Only the focused pane fans out, to the other visible panes;
                  // otherwise every pane would echo every other and loop.
                  broadcast && split && s.id === focusedId
                    ? visibleIds.filter((id) => id !== s.id)
                    : undefined
                }
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}
