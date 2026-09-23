import { AlertTriangle, Circle, CircleDot, Loader2, Plus, X } from 'lucide-react'
import type { Session, SessionStatus } from '../types'

export interface TabGroup {
  id: string
  sessions: Session[]
}

interface Props {
  /** One tab per group, not per session: a split tab holds several sessions. */
  groups: TabGroup[]
  activeId: string | null
  onSelect: (id: string) => void
  onClose: (id: string) => void
  onNew: () => void
  /** Right-click on a tab. Receives the focused session's id. */
  onTabMenu: (sessionId: string, x: number, y: number) => void
}

/** Status is carried by glyph *shape* first and hue second, so the three live
 *  states stay separable without relying on colour discrimination. */
function StatusGlyph({ status }: { status: SessionStatus }) {
  switch (status) {
    case 'connected':
      return <CircleDot size={11} className="shrink-0 text-ok" aria-label="connected" />
    case 'connecting':
      return (
        <Loader2
          size={11}
          className="shrink-0 animate-spin text-warn"
          aria-label="connecting"
        />
      )
    case 'error':
      return <AlertTriangle size={11} className="shrink-0 text-alert" aria-label="error" />
    default:
      return <Circle size={11} className="shrink-0 text-ink-faint" aria-label="disconnected" />
  }
}

export function SessionTabs({ groups, activeId, onSelect, onClose, onNew, onTabMenu }: Props) {
  return (
    <div
      role="tablist"
      aria-label="Active sessions"
      className="flex h-9 shrink-0 items-stretch border-b border-line bg-surface-1"
    >
      <div className="flex min-w-0 flex-1 items-stretch overflow-x-auto">
        {groups.map((group) => {
          // The focused session if this group owns it, else its first pane —
          // so the tab shows the state of whatever clicking it would focus.
          const focused =
            group.sessions.find((s) => s.id === activeId) ?? group.sessions[0]
          const s = focused
          const active = group.sessions.some((x) => x.id === activeId)
          return (
            <div
              key={group.id}
              role="tab"
              aria-selected={active}
              tabIndex={active ? 0 : -1}
              onClick={() => onSelect(s.id)}
              onKeyDown={(e) => e.key === 'Enter' && onSelect(s.id)}
              onAuxClick={(e) => e.button === 1 && onClose(s.id)} // middle-click closes
              onContextMenu={(e) => {
                e.preventDefault()
                onTabMenu(s.id, e.clientX, e.clientY)
              }}
              className={`group relative flex min-w-[9rem] max-w-[14rem] cursor-default items-center gap-2 border-r border-line px-3 text-[12.5px] transition-colors ${
                active
                  ? 'bg-surface-0 text-ink'
                  : 'bg-surface-1 text-ink-dim hover:bg-surface-2'
              }`}
            >
              {/* Top rule marks the active tab without shifting layout. */}
              {active && <span className="absolute inset-x-0 top-0 h-[2px] bg-accent" />}
              <StatusGlyph status={s.status} />
              <span className="truncate">{s.title}</span>
              {group.sessions.length > 1 && (
                <span
                  className="shrink-0 rounded-sm border border-line-strong px-1 text-[10px] tabular-nums text-ink-faint"
                  title={`${group.sessions.length} panes in this tab`}
                >
                  {group.sessions.length}
                </span>
              )}
              <button
                type="button"
                aria-label={`Close ${s.title}`}
                onClick={(e) => {
                  e.stopPropagation()
                  onClose(s.id)
                }}
                className="ml-auto grid h-4 w-4 shrink-0 place-items-center rounded text-ink-faint opacity-0 transition hover:bg-surface-4 hover:text-ink group-hover:opacity-100 focus-visible:opacity-100"
              >
                <X size={11} />
              </button>
            </div>
          )
        })}
      </div>

      <button
        type="button"
        aria-label="New session"
        title="New session to the active host"
        onClick={onNew}
        className="grid w-9 shrink-0 place-items-center border-l border-line text-ink-dim transition-colors hover:bg-surface-2 hover:text-ink"
      >
        <Plus size={15} />
      </button>
    </div>
  )
}
