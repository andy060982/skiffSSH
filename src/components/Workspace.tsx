import { Columns2, FolderTree, Radio, Rows2, ServerOff, SquareTerminal, Unlink } from 'lucide-react'
import type { Session, WorkspaceView } from '../types'
import { TerminalDeck, type SplitOrientation } from './TerminalDeck'
import { SftpView } from './SftpView'

interface Props {
  /** Every open session, so the terminal deck can keep them all alive. */
  sessions: Session[]
  session?: Session
  onChangeView: (view: WorkspaceView) => void
  onSize?: (sessionId: string, cols: number, rows: number) => void
  /** Sessions sharing the active session's group, left to right. */
  groupSessions: Session[]
  onFocusSession: (sessionId: string) => void
  onSplit: () => void
  onSeparate: (sessionId: string) => void
  orientation: SplitOrientation
  onToggleOrientation: () => void
  paneSizes: Record<string, number>
  onPaneResize: (sessionId: string, deltaPx: number, containerPx: number) => void
  onResetPaneSizes: () => void
  onStartTransfer: (
    sessionId: string,
    direction: 'upload' | 'download',
    jobs: { name: string; local: string; remote: string }[],
  ) => void
  sftpPaths: Record<string, { local?: string; remote?: string }>
  onSftpPathsChange: (
    fn: (prev: Record<string, { local?: string; remote?: string }>) => Record<string, { local?: string; remote?: string }>,
  ) => void
  transferTick: number
  /** Accent hex of the active host, or null. Paints a frame as a wrong-window
   *  guard. */
  accentHex: string | null
  broadcast: boolean
  onToggleBroadcast: () => void
}

export function Workspace({
  sessions, session, onChangeView, onSize, groupSessions, onFocusSession, onSplit, onSeparate,
  orientation, onToggleOrientation, paneSizes, onPaneResize, onResetPaneSizes,
  onStartTransfer, sftpPaths, onSftpPathsChange, transferTick, accentHex, broadcast, onToggleBroadcast,
}: Props) {
  if (!session || sessions.length === 0) return <EmptyState />

  return (
    <div
      className="flex min-h-0 flex-1 flex-col bg-surface-0"
      // A 2px inset frame in the host's accent colour. Cheap, always visible,
      // and the whole point of per-host colour: the wrong firewall looks wrong
      // before anything is typed. box-shadow rather than border so it does not
      // shift the layout by 2px when a plain host has no accent.
      style={accentHex ? { boxShadow: `inset 0 0 0 2px ${accentHex}` } : undefined}
    >
      {/* View switcher. Terminal and SFTP are two lenses on one connection, not
          two connections — the toggle lives here rather than in the tab strip so
          a tab keeps meaning "a host I am connected to". */}
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-surface-0 px-2">
        <div
          role="tablist"
          aria-label="Workspace view"
          className="flex items-center gap-0.5 rounded border border-line bg-surface-1 p-0.5"
        >
          <ViewTab
            active={session.view === 'terminal'}
            onClick={() => onChangeView('terminal')}
            icon={<SquareTerminal size={12} />}
            label="Terminal"
          />
          <ViewTab
            active={session.view === 'sftp'}
            onClick={() => onChangeView('sftp')}
            icon={<FolderTree size={12} />}
            label="Files"
          />
        </div>
        <div className="ml-auto flex items-center gap-1">
          {session.view === 'terminal' && (
            <>
              <button
                type="button"
                onClick={onSplit}
                title="Open a second session to this host, side by side"
                className="flex h-[22px] items-center gap-1 rounded border border-line px-1.5 text-[11.5px] text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink"
              >
                <Columns2 size={12} aria-hidden />
                Split
              </button>
              {groupSessions.length > 1 && (
                <button
                  type="button"
                  onClick={onToggleOrientation}
                  title={
                    orientation === 'columns'
                      ? 'Stack panes top and bottom'
                      : 'Place panes side by side'
                  }
                  className="flex h-[22px] items-center gap-1 rounded border border-line px-1.5 text-[11.5px] text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink"
                >
                  {orientation === 'columns' ? (
                    <Rows2 size={12} aria-hidden />
                  ) : (
                    <Columns2 size={12} aria-hidden />
                  )}
                  {orientation === 'columns' ? 'Stack' : 'Side by side'}
                </button>
              )}
              {groupSessions.length > 1 && (
                <button
                  type="button"
                  onClick={onToggleBroadcast}
                  aria-pressed={broadcast}
                  title="Type once, send to every pane in this tab"
                  className={`flex h-[22px] items-center gap-1 rounded border px-1.5 text-[11.5px] transition-colors ${
                    broadcast
                      ? 'border-warn/60 bg-warn/15 text-warn'
                      : 'border-line text-ink-dim hover:bg-surface-3 hover:text-ink'
                  }`}
                >
                  <Radio size={12} aria-hidden />
                  {broadcast ? 'Broadcasting' : 'Broadcast'}
                </button>
              )}
              {groupSessions.length > 1 && (
                <button
                  type="button"
                  onClick={() => onSeparate(session.id)}
                  title="Move this pane out into its own tab"
                  className="flex h-[22px] items-center gap-1 rounded border border-line px-1.5 text-[11.5px] text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink"
                >
                  <Unlink size={12} aria-hidden />
                  Separate
                </button>
              )}
            </>
          )}
          <span className="ml-1 font-mono text-[11px] text-ink-faint">Ctrl+Shift+E</span>
        </div>
      </div>

      {/* Both surfaces are absolutely positioned siblings in one relative box.
          The terminal deck is always mounted; SFTP is layered over it when
          selected. Swapping which one is *rendered* would destroy terminal
          state on every view toggle. */}
      <div className="relative min-h-0 flex-1">
        <TerminalDeck
          sessions={sessions}
          visibleIds={
            session.view === 'terminal' ? groupSessions.map((g) => g.id) : []
          }
          focusedId={session.id}
          orientation={orientation}
          sizes={paneSizes}
          broadcast={broadcast}
          onResize={onPaneResize}
          onResetSizes={onResetPaneSizes}
          onFocus={onFocusSession}
          onSize={onSize}
        />
        {session.view === 'sftp' && (
          <div className="absolute inset-0">
            <SftpView
              key={session.id}
              session={session}
              onStartTransfer={onStartTransfer}
              savedPaths={sftpPaths[session.id]}
              onPathsChange={(local, remote) =>
                onSftpPathsChange((prev) => ({ ...prev, [session.id]: { local, remote } }))
              }
              transferTick={transferTick}
            />
          </div>
        )}
      </div>
    </div>
  )
}

function ViewTab({
  active, onClick, icon, label,
}: {
  active: boolean
  onClick: () => void
  icon: React.ReactNode
  label: string
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={`flex h-[22px] items-center gap-1.5 rounded-sm px-2 text-[11.5px] transition-colors ${
        active ? 'bg-surface-4 text-ink' : 'text-ink-dim hover:text-ink'
      }`}
    >
      {icon}
      {label}
    </button>
  )
}

function EmptyState() {
  return (
    <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-3 bg-surface-0 text-center">
      <ServerOff size={28} className="text-ink-faint" aria-hidden />
      <div>
        <p className="text-[13px] text-ink-dim">No active session</p>
        <p className="mt-1 text-[12px] text-ink-faint">
          Double-click a host in the sidebar to connect. Press{' '}
          <kbd className="rounded border border-line bg-surface-2 px-1 py-px font-mono text-[10.5px]">
            Ctrl+Shift+K
          </kbd>{' '}
          to search hosts.
        </p>
      </div>
    </div>
  )
}
