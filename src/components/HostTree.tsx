import { ChevronRight, Folder, FolderOpen, KeyRound, Pencil, Server, UserRound, Wifi, WifiOff } from 'lucide-react'
import { type Host, type HostNode, isFolder } from '../types'
import { countHosts } from '../lib/tree'

interface Props {
  nodes: HostNode[]
  depth?: number
  expanded: Set<string>
  onToggle: (id: string) => void
  onOpen: (host: Host) => void
  /** Single click: focus this host's session if it has one, else just select. */
  onSelect: (host: Host) => void
  onEdit: (host: Host) => void
  /** Right-click on a host row. */
  onMenu: (host: Host, x: number, y: number) => void
  onFolderMenu: (folderId: string, name: string, x: number, y: number) => void
  /** Last reachability sweep, by host id. Absent = never probed. */
  reachability?: Record<string, { ok: boolean; ms?: number }>
  /** Host ids with a live session, so the tree can say so. */
  openHostIds?: Set<string>
  activeHostId?: string
}

/** Recursive tree. Indentation is applied via padding on the row rather than
 *  nested margins so the hover/selection highlight always spans the full
 *  sidebar width — nested containers would inset it one step per level. */
export function HostTree({
  nodes, depth = 0, expanded, onToggle, onOpen, onSelect, onEdit, onMenu, onFolderMenu, reachability, openHostIds, activeHostId,
}: Props) {
  return (
    <ul role="group" className="min-w-0">
      {nodes.map((node) =>
        isFolder(node) ? (
          <li key={node.id} role="treeitem" aria-expanded={expanded.has(node.id)}>
            <button
              type="button"
              onClick={() => onToggle(node.id)}
              onContextMenu={(e) => {
                e.preventDefault()
                onFolderMenu(node.id, node.name, e.clientX, e.clientY)
              }}
              style={{ paddingLeft: 8 + depth * 14 }}
              className="group flex h-7 w-full items-center gap-1.5 pr-2 text-left text-ink-dim transition-colors hover:bg-surface-2 hover:text-ink"
            >
              <ChevronRight
                size={12}
                className={`shrink-0 transition-transform duration-150 ${
                  expanded.has(node.id) ? 'rotate-90' : ''
                }`}
                aria-hidden
              />
              {expanded.has(node.id) ? (
                <FolderOpen size={13} className="shrink-0 text-warn" aria-hidden />
              ) : (
                <Folder size={13} className="shrink-0 text-warn" aria-hidden />
              )}
              <span className="truncate text-[12.5px]">{node.name}</span>
              <span className="ml-auto shrink-0 text-[10.5px] tabular-nums text-ink-faint opacity-0 transition-opacity group-hover:opacity-100">
                {countHosts(node.children)}
              </span>
            </button>

            {expanded.has(node.id) && (
              <HostTree
                nodes={node.children}
                depth={depth + 1}
                expanded={expanded}
                onToggle={onToggle}
                onOpen={onOpen}
                onSelect={onSelect}
                onEdit={onEdit}
                onMenu={onMenu}
                onFolderMenu={onFolderMenu}
                reachability={reachability}
                openHostIds={openHostIds}
                activeHostId={activeHostId}
              />
            )}
          </li>
        ) : (
          <li key={node.id} role="treeitem">
            <HostRow
              host={node}
              depth={depth}
              active={node.id === activeHostId}
              onOpen={onOpen}
              onSelect={onSelect}
              onEdit={onEdit}
              onMenu={onMenu}
              probe={reachability?.[node.id]}
              open={openHostIds?.has(node.id) ?? false}
            />
          </li>
        ),
      )}
    </ul>
  )
}

function HostRow({
  host, depth, active, onOpen, onSelect, onEdit, onMenu, probe, open,
}: {
  host: Host
  depth: number
  active: boolean
  onOpen: (h: Host) => void
  onSelect: (h: Host) => void
  onEdit: (h: Host) => void
  onMenu: (h: Host, x: number, y: number) => void
  probe?: { ok: boolean; ms?: number }
  open: boolean
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect(host)}
      onDoubleClick={() => onOpen(host)}
      onContextMenu={(e) => {
        e.preventDefault()
        onMenu(host, e.clientX, e.clientY)
      }}
      onKeyDown={(e) => e.key === 'Enter' && onOpen(host)}
      style={{ paddingLeft: 8 + depth * 14 + 14 }}
      title={
        open
          ? `${host.username}@${host.hostname}:${host.port} — session open, double-click to focus it`
          : `${host.username}@${host.hostname}:${host.port} — double-click to connect`
      }
      className={`group flex h-7 w-full items-center gap-1.5 pr-2 text-left transition-colors ${
        active
          ? 'bg-accent-soft text-ink'
          : 'text-ink-dim hover:bg-surface-2 hover:text-ink'
      }`}
    >
      <Server
        size={13}
        className={`shrink-0 ${active ? 'text-accent' : 'text-ink-faint'}`}
        aria-hidden
      />
      {/* A session already exists for this host. Without this cue the only way
          to know was to scan the tab strip, which is how duplicate connections
          kept getting opened. */}
      {open && (
        <span
          className="h-1.5 w-1.5 shrink-0 rounded-full bg-ok"
          title="session open"
          aria-label="session open"
        />
      )}
      {/* Reachability from the last sweep. Distinct glyph shapes, not just
          hue — and only rendered once a sweep has actually run, so the tree
          never claims knowledge it does not have. */}
      {probe && !open && (
        probe.ok ? (
          <Wifi
            size={10}
            className="shrink-0 text-ok"
            aria-label={`reachable${probe.ms != null ? `, ${probe.ms} ms` : ''}`}
          />
        ) : (
          <WifiOff size={10} className="shrink-0 text-alert" aria-label="unreachable" />
        )
      )}
      <span className="truncate text-[12.5px]">{host.name}</span>

      {/* Auth method as a glyph, not a colour: agent/key/password must stay
          distinguishable for colour-vision-deficient users. */}
      {host.auth === 'agent' && (
        <UserRound size={11} className="shrink-0 text-ink-faint" aria-label="agent auth" />
      )}
      {host.auth === 'key' && (
        <KeyRound size={11} className="shrink-0 text-ink-faint" aria-label="key auth" />
      )}

      {host.tag && (
        <span className="ml-auto shrink-0 rounded-sm border border-line-strong px-1 text-[10px] uppercase tracking-wide text-ink-faint">
          {host.tag}
        </span>
      )}

      {/* Edit affordance. Appears on hover so the row stays quiet at rest, but
          is always reachable by keyboard. */}
      <span
        role="button"
        tabIndex={0}
        aria-label={`Edit ${host.name}`}
        title="Edit host"
        onClick={(e) => { e.stopPropagation(); onEdit(host) }}
        onKeyDown={(e) => { if (e.key === 'Enter') { e.stopPropagation(); onEdit(host) } }}
        className={`grid h-4 w-4 shrink-0 place-items-center rounded text-ink-faint opacity-0 transition hover:bg-surface-4 hover:text-ink group-hover:opacity-100 focus-visible:opacity-100 ${host.tag ? 'ml-1' : 'ml-auto'}`}
      >
        <Pencil size={10} />
      </span>
    </div>
  )
}
