import { ArrowDownToLine, ArrowUpFromLine, Check, TriangleAlert, X } from 'lucide-react'
import type { Transfer } from '../types'

/** Global transfer queue.
 *
 *  Lives in AppLayout, not in SftpView, and that placement is the whole point:
 *  SftpView unmounts when you switch to the terminal, and a queue rendered
 *  inside it took the progress of every in-flight transfer down with it — the
 *  bytes kept moving in Rust, invisibly. Mounted at the shell root, the bar
 *  persists across view and tab switches, so a big download started in Files
 *  keeps showing progress while you work in the terminal. */
export function TransferBar({
  transfers, onClear,
}: {
  transfers: Transfer[]
  onClear: () => void
}) {
  if (transfers.length === 0) return null
  const active = transfers.filter((t) => t.status === 'active').length

  return (
    <div className="shrink-0 border-t border-line bg-surface-1">
      <div className="flex items-center justify-between px-3 py-1 text-[11px] text-ink-faint">
        <span>
          Transfers{active > 0 && <span className="ml-1 text-accent">· {active} active</span>}
        </span>
        <button
          type="button"
          onClick={onClear}
          className="flex items-center gap-1 rounded px-1 hover:bg-surface-3 hover:text-ink"
        >
          <X size={11} aria-hidden />
          Clear finished
        </button>
      </div>

      <ul className="max-h-28 overflow-y-auto">
        {transfers.map((t) => (
          <TransferRow key={t.id} transfer={t} />
        ))}
      </ul>
    </div>
  )
}

const fmtBytes = (n: number) => {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let u = 0
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++ }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[u]}`
}

function TransferRow({ transfer: t }: { transfer: Transfer }) {
  // A zero total means the server declined to report a size. Show an
  // indeterminate bar rather than inventing a denominator.
  const determinate = t.bytesTotal > 0
  const pct = determinate ? Math.min(100, (t.bytesDone / t.bytesTotal) * 100) : 0

  return (
    <li className="flex items-center gap-2 px-3 py-1 text-[11.5px] text-ink-dim">
      {t.direction === 'upload' ? (
        <ArrowUpFromLine size={11} className="shrink-0 text-accent" aria-label="upload" />
      ) : (
        <ArrowDownToLine size={11} className="shrink-0 text-accent" aria-label="download" />
      )}
      <span className="min-w-0 flex-1 truncate font-mono" title={t.path}>
        {t.name}
      </span>

      {t.status === 'active' && (
        <>
          <span
            role="progressbar"
            aria-valuenow={determinate ? Math.round(pct) : undefined}
            aria-valuemin={0}
            aria-valuemax={100}
            className="h-1.5 w-24 shrink-0 overflow-hidden rounded-full bg-surface-3"
          >
            <span
              className={`block h-full rounded-full bg-accent ${
                determinate ? 'transition-[width] duration-150' : 'w-1/3 animate-pulse'
              }`}
              style={determinate ? { width: `${pct}%` } : undefined}
            />
          </span>
          <span className="w-32 shrink-0 text-right font-mono text-[10.5px] tabular-nums text-ink-faint">
            {determinate
              ? `${fmtBytes(t.bytesDone)} / ${fmtBytes(t.bytesTotal)}`
              : fmtBytes(t.bytesDone)}
          </span>
        </>
      )}

      {t.status === 'done' && (
        <>
          <span className="font-mono text-[10.5px] tabular-nums text-ink-faint">
            {fmtBytes(t.bytesDone)}
          </span>
          <Check size={12} className="shrink-0 text-ok" aria-label="complete" />
        </>
      )}

      {t.status === 'error' && (
        <span className="flex min-w-0 items-center gap-1 text-alert" title={t.error}>
          <TriangleAlert size={12} className="shrink-0" aria-label="failed" />
          <span className="truncate">{t.error}</span>
        </span>
      )}
    </li>
  )
}
