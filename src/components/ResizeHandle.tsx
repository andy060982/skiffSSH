import { useRef } from 'react'

/** A thin drag strip with a generous hit area.
 *
 *  Uses pointer capture so the drag survives the cursor leaving the element —
 *  the usual failure mode of naive mousemove splitters, and the reason a
 *  half-dragged divider sticks when you move fast. Reports a delta along the
 *  relevant axis; the parent owns the sizes.
 *
 *  `axis` is the direction of movement, not the direction the bar is drawn:
 *  a vertical divider between side-by-side panes moves on x.
 */
export function ResizeHandle({
  onResize,
  onReset,
  axis = 'x',
  'aria-label': ariaLabel,
}: {
  onResize: (delta: number) => void
  onReset?: () => void
  axis?: 'x' | 'y'
  'aria-label': string
}) {
  const last = useRef(0)
  const horizontal = axis === 'x'

  return (
    <div
      role="separator"
      aria-orientation={horizontal ? 'vertical' : 'horizontal'}
      aria-label={ariaLabel}
      tabIndex={0}
      onDoubleClick={onReset}
      onKeyDown={(e) => {
        const back = horizontal ? 'ArrowLeft' : 'ArrowUp'
        const fwd = horizontal ? 'ArrowRight' : 'ArrowDown'
        if (e.key === back) onResize(-16)
        if (e.key === fwd) onResize(16)
      }}
      onPointerDown={(e) => {
        last.current = horizontal ? e.clientX : e.clientY
        e.currentTarget.setPointerCapture(e.pointerId)
      }}
      onPointerMove={(e) => {
        if (!e.currentTarget.hasPointerCapture(e.pointerId)) return
        const pos = horizontal ? e.clientX : e.clientY
        onResize(pos - last.current)
        last.current = pos
      }}
      onPointerUp={(e) => e.currentTarget.releasePointerCapture(e.pointerId)}
      className={`group relative z-10 shrink-0 ${
        horizontal
          ? '-mx-[2px] w-[5px] cursor-col-resize'
          : '-my-[2px] h-[5px] cursor-row-resize'
      }`}
    >
      <span
        className={`absolute bg-line transition-colors group-hover:bg-accent group-focus-visible:bg-accent ${
          horizontal
            ? 'inset-y-0 left-1/2 w-px -translate-x-1/2'
            : 'inset-x-0 top-1/2 h-px -translate-y-1/2'
        }`}
      />
    </div>
  )
}
