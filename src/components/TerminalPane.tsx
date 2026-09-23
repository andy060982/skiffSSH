import { useEffect, useRef } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebglAddon } from '@xterm/addon-webgl'
import { SearchAddon } from '@xterm/addon-search'
import type { Session } from '../types'
import { safeInvoke, safeListen, inTauri } from '../lib/tauri'
import { onLocal } from '../lib/localTerm'
import { registerTerm, unregisterTerm } from '../lib/termRegistry'
import {
  TERMINAL_FONT,
  TERMINAL_FONT_SIZE,
  TERMINAL_LINE_HEIGHT,
  buildTerminalTheme,
} from '../lib/terminalTheme'

/* ---------------------------------------------------------------------------
   One xterm instance, bound to one session, for the lifetime of that session.

   This component is mounted for EVERY open session (see TerminalDeck) and
   merely hidden when its tab is inactive. That is deliberate: destroying and
   recreating a Terminal on tab switch throws away scrollback, viewport
   position, and any in-progress line edit. Mount cost is a few hundred KB of
   buffer; the alternative is the most-reported bug in tabbed SSH clients.

   Consequence: the main effect must have a stable dependency list. If it
   re-runs on anything but session.id, the terminal is silently rebuilt and the
   bug returns through the side door.
--------------------------------------------------------------------------- */

interface Props {
  session: Session
  visible: boolean
  /** Reports the measured grid after every fit, so the status bar can show the
   *  real geometry instead of a guess. */
  onSize?: (sessionId: string, cols: number, rows: number) => void
  /** Other session ids to mirror this pane's input to (broadcast mode). Only
   *  the focused pane should carry these, or panes would echo each other. */
  broadcastTo?: string[]
}

export function TerminalPane({ session, visible, onSize, broadcastTo }: Props) {
  const hostRef = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  /** Last dimensions pushed to the backend, to suppress duplicate PTY resizes. */
  const sizeRef = useRef({ cols: 0, rows: 0 })
  // Held in refs: putting these in the effect deps would tear down and rebuild
  // the terminal whenever the parent re-rendered, losing all scrollback.
  const onSizeRef = useRef(onSize)
  onSizeRef.current = onSize
  const broadcastRef = useRef<string[]>(broadcastTo ?? [])
  broadcastRef.current = broadcastTo ?? []

  useEffect(() => {
    const host = hostRef.current
    if (!host) return

    const term = new Terminal({
      fontFamily: TERMINAL_FONT,
      fontSize: TERMINAL_FONT_SIZE,
      lineHeight: TERMINAL_LINE_HEIGHT,
      letterSpacing: 0,
      theme: buildTerminalTheme(),
      cursorBlink: true,
      cursorStyle: 'block',
      scrollback: 10_000,
      // SSH servers send well-formed CRLF; converting again doubles line breaks.
      convertEol: false,
      allowProposedApi: true,
    })

    const fit = new FitAddon()
    term.loadAddon(fit)
    const search = new SearchAddon()
    term.loadAddon(search)
    term.open(host)
    registerTerm(session.id, term, search)

    // WebGL renderer: the difference between smooth and unusable when tailing a
    // busy log. Context loss (GPU reset, driver update, RDP reconnect) silently
    // blanks the canvas unless we dispose and let xterm fall back to the DOM
    // renderer.
    let webgl: WebglAddon | null = null
    try {
      const addon = new WebglAddon()
      addon.onContextLoss(() => {
        addon.dispose()
        webgl = null
      })
      term.loadAddon(addon)
      webgl = addon
    } catch {
      // No WebGL available (software rendering, GPU policy) — DOM renderer.
    }

    termRef.current = term
    fitRef.current = fit

    /* ---------------------------------------------------- keystrokes out */

    // onData is the correct hook, not a keydown listener: it delivers decoded
    // input AFTER xterm has handled IME composition, bracketed paste, and
    // modifier encoding. Pasted text, dead keys, and arrow-key escape sequences
    // all arrive as the exact bytes the remote PTY expects.
    // ssh_write takes Vec<u8>. TextEncoder produces the UTF-8 bytes the PTY
    // expects; handing over the JS string would re-encode anything outside
    // ASCII and corrupt both pasted text and escape sequences.
    const encoder = new TextEncoder()

    // A write into a session that never connected rejects with "no open
    // session". Swallowing that is what made a dead tab look like a hung app:
    // keys vanish, Enter does nothing, no clue why. Report it once — per
    // keystroke would paint the screen with duplicates.
    let warnedDead = false
    const send = (bytes: number[]) => {
      void safeInvoke('ssh_write', { sessionId: session.id, data: bytes }).catch(
        (e: unknown) => {
          if (warnedDead) return
          warnedDead = true
          const msg = e instanceof Error ? e.message : String(e)
          term.write(
            `\r\n\x1b[38;2;242;178;92m● input not sent\x1b[0m ${msg}\r\n` +
              `\x1b[38;5;244mThis tab is not connected. Close it and reconnect from the sidebar.\x1b[0m\r\n`,
          )
        },
      )
      // Broadcast: mirror the same bytes to sibling panes. Fire-and-forget and
      // errors ignored — a dead sibling is not this pane's problem to report,
      // and the input-not-sent notice above already covers the focused one.
      for (const other of broadcastRef.current) {
        void safeInvoke('ssh_write', { sessionId: other, data: bytes }).catch(() => {})
      }
    }

    // Right-click pastes, PuTTY-style — the muscle memory every network admin
    // brings to a terminal. The browser context menu is suppressed only inside
    // the terminal surface; with a selection active, right-click copies it
    // first and then clears it (PuTTY's copy-on-select + paste-on-right-click
    // combined into the one gesture people actually use).
    const onCtx = (e: MouseEvent) => {
      e.preventDefault()
      if (term.hasSelection()) {
        void navigator.clipboard.writeText(term.getSelection())
        term.clearSelection()
        return
      }
      void navigator.clipboard
        .readText()
        .then((text) => {
          if (text) send(Array.from(encoder.encode(text)))
        })
        .catch(() => {
          term.write('\r\n\x1b[38;2;242;178;92m● clipboard read blocked\x1b[0m\r\n')
        })
    }
    host.addEventListener('contextmenu', onCtx)

    const dataSub = term.onData((data) => {
      send(Array.from(encoder.encode(data)))

      // Local echo so the layout stays usable in a plain browser (npm run dev)
      // with no backend attached.
      if (!inTauri()) term.write(data === '\r' ? '\r\n' : data)
    })

    // onBinary carries latin1-encoded bytes — one char per byte — so charCodeAt
    // is correct here and TextEncoder would be actively wrong.
    const binarySub = term.onBinary((data) => {
      send(Array.from(data, (ch) => ch.charCodeAt(0) & 0xff))
    })

    /* -------------------------------------------------- copy / paste keys */

    // Ctrl+C is overloaded: with a selection it means copy, without one it must
    // reach the remote as SIGINT. Returning false tells xterm "handled, do not
    // forward to the PTY". Ctrl+Shift+C/V are the unambiguous forms.
    term.attachCustomKeyEventHandler((e) => {
      if (e.type !== 'keydown') return true

      if (e.ctrlKey && e.shiftKey && e.code === 'KeyC') {
        const sel = term.getSelection()
        if (sel) void navigator.clipboard.writeText(sel)
        return false
      }
      if (e.ctrlKey && e.shiftKey && e.code === 'KeyV') {
        void navigator.clipboard
          .readText()
          .then((text) => {
            if (text) send(Array.from(encoder.encode(text)))
          })
          .catch(() => {
            // Clipboard read can be denied by the webview; say so rather than
            // looking like the paste silently did nothing.
            term.write('\r\n\x1b[38;2;242;178;92m● clipboard read blocked\x1b[0m\r\n')
          })
        return false
      }
      if (e.ctrlKey && !e.shiftKey && e.code === 'KeyC' && term.hasSelection()) {
        void navigator.clipboard.writeText(term.getSelection())
        term.clearSelection()
        return false
      }

      // Any other keystroke drops the selection.
      //
      // This is the fix for "Ctrl+C does not interrupt". A selection made ten
      // minutes ago stays active in xterm forever, so the branch above kept
      // winning: you type `dir`, hit Ctrl+C expecting SIGINT, and instead
      // re-copy stale text while the command keeps running. Real terminals
      // clear the selection as soon as you type, which makes Ctrl+C mean
      // "interrupt" in every case except the one where you *just* selected
      // something on purpose.
      if (term.hasSelection() && !e.ctrlKey && !e.altKey && !e.metaKey) {
        term.clearSelection()
      }
      return true
    })

    /* ---------------------------------------------------------- output in */

    let disposed = false
    let unlisten: (() => void) | null = null

    // Frontend-originated text (connect failures, local notices). Subscribed
    // before the backend listener so buffered messages flush immediately.
    const unLocal = onLocal(session.id, (text) => term.write(text))

    void safeListen<string>(`ssh://${session.id}`, (chunk) => {
      term.write(chunk)
    }).then((un) => {
      // The session may have closed while the listener was registering.
      if (disposed) un()
      else unlisten = un
    })

    /* ------------------------------------------------------------ sizing */

    const pushResize = () => {
      // fit() measures the container. A hidden pane measures 0 and would send a
      // nonsense 0x0 PTY resize, which some servers answer by hanging up.
      if (host.clientWidth === 0 || host.clientHeight === 0) return
      fit.fit()
      const { cols, rows } = term
      if (cols === sizeRef.current.cols && rows === sizeRef.current.rows) return
      sizeRef.current = { cols, rows }
      onSizeRef.current?.(session.id, cols, rows)

      // Do not swallow the rejection. If the PTY resize fails the remote keeps
      // drawing to the old geometry, which looks exactly like "the terminal
      // does not expand" while the local grid has in fact resized fine.
      void safeInvoke('ssh_resize', { sessionId: session.id, cols, rows }).catch(
        (e: unknown) => {
          const msg = e instanceof Error ? e.message : String(e)
          term.write(`\r\n\x1b[38;2;242;178;92m● PTY resize failed\x1b[0m ${msg}\r\n`)
        },
      )
    }

    // ResizeObserver rather than a window listener: this pane also changes size
    // when the sidebar is dragged, which fires no window resize event at all.
    let frame = 0
    const ro = new ResizeObserver(() => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(pushResize)
    })
    ro.observe(host)
    pushResize()

    if (!inTauri()) {
      term.writeln('\x1b[38;5;244mNo Tauri backend attached - local echo only.\x1b[0m')
      term.write('\x1b[38;2;79;156;249m$\x1b[0m ')
    }

    /* ---------------------------------------------------------- teardown */

    return () => {
      disposed = true
      cancelAnimationFrame(frame)
      ro.disconnect()
      unlisten?.()
      unLocal()
      host.removeEventListener('contextmenu', onCtx)
      unregisterTerm(session.id)
      dataSub.dispose()
      binarySub.dispose()
      // Dispose the renderer before the Terminal: the reverse order leaks the
      // WebGL context until GC, and browsers cap live contexts at roughly 16.
      webgl?.dispose()
      term.dispose()
      termRef.current = null
      fitRef.current = null
      void safeInvoke('ssh_disconnect', { sessionId: session.id })
    }
  }, [session.id])

  /* Becoming visible: the pane measured 0 while hidden, so re-fit before the
     user sees a stale grid, then take focus so typing goes straight through. */
  useEffect(() => {
    if (!visible) return
    const id = requestAnimationFrame(() => {
      const host = hostRef.current
      if (!host || host.clientWidth === 0) return
      fitRef.current?.fit()
      // A pane hidden with display:none has a zero-sized canvas, and the WebGL
      // renderer does not always repaint it on the way back. Without this the
      // returning tab can come up blank, which reads as "my session is gone"
      // even though the buffer is intact.
      const t = termRef.current
      if (t) t.refresh(0, t.rows - 1)
      t?.focus()
    })
    return () => cancelAnimationFrame(id)
  }, [visible])

  return (
    <div
      // `hidden` (display:none) rather than unmounting. The instance and its
      // scrollback survive; only layout stops.
      hidden={!visible}
      className="absolute inset-0 bg-surface-0 px-2.5 py-2"
    >
      {/* Padding lives on the wrapper, never on the xterm host: FitAddon sizes
          the grid from the host's client box, and padding there makes it
          overestimate by a column or two. */}
      <div ref={hostRef} className="selectable h-full w-full" />
    </div>
  )
}
