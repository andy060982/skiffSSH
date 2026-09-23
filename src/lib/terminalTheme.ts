import type { ITheme } from '@xterm/xterm'

/** Read a design token off :root. Tailwind v4's @theme emits real CSS custom
 *  properties, so the terminal can consume the exact same values as the rest of
 *  the shell instead of duplicating hex literals that drift apart. */
const token = (name: string, fallback: string): string => {
  if (typeof window === 'undefined') return fallback
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return v || fallback
}

/* ANSI palette.
 *
 * Terminal semantics are fixed — applications expect index 1 to be "red" and
 * index 2 to be "green", so those slots cannot be reassigned. What *can* be
 * controlled is separability: red is pushed warm-and-light, green is tilted
 * toward teal, and the two differ in lightness as well as hue. That keeps
 * `git diff` and test output readable with red/green colour blindness without
 * breaking any program's colour expectations. */
export function buildTerminalTheme(): ITheme {
  const bg = token('--color-surface-0', '#0b0e14')

  return {
    background: bg,
    foreground: token('--color-ink', '#e6e9ef'),

    // Block cursor in the accent hue; cursorAccent is the glyph *under* it.
    cursor: token('--color-accent', '#4f9cf9'),
    cursorAccent: bg,

    // Selection must stay translucent so the character under it is still legible.
    selectionBackground: 'rgba(79, 156, 249, 0.30)',
    selectionForeground: undefined,
    selectionInactiveBackground: 'rgba(79, 156, 249, 0.15)',

    black: '#11151d',
    red: '#ff7b72',
    green: '#4ec9a8',
    yellow: '#f2b25c',
    blue: '#4f9cf9',
    magenta: '#b98bfa',
    cyan: '#5bc8d8',
    white: '#d7dce5',

    brightBlack: '#64708a',
    brightRed: '#ff9a93',
    brightGreen: '#6fe0c0',
    brightYellow: '#ffc880',
    brightBlue: '#7cb7ff',
    brightMagenta: '#d0aaff',
    brightCyan: '#82e0ee',
    brightWhite: '#f2f5fa',
  }
}

/** Monospace stack.
 *
 * Cascadia *Mono* rather than Cascadia *Code*: the Code variant has programming
 * ligatures, and xterm renders per-cell, so ligatures either break glyph metrics
 * or require @xterm/addon-ligatures. Consolas is the guaranteed Windows floor.
 * Every face here is metric-consistent, which matters because xterm measures one
 * character and multiplies — a font with irregular advance widths produces a
 * grid that drifts out of alignment across a wide row. */
export const TERMINAL_FONT =
  '"Cascadia Mono", "JetBrains Mono", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace'

export const TERMINAL_FONT_SIZE = 13
export const TERMINAL_LINE_HEIGHT = 1.25
