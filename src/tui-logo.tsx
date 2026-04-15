/** @jsxImportSource @opentui/solid */
/**
 * OpenSploit TUI logo — replaces the OpenCode logo via home_logo slot.
 *
 * Simplified rendering: left half (muted) + right half (bold text).
 * No shadow markers — keeps it clean and avoids RGBA class construction
 * issues across @opentui/core versions.
 */

import type { RGBA } from "@opentui/core"
import { For } from "solid-js"

// "OPEN" left half + "SPLOIT" right half
// Standard block character typography
const left = [
  "                   ",
  "█▀▀█ █▀▀█ █▀▀█ █▀▀▄",
  "█  █ █  █ █▀▀▀ █  █",
  "▀▀▀▀ █▀▀▀ ▀▀▀▀ ▀  ▀",
]

const right = [
  "                               ",
  "█▀▀▀ █▀▀█ █    █▀▀█ ▀█▀ ▀▀█▀▀",
  "▀▀▀█ █▀▀▀ █    █  █  █    █  ",
  "▀▀▀▀ ▀    ▀▀▀▀ ▀▀▀▀ ▀▀▀   ▀  ",
]

export function OpenSploitLogo(props: {
  textMuted: RGBA
  text: RGBA
  background: RGBA
}) {
  return (
    <box>
      <For each={left}>
        {(line, index) => (
          <box flexDirection="row" gap={1}>
            <text fg={props.textMuted} selectable={false}>
              {line}
            </text>
            <text fg={props.text} attributes={1} selectable={false}>
              {right[index()]}
            </text>
          </box>
        )}
      </For>
    </box>
  )
}
