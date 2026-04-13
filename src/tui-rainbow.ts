/**
 * Rainbow post-processor for "ultrasploit" text.
 *
 * Scans the terminal render buffer for occurrences of "ultrasploit"
 * (case-insensitive) and paints each letter with its rainbow color.
 * Same colors as the fat fork's extmark-based implementation.
 *
 * Uses api.renderer.addPostProcessFn() — runs after every frame render.
 */

// Rainbow palette: 11 letters, 11 colors (0-1 range RGBA)
// Matching fat fork's theme.tsx extmark colors exactly
const RAINBOW: Array<{ r: number; g: number; b: number; a: number }> = [
  { r: 1.0, g: 0.42, b: 0.42, a: 1 },   // u - #ff6b6b coral red
  { r: 1.0, g: 0.663, b: 0.302, a: 1 },  // l - #ffa94d orange
  { r: 1.0, g: 0.831, b: 0.231, a: 1 },  // t - #ffd43b gold
  { r: 0.663, g: 0.89, b: 0.294, a: 1 },  // r - #a9e34b lime green
  { r: 0.412, g: 0.859, b: 0.486, a: 1 }, // a - #69db7c mint
  { r: 0.22, g: 0.851, b: 0.663, a: 1 },  // s - #38d9a9 teal
  { r: 0.302, g: 0.671, b: 0.969, a: 1 }, // p - #4dabf7 cyan
  { r: 0.455, g: 0.561, b: 0.988, a: 1 }, // l - #748ffc blue
  { r: 0.592, g: 0.459, b: 0.98, a: 1 },  // o - #9775fa purple
  { r: 0.855, g: 0.467, b: 0.949, a: 1 }, // i - #da77f2 violet
  { r: 0.969, g: 0.514, b: 0.675, a: 1 }, // t - #f783ac pink
]

// "ultrasploit" as char codes (lowercase)
const TARGET = "ultrasploit"
const TARGET_CODES = Array.from(TARGET, (c) => c.charCodeAt(0))
const TARGET_UPPER = Array.from(TARGET.toUpperCase(), (c) => c.charCodeAt(0))
const TARGET_LEN = TARGET.length

type RenderBuffer = {
  width: number
  height: number
  buffers: {
    char: ArrayLike<number>
    fg: Float32Array
    bg: Float32Array
  }
}

/**
 * Post-process function that colors "ultrasploit" occurrences with rainbow.
 * Register via api.renderer.addPostProcessFn(ultrasploitPostProcess)
 */
export function createUltrasploitPostProcess() {
  return (buffer: RenderBuffer, _delta: number) => {
    const { width, height } = buffer
    const { char, fg } = buffer.buffers
    const total = width * height

    // Scan for "ultrasploit" sequences in the character buffer
    for (let i = 0; i <= total - TARGET_LEN; i++) {
      // Check if we have a match (case-insensitive)
      let match = true
      for (let j = 0; j < TARGET_LEN; j++) {
        const c = char[i + j]
        if (c !== TARGET_CODES[j] && c !== TARGET_UPPER[j]) {
          match = false
          break
        }
      }

      if (match) {
        // Paint each character with its rainbow color
        for (let j = 0; j < TARGET_LEN; j++) {
          const slot = (i + j) * 4
          const color = RAINBOW[j]
          fg[slot] = color.r
          fg[slot + 1] = color.g
          fg[slot + 2] = color.b
          fg[slot + 3] = color.a
        }
        // Skip past this match
        i += TARGET_LEN - 1
      }
    }
  }
}
