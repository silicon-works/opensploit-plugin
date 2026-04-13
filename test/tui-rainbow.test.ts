import { describe, test, expect } from "bun:test"
import { createUltrasploitPostProcess } from "../src/tui-rainbow"

// Rainbow palette from the source — one color per letter of "ultrasploit"
const RAINBOW = [
  { r: 1.0, g: 0.42, b: 0.42, a: 1 },     // u
  { r: 1.0, g: 0.663, b: 0.302, a: 1 },    // l
  { r: 1.0, g: 0.831, b: 0.231, a: 1 },    // t
  { r: 0.663, g: 0.89, b: 0.294, a: 1 },   // r
  { r: 0.412, g: 0.859, b: 0.486, a: 1 },  // a
  { r: 0.22, g: 0.851, b: 0.663, a: 1 },   // s
  { r: 0.302, g: 0.671, b: 0.969, a: 1 },  // p
  { r: 0.455, g: 0.561, b: 0.988, a: 1 },  // l
  { r: 0.592, g: 0.459, b: 0.98, a: 1 },   // o
  { r: 0.855, g: 0.467, b: 0.949, a: 1 },  // i
  { r: 0.969, g: 0.514, b: 0.675, a: 1 },  // t
]

function createBuffer(
  text: string,
  width: number,
): {
  width: number
  height: number
  buffers: {
    char: ArrayLike<number>
    fg: Float32Array
    bg: Float32Array
  }
} {
  const height = Math.ceil(text.length / width)
  const total = width * height
  const char = new Uint32Array(total)
  for (let i = 0; i < text.length; i++) char[i] = text.charCodeAt(i)
  const fg = new Float32Array(total * 4).fill(1) // white by default
  const bg = new Float32Array(total * 4).fill(0) // black by default
  return { width, height, buffers: { char, fg, bg } }
}

/** Read RGBA from the fg buffer at the given cell index. */
function readFg(fg: Float32Array, cell: number) {
  const slot = cell * 4
  return { r: fg[slot], g: fg[slot + 1], b: fg[slot + 2], a: fg[slot + 3] }
}

/** Assert that cell's fg matches the expected rainbow color. */
function expectColor(
  fg: Float32Array,
  cell: number,
  expected: { r: number; g: number; b: number; a: number },
) {
  const actual = readFg(fg, cell)
  expect(actual.r).toBeCloseTo(expected.r, 3)
  expect(actual.g).toBeCloseTo(expected.g, 3)
  expect(actual.b).toBeCloseTo(expected.b, 3)
  expect(actual.a).toBeCloseTo(expected.a, 3)
}

describe("ultrasploit rainbow post-processor", () => {
  const postProcess = createUltrasploitPostProcess()

  test("colors 'ultrasploit' in lowercase", () => {
    const buf = createBuffer("ultrasploit", 80)
    postProcess(buf, 0)

    for (let i = 0; i < 11; i++) {
      expectColor(buf.buffers.fg, i, RAINBOW[i])
    }
  })

  test("colors 'ULTRASPLOIT' in uppercase", () => {
    const buf = createBuffer("ULTRASPLOIT", 80)
    postProcess(buf, 0)

    for (let i = 0; i < 11; i++) {
      expectColor(buf.buffers.fg, i, RAINBOW[i])
    }
  })

  test("colors mixed case 'UlTraSplOiT'", () => {
    const buf = createBuffer("UlTraSplOiT", 80)
    postProcess(buf, 0)

    for (let i = 0; i < 11; i++) {
      expectColor(buf.buffers.fg, i, RAINBOW[i])
    }
  })

  test("does not modify other text", () => {
    const buf = createBuffer("hello world", 80)
    // Snapshot the fg before
    const fgBefore = new Float32Array(buf.buffers.fg)
    postProcess(buf, 0)

    expect(buf.buffers.fg).toEqual(fgBefore)
  })

  test("colors multiple occurrences", () => {
    const text = "ultrasploit test ultrasploit"
    const buf = createBuffer(text, 80)
    postProcess(buf, 0)

    // First occurrence starts at index 0
    for (let i = 0; i < 11; i++) {
      expectColor(buf.buffers.fg, i, RAINBOW[i])
    }
    // "test" between them (indices 11..16) should stay white
    for (let i = 11; i < 17; i++) {
      const c = readFg(buf.buffers.fg, i)
      expect(c.r).toBeCloseTo(1, 3)
      expect(c.g).toBeCloseTo(1, 3)
      expect(c.b).toBeCloseTo(1, 3)
      expect(c.a).toBeCloseTo(1, 3)
    }
    // Second occurrence starts at index 17
    for (let i = 0; i < 11; i++) {
      expectColor(buf.buffers.fg, 17 + i, RAINBOW[i])
    }
  })

  test("handles 'ultrasploit' spanning line boundary", () => {
    // Width 8 means "ultrasploit" (11 chars) wraps across rows.
    // The function scans linearly through the char buffer so it should still match.
    const buf = createBuffer("ultrasploit", 8)
    expect(buf.height).toBe(2) // 11 chars / 8 width = 2 rows
    postProcess(buf, 0)

    for (let i = 0; i < 11; i++) {
      expectColor(buf.buffers.fg, i, RAINBOW[i])
    }
  })

  test("preserves surrounding text colors", () => {
    const text = "XXXultrasploitYYY"
    const buf = createBuffer(text, 80)

    // Set distinctive colors on surrounding chars before running
    const fg = buf.buffers.fg
    for (let i = 0; i < 3; i++) {
      // "XXX" — set to green
      const slot = i * 4
      fg[slot] = 0
      fg[slot + 1] = 1
      fg[slot + 2] = 0
      fg[slot + 3] = 1
    }
    for (let i = 14; i < 17; i++) {
      // "YYY" — set to blue
      const slot = i * 4
      fg[slot] = 0
      fg[slot + 1] = 0
      fg[slot + 2] = 1
      fg[slot + 3] = 1
    }

    postProcess(buf, 0)

    // "XXX" should still be green
    for (let i = 0; i < 3; i++) {
      const c = readFg(fg, i)
      expect(c.r).toBeCloseTo(0, 3)
      expect(c.g).toBeCloseTo(1, 3)
      expect(c.b).toBeCloseTo(0, 3)
      expect(c.a).toBeCloseTo(1, 3)
    }
    // "ultrasploit" (indices 3..13) should be rainbow
    for (let j = 0; j < 11; j++) {
      expectColor(fg, 3 + j, RAINBOW[j])
    }
    // "YYY" should still be blue
    for (let i = 14; i < 17; i++) {
      const c = readFg(fg, i)
      expect(c.r).toBeCloseTo(0, 3)
      expect(c.g).toBeCloseTo(0, 3)
      expect(c.b).toBeCloseTo(1, 3)
      expect(c.a).toBeCloseTo(1, 3)
    }
  })

  test("exact color values match fat fork", () => {
    const buf = createBuffer("ultrasploit", 80)
    postProcess(buf, 0)

    const fg = buf.buffers.fg

    // First letter 'u': coral red
    const u = readFg(fg, 0)
    expect(u.r).toBeCloseTo(1.0, 3)
    expect(u.g).toBeCloseTo(0.42, 3)
    expect(u.b).toBeCloseTo(0.42, 3)

    // Last letter 't': pink
    const t = readFg(fg, 10)
    expect(t.r).toBeCloseTo(0.969, 3)
    expect(t.g).toBeCloseTo(0.514, 3)
    expect(t.b).toBeCloseTo(0.675, 3)

    // Spot-check middle: 's' at index 5 is teal
    const s = readFg(fg, 5)
    expect(s.r).toBeCloseTo(0.22, 3)
    expect(s.g).toBeCloseTo(0.851, 3)
    expect(s.b).toBeCloseTo(0.663, 3)
  })
})
