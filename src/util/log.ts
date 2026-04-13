/**
 * Lightweight logger for the opensploit plugin.
 *
 * Silent by default — OpenCode's TUI owns the terminal, so writing to
 * stderr corrupts the display. Enable with OPENSPLOIT_DEBUG=true for
 * development/troubleshooting.
 */
const isDebug = process.env["OPENSPLOIT_DEBUG"] === "true"

export function createLog(name: string) {
  const noop = (..._args: any[]) => {}
  if (!isDebug) {
    return { info: noop, warn: noop, error: noop, debug: noop }
  }
  return {
    info: (...args: any[]) => console.error(`[${name}]`, ...args),
    warn: (...args: any[]) => console.error(`[${name}] WARN:`, ...args),
    error: (...args: any[]) => console.error(`[${name}] ERROR:`, ...args),
    debug: noop,
  }
}
