const isTest = process.env["OPENSPLOIT_TEST"] === "true"

export function createLog(name: string) {
  const noop = (..._args: any[]) => {}
  if (isTest) {
    return { info: noop, warn: noop, error: noop, debug: noop }
  }
  return {
    info: (...args: any[]) => console.error(`[${name}]`, ...args),
    warn: (...args: any[]) => console.error(`[${name}] WARN:`, ...args),
    error: (...args: any[]) => console.error(`[${name}] ERROR:`, ...args),
    debug: noop,
  }
}
