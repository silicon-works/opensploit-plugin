export function createLog(name: string) {
  return {
    info: (...args: any[]) => console.error(`[${name}]`, ...args),
    warn: (...args: any[]) => console.error(`[${name}] WARN:`, ...args),
    error: (...args: any[]) => console.error(`[${name}] ERROR:`, ...args),
    debug: (...args: any[]) => {},
  }
}
