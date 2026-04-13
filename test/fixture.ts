import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"

export function createTestDir(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "opensploit-test-"))
  return {
    path: dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  }
}

export function writeFile(dir: string, name: string, content: string) {
  const fullPath = join(dir, name)
  mkdirSync(join(dir, ...name.split("/").slice(0, -1)), { recursive: true })
  writeFileSync(fullPath, content)
  return fullPath
}

export function readFile(dir: string, name: string): string {
  return readFileSync(join(dir, name), "utf-8")
}
