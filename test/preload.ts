import { afterAll } from "bun:test"

// Suppress all log output during tests
// Our log shim at src/util/log.ts needs to support this
process.env["OPENSPLOIT_TEST"] = "true"

// Clean environment
delete process.env["ANTHROPIC_API_KEY"]
delete process.env["OPENAI_API_KEY"]

afterAll(() => {
  // Global cleanup if needed
})
