import { afterAll } from "bun:test"

// Ensure debug logging is off during tests (logs are silent by default,
// but explicitly clear in case someone has OPENSPLOIT_DEBUG in their env)
delete process.env["OPENSPLOIT_DEBUG"]

// Clean environment
delete process.env["ANTHROPIC_API_KEY"]
delete process.env["OPENAI_API_KEY"]

afterAll(() => {
  // Global cleanup if needed
})
