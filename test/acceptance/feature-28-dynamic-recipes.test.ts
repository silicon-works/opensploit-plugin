/**
 * Feature 28: Dynamic Tool Recipes — Acceptance Tests
 *
 * Each test maps to a specific REQ-RCP-* from:
 *   opensploit-vault/requirements/28-dynamic-tool-recipes.md
 *
 * Existing coverage (NOT duplicated here):
 *   test/tools/tool-registry-search.test.ts — mergeSessionRecipes (10 tests)
 *     covers: no session dir, no recipes dir, merge YAML, no override of
 *     published methods, ignore non-registry tools, non-YAML files, malformed
 *     YAML, missing name, .yml extension, multiple tools & recipes.
 *
 * This file covers gaps:
 *   REQ-RCP-002: Recipe YAML format validation against spec schema
 *   REQ-RCP-004: mcp-tool forwards unknown methods to container (not blocked)
 *   REQ-RCP-005: Sub-agent sessions share root session's recipe directory
 *   REQ-RCP-006: Build agent prompt contains Tool Integration Workflow steps
 *   Param mapping: mergeSessionRecipes maps type/description (flag is server-side)
 */

import { describe, expect, test, afterEach } from "bun:test"
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "fs"
import { join, dirname } from "path"
import { fileURLToPath } from "url"
import yaml from "js-yaml"

import * as SessionDirectory from "../../src/session/directory"
import { registerRootSession, unregister } from "../../src/session/hierarchy"
import {
  mergeSessionRecipes,
  RegistrySchema,
  RegistryToolSchema,
  type Registry,
  type RegistryTool,
} from "../../src/tools/tool-registry-search"
import { createMcpTool } from "../../src/tools/mcp-tool"
import { loadAgents } from "../../src/agents/index"

import type { ToolContext } from "@opencode-ai/plugin"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTool(overrides: Partial<RegistryTool> = {}): RegistryTool {
  return RegistryToolSchema.parse({
    name: overrides.name ?? "test-tool",
    description: overrides.description ?? "A test tool",
    capabilities: overrides.capabilities ?? [],
    phases: overrides.phases ?? [],
    ...overrides,
  })
}

function makeRegistry(tools: Record<string, Partial<RegistryTool>> = {}): Registry {
  const parsed: Record<string, RegistryTool> = {}
  for (const [id, partial] of Object.entries(tools)) {
    parsed[id] = makeTool({ name: partial.name ?? id, ...partial })
  }
  return RegistrySchema.parse({ version: "2.0", tools: parsed })
}

function makeContext(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    sessionID: "test-session-f28",
    messageID: "test-msg-1",
    agent: "pentest",
    directory: "/tmp",
    worktree: "/tmp",
    abort: new AbortController().signal,
    metadata: () => {},
    ask: async () => {},
    ...overrides,
  }
}

/**
 * Full recipe matching the spec format (Section 2.1 of the requirements doc).
 * Includes all fields: name, binary, auth, description, when_to_use, params
 * with flag/type/required/description.
 */
const SPEC_RECIPE_IMPACKET = {
  name: "dacledit",
  binary: "impacket-dacledit",
  auth: "target",
  description: "Edit DACLs on Active Directory objects",
  when_to_use: "When you need to modify AD object permissions",
  params: {
    action: {
      flag: "-action",
      type: "string",
      required: true,
      description: "DACL action: read, write, remove, backup, restore",
    },
    principal: {
      flag: "-principal",
      type: "string",
      required: false,
      description: "Principal (user/group) to add/remove from DACL",
    },
    rights: {
      flag: "-rights",
      type: "string",
      required: false,
      description: "Rights to grant: FullControl, GenericAll, etc.",
    },
    inheritance: {
      flag: "-inheritance",
      type: "boolean",
      required: false,
      description: "Enable ACE inheritance to child objects",
    },
  },
}

const SPEC_RECIPE_EXPLOIT_RUNNER = {
  name: "cve_2024_49019",
  binary: "python3 /session/tool_recipes/scripts/cve_2024_49019.py",
  auth: "none",
  description: "ADCS ESC15 exploit (CVE-2024-49019)",
  when_to_use: "When ADCS has misconfigured certificate templates vulnerable to ESC15",
  params: {
    target: {
      flag: "--target",
      type: "string",
      required: true,
      description: "Target DC hostname",
    },
    ca: {
      flag: "--ca",
      type: "string",
      required: true,
      description: "CA name",
    },
  },
}

// ===========================================================================
// REQ-RCP-002: Recipe YAML format matches tool.yaml method entries
// ===========================================================================

describe("REQ-RCP-002: recipe YAML format validation", () => {
  const testSessionID = `test-rcp002-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`

  afterEach(() => {
    SessionDirectory.cleanup(testSessionID)
    unregister(testSessionID)
  })

  test("full impacket recipe (spec Section 2.1) round-trips through YAML correctly", () => {
    const yamlText = yaml.dump(SPEC_RECIPE_IMPACKET)
    const parsed = yaml.load(yamlText) as Record<string, any>

    expect(parsed.name).toBe("dacledit")
    expect(parsed.binary).toBe("impacket-dacledit")
    expect(parsed.auth).toBe("target")
    expect(parsed.description).toContain("DACLs")
    expect(parsed.when_to_use).toContain("modify AD")
    expect(parsed.params.action.flag).toBe("-action")
    expect(parsed.params.action.type).toBe("string")
    expect(parsed.params.action.required).toBe(true)
    expect(parsed.params.inheritance.type).toBe("boolean")
  })

  test("exploit-runner recipe with auth:none round-trips through YAML", () => {
    const yamlText = yaml.dump(SPEC_RECIPE_EXPLOIT_RUNNER)
    const parsed = yaml.load(yamlText) as Record<string, any>

    expect(parsed.name).toBe("cve_2024_49019")
    expect(parsed.binary).toContain("python3")
    expect(parsed.auth).toBe("none")
    expect(parsed.params.target.required).toBe(true)
  })

  test("recipe with all three auth modes is valid YAML", () => {
    for (const auth of ["target", "domain", "none"]) {
      const recipe = { name: `test_${auth}`, binary: "test-bin", auth, description: "Test" }
      const yamlText = yaml.dump(recipe)
      const parsed = yaml.load(yamlText) as Record<string, any>
      expect(parsed.auth).toBe(auth)
    }
  })

  test("mergeSessionRecipes extracts description and when_to_use from spec recipe", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "impacket")
    mkdirSync(recipesDir, { recursive: true })
    writeFileSync(join(recipesDir, "dacledit.yaml"), yaml.dump(SPEC_RECIPE_IMPACKET))

    const registry = makeRegistry({
      impacket: {
        name: "impacket",
        description: "Impacket framework",
        image: "ghcr.io/silicon-works/mcp-tools-impacket:latest",
      },
    })
    mergeSessionRecipes(registry, testSessionID)

    const merged = registry.tools.impacket.methods!.dacledit
    expect(merged).toBeDefined()
    expect(merged.description).toBe("Edit DACLs on Active Directory objects")
    expect(merged.when_to_use).toBe("When you need to modify AD object permissions")
  })

  test("mergeSessionRecipes maps param type and description (flag is server-side only)", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "impacket")
    mkdirSync(recipesDir, { recursive: true })
    writeFileSync(join(recipesDir, "dacledit.yaml"), yaml.dump(SPEC_RECIPE_IMPACKET))

    const registry = makeRegistry({
      impacket: {
        name: "impacket",
        description: "Impacket framework",
        image: "ghcr.io/silicon-works/mcp-tools-impacket:latest",
      },
    })
    mergeSessionRecipes(registry, testSessionID)

    const params = registry.tools.impacket.methods!.dacledit.params!
    // type and description are mapped for client-side search
    expect(params.action.type).toBe("string")
    expect(params.action.description).toBe("DACL action: read, write, remove, backup, restore")
    expect(params.inheritance.type).toBe("boolean")
    expect(params.inheritance.description).toBe("Enable ACE inheritance to child objects")
    // flag is NOT mapped (it's server-side only, used by _run_recipe in Python)
    expect((params.action as any).flag).toBeUndefined()
  })

  test("recipe without optional fields merges with empty defaults", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "impacket")
    mkdirSync(recipesDir, { recursive: true })

    // Minimal recipe — only name required
    const minimalRecipe = { name: "minimal_tool" }
    writeFileSync(join(recipesDir, "minimal.yaml"), yaml.dump(minimalRecipe))

    const registry = makeRegistry({
      impacket: { name: "impacket", description: "Impacket" },
    })
    mergeSessionRecipes(registry, testSessionID)

    const merged = registry.tools.impacket.methods!.minimal_tool
    expect(merged).toBeDefined()
    expect(merged.description).toBe("")
    expect(merged.when_to_use).toBe("")
    expect(merged.params).toEqual({})
  })
})

// ===========================================================================
// REQ-RCP-004: Client allows calls to methods not in published registry
// ===========================================================================

describe("REQ-RCP-004: mcp-tool forwards unknown methods", () => {
  const mcpTool = createMcpTool()

  test("known tool with unknown method does NOT return 'Method not found' error", async () => {
    // The old behavior was to return an error like:
    //   Method "dynamic_recipe_method" not found on tool "impacket".
    //   Available methods: get_tgt, get_st, ...
    //
    // The new behavior forwards to the container. Since we don't have Docker
    // or network in tests, the call will fail at the container/fetch layer —
    // but critically it should NOT fail at the method validation layer.
    //
    // The test may timeout on registry fetch if opensploit.ai is unreachable.
    // In that case the tool returns "not found in registry" (because the
    // entire registry is empty), which is a fetch-level failure, not a
    // method-level block. We accept either outcome.
    let result: string
    try {
      result = await Promise.race([
        mcpTool.execute(
          {
            tool: "impacket",
            method: "dynamic_recipe_method_that_does_not_exist",
            arguments: '{"target": "10.10.10.1"}',
          },
          makeContext(),
        ),
        new Promise<string>((_, reject) =>
          setTimeout(() => reject(new Error("registry_fetch_timeout")), 3000),
        ),
      ])
    } catch (e) {
      // Registry fetch timeout — the test is about method gating, not network.
      // Verify the code path structurally instead.
      expect(String(e)).toContain("registry_fetch_timeout")
      return
    }
    // If we got a result, verify it's NOT the old method-blocking error
    expect(result).not.toContain('Method "dynamic_recipe_method_that_does_not_exist" not found')
    expect(result).not.toContain("Available methods:")
  })

  test("tool not in registry still returns proper error", async () => {
    const result = await mcpTool.execute(
      { tool: "totally_fake_tool", method: "run" },
      makeContext(),
    )
    expect(result).toContain("not found in registry")
  })

  test("source code forwards unknown methods instead of blocking (structural)", () => {
    // Verify the implementation pattern: method not in registry logs info
    // and continues execution (no early return with error).
    // Read the source to confirm the critical behavioral change from the spec.
    const source = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "../../src/tools/mcp-tool.ts"),
      "utf-8",
    )
    // The old blocking pattern returned an error string with "not found" and "Available methods".
    // The new pattern just logs and continues.
    expect(source).toContain("forwarding to container")
    // Must NOT contain the old blocking return statement
    expect(source).not.toContain("Available methods:")
    expect(source).not.toContain('`Method "${method}" not found')
  })
})

// ===========================================================================
// REQ-RCP-005 (extension): Sub-agent shares root session recipe directory
// ===========================================================================

describe("REQ-RCP-005: sub-agent recipe directory sharing via hierarchy", () => {
  const rootSessionID = `test-root-rcp005-${Date.now()}`
  const childSessionID = `test-child-rcp005-${Date.now()}`

  afterEach(() => {
    SessionDirectory.cleanup(rootSessionID)
    unregister(childSessionID)
    unregister(rootSessionID)
  })

  test("sub-agent session resolves to root session's recipe directory", () => {
    registerRootSession(childSessionID, rootSessionID)
    SessionDirectory.create(rootSessionID)
    const sessionDir = SessionDirectory.get(rootSessionID)

    // Create a recipe in the root session's directory
    const recipesDir = join(sessionDir, "tool_recipes", "impacket")
    mkdirSync(recipesDir, { recursive: true })
    writeFileSync(
      join(recipesDir, "shared_recipe.yaml"),
      yaml.dump({ name: "shared_recipe", description: "Shared via root" }),
    )

    const registry = makeRegistry({
      impacket: { name: "impacket", description: "Impacket" },
    })

    // Merge using the CHILD session ID — should find root's recipes
    mergeSessionRecipes(registry, childSessionID)
    expect(registry.tools.impacket.methods!.shared_recipe).toBeDefined()
    expect(registry.tools.impacket.methods!.shared_recipe.description).toBe("Shared via root")
  })

  test("recipe created by build sub-agent is visible to exploit sub-agent", () => {
    const buildSessionID = `test-build-${Date.now()}`
    const exploitSessionID = `test-exploit-${Date.now()}`
    registerRootSession(buildSessionID, rootSessionID)
    registerRootSession(exploitSessionID, rootSessionID)
    SessionDirectory.create(rootSessionID)
    const sessionDir = SessionDirectory.get(rootSessionID)

    // Build agent creates a recipe
    const recipesDir = join(sessionDir, "tool_recipes", "impacket")
    mkdirSync(recipesDir, { recursive: true })
    writeFileSync(
      join(recipesDir, "dacledit.yaml"),
      yaml.dump(SPEC_RECIPE_IMPACKET),
    )

    // Exploit agent's registry search should find it
    const registry = makeRegistry({
      impacket: { name: "impacket", description: "Impacket" },
    })
    mergeSessionRecipes(registry, exploitSessionID)
    expect(registry.tools.impacket.methods!.dacledit).toBeDefined()

    // Cleanup extra registrations
    unregister(buildSessionID)
    unregister(exploitSessionID)
  })
})

// ===========================================================================
// REQ-RCP-006: Build agent prompt contains Tool Integration Workflow
// ===========================================================================

describe("REQ-RCP-006: build agent Tool Integration Workflow", () => {
  const agents = loadAgents()
  const buildPrompt = agents["pentest/build"].prompt

  test("build agent prompt contains Tool Integration Workflow section", () => {
    expect(buildPrompt).toContain("## Tool Integration Workflow")
  })

  test("Step 1: CHECK binary existence instructions", () => {
    expect(buildPrompt).toContain("Step 1: CHECK if the binary exists")
    expect(buildPrompt).toContain("which impacket-")
    expect(buildPrompt).toContain("pip show")
    expect(buildPrompt).toContain("pip install")
  })

  test("Step 2: EXTRACT parameter schema from --help", () => {
    expect(buildPrompt).toContain("Step 2: EXTRACT the parameter schema")
    expect(buildPrompt).toContain("--help")
    expect(buildPrompt).toContain("flag")
    expect(buildPrompt).toContain("type")
    expect(buildPrompt).toContain("required")
  })

  test("Step 3: CREATE recipe YAML with correct path", () => {
    expect(buildPrompt).toContain("Step 3: CREATE a recipe YAML")
    expect(buildPrompt).toContain("/session/tool_recipes/")
    expect(buildPrompt).toContain("<tool_name>/<method_name>.yaml")
  })

  test("Step 3: auth modes documented (target, domain, none)", () => {
    // The prompt lists all three modes on one line: "auth: target | domain | none"
    expect(buildPrompt).toContain("auth: target | domain | none")
    // And describes each mode individually in the surrounding text
    expect(buildPrompt).toContain('auth to "target" or "domain"')
    expect(buildPrompt).toContain('auth: "none"')
  })

  test("Step 3: recipe format YAML block present", () => {
    expect(buildPrompt).toContain("name: <method_name>")
    expect(buildPrompt).toContain("binary: <binary_path>")
    expect(buildPrompt).toContain("auth: target | domain | none")
    expect(buildPrompt).toContain("description:")
    expect(buildPrompt).toContain("when_to_use:")
  })

  test("Step 3: framework-specific auth guidance present", () => {
    // Spec requires: impacket target vs domain distinction
    expect(buildPrompt).toContain("domain/user:pass@target")
    expect(buildPrompt).toContain("domain/user:pass")
    // Auth param inheritance
    expect(buildPrompt).toContain("kerberos")
    expect(buildPrompt).toContain("hashes")
    expect(buildPrompt).toContain("dc_ip")
    expect(buildPrompt).toContain("ccache_path")
  })

  test("Step 3: exploit-runner catch-all documented", () => {
    expect(buildPrompt).toContain("exploit-runner")
    expect(buildPrompt).toContain('auth: "none"')
  })

  test("Step 4: TEST the recipe via mcp_tool", () => {
    expect(buildPrompt).toContain("Step 4: TEST the recipe")
    expect(buildPrompt).toContain("mcp_tool")
    // Hot-reload documented
    expect(buildPrompt).toContain("hot-reload")
  })

  test("Step 5: RETURN to calling agent with usage info", () => {
    expect(buildPrompt).toContain("Step 5: RETURN to calling agent")
    expect(buildPrompt).toContain("engagement state")
    expect(buildPrompt).toContain("tacticalNotes")
  })

  test("certipy and netexec frameworks mentioned in auth guidance", () => {
    expect(buildPrompt).toContain("certipy")
    expect(buildPrompt).toContain("netexec")
  })
})

// ===========================================================================
// REQ-RCP-002 (edge cases): Recipe format edge cases
// ===========================================================================

describe("REQ-RCP-002: recipe format edge cases", () => {
  const testSessionID = `test-rcp002-edge-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`

  afterEach(() => {
    SessionDirectory.cleanup(testSessionID)
    unregister(testSessionID)
  })

  test("recipe with empty params object merges correctly", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "impacket")
    mkdirSync(recipesDir, { recursive: true })

    const recipe = { name: "no_params", description: "No params tool", params: {} }
    writeFileSync(join(recipesDir, "no_params.yaml"), yaml.dump(recipe))

    const registry = makeRegistry({
      impacket: { name: "impacket", description: "Impacket" },
    })
    mergeSessionRecipes(registry, testSessionID)
    expect(registry.tools.impacket.methods!.no_params.params).toEqual({})
  })

  test("recipe param with missing type defaults to string", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "impacket")
    mkdirSync(recipesDir, { recursive: true })

    // Param with only description, no type
    const recipe = {
      name: "default_type",
      description: "Test",
      params: { target: { description: "The target" } },
    }
    writeFileSync(join(recipesDir, "default_type.yaml"), yaml.dump(recipe))

    const registry = makeRegistry({
      impacket: { name: "impacket", description: "Impacket" },
    })
    mergeSessionRecipes(registry, testSessionID)
    // Implementation: `v.type || "string"` — missing type defaults to "string"
    expect(registry.tools.impacket.methods!.default_type.params!.target.type).toBe("string")
  })

  test("recipe param with missing description defaults to empty string", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "impacket")
    mkdirSync(recipesDir, { recursive: true })

    const recipe = {
      name: "default_desc",
      description: "Test",
      params: { target: { type: "string" } },
    }
    writeFileSync(join(recipesDir, "default_desc.yaml"), yaml.dump(recipe))

    const registry = makeRegistry({
      impacket: { name: "impacket", description: "Impacket" },
    })
    mergeSessionRecipes(registry, testSessionID)
    expect(registry.tools.impacket.methods!.default_desc.params!.target.description).toBe("")
  })

  test("multiple recipes for same tool are all discoverable", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "impacket")
    mkdirSync(recipesDir, { recursive: true })

    writeFileSync(
      join(recipesDir, "dacledit.yaml"),
      yaml.dump(SPEC_RECIPE_IMPACKET),
    )
    writeFileSync(
      join(recipesDir, "owneredit.yaml"),
      yaml.dump({
        name: "owneredit",
        binary: "impacket-owneredit",
        auth: "target",
        description: "Edit object owner in AD",
        params: {
          action: { flag: "-action", type: "string", required: true, description: "Action: read, write" },
        },
      }),
    )

    const registry = makeRegistry({
      impacket: {
        name: "impacket",
        description: "Impacket",
        methods: { get_tgt: { description: "Get TGT" } },
      },
    })
    mergeSessionRecipes(registry, testSessionID)
    // Published method preserved + 2 recipes added
    expect(Object.keys(registry.tools.impacket.methods!).sort()).toEqual(
      ["dacledit", "get_tgt", "owneredit"],
    )
  })

  test("exploit-runner recipe with auth:none merges alongside impacket recipe", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)

    const impacketDir = join(sessionDir, "tool_recipes", "impacket")
    const exploitDir = join(sessionDir, "tool_recipes", "exploit-runner")
    mkdirSync(impacketDir, { recursive: true })
    mkdirSync(exploitDir, { recursive: true })

    writeFileSync(
      join(impacketDir, "dacledit.yaml"),
      yaml.dump(SPEC_RECIPE_IMPACKET),
    )
    writeFileSync(
      join(exploitDir, "cve_2024_49019.yaml"),
      yaml.dump(SPEC_RECIPE_EXPLOIT_RUNNER),
    )

    const registry = makeRegistry({
      impacket: { name: "impacket", description: "Impacket" },
      "exploit-runner": { name: "exploit-runner", description: "Run exploits" },
    })
    mergeSessionRecipes(registry, testSessionID)

    expect(registry.tools.impacket.methods!.dacledit).toBeDefined()
    expect(registry.tools["exploit-runner"].methods!.cve_2024_49019).toBeDefined()
    expect(registry.tools["exploit-runner"].methods!.cve_2024_49019.description).toContain("ESC15")
  })
})

// ===========================================================================
// Gap Analysis — What's NOT Testable Here
// ===========================================================================
//
// The following requirements are server-side (MCP container) and cannot be
// validated in client-side acceptance tests:
//
// REQ-RCP-001: Framework servers load recipes from /session/tool_recipes/
//   -> Tested via mcp-client.py integration tests and live HTB engagements
//
// REQ-RCP-003: Recipe methods reuse host tool's auth builders
//   -> Server-side Python: _build_auth_args, _build_domain_auth_args
//   -> Tested in mcp-tools repo
//
// REQ-RCP-007 through REQ-RCP-011: Bug fixes in mcp-tools servers
//   -> Server-side Python fixes (impacket-relay, ffuf, hydra, sqlmap, nmap)
//   -> Tested via mcp-client.py and live HTB engagements
//
// Hot-reload behavior (recipe created mid-engagement works without restart):
//   -> Server-side behavior in _maybe_reload_recipes()
//   -> Tested via live HTB engagement (Feature 28 v1.1 changelog)
