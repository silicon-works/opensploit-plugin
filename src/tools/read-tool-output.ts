/**
 * Read Tool Output
 *
 * Built-in tool for querying stored MCP tool outputs.
 * Supports field:value queries on normalized records.
 *
 * Requirements (Feature 05):
 * - REQ-ARC-026: Provide retrieval tool for stored outputs
 * - REQ-ARC-027: Support field:value queries on records
 *
 * NOTE: In the fat fork this used Tool.define() for registration.
 * In the plugin, the execute function is exported directly and will be
 * wired into the plugin's tool registration separately.
 */

import z from "zod"
import { createLog } from "../util/log"
import * as OutputStore from "./output-store"
import { getRootSession } from "../session/hierarchy"

const log = createLog("tool.read-tool-output")

export const DESCRIPTION = `Query stored tool output by reference ID.

When tool outputs are large, they are stored externally and a summary with
reference ID is returned. Use this tool to query the full results.

**Query Syntax:**

1. **Field query** (exact match):
   - \`port:22\` - find records where port equals 22
   - \`status:200\` - find records where status equals 200
   - \`state:open\` - find records where state equals "open"

2. **Text search** (substring match):
   - \`ssh\` - find records containing "ssh" in any field
   - \`admin\` - find records containing "admin" in any field

**Parameters:**
- \`id\`: Reference ID from the stored output (e.g., "out_xxx")
- \`query\`: Field:value query or text search (optional)
- \`type\`: Filter by record type (e.g., "port", "directory", "vulnerability")
- \`limit\`: Maximum records to return (default: 50)

**Examples:**
\`\`\`
read_tool_output(id="out_abc", query="port:22")
read_tool_output(id="out_abc", query="open")
read_tool_output(id="out_abc", type="vulnerability")
\`\`\`
`

export const readToolOutputParameters = z.object({
  id: z.string().describe("Reference ID of the stored output"),
  query: z.string().optional().describe("Field:value query (e.g., 'port:22') or text search"),
  type: z.string().optional().describe("Filter by record type (e.g., 'port', 'directory')"),
  limit: z.number().optional().default(50).describe("Maximum records to return (default: 50)"),
})

export type ReadToolOutputParams = z.infer<typeof readToolOutputParameters>

/**
 * Execute the read_tool_output tool.
 *
 * @param params - Tool parameters (id, query, type, limit)
 * @param sessionID - The current session ID (used to resolve root session)
 */
export async function executeReadToolOutput(
  params: ReadToolOutputParams,
  sessionID: string,
): Promise<{
  output: string
  title: string
  metadata: Record<string, any>
}> {
  const { id, query, type, limit = 50 } = params

  // Auto-detect session ID from context using root session
  // This ensures outputs stored by any agent in the tree are accessible
  const session_id = getRootSession(sessionID)

  log.info("read_tool_output", { id, session_id, query, type, limit })

  // Query the output store
  const result = await OutputStore.query({
    sessionId: session_id,
    outputId: id,
    query,
    type,
    limit,
  })

  // Common metadata base
  const baseMeta = {
    id,
    session_id,
  }

  if (!result.found) {
    // Try to provide helpful error message
    const storedMeta = await OutputStore.getMetadata(session_id, id)
    if (!storedMeta.found) {
      return {
        output: `Output not found: ${id}

The referenced output may have expired (24 hour retention) or the session ID may be incorrect.

**Troubleshooting:**
- Check that the output ID matches exactly (copy from the summary)
- Verify the session ID is correct
- Outputs older than 24 hours are automatically cleaned up`,
        title: "read_tool_output: not found",
        metadata: baseMeta,
      }
    }

    return {
      output: result.error ?? "Unknown error reading output",
      title: "read_tool_output: error",
      metadata: baseMeta,
    }
  }

  // Format results
  const formattedOutput = OutputStore.formatQueryResults(result.records, result.total, limit)

  // Build metadata
  const storedMeta = await OutputStore.getMetadata(session_id, id)

  // Build header with context
  const header = [
    `**Output ID**: ${id}`,
    `**Tool**: ${storedMeta.tool ?? "unknown"}.${storedMeta.method ?? "execute"}`,
    `**Query**: ${query ?? "(all records)"}`,
    type ? `**Type Filter**: ${type}` : "",
    `**Results**: ${result.records.length} of ${result.total}`,
    "---",
  ]
    .filter(Boolean)
    .join("\n")

  const output = header + "\n\n" + formattedOutput

  return {
    output,
    title: `read_tool_output: ${id}`,
    metadata: baseMeta,
  }
}

// Re-export for backwards compatibility
export { OutputStore }
