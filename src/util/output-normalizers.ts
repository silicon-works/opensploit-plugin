/**
 * Output Normalizers
 *
 * Normalize nested MCP tool data structures to flat records for simple queries.
 * This enables field:value queries like "port:22" or "status:200" without
 * needing tool-specific nested traversal.
 *
 * Design Decision (from Feature 05 doc):
 * - Use MCP's structured `data` directly, don't re-parse raw_output with regex
 * - ~10 lines per tool (JSON traversal) vs ~50 lines (regex parsing)
 *
 * Requirements:
 * - REQ-ARC-027: Support field:value queries on records
 */

import { createLog } from "./log"

const log = createLog("output-normalizers")

/**
 * A flat record extracted from MCP tool data.
 * All records have a `type` field for filtering.
 */
export interface OutputRecord {
  type: string
  [key: string]: any
}

/**
 * Normalizer function type.
 * Takes MCP tool data and returns flat records.
 */
export type Normalizer = (data: any) => OutputRecord[]

/**
 * Normalize nmap scan results.
 * Flattens: data.hosts[].ports[] → flat port records
 */
export function normalizeNmap(data: any): OutputRecord[] {
  const records: OutputRecord[] = []

  const hosts = data?.hosts ?? []
  for (const host of hosts) {
    const hostIp = host?.ip ?? host?.address ?? "unknown"
    const hostname = host?.hostname ?? host?.hostnames?.[0]?.name ?? ""

    // Port records
    const ports = host?.ports ?? []
    for (const port of ports) {
      records.push({
        type: "port",
        host: hostIp,
        hostname,
        port: Number(port?.port ?? port?.portid) || 0,
        protocol: port?.protocol ?? "tcp",
        state: port?.state ?? "unknown",
        service: port?.service?.name ?? port?.service ?? "",
        product: port?.service?.product ?? "",
        version: port?.service?.version ?? "",
        extrainfo: port?.service?.extrainfo ?? "",
      })
    }

    // OS match records (if present)
    const osMatches = host?.os_matches ?? host?.osmatches ?? []
    for (const os of osMatches) {
      records.push({
        type: "os",
        host: hostIp,
        name: os?.name ?? os?.osmatch ?? "",
        accuracy: os?.accuracy ?? 0,
        family: os?.osfamily ?? "",
      })
    }

    // Vulnerability records (from NSE scripts)
    for (const port of ports) {
      const scripts = port?.scripts ?? []
      for (const script of scripts) {
        const output = (script?.output ?? "").toLowerCase()
        // Check if it looks like a vulnerability finding
        if (output.includes("vulnerable") || output.includes("cve-") || output.includes("exploit")) {
          records.push({
            type: "vulnerability",
            host: hostIp,
            port: Number(port?.port) || 0,
            script: script?.id ?? "",
            output: script?.output ?? "",
          })
        }
      }
    }
  }

  return records
}

/**
 * Normalize ffuf fuzzing results.
 * Flattens: data.results[] → flat directory/path records
 */
export function normalizeFfuf(data: any): OutputRecord[] {
  const records: OutputRecord[] = []

  const results = data?.results ?? []
  for (const result of results) {
    records.push({
      type: "directory",
      path: result?.input ?? result?.FUZZ ?? "",
      url: result?.url ?? "",
      status: result?.status ?? 0,
      length: result?.length ?? 0,
      words: result?.words ?? 0,
      lines: result?.lines ?? 0,
      content_type: result?.content_type ?? result?.["content-type"] ?? "",
      redirect: result?.redirect_location ?? result?.redirectlocation ?? "",
    })
  }

  return records
}

/**
 * Normalize nikto web scanner results.
 * Flattens: data.vulnerabilities[] → flat vulnerability records
 */
export function normalizeNikto(data: any): OutputRecord[] {
  const records: OutputRecord[] = []

  // Nikto typically returns findings/vulnerabilities array
  const vulns = data?.vulnerabilities ?? data?.findings ?? data?.items ?? []
  for (const vuln of vulns) {
    records.push({
      type: "vulnerability",
      id: vuln?.id ?? vuln?.osvdb ?? "",
      uri: vuln?.uri ?? vuln?.url ?? "",
      method: vuln?.method ?? "GET",
      description: vuln?.description ?? vuln?.msg ?? "",
      reference: vuln?.reference ?? vuln?.refs ?? "",
    })
  }

  // Also handle scan info if present
  const scanInfo = data?.scan_info ?? data?.scaninfo
  if (scanInfo) {
    records.push({
      type: "scan_info",
      target: scanInfo?.target ?? "",
      host_header: scanInfo?.host_header ?? "",
      start_time: scanInfo?.start_time ?? "",
      end_time: scanInfo?.end_time ?? "",
    })
  }

  return records
}

/**
 * Normalize gobuster directory enumeration results.
 * Flattens: data.results[] → flat directory records
 */
export function normalizeGobuster(data: any): OutputRecord[] {
  const records: OutputRecord[] = []

  const results = data?.results ?? data?.found ?? []
  for (const result of results) {
    records.push({
      type: "directory",
      path: result?.path ?? result?.url ?? "",
      status: result?.status ?? result?.status_code ?? 0,
      size: result?.size ?? result?.length ?? 0,
    })
  }

  return records
}

/**
 * Normalize sqlmap SQL injection results.
 */
export function normalizeSqlmap(data: any): OutputRecord[] {
  const records: OutputRecord[] = []

  // Injection points
  const injections = data?.injections ?? data?.injection_points ?? []
  for (const inj of injections) {
    records.push({
      type: "injection",
      parameter: inj?.parameter ?? inj?.param ?? "",
      type_name: inj?.type ?? "",
      title: inj?.title ?? "",
      payload: inj?.payload ?? "",
    })
  }

  // Database info
  const dbs = data?.databases ?? []
  for (const db of dbs) {
    if (typeof db === "string") {
      records.push({ type: "database", name: db })
    } else {
      records.push({
        type: "database",
        name: db?.name ?? "",
        tables: db?.tables?.length ?? 0,
      })
    }
  }

  // Tables
  const tables = data?.tables ?? []
  for (const table of tables) {
    if (typeof table === "string") {
      records.push({ type: "table", name: table })
    } else {
      records.push({
        type: "table",
        name: table?.name ?? "",
        database: table?.database ?? "",
        columns: table?.columns?.length ?? 0,
      })
    }
  }

  return records
}

/**
 * Normalize nuclei vulnerability scanner results.
 */
export function normalizeNuclei(data: any): OutputRecord[] {
  const records: OutputRecord[] = []

  const results = data?.results ?? data?.findings ?? []
  for (const result of results) {
    records.push({
      type: "vulnerability",
      template_id: result?.template_id ?? result?.templateID ?? "",
      name: result?.name ?? result?.info?.name ?? "",
      severity: result?.severity ?? result?.info?.severity ?? "",
      host: result?.host ?? result?.matched ?? "",
      matched_at: result?.matched_at ?? result?.matchedAt ?? "",
      extracted: result?.extracted_results?.join(", ") ?? "",
      description: result?.description ?? result?.info?.description ?? "",
      reference: Array.isArray(result?.reference) ? result.reference.join(", ") : (result?.reference ?? ""),
    })
  }

  return records
}

/**
 * Normalize hydra brute-force results.
 */
export function normalizeHydra(data: any): OutputRecord[] {
  const records: OutputRecord[] = []

  const results = data?.results ?? data?.credentials ?? data?.found ?? []
  for (const result of results) {
    records.push({
      type: "credential",
      host: result?.host ?? result?.target ?? "",
      port: Number(result?.port) || 0,
      service: result?.service ?? result?.protocol ?? "",
      login: result?.login ?? result?.username ?? "",
      password: result?.password ?? "",
    })
  }

  return records
}

/**
 * Registry of tool-specific normalizers.
 * Key is the MCP server name (e.g., "nmap", "ffuf").
 */
export const normalizers: Record<string, Normalizer> = {
  nmap: normalizeNmap,
  ffuf: normalizeFfuf,
  nikto: normalizeNikto,
  gobuster: normalizeGobuster,
  sqlmap: normalizeSqlmap,
  nuclei: normalizeNuclei,
  hydra: normalizeHydra,
}

/**
 * Generic fallback normalizer for unknown tools.
 * Attempts to flatten any arrays found in the data.
 */
export function normalizeGeneric(data: any, rawOutput?: string): OutputRecord[] {
  if (!data || typeof data !== "object") {
    return normalizeRawOutput(rawOutput ?? "")
  }

  const records: OutputRecord[] = []

  // Try to find and flatten arrays in the data
  for (const [key, value] of Object.entries(data)) {
    if (Array.isArray(value) && value.length > 0) {
      // Found an array - try to use it as records
      for (let i = 0; i < value.length; i++) {
        const item = value[i]
        if (typeof item === "object" && item !== null) {
          records.push({
            type: key.replace(/s$/, ""), // "results" -> "result"
            _index: i,
            ...item,
          })
        } else {
          records.push({
            type: key.replace(/s$/, ""),
            _index: i,
            value: item,
          })
        }
      }
      // Only use the first array found
      if (records.length > 0) break
    }
  }

  // If no arrays found, fall back to raw output
  if (records.length === 0 && rawOutput) {
    return normalizeRawOutput(rawOutput)
  }

  return records
}

/**
 * Normalize raw text output to line-based records.
 * Used as ultimate fallback for unstructured outputs.
 */
export function normalizeRawOutput(rawOutput: string): OutputRecord[] {
  return rawOutput
    .split("\n")
    .filter((line) => line.trim().length > 5)
    .map((line, i) => ({
      type: "line",
      _index: i,
      text: line,
    }))
}

/**
 * Normalize MCP tool data to flat records.
 * Uses tool-specific normalizer if available, otherwise falls back to generic.
 */
export function normalize(tool: string, data: any, rawOutput?: string): OutputRecord[] {
  // Extract tool name from MCP tool name (e.g., "nmap_port_scan" -> "nmap")
  const toolBase = tool.split("_")[0].toLowerCase()

  const normalizer = normalizers[toolBase]
  if (normalizer && data && typeof data === "object") {
    const records = normalizer(data)
    if (records.length > 0) {
      log.info("normalized", { tool: toolBase, records: records.length })
      return records
    }
  }

  // Fall back to generic normalizer
  log.info("using generic normalizer", { tool })
  return normalizeGeneric(data, rawOutput)
}
