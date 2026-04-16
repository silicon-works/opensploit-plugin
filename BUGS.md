# OpenSploit Plugin — Known Bugs

Found via adversarial testing. 103 bugs across 9 modules.
Review each and mark: confirm, dispute, or defer.

---

## HIGH severity (20)

### Registry Search

**BUG-RS-1: Regex injection crash in searchToolsInMemory**
- Query containing `(`, `[`, `{`, `*`, `+`, or `\` crashes with `SyntaxError: Invalid regular expression`
- Example: agent queries "scan (TCP)" or "check [http]"
- Line: ~1056 of tool-registry-search.ts (`new RegExp(\`\\b${word}\\b\`, "g")`)
- Fix: escape regex metacharacters before constructing RegExp

### Engagement State

**BUG-ES-1: Lost-update race on concurrent writes**
- Two sub-agents calling update_engagement_state simultaneously: both read same state, merge independently, second write silently overwrites first
- Confirmed: port 22 lost when agents wrote ports 22 and 80 concurrently
- Fix: write-to-temp + rename (atomic) combined with per-session mutex

**BUG-ES-2: loadEngagementState returns wrong type on corrupt YAML**
- If state.yaml contains a plain string, number, or array, `yaml.load()` returns that type
- `parsed ?? {}` only catches null/undefined
- Callers doing `Object.keys(state)` or accessing `.ports` on a non-object get silently wrong results
- Fix: add `typeof parsed === "object" && !Array.isArray(parsed)` validation

### Output Store

**BUG-OS-1: Path traversal in outputId**
- `query({ outputId: "../secret" })` reads files outside the `outputs/` directory
- `path.join(sessionDir, outputId + ".json")` with zero sanitization
- Fix: reject outputId containing `..` or `/`

**BUG-OS-2: Path traversal in sessionId**
- `sessionId = "../../tmp/evil"` creates directories and writes files outside `~/.opensploit/sessions/`
- Fix: validate sessionId contains no path separators or `..`

### Security + Hooks

**BUG-SH-1: IPv6 addresses bypass isPrivateIP entirely**
- `::1`, `fe80::1`, `fc00::1` all return false
- IPv6 loopback classified as "external"
- Fix: add IPv6 support to isPrivateIP

**BUG-SH-2: CIDR notation not parsed**
- `10.0.0.0/8` treated as hostname, classified as "external"
- The `/8` suffix breaks the IP regex
- Fix: strip CIDR suffix before IP classification

**BUG-SH-3: URL-encoded IPs bypass classification**
- Bare `%31%30%2e%31%30%2e%31%30%2e%31` treated as hostname
- Fix: URL-decode before classification

**BUG-SH-4: IP:port format not recognized**
- `10.10.10.1:8080` breaks IP regex, treated as hostname
- Fix: strip port suffix before classification

**BUG-SH-5: Bash blocking trivially bypassable**
- Case (`Nmap`), full path (`/usr/bin/nmap`), subshell (`$(nmap)`), pipe (`echo | nmap`), semicolon (`; nmap`), backticks all bypass glob patterns
- Note: this is OpenCode's permission system, not plugin code. Plugin's `BLOCKED_BASH_PATTERNS` is dead code.

**BUG-SH-6: Path traversal via /session/../../../etc/passwd**
- `translateSessionPath` does `path.join(sessionDir, relativePath)` which resolves `..` segments
- Fix: reject paths containing `..` after stripping `/session/` prefix

### Container + MCP

**BUG-CM-1: Negative memory_mb passed to Docker**
- `--memory -100m` sent to Docker (Docker rejects with raw error)
- Fix: validate memory_mb > 0

**BUG-CM-2: NaN/Infinity cpu passed to Docker**
- `--cpus NaN` or `--cpus Infinity` sent to Docker
- Fix: validate cpu is a finite positive number

**BUG-CM-3: imageExists("--help") returns true**
- Docker treats `--help` as a flag, exits 0
- Skips image pull, causes downstream failure
- Fix: add `--` before image argument

**BUG-CM-4: JSON.parse result not validated as object for MCP args**
- `JSON.parse('"hello"')` returns string, assigned as `args: Record<string, unknown>`
- MCP server receives wrong argument types
- Fix: validate `typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)`

**BUG-CM-5: Registry with tools:null crashes**
- `registry.tools[toolName]` throws on null
- Fix: validate registry shape before property access

### Memory + Patterns

**BUG-MP-1: Password regex misses "password: value" (colon+space)**
- `password: letmein` and `secret: my_api_key_123` pass through anonymization unredacted
- Training data leaks real credentials
- Fix: add `\s*` after `[=:\s]` in PASSWORD_PATTERNS

**BUG-MP-2: containsSensitiveData has regex /g lastIndex bug**
- `SSH_KEY_PATTERN` is global. `.test()` advances `lastIndex`
- Alternating true/false results for identical input
- Fix: remove `/g` flag or reset `lastIndex` before `.test()`

### Trajectory + Session

**BUG-TS-1: Path traversal in trajectory appendEntry**
- `appendEntry("../../tmp/evil", entry)` writes outside `~/.opensploit/sessions/`
- Fix: validate sessionID

**BUG-TS-2: Path traversal in SessionDirectory.create**
- `create("../../tmp/X")` escapes the `opensploit-session-` namespace
- Fix: validate sessionID

---

## MEDIUM severity (32)

### Registry Search

**BUG-RS-2: Routing penalty has no lower bound**
- 5 never_use_for matches → penalty = -1.0 with no floor
- Can dominate dense score

**BUG-RS-3: Negative _distance produces score > 1.0 or Infinity**
- `1/(1 + -0.5)` = 2.0, `1/(1 + -1.0)` = Infinity
- No guard against non-positive distances

### Engagement State

**BUG-ES-3: NaN port creates unkillable duplicates**
- `NaN !== NaN` in JS, so every NaN port treated as new
- Unbounded accumulation

**BUG-ES-4: Port dedup fails when protocol is missing from one side**
- Existing `protocol: "tcp"` vs update `protocol: undefined` → duplicate

**BUG-ES-5: Credential dedup splits on service=undefined vs service="ssh"**
- Same username appears twice

**BUG-ES-6: toolFailures count always increments by 1**
- Ignores incoming item's count value

**BUG-ES-7: toolFailures count=0 treated as 1**
- `(0 || 1) + 1 = 2` — should use `??` instead of `||`

### Output Store

**BUG-OS-3: Circular data crashes store()**
- `JSON.stringify` without try/catch
- Any MCP tool returning circular object crashes entire pipeline

**BUG-OS-4: Negative limit silently drops records**
- `slice(0, -1)` removes last record

**BUG-OS-5: Cleanup catch block missing inner try/catch**
- `statSync` after failed `readFileSync` can throw if file deleted between calls

### Security + Hooks

**BUG-SH-7: Trailing dot on hostname fails internal check**
- `target.htb.` doesn't match `/\.htb$/i`

**BUG-SH-8: Attacker domains ending .htb classified as internal**
- `evil.com.htb` matches internal regex

**BUG-SH-9: Regex /g flag on KEYWORD_REGEX causes stateful lastIndex**
- `/\bultrasploit\b/gi` with `.test()` advances lastIndex between calls

**BUG-SH-10: Path traversal in /session/ prefix**
- Already covered by BUG-SH-6

**BUG-SH-11: /session/ in bash argument values gets rewritten**
- `grep '/session/foo' file.txt` leaks real session directory

**BUG-SH-12: No message-based way to disable ultrasploit**
- "disable ultrasploit" re-triggers activation

### Container + MCP

**BUG-CM-6: activeCalls goes negative on acquire() throw**
- Decrement in finally runs but increment was never reached

**BUG-CM-7: idleTimeout=0 falls through to 5-minute default**
- `||` treats 0 as falsy. Fix: use `??`

**BUG-CM-8: Concurrent getClient() races orphan first container**

**BUG-CM-9: timeout=0 treated as "not specified"**
- Same `||` vs `??` issue

**BUG-CM-10: Env key with = creates malformed Docker flag**

**BUG-CM-11: MCP response with only non-text content produces empty rawOutput**

**BUG-CM-12: clockOffset silently overwrites existing LD_PRELOAD**

**BUG-CM-13: toolFailures count=0 → 2 instead of 1**
- Same `||` vs `??` as BUG-ES-7

### Memory + Patterns

**BUG-MP-3: deriveVulnType misclassifies "Java Deserialization RCE"**
- "rce" check before "deserialization" check

**BUG-MP-4: parseSparseJson accepts non-numeric values**
- NaN in downstream dot product/cosine scoring

**BUG-MP-5: parsePattern phases_json="null" produces null not []**
- `.map()` on null crashes

### Pattern + Output Tools

**BUG-PT-1: pattern-search has no try/catch**
- null results crash, thrown errors propagate unhandled

**BUG-PT-2: save-pattern has no try/catch**
- Thrown errors propagate unhandled

**BUG-PT-3: save-pattern crashes on null key_insights**
- `.map()` on null before `||` fallback

**BUG-PT-4: pattern-search limit accepts negative values**

**BUG-PT-5: read-tool-output negative limit silently drops records**

### Trajectory + Session

**BUG-TS-3: Circular refs in trajectory entries silently dropped**

**BUG-TS-4: writeSessionMeta writes "null" strings for null fields**

**BUG-TS-5: unregisterTree leaves orphaned grandchildren**

**BUG-TS-6: Null bytes in translateSessionPath pass through unsanitized**

---

## LOW severity (30)

### Registry Search
- BUG-RS-4: see_also_json with non-array JSON silently corrupts data
- BUG-RS-5: null entries in never_use_for bypass type check
- BUG-RS-6: BM25 normalization kills differentiation above score 20
- BUG-RS-7: Empty query matches ALL tools
- BUG-RS-8: Naive plural stripping ("status" → "statu")
- BUG-RS-9: parseSparseJson allows non-numeric values (NaN propagation)
- BUG-RS-10: Negative limit produces wrong results via slice(0,-1)

### Engagement State
- BUG-ES-8: Non-atomic file writes (truncated reads possible)
- BUG-ES-9: No port range validation (negative, >65535, Infinity, NaN)
- BUG-ES-10: No IP validation (empty, broadcast, garbage)
- BUG-ES-11: Unbounded vulnerability/failedAttempts growth

### Output Store
- BUG-OS-6: Normalizers don't coerce port types

### Security + Hooks
- BUG-SH-13: No size cap on system transform injection
- BUG-SH-14: Event hook messageCache grows unbounded
- BUG-SH-15: Missing tool blocks: ncat, socat, masscan, rustscan, python3
- BUG-SH-16: ultrasploit in code blocks still activates

### Container + MCP
- BUG-CM-14: CallMutex.acquire() after destroy() gives unclear error
- BUG-CM-15: Failure recording silently swallows ENOSPC
- BUG-CM-16: Clock offset string not validated
- BUG-CM-17: Service container names can collide (Date.now())

### Agents + Prompts
- BUG-AP-1: Bare curl/wget/nc/ssh/scp without args bypass deny patterns
- BUG-AP-2: Research agent prompt says "no bash" but config allows it
- BUG-AP-3: Post agent prompt says "no mcp_tool" but config allows it
- BUG-AP-4: Unicode character offset risk in rainbow post-processor

### Memory + Patterns
- BUG-MP-6: severityToScore is case-sensitive
- BUG-MP-7: NaN/Infinity in sparse vectors propagate silently
- BUG-MP-8: createExperience accepts wrong vector dimensions

### Trajectory + Session
- BUG-TS-7: messageCache/writtenParts grow unbounded
- BUG-TS-8: registerRootSession silently overwrites on duplicate
- BUG-TS-9: Empty tool name recorded without validation

---

## INFO (13)

- BUG-RS-INFO-1: never_use_for uses substring .includes() ("scan" matches "scanner")
- BUG-RS-INFO-2: checkAntiPatterns returns only first warning
- BUG-RS-INFO-3: 10,000-char method descriptions included verbatim
- BUG-ES-INFO-1: toolSearchCache summary undermined by full YAML dump
- BUG-ES-INFO-2: Triple backticks in passwords break markdown fence
- BUG-CM-INFO-1: Error messages expose Docker image names to LLM
- BUG-CM-INFO-2: No registry signature verification (cache poisoning possible)
- BUG-CM-INFO-3: Session dir with colon breaks Docker mount
- BUG-MP-INFO-1: IPv6 addresses not anonymized
- BUG-MP-INFO-2: Backtick-quoted passwords not matched
- BUG-MP-INFO-3: calculateDuration returns NaN on invalid dates
- BUG-MP-INFO-4: detectPivotalSteps skips step 0
- BUG-PT-INFO-1: VALID_OBJECTIVES is dead code
