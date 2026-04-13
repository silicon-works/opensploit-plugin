/** @jsxImportSource @opentui/solid */
import type { TuiPlugin, TuiPluginModule } from "@opencode-ai/plugin/tui"
import { toggleUltrasploit, isUltrasploitEnabled } from "./hooks/ultrasploit"

const tui: TuiPlugin = async (api, options, meta) => {
  api.command.register(() => [
    {
      title: "Toggle Ultrasploit mode",
      value: "opensploit.ultrasploit",
      category: "OpenSploit",
      description: "Auto-approve all permission requests for fast iteration",
      slash: {
        name: "ultrasploit",
      },
      onSelect() {
        const nowEnabled = toggleUltrasploit()
        api.kv.set("opensploit.ultrasploit", nowEnabled)
        api.ui.toast({
          variant: nowEnabled ? "warning" : "info",
          title: "Ultrasploit",
          message: nowEnabled
            ? "Enabled — all permissions auto-approved"
            : "Disabled",
        })
      },
    },
  ])

  // Restore state from kv on load
  const saved = api.kv.get<boolean>("opensploit.ultrasploit", false)
  if (saved) {
    const { setUltrasploit } = await import("./hooks/ultrasploit")
    setUltrasploit(true)
  }

  api.lifecycle.onDispose(() => {
    // cleanup if needed
  })
}

const plugin: TuiPluginModule = {
  id: "opensploit",
  tui,
}

export default plugin
