/** @jsxImportSource @opentui/solid */
import type { TuiPlugin, TuiPluginModule } from "@opencode-ai/plugin/tui"

const tui: TuiPlugin = async (api, options, meta) => {
  // Register opensploit-specific commands
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
        // TODO: toggle ultrasploit state via kv
        const current = api.kv.get<boolean>("opensploit.ultrasploit", false)
        api.kv.set("opensploit.ultrasploit", !current)
        api.ui.toast({
          variant: current ? "info" : "warning",
          title: "Ultrasploit",
          message: current ? "Disabled" : "Enabled — all permissions auto-approved",
        })
      },
    },
  ])

  // TODO Phase 5: sidebar engagement state widget via api.slots.register()
  // TODO Phase 5: home_logo slot for OpenSploit branding

  api.lifecycle.onDispose(() => {
    // cleanup if needed
  })
}

const plugin: TuiPluginModule = {
  id: "opensploit",
  tui,
}

export default plugin
