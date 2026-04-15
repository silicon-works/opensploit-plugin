/** @jsxImportSource @opentui/solid */
import type { TuiPlugin, TuiPluginModule } from "@opencode-ai/plugin/tui"
import { createSignal } from "solid-js"
import { toggleUltrasploit, isUltrasploitEnabled } from "./hooks/ultrasploit"
import { createUltrasploitPostProcess } from "./tui-rainbow"
import { OpenSploitLogo } from "./tui-logo"

const tui: TuiPlugin = async (api, options, meta) => {
  // Restore state from kv on load
  const saved = api.kv.get<boolean>("opensploit.ultrasploit", false)
  if (saved) {
    const { setUltrasploit } = await import("./hooks/ultrasploit")
    setUltrasploit(true)
  }

  // Reactive signal tracks ultrasploit state for the sidebar indicator
  const [ultrasploitActive, setUltrasploitActive] = createSignal(
    saved || isUltrasploitEnabled(),
  )

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
        setUltrasploitActive(nowEnabled)
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

  // Replace OpenCode logo with OpenSploit logo
  api.slots.register({
    order: 0,
    slots: {
      home_logo() {
        return (
          <OpenSploitLogo
            textMuted={api.theme.current.textMuted}
            text={api.theme.current.text}
            background={api.theme.current.background}
          />
        )
      },
      sidebar_footer() {
        if (!ultrasploitActive()) return null
        return (
          <text fg={api.theme.current.warning}>
            <b>{"\u26A1"} ULTRASPLOIT</b>
          </text>
        )
      },
    },
  })

  // Rainbow post-processor: colors "ultrasploit" text everywhere on screen
  const postProcess = createUltrasploitPostProcess()
  api.renderer.addPostProcessFn(postProcess)

  api.lifecycle.onDispose(() => {
    api.renderer.removePostProcessFn(postProcess)
  })
}

const plugin: TuiPluginModule = {
  id: "opensploit",
  tui,
}

export default plugin
