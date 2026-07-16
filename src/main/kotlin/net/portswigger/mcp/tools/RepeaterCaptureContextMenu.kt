package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.hotkey.HotKeyContext
import java.awt.Component
import java.awt.Toolkit
import java.awt.event.InputEvent
import java.awt.event.KeyEvent
import java.time.Instant
import javax.swing.JMenu
import javax.swing.JMenuItem
import javax.swing.KeyStroke

private const val CAPTURE_MENU_LABEL = "Capture Repeater item for MCP"

// On macOS Burp maps "Ctrl" in a hotkey to the Command (⌘) key, so slot N binds to ⌘+Shift+N.
private fun captureHotKey(slot: Int): String = "Ctrl+Shift+$slot"

// Display-only accelerator shown on each context menu item. Using the platform menu-shortcut
// mask keeps the hint consistent with Burp's "Ctrl" mapping: ⌘⇧N on macOS, Ctrl+Shift+N elsewhere.
private fun captureAccelerator(slot: Int): KeyStroke =
    KeyStroke.getKeyStroke(
        KeyEvent.VK_0 + slot,
        Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx or InputEvent.SHIFT_DOWN_MASK
    )

fun registerRepeaterCaptureContextMenu(api: MontoyaApi) {
    api.userInterface().registerContextMenuItemsProvider(object : ContextMenuItemsProvider {
        override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
            if (!event.isFromTool(ToolType.REPEATER)) {
                return emptyList()
            }

            val menu = JMenu(CAPTURE_MENU_LABEL)

            for (slot in 1..RepeaterCaptureStore.SLOT_COUNT) {
                val menuItem = JMenuItem("Slot $slot")
                menuItem.accelerator = captureAccelerator(slot)
                menuItem.addActionListener {
                    val requestResponse = event.messageEditorRequestResponse().orElse(null)?.requestResponse()
                        ?: event.selectedRequestResponses().firstOrNull()

                    captureRepeaterItem(api, slot, requestResponse)
                }
                menu.add(menuItem)
            }

            return listOf(menu)
        }
    })
}

fun registerRepeaterCaptureHotKeys(api: MontoyaApi) {
    for (slot in 1..RepeaterCaptureStore.SLOT_COUNT) {
        api.userInterface().registerHotKeyHandler(
            HotKeyContext.HTTP_MESSAGE_EDITOR,
            captureHotKey(slot)
        ) { event ->
            if (!event.isFromTool(ToolType.REPEATER)) {
                return@registerHotKeyHandler
            }

            val requestResponse = event.messageEditorRequestResponse().orElse(null)?.requestResponse()

            captureRepeaterItem(api, slot, requestResponse)
        }
    }
}

private fun captureRepeaterItem(api: MontoyaApi, slot: Int, requestResponse: HttpRequestResponse?) {
    if (requestResponse == null) {
        api.logging().logToOutput("No Repeater request/response available to capture")
        return
    }

    RepeaterCaptureStore.set(
        slot, CapturedRepeaterItem(
            request = requestResponse.request()?.toString(),
            response = requestResponse.response()?.toString(),
            capturedAt = Instant.now().toString()
        )
    )

    api.logging().logToOutput("Captured Repeater item for MCP slot $slot")
}
