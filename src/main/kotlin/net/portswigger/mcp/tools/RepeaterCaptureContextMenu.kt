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
import javax.swing.JMenuItem
import javax.swing.KeyStroke

private const val CAPTURE_MENU_LABEL = "Capture Repeater item for MCP"

// On macOS Burp maps "Ctrl" in a hotkey to the Command (⌘) key, so this binds to ⌘+Shift+S.
private const val CAPTURE_HOTKEY = "Ctrl+Shift+S"

// Display-only accelerator shown on the context menu item. Using the platform menu-shortcut
// mask keeps the hint consistent with Burp's "Ctrl" mapping: ⌘⇧S on macOS, Ctrl+Shift+S elsewhere.
private val CAPTURE_ACCELERATOR: KeyStroke =
    KeyStroke.getKeyStroke(
        KeyEvent.VK_S,
        Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx or InputEvent.SHIFT_DOWN_MASK
    )

fun registerRepeaterCaptureContextMenu(api: MontoyaApi) {
    api.userInterface().registerContextMenuItemsProvider(object : ContextMenuItemsProvider {
        override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
            if (!event.isFromTool(ToolType.REPEATER)) {
                return emptyList()
            }

            val menuItem = JMenuItem(CAPTURE_MENU_LABEL)
            menuItem.accelerator = CAPTURE_ACCELERATOR
            menuItem.addActionListener {
                val requestResponse = event.messageEditorRequestResponse().orElse(null)?.requestResponse()
                    ?: event.selectedRequestResponses().firstOrNull()

                captureRepeaterItem(api, requestResponse)
            }

            return listOf(menuItem)
        }
    })
}

fun registerRepeaterCaptureHotKey(api: MontoyaApi) {
    api.userInterface().registerHotKeyHandler(
        HotKeyContext.HTTP_MESSAGE_EDITOR,
        CAPTURE_HOTKEY
    ) { event ->
        if (!event.isFromTool(ToolType.REPEATER)) {
            return@registerHotKeyHandler
        }

        val requestResponse = event.messageEditorRequestResponse().orElse(null)?.requestResponse()

        captureRepeaterItem(api, requestResponse)
    }
}

private fun captureRepeaterItem(api: MontoyaApi, requestResponse: HttpRequestResponse?) {
    if (requestResponse == null) {
        api.logging().logToOutput("No Repeater request/response available to capture")
        return
    }

    RepeaterCaptureStore.lastCapturedItem = CapturedRepeaterItem(
        request = requestResponse.request()?.toString(),
        response = requestResponse.response()?.toString(),
        capturedAt = Instant.now().toString()
    )

    api.logging().logToOutput("Captured Repeater item for MCP")
}
