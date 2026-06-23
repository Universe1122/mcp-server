package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import java.awt.Component
import java.time.Instant
import javax.swing.JMenuItem

fun registerRepeaterCaptureContextMenu(api: MontoyaApi) {
    api.userInterface().registerContextMenuItemsProvider(object : ContextMenuItemsProvider {
        override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
            if (!event.isFromTool(ToolType.REPEATER)) {
                return emptyList()
            }

            val menuItem = JMenuItem("Capture Repeater item for MCP")
            menuItem.addActionListener {
                val requestResponse = event.messageEditorRequestResponse().orElse(null)?.requestResponse()
                    ?: event.selectedRequestResponses().firstOrNull()

                if (requestResponse == null) {
                    api.logging().logToOutput("No Repeater request/response available to capture")
                    return@addActionListener
                }

                RepeaterCaptureStore.lastCapturedItem = CapturedRepeaterItem(
                    request = requestResponse.request()?.toString(),
                    response = requestResponse.response()?.toString(),
                    capturedAt = Instant.now().toString()
                )

                api.logging().logToOutput("Captured Repeater item for MCP")
            }

            return listOf(menuItem)
        }
    })
}
