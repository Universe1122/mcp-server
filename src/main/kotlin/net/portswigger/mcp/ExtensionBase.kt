package net.portswigger.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.editor.EditorOptions
import net.portswigger.mcp.config.ConfigUi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager
import net.portswigger.mcp.openapi.OpenApiViewer
import net.portswigger.mcp.packet.ApiInventoryViewer
import net.portswigger.mcp.packet.PacketDetail
import net.portswigger.mcp.tools.registerRepeaterCaptureContextMenu
import net.portswigger.mcp.tools.registerRepeaterCaptureHotKeys
import javax.swing.JTabbedPane
import java.nio.charset.StandardCharsets
import java.util.Base64

@Suppress("unused")
class ExtensionBase : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Burp MCP Server")
        registerRepeaterCaptureContextMenu(api)
        registerRepeaterCaptureHotKeys(api)

        val config = McpConfig(api.persistence().extensionData(), api.logging())
        val serverManager = KtorServerManager(api)

        val proxyJarManager = ProxyJarManager(api.logging())

        val configUi = ConfigUi(
            config = config, providers = listOf(
                ClaudeDesktopProvider(api.logging(), proxyJarManager),
                ManualProxyInstallerProvider(api.logging(), proxyJarManager),
            )
        )

        configUi.onEnabledToggled { enabled ->
            configUi.getConfig()

            if (enabled) {
                serverManager.start(config) { state ->
                    configUi.updateServerState(state)
                }
            } else {
                serverManager.stop { state ->
                    configUi.updateServerState(state)
                }
            }
        }

        val openApiViewer = OpenApiViewer(
            store = serverManager.openApiStore,
            tagStore = serverManager.packetRepository,
            createRepeaterTab = { draft ->
                val service = HttpService.httpService(draft.host, draft.port, draft.usesHttps)
                val request = HttpRequest.httpRequest(service, draft.rawRequest)
                api.repeater().sendToRepeater(request, draft.tabName)
            },
            loadPacket = { historyId, packetId ->
                serverManager.packetRepository.getPacketByHistoryId(historyId, packetId, 1_048_576)
            },
            sendPacketToRepeater = { packet -> sendSavedPacketToRepeater(api, packet) },
            createPacketRequestEditor = { packet ->
                api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY).apply {
                    request = savedRequest(packet)
                }.uiComponent()
            },
            createPacketResponseEditor = { packet ->
                api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY).apply {
                    response = HttpResponse.httpResponse(savedMessage(packet.responseHeaders.orEmpty(), packet.responseBodyBase64))
                }.uiComponent()
            },
        )
        val inventoryViewer = ApiInventoryViewer(serverManager.packetRepository)
        val mcpTabs = JTabbedPane().apply {
            addTab("Inventory", inventoryViewer)
            addTab("Swagger", openApiViewer)
            addTab("Settings", configUi.component)
            selectedIndex = 1
        }
        api.userInterface().registerSuiteTab("MCP", mcpTabs)

        api.extension().registerUnloadingHandler {
            serverManager.shutdown()
            openApiViewer.close()
            inventoryViewer.close()
            configUi.cleanup()
            config.cleanup()
        }

        if (config.enabled) {
            serverManager.start(config) { state ->
                configUi.updateServerState(state)
            }
        }
    }

    private fun sendSavedPacketToRepeater(api: MontoyaApi, packet: PacketDetail) {
        require(!packet.requestBodyTruncated) { "The saved request is too large for the packet preview" }
        api.repeater().sendToRepeater(
            savedRequest(packet),
            "DB #${packet.id} ${packet.method}",
        )
    }

    private fun savedRequest(packet: PacketDetail): HttpRequest {
        val service = HttpService.httpService(packet.host, packet.port, packet.usesHttps)
        return HttpRequest.httpRequest(service, savedMessage(packet.requestHeaders, packet.requestBodyBase64))
    }

    private fun savedMessage(headers: String, bodyBase64: String?): BurpByteArray {
        val head = headers.trimEnd('\r', '\n').toByteArray(StandardCharsets.ISO_8859_1)
        val body = bodyBase64?.let(Base64.getDecoder()::decode) ?: byteArrayOf()
        return BurpByteArray.byteArray(*(head + "\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1) + body))
    }
}
