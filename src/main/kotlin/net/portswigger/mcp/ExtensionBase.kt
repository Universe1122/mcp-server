package net.portswigger.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import net.portswigger.mcp.config.ConfigUi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager
import net.portswigger.mcp.openapi.OpenApiViewer
import net.portswigger.mcp.tools.registerRepeaterCaptureContextMenu
import net.portswigger.mcp.tools.registerRepeaterCaptureHotKeys
import javax.swing.JTabbedPane

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

        val openApiViewer = OpenApiViewer(serverManager.openApiStore) { draft ->
            val service = HttpService.httpService(draft.host, draft.port, draft.usesHttps)
            val request = HttpRequest.httpRequest(service, draft.rawRequest)
            api.repeater().sendToRepeater(request, draft.tabName)
        }
        val mcpTabs = JTabbedPane().apply {
            addTab("Swagger", openApiViewer)
            addTab("Settings", configUi.component)
            selectedIndex = 1
        }
        api.userInterface().registerSuiteTab("MCP", mcpTabs)

        api.extension().registerUnloadingHandler {
            serverManager.shutdown()
            openApiViewer.close()
            configUi.cleanup()
            config.cleanup()
        }

        if (config.enabled) {
            serverManager.start(config) { state ->
                configUi.updateServerState(state)
            }
        }
    }
}
