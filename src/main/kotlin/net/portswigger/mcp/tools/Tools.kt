package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.sitemap.SiteMapFilter
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.packet.PacketRepository
import net.portswigger.mcp.schema.buildSiteMapTree
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HistoryAccessSecurity
import net.portswigger.mcp.security.HistoryAccessType
import java.awt.KeyboardFocusManager
import java.util.Base64
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkHistoryPermissionOrDeny(
    accessType: HistoryAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = HistoryAccessSecurity.checkHistoryAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private class HistoryAccessDeniedException(historyName: String) :
    Exception("$historyName access denied by Burp Suite")

/**
 * 거부를 예외로 올린다. mcpTool 의 try/catch 가 isError = true 로 바꿔 준다.
 *
 * 페이징 도구가 원소 타입 그대로(List<ProxyHttpRequestResponse> 등)를 반환하게 되면서,
 * 거부 메시지를 결과 시퀀스에 끼워 넣던 기존 방식(sequenceOf("... denied ...")) 은
 * 타입이 맞지 않아 쓸 수 없다.
 */
private fun requireHistoryAccess(
    accessType: HistoryAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
) {
    val allowed = runBlocking { checkHistoryPermissionOrDeny(accessType, config, api, logMessage) }
    if (!allowed) throw HistoryAccessDeniedException(logMessage)
}

private const val MAX_HTTP_HISTORY_PAGE_CHARS = 16_777_216
internal const val MAX_HTTP_HISTORY_BODY_CHUNK_BYTES = 262_144

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedNames = listOf(":scheme", ":method", ":path", ":authority")
    val fixed = LinkedHashMap<String, String>().apply {
        orderedNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) put(name, value)
        }
        pseudoHeaders.forEach { (key, value) ->
            val name = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(name)) put(name, value)
        }
    }
    return (fixed + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/** Normalize the request line and headers while preserving the body verbatim. */
internal fun normalizeHttpContent(content: String): String {
    val markers = listOf("\r\n\r\n", "\n\n", "\\r\\n\\r\\n", "\\n\\n")
    val end = markers.mapNotNull { marker ->
        content.indexOf(marker).takeIf { it >= 0 }?.let { it to marker.length }
    }.minByOrNull { it.first }?.let { it.first + it.second }
    return if (end == null) normalizePrelude(content)
    else normalizePrelude(content.substring(0, end)) + content.substring(end)
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")
    .replace("\\n", "\n")
    .replace("\\r", "")
    .replace("\r", "")
    .replace("\n", "\r\n")

fun Server.registerTools(api: MontoyaApi, config: McpConfig, packets: PacketRepository) {
    // Direct-send tools are intentionally not exposed: agent traffic should pass through Burp Proxy.
    mcpUnitTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Prefer create_repeater_tab_http2 for HTTP/2 targets.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), normalizeHttpContent(content))
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Do NOT pass headers to the body parameter.") {
        val request = HttpRequest.http2Request(toMontoyaService(), buildHttp2HeaderList(pseudoHeaders, headers), requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. HTTP/1 line endings are normalized to CRLF.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), normalizeHttpContent(content))
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportProjectOptionsAsJson()
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportUserOptionsAsJson()
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpTool<GetSiteMap>(
        "Returns the Burp site map as a tree (mirroring Target > Site map). " +
                "Top-level keys are \"scheme://host[:port]\"; each node has optional \"entries\" " +
                "(requests recorded at that exact path) and \"children\" (sub-path segments). " +
                "Each entry contains method, URL, host, status code, response length, MIME type, " +
                "params flag, and notes. " +
                "Optionally filter by URL prefix (e.g. \"https://example.com\") to limit the tree " +
                "to a specific scheme/host/path. " +
                "Montoya's API only exposes a flat List<HttpRequestResponse> via siteMap().requestResponses(); " +
                "the tree is reconstructed from each item's URL."
    ) {
        val items = if (urlPrefix.isNullOrBlank()) {
            api.siteMap().requestResponses()
        } else {
            api.siteMap().requestResponses(SiteMapFilter.prefixFilter(urlPrefix))
        }
        val tree = buildSiteMapTree(items)
        Json.encodeToString(tree)
    }

    // 아래 히스토리 도구들은 원소를 그대로 반환하고 직렬화는 mapper 에 맡긴다.
    // Sequence 오버로드는 map 이 붙은 뒤에 drop(offset) 을 걸어서, 버려지는 offset 구간의
    // 메시지까지 전부 문자열로 물린 다음 폐기했다. List 오버로드는 subList 로 먼저 자르고
    // transform 을 적용하므로, 실제로 반환되는 count 개만 직렬화된다.
    mcpPaginatedTool<GetProxyHttpHistory, ProxyHttpRequestResponse>(
        "Displays items within the proxy HTTP history. To bound memory use, request bodies are " +
                "limited to 1 MiB, non-JavaScript response bodies to 4 MiB, and each page to roughly " +
                "16 MiB of characters. JavaScript bodies are omitted here and marked with " +
                "responseIsJavaScript=true so they can be fetched through the bounded chunk tool. " +
                "Each item reports the original body sizes and truncation flags. A " +
                "byte-limited page can contain fewer items than count; advance offset by the number " +
                "of items actually returned.",
        maxOutputChars = MAX_HTTP_HISTORY_PAGE_CHARS,
        mapper = { Json.encodeToString(it.toSerializableForm()) }
    ) {
        requireHistoryAccess(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")

        api.proxy().history()
    }

    mcpTool(
        "get_proxy_http_history_size",
        "Returns the number of items currently in the proxy HTTP history. " +
                "Cheap compared to get_proxy_http_history because message bodies are never read. " +
                "Poll this to detect whether new items arrived before fetching a page."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }

        if (!allowed) {
            "HTTP history access denied by Burp Suite"
        } else {
            api.proxy().history().size.toString()
        }
    }

    mcpTool<GetProxyHttpResponseBodyChunk>(
        "Returns one bounded Base64 chunk of a proxy-history response body. Use this for JavaScript " +
                "items whose get_proxy_http_history result has responseIsJavaScript=true. The body " +
                "is never converted to a complete String or byte array; length is capped at 256 KiB."
    ) {
        requireHistoryAccess(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history response body")
        require(index >= 0) { "index must be non-negative" }
        require(offset >= 0) { "offset must be non-negative" }
        require(length in 1..MAX_HTTP_HISTORY_BODY_CHUNK_BYTES) {
            "length must be between 1 and $MAX_HTTP_HISTORY_BODY_CHUNK_BYTES"
        }

        val history = api.proxy().history()
        val item = history.getOrNull(index) ?: error("No proxy HTTP history item at index $index")
        val response = item.response() ?: error("Proxy HTTP history item $index has no response")
        val body = response.body()
        val bodySize = body.length()
        require(offset <= bodySize) { "offset $offset exceeds response body size $bodySize" }

        val endExclusive = minOf(offset.toLong() + length.toLong(), bodySize.toLong()).toInt()
        val bytes = if (offset == endExclusive) {
            byteArrayOf()
        } else {
            body.subArray(offset, endExclusive).getBytes()
        }

        Json.encodeToString(
            ProxyHttpResponseBodyChunk(
                index = index,
                offset = offset,
                bodySize = bodySize,
                dataBase64 = Base64.getEncoder().encodeToString(bytes),
                eof = endExclusive == bodySize,
            )
        )
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex, ProxyHttpRequestResponse>(
        "Displays items matching a specified regex within the proxy HTTP history. Request bodies " +
                "are limited to 1 MiB, non-JavaScript response bodies to 4 MiB, and each page to " +
                "roughly 16 MiB of characters. JavaScript bodies are fetched separately through " +
                "get_proxy_http_response_body_chunk. Advance offset by the number of items actually returned.",
        maxOutputChars = MAX_HTTP_HISTORY_PAGE_CHARS,
        mapper = { Json.encodeToString(it.toSerializableForm()) }
    ) {
        requireHistoryAccess(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory, ProxyWebSocketMessage>(
        "Displays items within the proxy WebSocket history",
        mapper = { Json.encodeToString(it.toSerializableForm()) }
    ) {
        requireHistoryAccess(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")

        api.proxy().webSocketHistory()
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex, ProxyWebSocketMessage>(
        "Displays items matching a specified regex within the proxy WebSocket history",
        mapper = { Json.encodeToString(it.toSerializableForm()) }
    ) {
        requireHistoryAccess(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<GetCapturedRepeaterItem>(
        "Returns Repeater request/response items captured by the user. There are ${RepeaterCaptureStore.SLOT_COUNT} capture slots. " +
                "Provide 'slot' (1-${RepeaterCaptureStore.SLOT_COUNT}) to return a specific slot, or omit it to return all captured slots."
    ) {
        if (slot != null) {
            if (!RepeaterCaptureStore.isValidSlot(slot)) {
                return@mcpTool "<Invalid slot: must be between 1 and ${RepeaterCaptureStore.SLOT_COUNT}>"
            }
            RepeaterCaptureStore.get(slot)?.let { Json.encodeToString(it) }
                ?: "<No captured Repeater item in slot $slot>"
        } else {
            val captured = RepeaterCaptureStore.all()
            if (captured.isEmpty()) "<No captured Repeater items>" else Json.encodeToString(captured)
        }
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetCapturedRepeaterItem(val slot: Int? = null)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetSiteMap(
    val urlPrefix: String? = null
)

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpResponseBodyChunk(val index: Int, val offset: Int, val length: Int)

@Serializable
data class ProxyHttpResponseBodyChunk(
    val index: Int,
    val offset: Int,
    val bodySize: Int,
    val dataBase64: String,
    val eof: Boolean,
)

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)
