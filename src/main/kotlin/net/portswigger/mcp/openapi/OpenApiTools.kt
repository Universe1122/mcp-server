package net.portswigger.mcp.openapi

import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.GetPromptResult
import io.modelcontextprotocol.kotlin.sdk.types.PromptMessage
import io.modelcontextprotocol.kotlin.sdk.types.ReadResourceResult
import io.modelcontextprotocol.kotlin.sdk.types.Role
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.TextResourceContents
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.packet.PacketRepository
import net.portswigger.mcp.tools.mcpTool

private const val METHODOLOGY_URI = "burp-mcp://skills/openapi-from-packets"

fun Server.registerOpenApiTools(store: OpenApiStore, packets: PacketRepository) {
    mcpTool("list_openapi_specs", "List host-specific OpenAPI YAML files in the effective OpenAPI directory, including hashes and parse errors.") {
        Json.encodeToString(store.list())
    }
    mcpTool<GetOpenapiSpec>(
        "Read an existing host-specific OpenAPI YAML file in bounded chunks. Use the bundled OpenAPI methodology when updating it, including x-burp-history-refs references."
    ) { Json.encodeToString(store.read(host, offset, maxChars)) }
    mcpTool<ValidateOpenapiSpec>(
        "Check an agent-written host YAML file for parse errors, required OpenAPI fields, responses, and path parameters. " +
            "Read-only structural validation; not a complete OpenAPI schema validator."
    ) { Json.encodeToString(store.validate(host)) }
    mcpTool<ListEndpointTags>(
        "List saved VULN, SUSPECT, or SAFE inspection tags. host is the exact OpenAPI YAML filename stem returned by list_openapi_specs (including any --scheme--port suffix), not the network hostname. Pass the exact operation serverUrl from the spec, including base path, to filter to one server. Without serverUrl, returns all saved tags for that spec, including legacy tags with an empty serverUrl."
    ) {
        val url = serverUrl?.let { parseOpenApiServer(host, it)?.canonicalUrl ?: error("Invalid serverUrl") }
        Json.encodeToString(packets.endpointInspectionTags(host, url))
    }
    mcpTool<SetEndpointTag>(
        "Set one operation's VULN, SUSPECT, or SAFE tag, or clear with tag=null. First call list_openapi_specs and get_openapi_spec. host is the exact YAML filename stem, method and path are the OpenAPI operation key, and serverUrl is the exact effective server URL assigned to that operation (scheme, host, port, and base path). Verify the operation and server before tagging; the MCP does not determine vulnerability status. VULN requires a confirmed finding; SUSPECT means a potential issue awaiting verification; SAFE means reviewed with no issue identified."
    ) {
        val normalizedHost = host.trim().lowercase()
        val document = store.load(normalizedHost)
        val operation = document.operations.firstOrNull { it.method == method.uppercase() && it.path == path }
        require(tag == null || operation != null) { "Operation is not present in the current OpenAPI document" }
        val supported = operation?.let { effectiveServerUrls(document, it).mapNotNull { url ->
            parseOpenApiServer(normalizedHost, url)
        } } ?: emptyList()
        val chosen = parseOpenApiServer(normalizedHost, serverUrl) ?: error("Invalid serverUrl")
        require(tag == null && operation == null || supported.any {
            it.canonicalUrl == chosen.canonicalUrl
        }) {
            "serverUrl is not assigned to this operation"
        }
        val saved = packets.setEndpointInspectionTag(normalizedHost, method, path, tag, "agent", chosen.canonicalUrl)
        Json.encodeToString(EndpointTagResult(normalizedHost, method.uppercase(), path, saved?.tag, saved?.updatedAt, chosen.canonicalUrl))
    }
    mcpTool<GetEndpointTagHistory>(
        "Read newest VULN/SUSPECT/SAFE tag changes, including whether an agent or human changed or cleared a tag and the previous value. host is the exact OpenAPI YAML filename stem; serverUrl includes the server base path; method and path identify the OpenAPI operation."
    ) {
        Json.encodeToString(packets.endpointTagHistory(host, serverUrl, method, path, limit))
    }

    val methodology = checkNotNull(OpenApiStore::class.java.getResourceAsStream("/openapi-from-packets.md")) {
        "Bundled OpenAPI methodology is missing"
    }.bufferedReader().use { it.readText() }
    addResource(METHODOLOGY_URI, "OpenAPI from Burp packets",
        "Method for creating and updating host-specific OpenAPI 3.x specifications from captured API packets, including Burp History references, Korean descriptions, and observed examples.",
        "text/markdown") { _ ->
        ReadResourceResult(listOf(TextResourceContents(methodology, METHODOLOGY_URI, "text/markdown")))
    }
    addPrompt("build_openapi_from_packets",
        "Read the packet database and existing host spec, then write an OpenAPI YAML file with representative x-burp-history-refs to the configured directory.",
        emptyList()) { _ ->
        GetPromptResult(listOf(PromptMessage(Role.User, TextContent(methodology))),
            "OpenAPI authoring method")
    }
}

@Serializable data class GetOpenapiSpec(val host: String, val offset: Int = 0, val maxChars: Int = 32_000)
@Serializable data class ValidateOpenapiSpec(val host: String)
@Serializable data class ListEndpointTags(val host: String, val serverUrl: String? = null)
@Serializable data class SetEndpointTag(val host: String, val method: String, val path: String, val tag: String? = null,
                                         val serverUrl: String)
@Serializable data class GetEndpointTagHistory(val host: String, val serverUrl: String, val method: String,
                                               val path: String, val limit: Int = 50)
@Serializable data class EndpointTagResult(val host: String, val method: String, val path: String, val tag: String?,
                                            val updatedAt: String?, val serverUrl: String)
