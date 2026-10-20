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
        "List saved VULN or SAFE inspection tags for one OpenAPI host. Untagged endpoints are unreviewed; SAFE means no issue was found during review, not a security guarantee. Tags persist in the packet database across OpenAPI YAML rewrites."
    ) { Json.encodeToString(packets.endpointInspectionTags(host)) }
    mcpTool<SetEndpointTag>(
        "Set one OpenAPI operation's inspection tag to VULN or SAFE, or clear it with tag=null. Use VULN only for a confirmed finding; SAFE means reviewed with no identified issue. Identify the operation by host, uppercase HTTP method, and exact OpenAPI path template. Tags live in the packet database, separately from the YAML."
    ) {
        val normalizedHost = host.trim().lowercase()
        if (tag != null) {
            require(store.load(normalizedHost).operations.any { it.method == method.uppercase() && it.path == path }) {
                "Operation is not present in the current OpenAPI document"
            }
        }
        val saved = packets.setEndpointInspectionTag(normalizedHost, method, path, tag, "agent")
        Json.encodeToString(EndpointTagResult(normalizedHost, method.uppercase(), path, saved?.tag, saved?.updatedAt))
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
@Serializable data class ListEndpointTags(val host: String)
@Serializable data class SetEndpointTag(val host: String, val method: String, val path: String, val tag: String? = null)
@Serializable data class EndpointTagResult(val host: String, val method: String, val path: String, val tag: String?, val updatedAt: String?)
