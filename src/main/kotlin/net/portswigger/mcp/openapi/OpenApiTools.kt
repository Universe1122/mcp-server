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
import net.portswigger.mcp.tools.mcpTool

private const val METHODOLOGY_URI = "burp-mcp://skills/openapi-from-packets"

fun Server.registerOpenApiTools(store: OpenApiStore) {
    mcpTool("list_openapi_specs", "List host-specific OpenAPI YAML files in the effective OpenAPI directory, including hashes and parse errors.") {
        Json.encodeToString(store.list())
    }
    mcpTool<GetOpenapiSpec>(
        "Read an existing host-specific OpenAPI YAML file in bounded chunks. Preserve operation x-burp-packet-ids references when updating it."
    ) { Json.encodeToString(store.read(host, offset, maxChars)) }
    mcpTool<ValidateOpenapiSpec>(
        "Check an agent-written host YAML file for parse errors, required OpenAPI fields, responses, and path parameters. " +
            "Read-only structural validation; not a complete OpenAPI schema validator."
    ) { Json.encodeToString(store.validate(host)) }

    val methodology = checkNotNull(OpenApiStore::class.java.getResourceAsStream("/openapi-from-packets.md")) {
        "Bundled OpenAPI methodology is missing"
    }.bufferedReader().use { it.readText() }
    addResource(METHODOLOGY_URI, "OpenAPI from Burp packets",
        "Method for creating and updating host-specific OpenAPI 3.x specifications from the packet database, including operation x-burp-packet-ids references.",
        "text/markdown") { _ ->
        ReadResourceResult(listOf(TextResourceContents(methodology, METHODOLOGY_URI, "text/markdown")))
    }
    addPrompt("build_openapi_from_packets",
        "Read the packet database and existing host spec, then write an OpenAPI YAML file with representative x-burp-packet-ids to the configured directory.",
        emptyList()) { _ ->
        GetPromptResult(listOf(PromptMessage(Role.User, TextContent(methodology))),
            "OpenAPI authoring method")
    }
}

@Serializable data class GetOpenapiSpec(val host: String, val offset: Int = 0, val maxChars: Int = 32_000)
@Serializable data class ValidateOpenapiSpec(val host: String)
