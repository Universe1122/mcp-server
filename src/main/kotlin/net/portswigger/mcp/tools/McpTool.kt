package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.PromptMessageContent
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.modelcontextprotocol.kotlin.sdk.Tool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import net.portswigger.mcp.schema.asInputSchema
import kotlin.experimental.ExperimentalTypeInference

@PublishedApi
internal fun <J> buildPaginatedText(
    items: List<J>,
    offset: Int,
    count: Int,
    maxOutputChars: Int,
    mapper: (J) -> CharSequence,
): String {
    require(maxOutputChars > 0) { "maxOutputChars must be positive" }

    if (offset >= items.size) return "Reached end of items"

    val upperLimit = (offset + count).coerceAtMost(items.size)
    val output = StringBuilder()

    for (item in items.subList(offset, upperLimit)) {
        val serialized = mapper(item)
        val separatorLength = if (output.isEmpty()) 0 else 2

        // Always return at least one item so the caller can advance its offset. HTTP history
        // items are bounded before they reach this function, so that first item is itself bounded.
        if (output.isNotEmpty() && output.length + separatorLength + serialized.length > maxOutputChars) {
            break
        }

        if (separatorLength > 0) output.append("\n\n")
        output.append(serialized)
    }

    return output.toString()
}

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> List<PromptMessageContent>
) {
    val toolName = I::class.simpleName?.toLowerSnakeCase() ?: error("Couldn't find name for ${I::class}")

    addTool(
        name = toolName,
        description = description,
        inputSchema = I::class.asInputSchema(),
        handler = { request ->
            try {
                CallToolResult(
                    content = execute(
                        Json.decodeFromJsonElement(
                            I::class.serializer(),
                            request.arguments
                        )
                    )
                )
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("Error: ${e.message}")),
                    isError = true
                )
            }
        }
    )
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolString")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> String
) {
    mcpTool<I>(description, execute = {
        listOf(TextContent(execute(this)))
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolUnit")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> Unit
) {
    mcpTool<I>(description, execute = {
        execute(this)

        listOf(TextContent("Executed tool"))
    })
}

inline fun <reified I : Paginated, J : Any> Server.mcpPaginatedTool(
    description: String,
    maxOutputChars: Int = Int.MAX_VALUE,
    noinline mapper: (J) -> CharSequence = { it.toString() },
    crossinline execute: I.() -> List<J>
) {
    mcpTool<I>(description, execute = {

        val items = execute(this)

        buildPaginatedText(items, offset, count, maxOutputChars, mapper)
    })
}

inline fun <reified I : Paginated> Server.mcpPaginatedTool(
    description: String,
    crossinline execute: I.() -> Sequence<String>
) {
    mcpTool<I>(description, execute = {
        val seq = execute(this)
        val paginated = seq.drop(offset).take(count).toList()

        if (paginated.isEmpty()) {
            listOf(TextContent("Reached end of items"))
        } else {
            listOf(TextContent(paginated.joinToString(separator = "\n\n")))
        }
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpNamedToolString")
inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> List<PromptMessageContent>
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            CallToolResult(
                content = execute()
            )
        }
    )
}

inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> String
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            CallToolResult(
                content = listOf(TextContent(execute()))
            )
        }
    )
}

fun String.toLowerSnakeCase(): String {
    return this
        .replace(Regex("([a-z0-9])([A-Z])"), "$1_$2")
        .replace(Regex("([A-Z])([A-Z][a-z])"), "$1_$2")
        .replace(Regex("[\\s-]+"), "_")
        .lowercase()
}

interface Paginated {
    val count: Int
    val offset: Int
}
