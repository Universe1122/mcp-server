package net.portswigger.mcp.openapi

import kotlinx.serialization.Serializable
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

private const val MAX_SPEC_BYTES = 2 * 1024 * 1024
private const val SPEC_DIRECTORY = "raw/resources/mcp-server/openapi"
private val HTTP_METHODS = setOf("get", "put", "post", "delete", "options", "head", "patch", "trace")
private val HOST_PATTERN = Regex("[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")

@Serializable
data class OpenApiSpecInfo(
    val host: String,
    val path: String,
    val sha256: String,
    val title: String?,
    val version: String?,
    val operationCount: Int,
    val updatedAt: String,
    val error: String? = null,
    val servers: List<String> = emptyList(),
)

@Serializable
data class OpenApiSpecPage(
    val host: String,
    val sha256: String,
    val totalChars: Int,
    val offset: Int,
    val text: String,
    val nextOffset: Int?,
)

@Serializable
data class OpenApiValidationReport(
    val host: String,
    val path: String?,
    val valid: Boolean,
    val errors: List<String>,
    val warnings: List<String>,
    val operationCount: Int,
    val sha256: String?,
)

data class OpenApiOperation(
    val method: String,
    val path: String,
    val summary: String,
    val description: String,
    val tags: List<String>,
    val details: String,
    val operationId: String? = null,
    val parameters: List<Map<*, *>> = emptyList(),
    val requestBody: Map<*, *>? = null,
    val responses: Map<*, *> = emptyMap<Any, Any>(),
    val historyRefs: List<OpenApiHistoryRef> = emptyList(),
    val servers: List<String> = emptyList(),
)

data class OpenApiHistoryRef(val historyId: Int, val packetId: Long)

data class OpenApiDocument(
    val info: OpenApiSpecInfo,
    val operations: List<OpenApiOperation>,
    val description: String = "",
    val servers: List<String> = emptyList(),
    val schemas: Map<*, *> = emptyMap<Any, Any>(),
    val openApiVersion: String = "3.0",
)

/** Reads agent-authored YAML files from the configured directory. */
class OpenApiStore(
    private val projectDirectory: () -> Path?,
    private val configuredDirectory: () -> Path? = { null },
) {
    fun projectPath(): Path? = projectDirectory()
    fun directoryPath(): Path? = directory()

    @Synchronized
    fun list(): List<OpenApiSpecInfo> {
        val directory = directory() ?: return emptyList()
        if (!Files.isDirectory(directory)) return emptyList()
        val files = Files.list(directory).use { stream ->
            stream.filter { Files.isRegularFile(it) && (it.fileName.toString().endsWith(".yaml") || it.fileName.toString().endsWith(".yml")) }
                .toList().sortedWith(compareBy({ it.fileName.toString().substringAfterLast('.') != "yaml" }, { it.toString() }))
        }
        return files.map { path ->
            val host = path.fileName.toString().substringBeforeLast('.')
            runCatching { load(host).info }.getOrElse { error ->
                OpenApiSpecInfo(host, path.toString(), "", null, null, 0,
                    if (Files.exists(path)) Files.getLastModifiedTime(path).toInstant().toString() else "",
                    error.message ?: "Invalid OpenAPI document")
            }
        }.distinctBy { it.host }.sortedBy { it.host }
    }

    @Synchronized
    fun load(host: String): OpenApiDocument {
        val file = fileFor(host)
        val bytes = readBytes(file)
        val text = String(bytes, StandardCharsets.UTF_8)
        val root = parse(text)
        val info = info(host, file, bytes, root)
        val metadata = root["info"] as Map<*, *>
        val components = root["components"] as? Map<*, *>
        return OpenApiDocument(
            info = info,
            operations = operations(root),
            description = metadata["description"]?.toString() ?: "",
            servers = (root["servers"] as? List<*>)?.mapNotNull {
                (it as? Map<*, *>)?.get("url")?.toString()
            } ?: emptyList(),
            schemas = components?.get("schemas") as? Map<*, *> ?: emptyMap<Any, Any>(),
            openApiVersion = root["openapi"]?.toString() ?: "3.0",
        )
    }

    @Synchronized
    fun read(host: String, offset: Int = 0, maxChars: Int = 32_000): OpenApiSpecPage {
        require(offset >= 0 && maxChars in 1..64_000) { "offset must be non-negative and maxChars must be 1..64000" }
        val bytes = readBytes(fileFor(host))
        val text = String(bytes, StandardCharsets.UTF_8)
        require(offset <= text.length) { "offset exceeds document length" }
        val end = (offset.toLong() + maxChars).coerceAtMost(text.length.toLong()).toInt()
        return OpenApiSpecPage(normalizeHost(host), sha256(bytes), text.length, offset,
            text.substring(offset, end), if (end < text.length) end else null)
    }

    /** Bounded structural checks for an agent-written file; this is not full OpenAPI schema validation. */
    @Synchronized
    fun validate(host: String): OpenApiValidationReport {
        val file = runCatching { fileFor(host) }.getOrElse {
            return OpenApiValidationReport(host, null, false, listOf(it.message ?: "Invalid host"), emptyList(), 0, null)
        }
        val bytes = runCatching { readBytes(file) }.getOrElse {
            return OpenApiValidationReport(host, file.toString(), false,
                listOf(it.message ?: "Could not read OpenAPI file"), emptyList(), 0, null)
        }
        val root = runCatching { parse(String(bytes, StandardCharsets.UTF_8)) }.getOrElse {
            return OpenApiValidationReport(host, file.toString(), false,
                listOf(it.message ?: "Invalid OpenAPI document"), emptyList(), 0, sha256(bytes))
        }
        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        if ((root["servers"] as? List<*>)?.isEmpty() != false) warnings += "No servers URL; Send to Repeater will use the selected host"
        var count = 0
        val paths = root["paths"] as Map<*, *>
        val placeholders = Regex("\\{([^{}]+)}")
        for ((rawPath, rawItem) in paths) {
            val path = rawPath?.toString() ?: "null"
            if (!path.startsWith('/')) errors += "$path: path must start with /"
            val pathItem = rawItem as? Map<*, *>
            if (pathItem == null) { errors += "$path: path item must be an object"; continue }
            for ((rawMethod, rawOperation) in pathItem) {
                val method = rawMethod?.toString()?.lowercase() ?: continue
                if (method !in HTTP_METHODS) continue
                count++
                val label = "${method.uppercase()} $path"
                val operation = rawOperation as? Map<*, *>
                if (operation == null) { errors += "$label: operation must be an object"; continue }
                if ((operation["responses"] as? Map<*, *>)?.isNotEmpty() != true) {
                    errors += "$label: responses must be a non-empty object"
                }
                if ("x-burp-packet-ids" in operation || "x-burp-history-ids" in operation) {
                    errors += "$label: use x-burp-history-refs with historyId and packetId pairs"
                }
                if ("x-burp-history-refs" in operation) {
                    val refs = operation["x-burp-history-refs"] as? List<*>
                    if (refs == null || refs.any { raw ->
                        val pair = raw as? Map<*, *> ?: return@any true
                        (pair["historyId"]?.toString()?.toIntOrNull() ?: -1) < 0 ||
                            (pair["packetId"]?.toString()?.toLongOrNull() ?: 0) <= 0
                    }) errors += "$label: x-burp-history-refs must contain non-negative historyId and positive packetId pairs"
                    if (refs != null && refs.size > 20) warnings += "$label: only the latest 20 History references are displayed"
                }
                val parameters = operationParameters(root, pathItem, operation)
                for (match in placeholders.findAll(path)) {
                    val name = match.groupValues[1]
                    val declared = parameters.any { parameter ->
                        parameter["in"] == "path" && parameter["name"] == name && parameter["required"] == true
                    }
                    if (!declared) errors += "$label: {$name} needs a required path parameter"
                }
            }
        }
        if (count == 0) warnings += "No HTTP operations found"
        return OpenApiValidationReport(host, file.toString(), errors.isEmpty(), errors, warnings, count, sha256(bytes))
    }

    private fun parse(text: String): Map<*, *> {
        val settings = LoadSettings.builder()
            .setAllowDuplicateKeys(false)
            .setMaxAliasesForCollections(20)
            .setCodePointLimit(MAX_SPEC_BYTES)
            .build()
        val root = Load(settings).loadFromString(text) as? Map<*, *>
            ?: throw IllegalArgumentException("OpenAPI document must be a YAML or JSON object")
        require((root["openapi"] as? String)?.startsWith("3.") == true) { "Only OpenAPI 3.x documents are supported" }
        val info = root["info"] as? Map<*, *> ?: throw IllegalArgumentException("OpenAPI info is required")
        require((info["title"] as? String)?.isNotBlank() == true) { "OpenAPI info.title is required" }
        require(info["version"]?.toString()?.isNotBlank() == true) { "OpenAPI info.version is required" }
        require(root["paths"] is Map<*, *>) { "OpenAPI paths must be an object" }
        return root
    }

    private fun info(host: String, file: Path, bytes: ByteArray, root: Map<*, *>): OpenApiSpecInfo {
        val metadata = root["info"] as Map<*, *>
        val rootServers = (root["servers"] as? List<*>)?.mapNotNull { (it as? Map<*, *>)?.get("url")?.toString() }
            ?: emptyList()
        val operations = operations(root)
        val effectiveServers = operations.flatMap { operation ->
            operation.servers.ifEmpty { rootServers }.mapNotNull { parseOpenApiServer(host, it)?.url }
                .ifEmpty { listOf("https://$host") }
        }
        return OpenApiSpecInfo(host, file.toString(), sha256(bytes), metadata["title"]?.toString(),
            metadata["version"]?.toString(), operations.size,
            Files.getLastModifiedTime(file).toInstant().toString(),
            servers = effectiveServers.ifEmpty { rootServers.ifEmpty { listOf("https://$host") } }.distinct())
    }

    private fun operations(root: Map<*, *>): List<OpenApiOperation> {
        val paths = root["paths"] as Map<*, *>
        return paths.flatMap { (path, value) ->
            val pathItem = value as? Map<*, *> ?: return@flatMap emptyList()
            pathItem.mapNotNull { (method, rawOperation) ->
                val name = method?.toString()?.lowercase() ?: return@mapNotNull null
                if (name !in HTTP_METHODS) return@mapNotNull null
                val operation = rawOperation as? Map<*, *> ?: return@mapNotNull null
                OpenApiOperation(name.uppercase(), path.toString(), operation["summary"]?.toString() ?: "",
                    operation["description"]?.toString() ?: "",
                    (operation["tags"] as? List<*>)?.map { it.toString() } ?: emptyList(),
                    renderOperation(name.uppercase(), path.toString(), operation),
                    operation["operationId"]?.toString(),
                    operationParameters(root, pathItem, operation),
                    operation["requestBody"] as? Map<*, *>,
                    operation["responses"] as? Map<*, *> ?: emptyMap<Any, Any>(),
                    (operation["x-burp-history-refs"] as? List<*>)?.mapNotNull { raw ->
                        val ref = raw as? Map<*, *> ?: return@mapNotNull null
                        val historyId = ref["historyId"]?.toString()?.toIntOrNull()?.takeIf { it >= 0 }
                        val packetId = ref["packetId"]?.toString()?.toLongOrNull()?.takeIf { it > 0 }
                        if (historyId != null && packetId != null) OpenApiHistoryRef(historyId, packetId) else null
                    } ?: emptyList(),
                    ((operation["servers"] ?: pathItem["servers"]) as? List<*>)?.mapNotNull {
                        (it as? Map<*, *>)?.get("url")?.toString()
                    } ?: emptyList())
            }
        }.sortedWith(compareBy({ it.path }, { it.method }))
    }

    private fun operationParameters(root: Map<*, *>, pathItem: Map<*, *>, operation: Map<*, *>): List<Map<*, *>> {
        val pathParameters = pathItem["parameters"] as? List<*> ?: emptyList<Any>()
        val localParameters = operation["parameters"] as? List<*> ?: emptyList<Any>()
        // Operation parameters take precedence over path-item parameters with the same name and location.
        return (localParameters + pathParameters).mapNotNull { resolveParameter(root, it) }
            .distinctBy { "${it["in"]}:${it["name"]}" }
    }

    private fun resolveParameter(root: Map<*, *>, raw: Any?, seen: Set<String> = emptySet()): Map<*, *>? {
        val parameter = raw as? Map<*, *> ?: return null
        val ref = parameter["\$ref"]?.toString() ?: return parameter
        val prefix = "#/components/parameters/"
        if (!ref.startsWith(prefix) || ref in seen || seen.size >= 8) return null
        val name = ref.removePrefix(prefix).replace("~1", "/").replace("~0", "~")
        val components = root["components"] as? Map<*, *> ?: return null
        val definitions = components["parameters"] as? Map<*, *> ?: return null
        return resolveParameter(root, definitions[name], seen + ref)
    }

    private fun fileFor(host: String): Path {
        val directory = directory() ?: error("OpenAPI directory is not configured; load config.yaml or call start_packet_capture")
        val normalized = normalizeHost(host)
        return listOf(directory.resolve("$normalized.yaml"), directory.resolve("$normalized.yml"))
            .firstOrNull(Files::isRegularFile) ?: directory.resolve("$normalized.yaml")
    }
    private fun directory(): Path? = configuredDirectory() ?: projectDirectory()?.resolve(SPEC_DIRECTORY)
    private fun normalizeHost(host: String): String = host.trim().lowercase().also {
        require(HOST_PATTERN.matches(it) && ".." !in it) { "spec key must use hostname-safe characters without a colon or path" }
    }

    private fun readBytes(file: Path): ByteArray {
        require(Files.isRegularFile(file)) { "OpenAPI document does not exist: $file" }
        require(!Files.isSymbolicLink(file)) { "OpenAPI document must not be a symbolic link" }
        require(Files.size(file) <= MAX_SPEC_BYTES) { "OpenAPI document exceeds $MAX_SPEC_BYTES bytes" }
        return Files.readAllBytes(file)
    }

}

private fun renderOperation(method: String, path: String, operation: Map<*, *>): String = buildString {
    appendLine("$method $path")
    operation["summary"]?.let { appendLine("\n$it") }
    operation["description"]?.let { appendLine("\n$it") }
    operation["operationId"]?.let { appendLine("\nOperation ID: $it") }
    operation["tags"]?.let { appendLine("Tags: ${(it as? List<*>)?.joinToString() ?: it}") }
    for (name in listOf("parameters", "requestBody", "responses")) {
        operation[name]?.let {
            appendLine("\n${name.replaceFirstChar(Char::uppercaseChar)}:")
            append(renderValue(it, 1))
        }
    }
}.take(200_000)

private fun renderValue(value: Any?, depth: Int): String = buildString {
    if (depth > 20) { appendLine("  ..."); return@buildString }
    val indent = "  ".repeat(depth.coerceAtMost(20))
    when (value) {
        is Map<*, *> -> value.forEach { (key, child) ->
            if (child is Map<*, *> || child is List<*>) {
                appendLine("$indent$key:")
                append(renderValue(child, depth + 1))
            } else appendLine("$indent$key: $child")
        }
        is List<*> -> value.forEach { child ->
            if (child is Map<*, *> || child is List<*>) {
                appendLine("$indent-")
                append(renderValue(child, depth + 1))
            } else appendLine("$indent- $child")
        }
        else -> appendLine("$indent$value")
    }
}

private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(bytes).joinToString("") { "%02x".format(it) }
