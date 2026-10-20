package net.portswigger.mcp.openapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import java.net.URLEncoder

data class RepeaterDraft(
    val host: String,
    val port: Int,
    val usesHttps: Boolean,
    val rawRequest: String,
    val tabName: String,
)

/** Build an editable request template from an OpenAPI operation. Never sends it. */
object OpenApiRequestBuilder {
    private val prettyJson = Json { prettyPrint = true }
    private val headerName = Regex("[A-Za-z0-9-]+")

    fun build(
        document: OpenApiDocument,
        operation: OpenApiOperation,
        parameterValues: Map<String, String> = emptyMap(),
    ): RepeaterDraft {
        val server = (operation.servers + document.servers + "https://${document.info.host}")
            .asSequence().mapNotNull { runCatching { URI(it) }.getOrNull() }
            .firstOrNull { it.scheme in listOf("http", "https") && it.host != null &&
                it.userInfo == null && it.rawQuery == null && it.rawFragment == null }
            ?: error("No usable HTTP server URL in OpenAPI document")
        val https = server.scheme == "https"
        val port = if (server.port > 0) server.port else if (https) 443 else 80
        val host = server.host
        val base = server.rawPath.orEmpty().trimEnd('/')
        val operationPath = operation.path.let { if (it.startsWith('/')) it else "/$it" }
        val path = base + operationPath.replace(Regex("\\{([^/{}]+)}")) { match ->
            val name = match.groupValues[1]
            val key = "path:$name"
            val value = parameterValues[key]
            if (value == null) match.value
            else {
                require(value.isNotBlank()) { "Fill the required path parameter: $name" }
                encode(value)
            }
        }
        require(!path.any { it == '\r' || it == '\n' } && !path.contains('?')) {
            "OpenAPI path contains an invalid request target"
        }
        val query = operation.parameters.filter { it["in"] == "query" }.mapNotNull { parameter ->
            val name = parameter["name"]?.toString()?.takeIf { headerName.matches(it) } ?: return@mapNotNull null
            val value = parameterValues["query:$name"]
            if (value != null) {
                if (value.isBlank()) {
                    require(parameter["required"] != true) { "Fill the required query parameter: $name" }
                    null
                } else "$name=${encode(value)}"
            } else if (parameter["required"] == true) "$name={$name}" else null
        }.joinToString("&")
        val target = path + if (query.isBlank()) "" else "?$query"
        val hostHeader = host + if (port == if (https) 443 else 80) "" else ":$port"
        val headers = linkedMapOf("Host" to hostHeader)
        operation.responses.values.firstNotNullOfOrNull { response ->
            ((response as? Map<*, *>)?.get("content") as? Map<*, *>)?.keys?.firstOrNull()?.toString()
        }?.let { headers["Accept"] = it }
        operation.parameters.filter { it["in"] == "header" }.forEach {
            val name = it["name"]?.toString()
            if (name != null && headerName.matches(name) && name.lowercase() !in setOf("host", "content-length")) {
                val value = parameterValues["header:$name"]
                if (value != null && value.isBlank()) {
                    require(it["required"] != true) { "Fill the required header parameter: $name" }
                } else if (value != null) {
                    require('\r' !in value && '\n' !in value) { "Header value contains a line break: $name" }
                    headers[name] = value
                } else if (it["required"] == true) headers[name] = "{$name}"
            }
        }
        val cookies = operation.parameters.filter { it["in"] == "cookie" }.mapNotNull {
            val name = it["name"]?.toString()?.takeIf(headerName::matches) ?: return@mapNotNull null
            val value = parameterValues["cookie:$name"]
            if (value != null) {
                if (value.isBlank()) {
                    require(it["required"] != true) { "Fill the required cookie parameter: $name" }
                    null
                } else "$name=${encode(value)}"
            } else if (it["required"] == true) "$name={$name}" else null
        }
        if (cookies.isNotEmpty()) headers["Cookie"] = cookies.joinToString("; ")

        val content = operation.requestBody?.get("content") as? Map<*, *>
        val mediaType = content?.keys?.firstOrNull()?.toString()
        val media = content?.get(mediaType) as? Map<*, *>
        val body = when {
            mediaType == null -> ""
            mediaType.contains("json", ignoreCase = true) -> {
                val example = media?.get("example") ?: (media?.get("examples") as? Map<*, *>)
                    ?.values?.firstOrNull()?.let { (it as? Map<*, *>)?.get("value") }
                if (example != null) prettyJson.encodeToString(JsonElement.serializer(), toJson(example))
                else ""
            }
            else -> media?.get("example")?.toString().orEmpty()
        }
        if (mediaType != null) headers["Content-Type"] = mediaType
        if (mediaType != null || body.isNotEmpty()) headers["Content-Length"] = body.toByteArray(Charsets.UTF_8).size.toString()
        val raw = buildString {
            append(operation.method).append(' ').append(target).append(" HTTP/1.1\r\n")
            headers.forEach { (name, value) -> append(name).append(": ").append(value).append("\r\n") }
            append("\r\n").append(body)
        }
        return RepeaterDraft(host, port, https, raw, "Swagger ${operation.method} ${operation.path}".take(80))
    }

    fun exampleJson(rawSchema: Any?, schemas: Map<*, *>): String {
        val element = schemaExample(rawSchema, schemas, 0, emptySet())
        return prettyJson.encodeToString(JsonElement.serializer(), element)
    }

    fun parameterSample(parameter: Map<*, *>): String {
        val schema = parameter["schema"] as? Map<*, *>
        val explicit = parameter["example"] ?: schema?.get("example") ?: schema?.get("default")
            ?: (schema?.get("enum") as? List<*>)?.firstOrNull()
        return explicit?.toString().orEmpty()
    }

    private fun encode(value: String): String = URLEncoder.encode(value, Charsets.UTF_8).replace("+", "%20")

    private fun schemaExample(raw: Any?, schemas: Map<*, *>, depth: Int, seen: Set<String>): JsonElement {
        if (depth >= 6) return JsonNull
        val schema = raw as? Map<*, *> ?: return JsonObject(emptyMap())
        schema["example"]?.let { return toJson(it) }
        val ref = schema['$' + "ref"]?.toString()
        if (ref != null) {
            val prefix = "#/components/schemas/"
            if (!ref.startsWith(prefix) || ref in seen) return JsonObject(emptyMap())
            return schemaExample(schemas[ref.removePrefix(prefix)], schemas, depth + 1, seen + ref)
        }
        (schema["enum"] as? List<*>)?.firstOrNull()?.let { return toJson(it) }
        return when (schema["type"]?.toString() ?: if (schema["properties"] is Map<*, *>) "object" else "") {
            "object" -> JsonObject(((schema["properties"] as? Map<*, *>) ?: emptyMap<Any, Any>())
                .entries.take(40).associate { (name, value) ->
                    name.toString() to schemaExample(value, schemas, depth + 1, seen)
                })
            "array" -> JsonArray(listOf(schemaExample(schema["items"], schemas, depth + 1, seen)))
            "integer", "number" -> JsonPrimitive(0)
            "boolean" -> JsonPrimitive(false)
            "string" -> JsonPrimitive("string")
            else -> JsonObject(emptyMap())
        }
    }

    private fun toJson(value: Any?): JsonElement = when (value) {
        null -> JsonNull
        is Boolean -> JsonPrimitive(value)
        is Number -> JsonPrimitive(value)
        is Map<*, *> -> JsonObject(value.entries.associate { it.key.toString() to toJson(it.value) })
        is List<*> -> JsonArray(value.map(::toJson))
        else -> JsonPrimitive(value.toString())
    }
}
