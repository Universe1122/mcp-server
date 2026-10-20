package net.portswigger.mcp.openapi

import java.net.URI

/** Search fields that belong to the operation, including its documented parameters and examples. */
internal fun matchesOpenApiSearch(operation: OpenApiOperation, inspectionTag: String?, query: String,
                                  schemas: Map<*, *> = emptyMap<Any, Any>()): Boolean {
    if (query.isBlank()) return true
    val term = query.trim().lowercase()
    val direct = sequenceOf(operation.method, operation.path, operation.summary, operation.description,
        operation.operationId.orEmpty(), operation.tags.joinToString(" "), inspectionTag.orEmpty(),
        operation.parameters.toString(), operation.requestBody?.toString().orEmpty(),
        operation.responses.toString()).joinToString(" ")
    if (term in direct.lowercase()) return true
    val references = Regex("#/components/schemas/([^,}\\]\\s]+)")
    val pending = ArrayDeque(references.findAll(direct).map { it.groupValues[1] }.toList())
    val visited = mutableSetOf<String>()
    while (pending.isNotEmpty() && visited.size < 32) {
        val key = pending.removeFirst().replace("~1", "/").replace("~0", "~")
        if (!visited.add(key)) continue
        val schema = schemas[key]?.toString() ?: continue
        if (term in schema.lowercase()) return true
        references.findAll(schema).forEach { pending.addLast(it.groupValues[1]) }
    }
    return false
}

/** Select the most specific documented route when templates overlap. */
internal fun matchingOpenApiOperation(operations: List<OpenApiOperation>, method: String, url: String): OpenApiOperation? {
    val actual = runCatching { URI(url).path.split('/') }.getOrNull() ?: return null
    return operations.asSequence().filter { it.method.equals(method, ignoreCase = true) }
        .filter { operation ->
            val template = operation.path.split('/')
            template.size == actual.size && template.zip(actual).all { (part, value) ->
                (part.startsWith('{') && part.endsWith('}') && value.isNotEmpty()) || part == value
            }
        }
        .maxByOrNull { operation -> operation.path.split('/').count { !it.startsWith('{') } }
}
