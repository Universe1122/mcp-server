package net.portswigger.mcp.openapi

import java.net.URI

/** A concrete target from an OpenAPI server URL. */
data class OpenApiServer(val specHost: String, val url: String, val scheme: String, val host: String,
                         val port: Int, val basePath: String) {
    val usesHttps: Boolean get() = scheme == "https"
    val origin: String get() = "$scheme://$host:$port"
    val canonicalUrl: String get() = "$origin$basePath"
}

internal fun parseOpenApiServer(specHost: String, url: String): OpenApiServer? {
    val uri = runCatching { URI(url.trim()) }.getOrNull() ?: return null
    val scheme = uri.scheme?.lowercase() ?: return null
    if (scheme !in setOf("http", "https") || uri.host == null || uri.userInfo != null ||
        uri.rawQuery != null || uri.rawFragment != null) return null
    if (uri.port != -1 && uri.port !in 1..65535) return null
    val port = uri.port.takeIf { it in 1..65535 } ?: if (scheme == "https") 443 else 80
    val base = uri.path.orEmpty().trimEnd('/').ifEmpty { "" }
    return OpenApiServer(specHost, url.trim(), scheme, uri.host.lowercase(), port, base)
}

internal fun effectiveServerUrls(document: OpenApiDocument, operation: OpenApiOperation): List<String> =
    (operation.servers.ifEmpty { document.servers }).mapNotNull {
        parseOpenApiServer(document.info.host, it)?.url
    }.ifEmpty { listOf("https://${document.info.host}") }.distinct()

internal fun documentServers(document: OpenApiDocument): List<OpenApiServer> =
    (document.operations.flatMap { effectiveServerUrls(document, it) }.ifEmpty {
        document.servers.ifEmpty { listOf("https://${document.info.host}") }
    }).mapNotNull { parseOpenApiServer(document.info.host, it) }
        .distinctBy { Triple(it.origin, it.basePath, it.specHost) }

internal fun supportsServer(document: OpenApiDocument, operation: OpenApiOperation,
                            server: OpenApiServer): Boolean =
    effectiveServerUrls(document, operation).any { url ->
        parseOpenApiServer(document.info.host, url)?.let {
            it.origin == server.origin && it.basePath == server.basePath
        } == true
    }

internal fun packetMatchesServer(url: String, port: Int, usesHttps: Boolean,
                                 server: OpenApiServer): Boolean {
    val uri = runCatching { URI(url) }.getOrNull() ?: return false
    return uri.host.equals(server.host, ignoreCase = true) && port == server.port && usesHttps == server.usesHttps &&
        (server.basePath.isEmpty() || uri.path == server.basePath || uri.path.startsWith("${server.basePath}/"))
}

internal fun operationPathForServer(url: String, server: OpenApiServer): String? {
    val path = runCatching { URI(url).path }.getOrNull() ?: return null
    if (server.basePath.isEmpty()) return path
    if (path == server.basePath) return "/"
    return if (path.startsWith("${server.basePath}/")) path.removePrefix(server.basePath) else null
}
