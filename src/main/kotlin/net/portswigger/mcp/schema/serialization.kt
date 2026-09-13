package net.portswigger.mcp.schema

import burp.api.montoya.collaborator.Interaction as CollaboratorInteraction
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import kotlinx.serialization.Serializable

internal const val MAX_HISTORY_REQUEST_BODY_BYTES = 1_048_576
internal const val MAX_HISTORY_RESPONSE_BODY_BYTES = 4_194_304

private val JAVASCRIPT_MEDIA_TYPES = setOf(
    "application/ecmascript",
    "application/javascript",
    "text/ecmascript",
    "text/javascript",
)

private val JAVASCRIPT_FILE_EXTENSIONS = setOf("js", "mjs", "cjs")

private data class BoundedHttpMessage(
    val raw: String,
    val bodySize: Int,
    val bodyTruncated: Boolean,
)

private fun boundedRawMessage(
    startLine: String,
    headers: List<HttpHeader>,
    body: burp.api.montoya.core.ByteArray,
    maxBodyBytes: Int,
    bodyKind: String,
): BoundedHttpMessage {
    require(maxBodyBytes >= 0) { "maxBodyBytes must be non-negative" }

    val bodySize = body.length()
    val bodyTruncated = bodySize > maxBodyBytes
    val storedBody = when {
        bodySize == 0 || maxBodyBytes == 0 -> ""
        bodyTruncated -> body.subArray(0, maxBodyBytes).toString()
        else -> body.toString()
    }

    val raw = buildString {
        append(startLine)
        append("\r\n")
        headers.forEach { header ->
            append(header.name())
            append(": ")
            append(header.value())
            append("\r\n")
        }
        append("\r\n")
        append(storedBody)
        if (bodyTruncated) {
            append("[truncated $bodyKind body: stored $maxBodyBytes of $bodySize bytes]")
        }
    }

    return BoundedHttpMessage(raw, bodySize, bodyTruncated)
}

private fun HttpRequest.toBoundedRaw(maxBodyBytes: Int): BoundedHttpMessage = boundedRawMessage(
    startLine = "${method()} ${path()} ${httpVersion()}",
    headers = headers(),
    body = body(),
    maxBodyBytes = maxBodyBytes,
    bodyKind = "request",
)

private fun HttpResponse.toBoundedRaw(maxBodyBytes: Int): BoundedHttpMessage = boundedRawMessage(
    startLine = "${httpVersion()} ${statusCode()} ${reasonPhrase()}",
    headers = headers(),
    body = body(),
    maxBodyBytes = maxBodyBytes,
    bodyKind = "response",
)

private fun ProxyHttpRequestResponse.isJavaScriptResponse(): Boolean {
    val request = request()
    val response = response() ?: return false

    val extension = request?.fileExtension()?.trimStart('.')?.lowercase()
    if (extension in JAVASCRIPT_FILE_EXTENSIONS) return true

    val mediaType = response.headerValue("Content-Type")
        ?.substringBefore(';')
        ?.trim()
        ?.lowercase()
    if (mediaType in JAVASCRIPT_MEDIA_TYPES || mediaType?.endsWith("+javascript") == true) return true

    val disposition = response.headerValue("Content-Disposition")?.lowercase().orEmpty()
    if (JAVASCRIPT_FILE_EXTENSIONS.any { disposition.contains(".$it") }) return true

    return response.statedMimeType().name == "SCRIPT" || response.inferredMimeType().name == "SCRIPT"
}

fun AuditIssue.toSerializableForm(): IssueDetails {
    return IssueDetails(
        name = name(),
        detail = detail(),
        remediation = remediation(),
        httpService = HttpService(
            host = httpService().host(),
            port = httpService().port(),
            secure = httpService().secure()
        ),
        baseUrl = baseUrl(),
        severity = AuditIssueSeverity.valueOf(severity().name),
        confidence = AuditIssueConfidence.valueOf(confidence().name),
        requestResponses = requestResponses().map { it.toSerializableForm() },
        collaboratorInteractions = collaboratorInteractions().map {
            Interaction(
                interactionId = it.id().toString(),
                timestamp = it.timeStamp().toString()
            )
        },
        definition = AuditIssueDefinition(
            id = definition().name(),
            background = definition().background(),
            remediation = definition().remediation(),
            typeIndex = definition().typeIndex(),
        )
    )
}

fun burp.api.montoya.http.message.HttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun burp.api.montoya.http.message.HttpRequestResponse.toSiteMapEntry(): SiteMapEntry {
    val req = request()
    val res = response()
    return SiteMapEntry(
        method = req?.method(),
        url = req?.url(),
        host = httpService()?.host(),
        statusCode = res?.statusCode()?.toInt(),
        responseLength = res?.body()?.length(),
        mimeType = res?.statedMimeType()?.name,
        hasParams = req?.parameters()?.isNotEmpty() ?: false,
        notes = annotations().notes()
    )
}

fun buildSiteMapTree(
    items: List<burp.api.montoya.http.message.HttpRequestResponse>
): Map<String, SiteMapTreeNode> {
    class MutableNode {
        val entries = mutableListOf<SiteMapEntry>()
        val children = mutableMapOf<String, MutableNode>()
        fun toImmutable(): SiteMapTreeNode = SiteMapTreeNode(
            entries = entries.toList(),
            children = children.toSortedMap().mapValues { it.value.toImmutable() }
        )
    }

    val byHost = sortedMapOf<String, MutableNode>()
    for (item in items) {
        val req = item.request() ?: continue
        val res = item.response() ?: continue
        if (res.statusCode().toInt() == 0) continue
        val service = item.httpService() ?: continue
        val scheme = if (service.secure()) "https" else "http"
        val port = service.port()
        val defaultPort = (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
        val hostKey = "$scheme://${service.host()}${if (defaultPort) "" else ":$port"}"

        val hostNode = byHost.getOrPut(hostKey) { MutableNode() }

        val rawPath = try {
            val url = req.url() ?: ""
            java.net.URI(url).rawPath ?: ""
        } catch (_: Exception) {
            req.pathWithoutQuery() ?: ""
        }
        val segments = rawPath.split("/").filter { it.isNotEmpty() }

        var current = hostNode
        for (seg in segments) {
            current = current.children.getOrPut(seg) { MutableNode() }
        }
        current.entries.add(item.toSiteMapEntry())
    }

    return byHost.mapValues { it.value.toImmutable() }
}

fun ProxyHttpRequestResponse.toSerializableForm(
    maxRequestBodyBytes: Int = MAX_HISTORY_REQUEST_BODY_BYTES,
    maxResponseBodyBytes: Int = MAX_HISTORY_RESPONSE_BODY_BYTES,
): HttpRequestResponse {
    val isJavaScript = isJavaScriptResponse()
    val request = request()?.toBoundedRaw(maxRequestBodyBytes)
    // JavaScript is transferred through the bounded chunk tool and persisted by the collector.
    // Keeping it out of this JSON page prevents the full bundle from being copied repeatedly.
    val response = response()?.toBoundedRaw(if (isJavaScript) 0 else maxResponseBodyBytes)

    return HttpRequestResponse(
        request = request?.raw ?: "<no request>",
        response = response?.raw ?: "<no response>",
        notes = annotations().notes(),
        requestBodySize = request?.bodySize,
        responseBodySize = response?.bodySize,
        requestBodyTruncated = request?.bodyTruncated ?: false,
        responseBodyTruncated = response?.bodyTruncated ?: false,
        responseIsJavaScript = isJavaScript,
    )
}

fun ProxyWebSocketMessage.toSerializableForm(): WebSocketMessage {
    return WebSocketMessage(
        payload = payload()?.toString() ?: "<no payload>",
        direction =
            if (direction() == Direction.CLIENT_TO_SERVER)
                WebSocketMessageDirection.CLIENT_TO_SERVER
            else
                WebSocketMessageDirection.SERVER_TO_CLIENT,
        notes = annotations().notes()
    )
}

@Serializable
data class IssueDetails(
    val name: String?,
    val detail: String?,
    val remediation: String?,
    val httpService: HttpService?,
    val baseUrl: String?,
    val severity: AuditIssueSeverity,
    val confidence: AuditIssueConfidence,
    val requestResponses: List<HttpRequestResponse>,
    val collaboratorInteractions: List<Interaction>,
    val definition: AuditIssueDefinition
)

@Serializable
data class HttpService(
    val host: String,
    val port: Int,
    val secure: Boolean
)

@Serializable
enum class AuditIssueSeverity {
    HIGH,
    MEDIUM,
    LOW,
    INFORMATION,
    FALSE_POSITIVE;
}

@Serializable
enum class AuditIssueConfidence {
    CERTAIN,
    FIRM,
    TENTATIVE
}

@Serializable
data class HttpRequestResponse(
    val request: String?,
    val response: String?,
    val notes: String?,
    val requestBodySize: Int? = null,
    val responseBodySize: Int? = null,
    val requestBodyTruncated: Boolean = false,
    val responseBodyTruncated: Boolean = false,
    val responseIsJavaScript: Boolean = false,
)

@Serializable
data class SiteMapEntry(
    val method: String?,
    val url: String?,
    val host: String?,
    val statusCode: Int?,
    val responseLength: Int?,
    val mimeType: String?,
    val hasParams: Boolean,
    val notes: String?
)

@Serializable
data class SiteMapTreeNode(
    val entries: List<SiteMapEntry> = emptyList(),
    val children: Map<String, SiteMapTreeNode> = emptyMap()
)

@Serializable
data class Interaction(
    val interactionId: String,
    val timestamp: String
)

@Serializable
data class AuditIssueDefinition(
    val id: String,
    val background: String?,
    val remediation: String?,
    val typeIndex: Int
)


@Serializable
enum class WebSocketMessageDirection {
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT
}

@Serializable
data class WebSocketMessage(
    val payload: String?,
    val direction: WebSocketMessageDirection,
    val notes: String?
)

fun CollaboratorInteraction.toSerializableForm(): CollaboratorInteractionDetails {
    return CollaboratorInteractionDetails(
        id = id().toString(),
        type = type().name,
        timestamp = timeStamp().toString(),
        clientIp = clientIp().hostAddress,
        clientPort = clientPort(),
        customData = customData().orElse(null),
        dnsDetails = dnsDetails().orElse(null)?.let {
            CollaboratorDnsDetails(queryType = it.queryType().name)
        },
        httpDetails = httpDetails().orElse(null)?.let {
            CollaboratorHttpDetails(
                protocol = it.protocol().name,
                request = it.requestResponse()?.request()?.toString(),
                response = it.requestResponse()?.response()?.toString()
            )
        },
        smtpDetails = smtpDetails().orElse(null)?.let {
            CollaboratorSmtpDetails(
                protocol = it.protocol().name,
                conversation = it.conversation()
            )
        }
    )
}

@Serializable
data class CollaboratorInteractionDetails(
    val id: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val clientPort: Int,
    val customData: String?,
    val dnsDetails: CollaboratorDnsDetails?,
    val httpDetails: CollaboratorHttpDetails?,
    val smtpDetails: CollaboratorSmtpDetails?
)

@Serializable
data class CollaboratorDnsDetails(
    val queryType: String
)

@Serializable
data class CollaboratorHttpDetails(
    val protocol: String,
    val request: String?,
    val response: String?
)

@Serializable
data class CollaboratorSmtpDetails(
    val protocol: String,
    val conversation: String
)
