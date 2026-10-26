package net.portswigger.mcp.packet

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.CopyOnWriteArrayList

private const val DATABASE_FILE = "packets.sqlite3"
private const val INLINE_BLOB_LIMIT = 16 * 1024 * 1024
private const val FTS_PREFIX_LIMIT = 4 * 1024 * 1024
private const val COPY_CHUNK = 262_144
private const val METADATA_TEXT_LIMIT = 4096
private const val RESPONSE_QUEUE_LIMIT = 256

@Serializable
data class CaptureStatus(
    val databasePath: String?,
    val collecting: Boolean,
    val packetCount: Long,
    val historyPosition: Int,
    val scanned: Int = 0,
    val inserted: Int = 0,
    val historyScanPhase: String = "idle",
    val historyScanTotal: Int = 0,
    val historyScanProcessed: Int = 0,
    val historyScanInserted: Int = 0,
    val queueOverflowCount: Long = 0,
    val pendingResponseCount: Int = 0,
    val saveFailureCount: Long = 0,
    val historyCatchupCount: Long = 0,
    val lastCaptureError: String? = null,
)

@Serializable
data class PacketSummary(
    val id: Long,
    val host: String,
    val method: String,
    val url: String,
    val statusCode: Int?,
    val requestBodySize: Int,
    val responseBodySize: Int?,
    val isSentFromMcp: Boolean,
    val snippet: String? = null,
    val similarCount: Int = 1,
)

data class SwaggerPacketSearchHit(
    val packetId: Long,
    val historyId: Int?,
    val method: String,
    val url: String,
    val port: Int,
    val usesHttps: Boolean,
    val statusCode: Int?,
    val location: String,
    val snippet: String,
)

data class SwaggerPacketSearchPage(
    val hits: List<SwaggerPacketSearchHit>,
    val hasMore: Boolean,
    val nextBeforeId: Long?,
)

private fun matchingHeaderLine(headers: String?, query: String): String {
    val line = headers?.lineSequence()?.firstOrNull { it.contains(query, ignoreCase = true) }?.trim()
        ?: return "Header match"
    val name = line.substringBefore(':', "").trim()
    return if (name.lowercase() in setOf("authorization", "proxy-authorization", "cookie", "set-cookie",
            "x-api-key", "x-auth-token")) "$name: [redacted]" else line.take(240)
}

@Serializable
data class PacketDetail(
    val id: Long,
    val burpHistoryId: Int?,
    val host: String,
    val port: Int,
    val usesHttps: Boolean,
    val method: String,
    val url: String,
    val statusCode: Int?,
    val isSentFromMcp: Boolean,
    val requestHeaders: String,
    val responseHeaders: String?,
    val requestBodySize: Int,
    val responseBodySize: Int?,
    val requestBodyHash: String,
    val responseBodyHash: String?,
    val requestBodyBase64: String?,
    val responseBodyBase64: String?,
    val requestBodyTruncated: Boolean,
    val responseBodyTruncated: Boolean,
)

@Serializable
data class DatabaseInfo(val status: CaptureStatus, val tables: Map<String, List<String>>)

@Serializable
data class DatabaseQueryPage(
    val rows: List<Map<String, String?>>,
    val offset: Int,
    val limit: Int,
    val hasMore: Boolean,
    val nextOffset: Int?,
)

@Serializable
data class DatabaseSchema(
    val databasePath: String,
    val createStatements: Map<String, String>,
    val bodyStorage: String,
)

@Serializable
data class EndpointInspectionTag(
    val host: String,
    val method: String,
    val path: String,
    val tag: String,
    val source: String,
    val updatedAt: String,
    val serverUrl: String = "",
)

@Serializable
data class EndpointTagChange(
    val id: Long,
    val host: String,
    val serverUrl: String,
    val method: String,
    val path: String,
    val oldTag: String?,
    val newTag: String?,
    val source: String,
    val updatedAt: String,
)

@Serializable
data class HarExportResult(
    val outputPath: String,
    val exported: Int,
    val lastId: Long?,
    val hasMore: Boolean,
    val skippedRequestBodies: Int,
    val skippedResponseBodies: Int,
)

@Serializable
data class PacketDeltaItem(
    val id: Long,
    val host: String,
    val method: String,
    val path: String,
    val url: String,
    val statusCode: Int?,
    val requestBodySize: Int,
    val responseBodySize: Int?,
    val isSentFromMcp: Boolean,
    val capturedAt: String,
    val pathTruncated: Boolean,
    val urlTruncated: Boolean,
    val changeSeq: Long? = null,
    val changeKind: String? = null,
)

@Serializable
data class PacketDeltaPage(
    val databasePath: String,
    val databaseId: String,
    val afterId: Long,
    val items: List<PacketDeltaItem>,
    val lastId: Long,
    val hasMore: Boolean,
    val afterChangeSeq: Long? = null,
    val lastChangeSeq: Long? = null,
)

@Serializable
data class ApiRouteSummary(
    val host: String,
    val method: String,
    val path: String,
    val packetCount: Long,
    val firstPacketId: Long,
    val lastPacketId: Long,
    val firstSeen: String,
    val lastSeen: String,
    val statusCodes: List<Int>,
    val hasQuery: Boolean,
    val hasRequestBody: Boolean,
    val sampleResponseMimeType: String?,
    val sampleUrl: String,
    val pathTruncated: Boolean,
    val sampleUrlTruncated: Boolean,
)

@Serializable
data class ApiInventoryPage(
    val databasePath: String,
    val databaseId: String,
    val host: String,
    val snapshotMaxId: Long,
    val routes: List<ApiRouteSummary>,
    val hasMore: Boolean,
    val nextCursor: String?,
)

@Serializable
private data class InventoryCursor(
    val databaseId: String,
    val host: String,
    val excludeMcpSent: Boolean,
    val snapshotMaxId: Long,
    val lastFirstPacketId: Long,
)

/** One writer and one collector belong to the Burp extension; long reads use separate SQLite connections. */
class PacketRepository(private val api: MontoyaApi) : AutoCloseable {
    private val executor = Executors.newSingleThreadExecutor { work ->
        Thread(work, "burp-mcp-packet-collector").apply { isDaemon = true }
    }
    private var responseRegistration: Registration? = null
    private val pendingResponses = ArrayBlockingQueue<QueuedResponse>(RESPONSE_QUEUE_LIMIT)
    private val drainingResponses = AtomicBoolean(false)
    private val needsHistoryCatchup = AtomicBoolean(false)
    private val queueOverflowCount = AtomicLong()
    private val saveFailureCount = AtomicLong()
    private val historyCatchupCount = AtomicLong()
    private val inventoryListeners = CopyOnWriteArrayList<() -> Unit>()
    private val inspectionTagRevision = AtomicLong()
    @Volatile private var captureGeneration = 0L
    @Volatile private var collecting = false
    @Volatile private var historyScanPhase = "idle"
    @Volatile private var historyScanTotal = 0
    @Volatile private var historyScanProcessed = 0
    @Volatile private var historyScanInserted = 0
    @Volatile private var lastCaptureError: String? = null
    private var connection: Connection? = null
    private var dbPath: Path? = null
    private var historyPosition = 0
    private var lastHistoryId: Int? = null
    private val pendingResponsePositions = mutableSetOf<Int>()

    private data class QueuedResponse(
        val request: HttpRequest, val response: HttpResponse, val burpId: Int, val generation: Long,
    )

    fun addInventoryListener(listener: () -> Unit): AutoCloseable {
        inventoryListeners.add(listener)
        return AutoCloseable { inventoryListeners.remove(listener) }
    }

    private fun notifyInventoryChanged() {
        inventoryListeners.forEach { listener -> runCatching { listener() }.onFailure { api.logging().logToError(it) } }
    }

    @Synchronized
    fun start(projectPath: String, backgroundScan: Boolean = false): CaptureStatus {
        val project = Path.of(projectPath).toRealPath()
        require(Files.isDirectory(project)) { "projectPath must be an existing directory" }
        val path = project.resolve(DATABASE_FILE)
        stopCollection()
        if (connection != null) runCatching { syncHistory() }.onFailure { api.logging().logToError(it) }
        connection?.close()
        connection = null
        dbPath = null
        historyPosition = 0
        lastHistoryId = null
        pendingResponsePositions.clear()
        historyScanPhase = "idle"
        historyScanTotal = 0
        historyScanProcessed = 0
        historyScanInserted = 0
        lastCaptureError = null
        queueOverflowCount.set(0)
        saveFailureCount.set(0)
        historyCatchupCount.set(0)

        Class.forName("org.sqlite.JDBC")
        val opened = DriverManager.getConnection("jdbc:sqlite:${path}")
        try {
            opened.createStatement().use { statement ->
                statement.execute("PRAGMA journal_mode=WAL")
                statement.execute("PRAGMA busy_timeout=5000")
                statement.execute("PRAGMA foreign_keys=ON")
            }
            initialize(opened)
            connection = opened
            dbPath = path
            inspectionTagRevision.incrementAndGet()
            notifyInventoryChanged()
            collecting = true
            val generation = captureGeneration
            responseRegistration = api.proxy().registerResponseHandler(responseHandler(generation))
            // Every connection deliberately scans Burp history from the beginning.
            if (backgroundScan) {
                historyScanPhase = "loading_history"
                executor.execute { syncHistoryProgressive(generation) }
                return status()
            }
            historyScanPhase = "scanning"
            val scanned = syncHistory()
            historyScanTotal = historyPosition
            historyScanProcessed = historyPosition
            historyScanInserted = scanned.second
            historyScanPhase = "complete"
            return status(scanned.first, scanned.second)
        } catch (error: Exception) {
            stopCollection()
            connection = null
            dbPath = null
            opened.close()
            throw error
        }
    }

    @Synchronized
    fun stop(closeDatabase: Boolean = false): CaptureStatus {
        stopCollection()
        try {
            if (connection != null) syncHistory()
            return status().copy(collecting = false)
        } finally {
            if (closeDatabase) {
                connection?.close()
                connection = null
                dbPath = null
                inspectionTagRevision.incrementAndGet()
                historyPosition = 0
                lastHistoryId = null
                pendingResponsePositions.clear()
                notifyInventoryChanged()
            }
        }
    }

    @Synchronized
    fun status(scanned: Int = 0, inserted: Int = 0): CaptureStatus = CaptureStatus(
        dbPath?.toString(), collecting, count(), historyPosition, scanned, inserted,
        historyScanPhase, historyScanTotal, historyScanProcessed, historyScanInserted,
        queueOverflowCount.get(), pendingResponses.size, saveFailureCount.get(), historyCatchupCount.get(), lastCaptureError
    )

    @Synchronized
    fun projectDirectory(): Path? = dbPath?.parent

    fun inspectionTagRevision(): Long = inspectionTagRevision.get()

    @Synchronized
    fun endpointInspectionTags(host: String, serverUrl: String? = null): List<EndpointInspectionTag> {
        val normalizedHost = normalizeTagHost(host)
        val normalizedUrl = serverUrl?.let(::normalizeTagServerUrl)
        val db = requireDb()
        db.prepareStatement("SELECT host,method,path,tag,source,updated_at,server_url FROM endpoint_inspection_tags WHERE host=? AND (? IS NULL OR server_url=?) ORDER BY server_url,method,path").use { st ->
            st.setString(1, normalizedHost)
            st.setString(2, normalizedUrl)
            st.setString(3, normalizedUrl)
            st.executeQuery().use { rows ->
                return buildList {
                    while (rows.next()) add(EndpointInspectionTag(
                        rows.getString("host"), rows.getString("method"), rows.getString("path"),
                        rows.getString("tag"), rows.getString("source"), rows.getString("updated_at"), rows.getString("server_url"),
                    ))
                }
            }
        }
    }

    @Synchronized
    fun setEndpointInspectionTag(host: String, method: String, path: String, tag: String?, source: String,
                                 serverUrl: String): EndpointInspectionTag? {
        val normalizedHost = normalizeTagHost(host)
        val normalizedUrl = normalizeTagServerUrl(serverUrl)
        val normalizedMethod = method.uppercase()
        require(normalizedMethod in setOf("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE")) { "Unsupported HTTP method" }
        require(path.startsWith('/') && path.length <= 2048 && path.none { it.isWhitespace() || it.isISOControl() }) { "Invalid OpenAPI path" }
        require(tag == null || tag in setOf("VULN", "SUSPECT", "SAFE")) { "tag must be VULN, SUSPECT, SAFE, or null to clear" }
        require(source == "agent" || source == "human") { "Invalid tag source" }
        val db = requireDb()
        val updatedAt = Instant.now().toString()
        db.autoCommit = false
        try {
            val previous = db.prepareStatement("SELECT tag FROM endpoint_inspection_tags WHERE host=? AND server_url=? AND method=? AND path=?").use { st ->
                st.setString(1, normalizedHost); st.setString(2, normalizedUrl)
                st.setString(3, normalizedMethod); st.setString(4, path)
                st.executeQuery().use { rows -> if (rows.next()) rows.getString(1) else null }
            }
            if (tag == null) {
                if (previous != null) db.prepareStatement("DELETE FROM endpoint_inspection_tags WHERE host=? AND server_url=? AND method=? AND path=?").use { st ->
                    st.setString(1, normalizedHost); st.setString(2, normalizedUrl)
                    st.setString(3, normalizedMethod); st.setString(4, path)
                    st.executeUpdate()
                }
            } else db.prepareStatement("""
                INSERT INTO endpoint_inspection_tags(host,server_url,method,path,tag,source,updated_at) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(host,server_url,method,path) DO UPDATE SET tag=excluded.tag,source=excluded.source,updated_at=excluded.updated_at
            """).use { st ->
                st.setString(1, normalizedHost); st.setString(2, normalizedUrl)
                st.setString(3, normalizedMethod); st.setString(4, path)
                st.setString(5, tag); st.setString(6, source); st.setString(7, updatedAt)
                st.executeUpdate()
            }
            if (tag != null || previous != null) db.prepareStatement("""
                INSERT INTO endpoint_inspection_tag_events(host,server_url,method,path,old_tag,new_tag,source,updated_at)
                VALUES(?,?,?,?,?,?,?,?)
            """).use { st ->
                st.setString(1, normalizedHost); st.setString(2, normalizedUrl)
                st.setString(3, normalizedMethod); st.setString(4, path)
                st.setString(5, previous); st.setString(6, tag)
                st.setString(7, source); st.setString(8, updatedAt)
                st.executeUpdate()
            }
            db.commit()
            if (tag != null || previous != null) inspectionTagRevision.incrementAndGet()
        } catch (error: Exception) {
            db.rollback()
            throw error
        } finally {
            db.autoCommit = true
        }
        return tag?.let { EndpointInspectionTag(normalizedHost, normalizedMethod, path, it, source, updatedAt, normalizedUrl) }
    }

    @Synchronized
    fun endpointTagHistory(host: String, serverUrl: String, method: String, path: String, limit: Int = 50): List<EndpointTagChange> {
        val normalizedHost = normalizeTagHost(host)
        val normalizedUrl = normalizeTagServerUrl(serverUrl)
        require(limit in 1..200) { "limit must be between 1 and 200" }
        val db = requireDb()
        db.prepareStatement("""
            SELECT id,host,server_url,method,path,old_tag,new_tag,source,updated_at
            FROM endpoint_inspection_tag_events
            WHERE host=? AND server_url=? AND method=? AND path=? ORDER BY id DESC LIMIT ?
        """).use { st ->
            st.setString(1, normalizedHost); st.setString(2, normalizedUrl)
            st.setString(3, method.uppercase()); st.setString(4, path); st.setInt(5, limit)
            st.executeQuery().use { rows -> return buildList {
                while (rows.next()) add(EndpointTagChange(
                    rows.getLong("id"), rows.getString("host"), rows.getString("server_url"),
                    rows.getString("method"), rows.getString("path"), rows.getString("old_tag"),
                    rows.getString("new_tag"), rows.getString("source"), rows.getString("updated_at"),
                ))
            } }
        }
    }

    @Synchronized
    fun count(): Long {
        val db = connection ?: return 0
        db.createStatement().use { st ->
            st.executeQuery("SELECT count(*) FROM burp_packets").use { rs -> rs.next(); return rs.getLong(1) }
        }
    }

    @Synchronized
    fun info(): DatabaseInfo {
        val db = connection ?: return DatabaseInfo(status(), emptyMap())
        val tables = listOf(
            "burp_packets", "packet_blobs", "packet_body_fts",
            "packet_history_refs", "api_route_summary", "api_route_status_codes", "packet_changes", "endpoint_inspection_tags", "endpoint_inspection_tag_events",
        ).associateWith { name ->
            db.createStatement().use { st ->
                st.executeQuery("PRAGMA table_info($name)").use { rs ->
                    buildList { while (rs.next()) add(rs.getString("name")) }
                }
            }
        }
        return DatabaseInfo(status(), tables)
    }

    @Synchronized
    fun schema(): DatabaseSchema {
        val db = requireDb()
        val statements = linkedMapOf<String, String>()
        db.prepareStatement("""
            SELECT name, sql FROM sqlite_master
            WHERE type='table' AND name IN
              ('burp_packets','packet_blobs','packet_body_fts','api_route_summary','api_route_status_codes','packet_changes','endpoint_inspection_tags','endpoint_inspection_tag_events')
            ORDER BY name
        """).use { st ->
            st.executeQuery().use { rs -> while (rs.next()) statements[rs.getString("name")] = rs.getString("sql") }
        }
        return DatabaseSchema(
            requireNotNull(dbPath).toString(), statements,
            "burp_packets.request_body_hash/response_body_hash reference packet_blobs.hash; " +
                "packet_blobs.data contains inline bytes, or file_path is relative to the database directory. " +
                "request_head/response_head are raw HTTP header bytes without the body."
        )
    }

    @Synchronized
    fun saveSent(request: HttpRequest, response: HttpResponse?): Long? {
        if (connection == null || response == null) return null
        return save(request, response, null, true)
    }

    @Synchronized
    fun getPacket(id: Long, maxBodyBytes: Int = 65_536): PacketDetail? {
        require(maxBodyBytes in 0..1_048_576) { "maxBodyBytes must be between 0 and 1048576" }
        val db = requireDb()
        db.prepareStatement("""
            SELECT p.*, rq.data AS request_body_data, rq.file_path AS request_body_path,
                   rq.size AS request_body_size, rs.data AS response_body_data,
                   rs.file_path AS response_body_path, rs.size AS response_body_size
            FROM burp_packets p
            JOIN packet_blobs rq ON rq.hash = p.request_body_hash
            LEFT JOIN packet_blobs rs ON rs.hash = p.response_body_hash
            WHERE p.id = ?
        """).use { st ->
            st.setLong(1, id)
            st.executeQuery().use { rs ->
                if (!rs.next()) return null
                val requestSize = rs.getInt("request_body_size")
                val responseSize = rs.intOrNull("response_body_size")
                val requestPreview = readBlobPrefix(rs.getBytes("request_body_data"), rs.getString("request_body_path"), maxBodyBytes)
                val responsePreview = if (responseSize == null) null else readBlobPrefix(
                    rs.getBytes("response_body_data"), rs.getString("response_body_path"), maxBodyBytes
                )
                return PacketDetail(
                    id = id,
                    burpHistoryId = rs.intOrNull("burp_id"),
                    host = rs.getString("host"), port = rs.getInt("port"),
                    usesHttps = rs.getInt("uses_https") != 0, method = rs.getString("method"),
                    url = rs.getString("url"), statusCode = rs.intOrNull("status_code"),
                    isSentFromMcp = rs.getInt("is_sent_from_mcp") != 0,
                    requestHeaders = String(rs.getBytes("request_head"), StandardCharsets.ISO_8859_1),
                    responseHeaders = rs.getBytes("response_head")?.let { String(it, StandardCharsets.ISO_8859_1) },
                    requestBodySize = requestSize, responseBodySize = responseSize,
                    requestBodyHash = rs.getString("request_body_hash"),
                    responseBodyHash = rs.getString("response_body_hash"),
                    requestBodyBase64 = requestPreview.base64(),
                    responseBodyBase64 = responsePreview?.base64(),
                    requestBodyTruncated = requestSize > maxBodyBytes,
                    responseBodyTruncated = responseSize != null && responseSize > maxBodyBytes,
                )
            }
        }
    }

    @Synchronized
    fun getPacketByHistoryId(historyId: Int, packetId: Long, maxBodyBytes: Int = 65_536): PacketDetail? {
        require(historyId >= 0) { "historyId must be non-negative" }
        require(packetId > 0) { "packetId must be positive" }
        val db = requireDb()
        val linked = db.prepareStatement("SELECT 1 FROM packet_history_refs WHERE history_id=? AND packet_id=?").use { st ->
            st.setInt(1, historyId)
            st.setLong(2, packetId)
            st.executeQuery().use { rs -> rs.next() }
        }
        if (!linked) return null
        return getPacket(packetId, maxBodyBytes)?.copy(burpHistoryId = historyId)
    }

    @Synchronized
    fun hosts(): List<String> {
        val db = requireDb()
        db.createStatement().use { st ->
            st.executeQuery("SELECT DISTINCT host FROM api_route_summary WHERE scope=0 ORDER BY host").use { rs ->
                return buildList { while (rs.next()) add(rs.getString(1)) }
            }
        }
    }

    @Synchronized
    fun hostRelationshipGraph(sampleLimit: Int = 5_000): HostGraphSnapshot? =
        connection?.let { readHostRelationshipGraph(it, sampleLimit) }

    /** Cheap change marker for the all-packets inventory shown in the Burp tab. */
    @Synchronized
    fun inventoryRevision(): Pair<String, Long>? {
        val db = connection ?: return null
        val lastId = db.createStatement().use { st ->
            st.executeQuery("SELECT COALESCE(MAX(seq),0) FROM packet_changes").use { rs -> rs.next(); rs.getLong(1) }
        }
        return databaseId(db) to lastId
    }

    /** Return packet metadata in insertion order. The lastId is safe to reuse after a Burp restart. */
    @Synchronized
    fun packetDelta(afterId: Long, limit: Int, host: String?, excludeMcpSent: Boolean,
                    expectedDatabaseId: String?, afterChangeSeq: Long? = null): PacketDeltaPage {
        require(afterId >= 0) { "afterId must be non-negative" }
        require(afterChangeSeq == null || afterChangeSeq >= 0) { "afterChangeSeq must be non-negative" }
        require(limit in 1..500) { "limit must be between 1 and 500" }
        require(host == null || host.isNotBlank()) { "host must be non-blank" }
        val db = requireDb()
        val identity = databaseId(db)
        require(expectedDatabaseId == null || expectedDatabaseId == identity) {
            "Packet database has changed; restart from afterChangeSeq=0"
        }
        val journal = afterChangeSeq != null
        val sql = """
            SELECT p.id,p.host,p.method,p.path,p.url,p.status_code,p.is_sent_from_mcp,p.captured_at,
                   ${if (journal) "c.seq AS change_seq,c.kind AS change_kind" else "NULL AS change_seq,NULL AS change_kind"},
                   rq.size AS request_size,rs.size AS response_size
            FROM burp_packets p
            ${if (journal) "JOIN packet_changes c ON c.packet_id=p.id" else ""}
            JOIN packet_blobs rq ON rq.hash=p.request_body_hash
            LEFT JOIN packet_blobs rs ON rs.hash=p.response_body_hash
            WHERE ${if (journal) "c.seq" else "p.id"} > ?
            ${if (host != null) "AND p.host = ?" else ""}
            ${if (journal) {
                if (excludeMcpSent) "AND c.is_sent_from_mcp=0" else "AND c.kind='insert'"
            } else if (excludeMcpSent) "AND p.is_sent_from_mcp = 0" else ""}
            ORDER BY ${if (journal) "c.seq" else "p.id"} LIMIT ?
        """
        val results = db.prepareStatement(sql).use { st ->
            st.setLong(1, afterChangeSeq ?: afterId)
            var index = 2
            if (host != null) st.setString(index++, host)
            st.setInt(index, limit + 1)
            st.executeQuery().use { rs -> buildList {
                while (rs.next()) add(PacketDeltaItem(
                    rs.getLong("id"), rs.getString("host"), rs.getString("method"),
                    boundedMetadata(rs.getString("path")), boundedMetadata(rs.getString("url")),
                    rs.intOrNull("status_code"),
                    rs.getInt("request_size"), rs.intOrNull("response_size"),
                    rs.getInt("is_sent_from_mcp") != 0, rs.getString("captured_at"),
                    rs.getString("path").length > METADATA_TEXT_LIMIT,
                    rs.getString("url").length > METADATA_TEXT_LIMIT,
                    rs.getLong("change_seq").let { if (rs.wasNull()) null else it },
                    rs.getString("change_kind"),
                ))
            } }
        }
        val hasMore = results.size > limit
        val items = if (hasMore) results.dropLast(1) else results
        // A filtered page with no further matches can still advance past non-matching packets.
        val lastId = if (hasMore) items.last().id else db.createStatement().use { st ->
            st.executeQuery("SELECT COALESCE(MAX(id),0) FROM burp_packets").use { rs ->
                rs.next()
                maxOf(afterId, rs.getLong(1))
            }
        }
        val lastChangeSeq = if (!journal) null else if (hasMore) items.last().changeSeq else
            db.createStatement().use { st ->
                st.executeQuery("SELECT COALESCE(MAX(seq),0) FROM packet_changes").use { rs ->
                    rs.next(); maxOf(afterChangeSeq, rs.getLong(1))
                }
            }
        return PacketDeltaPage(requireNotNull(dbPath).toString(), identity, afterId, items,
            lastId, hasMore, afterChangeSeq, lastChangeSeq)
    }

    /** Page exact observed routes from the incrementally maintained summary table. */
    @Synchronized
    fun apiInventory(host: String, limit: Int, cursor: String?, excludeMcpSent: Boolean): ApiInventoryPage {
        require(host.isNotBlank()) { "host is required" }
        require(limit in 1..500) { "limit must be between 1 and 500" }
        val db = requireDb()
        val identity = databaseId(db)
        val decoded = cursor?.let {
            require(it.length <= 4096) { "cursor is too long" }
            runCatching { Json.decodeFromString<InventoryCursor>(String(Base64.getUrlDecoder().decode(it), StandardCharsets.UTF_8)) }
                .getOrElse { throw IllegalArgumentException("Invalid inventory cursor", it) }
        }
        require(decoded == null || (decoded.databaseId == identity && decoded.host == host &&
            decoded.excludeMcpSent == excludeMcpSent)) { "Inventory cursor belongs to another database or filter" }
        val snapshotMaxId = decoded?.snapshotMaxId ?: db.createStatement().use { st ->
            st.executeQuery("SELECT COALESCE(MAX(id),0) FROM burp_packets").use { rs -> rs.next(); rs.getLong(1) }
        }
        val sql = """
            SELECT s.*,
                   (SELECT group_concat(code) FROM api_route_status_codes c
                    WHERE c.scope=s.scope AND c.host=s.host AND c.method=s.method
                      AND c.route_path=s.route_path) AS status_codes,
                   sample.url AS sample_url,sample.response_head AS sample_response_head
            FROM api_route_summary s JOIN burp_packets sample ON sample.id=s.first_id
            WHERE s.host=? AND s.scope=? AND s.first_id<=? AND s.first_id>?
            ORDER BY s.first_id LIMIT ?
        """
        val results = db.prepareStatement(sql).use { st ->
            st.setString(1, host)
            st.setInt(2, if (excludeMcpSent) 1 else 0)
            st.setLong(3, snapshotMaxId)
            st.setLong(4, decoded?.lastFirstPacketId ?: 0)
            st.setInt(5, limit + 1)
            st.executeQuery().use { rs -> buildList {
                while (rs.next()) add(ApiRouteSummary(
                    host, rs.getString("method"), boundedMetadata(rs.getString("route_path")),
                    rs.getLong("packet_count"), rs.getLong("first_id"), rs.getLong("last_id"),
                    rs.getString("first_seen"), rs.getString("last_seen"),
                    rs.getString("status_codes")?.split(',')?.mapNotNull(String::toIntOrNull)?.distinct()?.sorted() ?: emptyList(),
                    rs.getInt("has_query") != 0, rs.getInt("has_request_body") != 0,
                    responseMimeType(rs.getBytes("sample_response_head")), boundedMetadata(rs.getString("sample_url")),
                    rs.getString("route_path").length > METADATA_TEXT_LIMIT,
                    rs.getString("sample_url").length > METADATA_TEXT_LIMIT,
                ))
            } }
        }
        val hasMore = results.size > limit
        val routes = if (hasMore) results.dropLast(1) else results
        val nextCursor = if (hasMore) routes.lastOrNull()?.let {
            Base64.getUrlEncoder().withoutPadding().encodeToString(Json.encodeToString(
                InventoryCursor(identity, host, excludeMcpSent, snapshotMaxId, it.firstPacketId)
            ).toByteArray(StandardCharsets.UTF_8))
        } else null
        return ApiInventoryPage(requireNotNull(dbPath).toString(), identity, host, snapshotMaxId,
            routes, hasMore, nextCursor)
    }

    private fun databaseId(db: Connection): String = db.prepareStatement(
        "SELECT value FROM capture_metadata WHERE key='database_id'"
    ).use { st -> st.executeQuery().use { rs -> rs.next(); rs.getString(1) } }

    fun search(
        query: String, targets: List<String>, hosts: List<String>, url: String?, method: String?,
        statusCode: Int?, excludeMcpSent: Boolean, groupSimilar: Boolean, limit: Int, offset: Int,
    ): List<PacketSummary> {
        require(query.isNotBlank()) { "ftsSearchQuery is required" }
        require(targets.isNotEmpty() && targets.all { it == "request_body" || it == "response_body" }) {
            "targets must contain request_body or response_body"
        }
        require(limit in 1..500 && offset >= 0) { "limit must be 1..500 and offset non-negative" }
        val db = openReader()
        db.use { reader ->
        val targetCondition = targets.joinToString(" OR ") {
            if (it == "request_body") "p.request_body_hash = h.hash" else "p.response_body_hash = h.hash"
        }
        val sql = buildString {
            append("""
                WITH hits AS (
                    SELECT b.hash, snippet(packet_body_fts,0,'<<<','>>>','...',12) AS snippet
                      FROM packet_body_fts JOIN packet_blobs b ON b.rowid=packet_body_fts.rowid
                      WHERE packet_body_fts MATCH ?
                ), matches AS (
                SELECT p.id,p.host,p.method,p.url,p.status_code,p.is_sent_from_mcp,
                       rq.size AS request_size,rs.size AS response_size,h.snippet,
                       row_number() OVER (PARTITION BY p.host,p.method,p.url,p.status_code,
                           p.request_body_hash,p.response_body_hash ORDER BY p.is_sent_from_mcp,p.id) AS group_rank,
                       count(*) OVER (PARTITION BY p.host,p.method,p.url,p.status_code,
                           p.request_body_hash,p.response_body_hash) AS similar_count
                FROM hits h
                JOIN burp_packets p ON ($targetCondition)
                JOIN packet_blobs rq ON rq.hash=p.request_body_hash
                LEFT JOIN packet_blobs rs ON rs.hash=p.response_body_hash
                WHERE 1=1
            """)
            if (hosts.isNotEmpty()) append(" AND p.host IN (${hosts.joinToString(",") { "?" }})")
            if (url != null) append(" AND instr(p.url,?)>0")
            if (method != null) append(" AND upper(p.method)=upper(?)")
            if (statusCode != null) append(" AND p.status_code=?")
            if (excludeMcpSent) append(" AND p.is_sent_from_mcp=0")
            append(") SELECT id,host,method,url,status_code,is_sent_from_mcp,request_size,response_size,snippet,similar_count FROM matches")
            if (groupSimilar) append(" WHERE group_rank=1")
            append(" ORDER BY id LIMIT ? OFFSET ?")
        }
        reader.prepareStatement(sql).use { st ->
            var i = 1
            st.setString(i++, query)
            hosts.forEach { st.setString(i++, it) }
            if (url != null) st.setString(i++, url)
            if (method != null) st.setString(i++, method)
            if (statusCode != null) st.setInt(i++, statusCode)
            st.setInt(i++, limit)
            st.setInt(i, offset)
            st.executeQuery().use { rs -> return buildList { while (rs.next()) add(rs.summary()) } }
        }
        }
    }

    /** Bounded, newest-first literal search for the Swagger viewer. Bodies use the shared FTS index. */
    fun searchSwaggerPackets(host: String, query: String, beforeId: Long = Long.MAX_VALUE,
                             limit: Int = 100, port: Int? = null, usesHttps: Boolean? = null): SwaggerPacketSearchPage {
        require(host.isNotBlank()) { "host is required" }
        require(query.length in 3..200) { "query length must be between 3 and 200" }
        require(beforeId > 0 && limit in 1..200) { "Invalid search page" }
        require(port == null || port in 1..65535) { "Invalid port" }
        val literal = query.lowercase()
        val ftsPhrase = "\"${query.replace("\"", "\"\"")}\""
        val sql = """
            WITH body_hits AS (
                SELECT b.hash, snippet(packet_body_fts,0,'<<<','>>>','…',12) AS excerpt
                FROM packet_body_fts JOIN packet_blobs b ON b.rowid=packet_body_fts.rowid
                WHERE packet_body_fts MATCH ?
            )
            SELECT p.id,p.method,p.url,p.port,p.uses_https,p.status_code,p.request_head,p.response_head,
                   (SELECT MAX(r.history_id) FROM packet_history_refs r WHERE r.packet_id=p.id) AS history_id,
                   CASE WHEN instr(lower(p.url),?)>0 THEN 'URL'
                        WHEN instr(lower(CAST(p.request_head AS TEXT)),?)>0 THEN 'Request headers'
                        WHEN instr(lower(CAST(p.response_head AS TEXT)),?)>0 THEN 'Response headers'
                        WHEN req.hash IS NOT NULL THEN 'Request body'
                        ELSE 'Response body' END AS location,
                   CASE WHEN instr(lower(p.url),?)>0 THEN substr(p.url,1,240)
                        WHEN req.hash IS NOT NULL THEN substr(req.excerpt,1,240)
                        WHEN res.hash IS NOT NULL THEN substr(res.excerpt,1,240)
                        ELSE '' END AS excerpt
            FROM burp_packets p
            LEFT JOIN body_hits req ON req.hash=p.request_body_hash
            LEFT JOIN body_hits res ON res.hash=p.response_body_hash
            WHERE p.host=? AND p.id<? AND (? IS NULL OR p.port=?) AND (? IS NULL OR p.uses_https=?) AND (
                instr(lower(p.url),?)>0 OR
                instr(lower(CAST(p.request_head AS TEXT)),?)>0 OR
                instr(lower(CAST(p.response_head AS TEXT)),?)>0 OR
                req.hash IS NOT NULL OR res.hash IS NOT NULL
            )
            ORDER BY p.id DESC LIMIT ?
        """.trimIndent()
        openReader().use { reader ->
            reader.prepareStatement(sql).use { st ->
                st.queryTimeout = 5
                st.setString(1, ftsPhrase)
                st.setString(2, literal)
                st.setString(3, literal)
                st.setString(4, literal)
                st.setString(5, literal)
                st.setString(6, host.lowercase())
                st.setLong(7, beforeId)
                if (port == null) st.setNull(8, java.sql.Types.INTEGER) else st.setInt(8, port)
                if (port == null) st.setNull(9, java.sql.Types.INTEGER) else st.setInt(9, port)
                if (usesHttps == null) st.setNull(10, java.sql.Types.INTEGER) else st.setInt(10, if (usesHttps) 1 else 0)
                if (usesHttps == null) st.setNull(11, java.sql.Types.INTEGER) else st.setInt(11, if (usesHttps) 1 else 0)
                st.setString(12, literal)
                st.setString(13, literal)
                st.setString(14, literal)
                st.setInt(15, limit + 1)
                st.executeQuery().use { rows ->
                    val found = buildList {
                        while (rows.next()) {
                            val historyId = rows.getInt("history_id").let { if (rows.wasNull()) null else it }
                            val statusCode = rows.getInt("status_code").let { if (rows.wasNull()) null else it }
                            val location = rows.getString("location")
                            val excerpt = when (location) {
                                "Request headers" -> matchingHeaderLine(rows.getString("request_head"), literal)
                                "Response headers" -> matchingHeaderLine(rows.getString("response_head"), literal)
                                else -> rows.getString("excerpt") ?: ""
                            }
                            add(SwaggerPacketSearchHit(rows.getLong("id"), historyId, rows.getString("method"),
                                rows.getString("url"), rows.getInt("port"), rows.getInt("uses_https") != 0,
                                statusCode, location, excerpt))
                        }
                    }
                    val hasMore = found.size > limit
                    val page = found.take(limit)
                    return SwaggerPacketSearchPage(page, hasMore,
                        if (hasMore) page.lastOrNull()?.packetId else null)
                }
            }
        }
    }

    /** Resolve a bounded set of stored references on the selected HTTP origin without loading bodies. */
    fun packetUrlsForServer(packetIds: List<Long>, host: String, port: Int, usesHttps: Boolean): Map<Long, String> {
        if (packetIds.isEmpty()) return emptyMap()
        require(packetIds.size <= 100 && packetIds.all { it > 0 }) { "Invalid packet references" }
        require(port in 1..65535) { "Invalid port" }
        val placeholders = packetIds.joinToString(",") { "?" }
        val sql = "SELECT id,url FROM burp_packets WHERE id IN ($placeholders) AND host=? AND port=? AND uses_https=?"
        openReader().use { reader ->
            reader.prepareStatement(sql).use { st ->
                packetIds.forEachIndexed { index, id -> st.setLong(index + 1, id) }
                st.setString(packetIds.size + 1, host.lowercase())
                st.setInt(packetIds.size + 2, port)
                st.setInt(packetIds.size + 3, if (usesHttps) 1 else 0)
                st.executeQuery().use { rows -> return buildMap {
                    while (rows.next()) put(rows.getLong("id"), rows.getString("url"))
                } }
            }
        }
    }

    @Synchronized
    fun referersOf(urlPart: String, distinct: Boolean, limit: Int): List<Map<String, String?>> {
        require(urlPart.isNotBlank() && limit in 1..500)
        val sql = "SELECT ${if (distinct) "DISTINCT" else ""} url,referer FROM burp_packets WHERE instr(url,?)>0 AND referer IS NOT NULL LIMIT ?"
        requireDb().prepareStatement(sql).use { st ->
            st.setString(1, urlPart); st.setInt(2, limit)
            st.executeQuery().use { rs -> return buildList { while (rs.next()) add(mapOf("url" to rs.getString(1), "referer" to rs.getString(2))) } }
        }
    }

    @Synchronized
    fun packetsByReferer(referer: String, match: String, distinct: Boolean, limit: Int): List<PacketSummary> {
        require(referer.isNotBlank() && match in setOf("exact", "prefix", "contains") && limit in 1..500)
        val condition = when (match) { "exact" -> "p.referer=?"; "prefix" -> "p.referer LIKE ? ESCAPE '\\'"; else -> "p.referer LIKE ? ESCAPE '\\'" }
        val whereValue = when (match) { "exact" -> referer; "prefix" -> escapeLike(referer) + "%"; else -> "%" + escapeLike(referer) + "%" }
        val sql = """
            WITH matches AS (
            SELECT p.id,p.host,p.method,p.url,p.status_code,p.is_sent_from_mcp,
                   rq.size AS request_size,rs.size AS response_size,NULL AS snippet,1 AS similar_count,
                   row_number() OVER (PARTITION BY p.method,p.url ORDER BY p.id) AS endpoint_rank
            FROM burp_packets p JOIN packet_blobs rq ON rq.hash=p.request_body_hash
            LEFT JOIN packet_blobs rs ON rs.hash=p.response_body_hash
            WHERE $condition)
            SELECT id,host,method,url,status_code,is_sent_from_mcp,request_size,response_size,snippet,similar_count
            FROM matches ${if (distinct) "WHERE endpoint_rank=1" else ""} ORDER BY id LIMIT ?
        """
        requireDb().prepareStatement(sql).use { st ->
            st.setString(1, whereValue); st.setInt(2, limit)
            st.executeQuery().use { rs -> return buildList { while (rs.next()) add(rs.summary()) } }
        }
    }

    fun querySelect(query: String, maxRows: Int, offset: Int = 0): DatabaseQueryPage {
        require(maxRows in 1..500) { "maxRows must be between 1 and 500" }
        require(offset >= 0 && offset <= Int.MAX_VALUE - maxRows) { "offset must be non-negative and within range" }
        require(Regex("(?is)^\\s*select\\b").containsMatchIn(query) && !query.contains(';')) {
            "Only a single SELECT statement is allowed"
        }
        val path = synchronized(this) { dbPath ?: error("Packet database is not connected") }
        DriverManager.getConnection("jdbc:sqlite:file:${path.toUri().rawPath}?mode=ro").use { reader ->
            reader.prepareStatement("SELECT * FROM (\n$query\n) AS query_page LIMIT ? OFFSET ?").use { st ->
                st.queryTimeout = 5
                st.maxRows = maxRows + 1
                st.maxFieldSize = 4096
                st.setInt(1, maxRows + 1)
                st.setInt(2, offset)
                st.executeQuery().use { rs ->
                    val metadata = rs.metaData
                    val rows = buildList {
                        while (rs.next()) add((1..metadata.columnCount).associate { column ->
                            metadata.getColumnLabel(column) to when (val value =
                                if (metadata.getColumnType(column) == java.sql.Types.BLOB) "<BLOB; use get_packet or save_packets>"
                                else rs.getObject(column)) {
                                is ByteArray -> "<BLOB ${value.size} bytes; use get_packet or save_packets>"
                                null -> null
                                else -> value.toString().let { if (it.length > 4096) it.take(4096) + "...[truncated]" else it }
                            }
                        })
                    }
                    val hasMore = rows.size > maxRows
                    return DatabaseQueryPage(
                        rows = if (hasMore) rows.dropLast(1) else rows,
                        offset = offset,
                        limit = maxRows,
                        hasMore = hasMore,
                        nextOffset = if (hasMore) offset + maxRows else null,
                    )
                }
            }
        }
    }

    fun savePackets(ids: List<Long>, directory: String): List<Map<String, String>> {
        require(ids.isNotEmpty() && ids.size <= 100) { "packetIds must contain 1..100 ids" }
        val target = Path.of(directory).toAbsolutePath().normalize()
        Files.createDirectories(target)
        val databasePath = synchronized(this) { dbPath ?: error("Packet database is not connected") }
        return DriverManager.getConnection("jdbc:sqlite:file:${databasePath.toUri().rawPath}?mode=ro").use { db -> ids.map { id ->
            db.prepareStatement("""
                SELECT p.request_head,p.response_head,rq.data AS request_body,rq.file_path AS request_body_path,
                       rs.data AS response_body,rs.file_path AS response_body_path
                FROM burp_packets p JOIN packet_blobs rq ON rq.hash=p.request_body_hash
                LEFT JOIN packet_blobs rs ON rs.hash=p.response_body_hash WHERE p.id=?
            """).use { st ->
                st.setLong(1, id)
                st.executeQuery().use { rs ->
                    require(rs.next()) { "Packet $id does not exist" }
                    val requestFile = target.resolve("$id.request.raw")
                    writeMessage(requestFile, rs.getBytes("request_head"), rs.getBytes("request_body"), rs.getString("request_body_path"), databasePath.parent)
                    val responseFile = rs.getBytes("response_head")?.let { head ->
                        target.resolve("$id.response.raw").also {
                            writeMessage(it, head, rs.getBytes("response_body"), rs.getString("response_body_path"), databasePath.parent)
                        }
                    }
                    mapOf("packetId" to id.toString(), "requestPath" to requestFile.toString(), "responsePath" to (responseFile?.toString() ?: ""))
                }
            }
        } }
    }

    /** Stream one bounded database page into a local HAR file for traffic-to-OpenAPI tools. */
    fun exportHar(
        outputPath: String, host: String?, afterId: Long, limit: Int,
        maxBodyBytes: Int, excludeMcpSent: Boolean,
    ): HarExportResult {
        require(afterId >= 0) { "afterId must be non-negative" }
        require(limit in 1..5000) { "limit must be between 1 and 5000" }
        require(maxBodyBytes in 0..1_048_576) { "maxBodyBytes must be between 0 and 1048576" }
        require(host == null || host.isNotBlank()) { "host must be non-blank" }
        val databasePath = synchronized(this) { dbPath ?: error("Packet database is not connected") }
        val output = Path.of(outputPath).toAbsolutePath().normalize()
        require(output != databasePath) { "outputPath must not be the packet database" }
        require(!Files.exists(output)) { "outputPath already exists: $output" }
        Files.createDirectories(output.parent)
        val temp = Files.createTempFile(output.parent, ".packets-har-", ".tmp")
        var exported = 0
        var lastId: Long? = null
        var hasMore = false
        var skippedRequests = 0
        var skippedResponses = 0
        val sql = """
            SELECT p.id,p.method,p.url,p.status_code,p.request_head,p.response_head,p.captured_at,
                   rq.size AS request_size,
                   CASE WHEN rq.size <= ? THEN rq.data END AS request_data,
                   CASE WHEN rq.size <= ? THEN rq.file_path END AS request_file,
                   rs.size AS response_size,
                   CASE WHEN rs.size <= ? THEN rs.data END AS response_data,
                   CASE WHEN rs.size <= ? THEN rs.file_path END AS response_file
            FROM burp_packets p
            JOIN packet_blobs rq ON rq.hash=p.request_body_hash
            LEFT JOIN packet_blobs rs ON rs.hash=p.response_body_hash
            WHERE p.id > ? AND p.status_code IS NOT NULL
            ${if (host != null) "AND p.host = ?" else ""}
            ${if (excludeMcpSent) "AND p.is_sent_from_mcp = 0" else ""}
            ORDER BY p.id LIMIT ?
        """
        try {
            DriverManager.getConnection("jdbc:sqlite:file:${databasePath.toUri().rawPath}?mode=ro").use { db ->
            Files.newBufferedWriter(temp, StandardCharsets.UTF_8).use { writer ->
                writer.write("{\"log\":{\"version\":\"1.2\",\"creator\":{\"name\":\"burp-mcp\",\"version\":\"1\"},\"entries\":[")
                db.prepareStatement(sql).use { st ->
                    repeat(4) { st.setInt(it + 1, maxBodyBytes) }
                    st.setLong(5, afterId)
                    var next = 6
                    if (host != null) st.setString(next++, host)
                    st.setInt(next, limit + 1)
                    st.executeQuery().use { rs ->
                        while (rs.next()) {
                            if (exported == limit) { hasMore = true; break }
                            val requestHead = rs.getBytes("request_head")
                            val responseHead = rs.getBytes("response_head") ?: continue
                            val requestHeaders = harHeaders(requestHead)
                            val responseHeaders = harHeaders(responseHead)
                            val requestBody = harBodyText(rs, "request", maxBodyBytes, databasePath.parent)
                            val responseBody = harBodyText(rs, "response", maxBodyBytes, databasePath.parent)
                            if (rs.getInt("request_size") > 0 && requestBody == null) skippedRequests++
                            if ((rs.intOrNull("response_size") ?: 0) > 0 && responseBody == null) skippedResponses++
                            val entry = buildJsonObject {
                                put("startedDateTime", rs.getString("captured_at"))
                                put("time", 0)
                                put("request", buildJsonObject {
                                    put("method", rs.getString("method"))
                                    put("url", rs.getString("url"))
                                    put("httpVersion", "HTTP/1.1")
                                    put("headers", requestHeaders)
                                    put("queryString", buildJsonArray { })
                                    put("cookies", buildJsonArray { })
                                    put("headersSize", requestHead.size)
                                    put("bodySize", rs.getInt("request_size"))
                                    if (requestBody != null) put("postData", buildJsonObject {
                                        put("mimeType", harMimeType(requestHead))
                                        put("text", requestBody)
                                    })
                                })
                                put("response", buildJsonObject {
                                    put("status", rs.getInt("status_code"))
                                    put("statusText", harStatusText(responseHead))
                                    put("httpVersion", "HTTP/1.1")
                                    put("headers", responseHeaders)
                                    put("cookies", buildJsonArray { })
                                    put("content", buildJsonObject {
                                        put("size", rs.intOrNull("response_size") ?: 0)
                                        put("mimeType", harMimeType(responseHead))
                                        if (responseBody != null) put("text", responseBody)
                                    })
                                    put("redirectURL", "")
                                    put("headersSize", responseHead.size)
                                    put("bodySize", rs.intOrNull("response_size") ?: 0)
                                })
                                put("cache", buildJsonObject { })
                                put("timings", buildJsonObject { put("send", 0); put("wait", 0); put("receive", 0) })
                            }
                            if (exported > 0) writer.write(",")
                            writer.write(Json.encodeToString(JsonObject.serializer(), entry))
                            exported++
                            lastId = rs.getLong("id")
                        }
                    }
                }
                writer.write("]}}")
            }
            }
            Files.move(temp, output)
            return HarExportResult(output.toString(), exported, lastId, hasMore, skippedRequests, skippedResponses)
        } finally {
            Files.deleteIfExists(temp)
        }
    }

    @Synchronized
    override fun close() {
        stopCollection()
        connection?.close()
        connection = null
        dbPath = null
        notifyInventoryChanged()
        executor.shutdownNow()
    }

    private fun stopCollection() {
        val previousGeneration = captureGeneration
        collecting = false
        captureGeneration++
        responseRegistration?.deregister()
        responseRegistration = null
        while (true) {
            val queued = pendingResponses.poll() ?: break
            if (queued.generation == previousGeneration && connection != null) {
                try { save(queued.request, queued.response, queued.burpId, false) }
                catch (error: Exception) { recordSaveFailure(error) }
            }
        }
        needsHistoryCatchup.set(false)
    }

    private fun responseHandler(generation: Long) = object : ProxyResponseHandler {
        override fun handleResponseReceived(response: InterceptedResponse): ProxyResponseReceivedAction =
            ProxyResponseReceivedAction.continueWith(response)

        override fun handleResponseToBeSent(response: InterceptedResponse): ProxyResponseToBeSentAction {
            try {
                if (collecting && generation == captureGeneration) {
                    val queued = QueuedResponse(response.request(), response, response.messageId(), generation)
                    if (!pendingResponses.offer(queued)) {
                        queueOverflowCount.incrementAndGet()
                        needsHistoryCatchup.set(true)
                    }
                    scheduleResponseDrain()
                }
            } catch (error: Exception) {
                needsHistoryCatchup.set(true)
                recordSaveFailure(error)
                scheduleResponseDrain()
            }
            return ProxyResponseToBeSentAction.continueWith(response)
        }
    }

    private fun scheduleResponseDrain() {
        if (!drainingResponses.compareAndSet(false, true)) return
        try {
            executor.execute {
                try {
                    while (true) {
                        val hadItem = synchronized(this) {
                            val queued = pendingResponses.poll() ?: return@synchronized false
                            if (collecting && queued.generation == captureGeneration && connection != null) {
                                try { save(queued.request, queued.response, queued.burpId, false) }
                                catch (error: Exception) {
                                    needsHistoryCatchup.set(true)
                                    recordSaveFailure(error)
                                }
                            }
                            true
                        }
                        if (!hadItem) break
                    }
                    if (needsHistoryCatchup.getAndSet(false)) {
                        synchronized(this) {
                            if (collecting && connection != null) {
                                try {
                                    historyCatchupCount.incrementAndGet()
                                    syncHistory()
                                    if (historyScanPhase == "error") historyScanPhase = "complete"
                                    lastCaptureError = null
                                }
                                catch (error: Exception) { recordSaveFailure(error) }
                            }
                        }
                    }
                } finally {
                    drainingResponses.set(false)
                    if (pendingResponses.isNotEmpty() || needsHistoryCatchup.get()) scheduleResponseDrain()
                }
            }
        } catch (_: RejectedExecutionException) {
            drainingResponses.set(false)
        }
    }

    private fun requireDb(): Connection = connection ?: error("Packet database is not connected; call start_packet_capture first")

    private fun openReader(): Connection {
        val path = synchronized(this) { dbPath ?: error("Packet database is not connected") }
        return DriverManager.getConnection("jdbc:sqlite:file:${path.toUri().rawPath}?mode=ro").apply {
            createStatement().use { it.execute("PRAGMA busy_timeout=5000") }
        }
    }

    private fun recordSaveFailure(error: Exception) {
        saveFailureCount.incrementAndGet()
        lastCaptureError = "${error.javaClass.simpleName}: ${error.message}"
        api.logging().logToError(error)
    }

    /** Load the History snapshot off the MCP thread and release the repository lock after each item. */
    private fun syncHistoryProgressive(generation: Long) {
        try {
            val history = api.proxy().history()
            synchronized(this) {
                if (generation != captureGeneration || connection == null) return
                historyScanTotal = history.size
                historyScanPhase = "scanning"
                if (history.size < historyPosition ||
                    (historyPosition > 0 && history[historyPosition - 1].id() != lastHistoryId)) {
                    historyPosition = 0
                    lastHistoryId = null
                    pendingResponsePositions.clear()
                }
            }
            for (position in history.indices) {
                synchronized(this) {
                    if (generation != captureGeneration || connection == null) return
                    val item = history[position]
                    if (position < historyPosition) {
                        if (position in pendingResponsePositions && item.response() != null) {
                            if (saveHistoryItem(item, position) != null) historyScanInserted++
                            pendingResponsePositions.remove(position)
                        }
                    } else {
                        if (item.response() == null) pendingResponsePositions.add(position)
                        else if (saveHistoryItem(item, position) != null) historyScanInserted++
                        lastHistoryId = item.id()
                        historyPosition = position + 1
                    }
                    historyScanProcessed = position + 1
                }
            }
            synchronized(this) {
                if (generation == captureGeneration) historyScanPhase = "complete"
            }
        } catch (error: Exception) {
            historyScanPhase = "error"
            needsHistoryCatchup.set(true)
            recordSaveFailure(error)
        } finally {
            if (generation == captureGeneration) scheduleResponseDrain()
        }
    }

    private fun blobPath(hash: String): Path = requireNotNull(dbPath).parent.resolve("raw/resources/mcp-server/blobs/$hash.bin")

    private fun readBlobPrefix(inline: ByteArray?, relativePath: String?, limit: Int): ByteArray = when {
        inline != null -> inline.takeBytes(limit)
        relativePath != null -> Files.newInputStream(requireNotNull(dbPath).parent.resolve(relativePath)).use { it.readNBytes(limit) }
        else -> error("Stored body has neither inline data nor a file")
    }

    private fun writeMessage(output: Path, head: ByteArray, inline: ByteArray?, relativePath: String?, project: Path) {
        Files.newOutputStream(output, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING).use { stream ->
            stream.write(head)
            stream.write("\r\n\r\n".toByteArray())
            when {
                inline != null -> stream.write(inline)
                relativePath != null -> Files.newInputStream(project.resolve(relativePath)).use { it.copyTo(stream) }
                else -> error("Stored body has neither inline data nor a file")
            }
        }
    }

    private fun syncHistory(): Pair<Int, Int> {
        val history = api.proxy().history()
        if (history.size < historyPosition || (historyPosition > 0 && history[historyPosition - 1].id() != lastHistoryId)) {
            historyPosition = 0
            lastHistoryId = null
            pendingResponsePositions.clear()
        }
        var scanned = 0
        var inserted = 0
        val pending = pendingResponsePositions.toList()
        for (position in pending) {
            if (position >= history.size) { pendingResponsePositions.remove(position); continue }
            val item = history[position]
            if (item.response() != null) {
                if (saveHistoryItem(item, position) != null) inserted++
                pendingResponsePositions.remove(position)
            }
        }
        while (historyPosition < history.size) {
            val item = history[historyPosition]
            if (item.response() == null) pendingResponsePositions.add(historyPosition)
            else if (saveHistoryItem(item, historyPosition) != null) inserted++
            lastHistoryId = item.id()
            historyPosition++
            scanned++
        }
        return scanned to inserted
    }

    private fun saveHistoryItem(item: ProxyHttpRequestResponse, position: Int): Long? = try {
        save(item.request(), item.response(), item.id(), false)
    } catch (error: Exception) {
        throw IllegalStateException(
            "Could not store Burp history item ${item.id()} at position $position: ${error.javaClass.name}: ${error.message}",
            error,
        )
    }

    private fun save(request: HttpRequest, response: HttpResponse?, burpId: Int?, sent: Boolean): Long? {
        val db = requireDb()
        val requestHead = headBytes(request.toByteArray(), request.bodyOffset())
        val responseHead = response?.let { headBytes(it.toByteArray(), it.bodyOffset()) }
        val requestBody = request.body()
        val responseBody = response?.body()
        val requestHash = hashBody(requestBody)
        val responseHash = responseBody?.let(::hashBody)
        val service = request.httpService()
        val fingerprint = packetHash(service.host(), service.port(), service.secure(), requestHead, requestHash, responseHead, responseHash)
        db.prepareStatement("SELECT id,is_sent_from_mcp FROM burp_packets WHERE fingerprint=?").use { st ->
            st.setString(1, fingerprint)
            st.executeQuery().use { rs -> if (rs.next()) {
                val existingId = rs.getLong("id")
                // A request sent through MCP may later be observed in Proxy. Keep the observed origin.
                if (!sent && rs.getInt("is_sent_from_mcp") != 0) db.prepareStatement("UPDATE burp_packets SET is_sent_from_mcp=0,burp_id=COALESCE(burp_id,?) WHERE id=?").use { update ->
                    if (burpId == null) update.setNull(1, java.sql.Types.INTEGER) else update.setInt(1, burpId)
                    update.setLong(2, existingId)
                    update.executeUpdate()
                    notifyInventoryChanged()
                }
                if (burpId != null) saveHistoryReference(db, burpId, existingId)
                return null
            } }
        }
        db.autoCommit = false
        try {
            storeBlob(db, requestBody, requestHash, request.headerValue("Content-Type"))
            if (responseBody != null && responseHash != null) storeBlob(db, responseBody, responseHash, response.headerValue("Content-Type"))
            db.prepareStatement("""
            INSERT OR IGNORE INTO burp_packets(
                fingerprint,burp_id,host,port,uses_https,method,url,path,status_code,is_sent_from_mcp,
                request_head,response_head,request_body_hash,response_body_hash,referer,captured_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, java.sql.Statement.RETURN_GENERATED_KEYS).use { st ->
                st.setString(1, fingerprint); if (burpId == null) st.setNull(2, java.sql.Types.INTEGER) else st.setInt(2, burpId)
                st.setString(3, service.host()); st.setInt(4, service.port()); st.setInt(5, if (service.secure()) 1 else 0)
                st.setString(6, request.method()); st.setString(7, request.url()); st.setString(8, request.path())
                if (response == null) st.setNull(9, java.sql.Types.INTEGER) else st.setInt(9, response.statusCode().toInt())
                st.setInt(10, if (sent) 1 else 0); st.setBytes(11, requestHead); st.setBytes(12, responseHead)
                st.setString(13, requestHash); st.setString(14, responseHash)
                st.setString(15, request.headerValue("Referer")); st.setString(16, Instant.now().toString())
                if (st.executeUpdate() == 0) {
                    db.rollback()
                    return null
                }
                val id = st.generatedKeys.use { rs -> if (rs.next()) rs.getLong(1) else null }
                if (id != null && burpId != null) saveHistoryReference(db, burpId, id)
                db.commit()
                notifyInventoryChanged()
                return id
            }
        } catch (error: Exception) {
            db.rollback()
            throw error
        } finally {
            db.autoCommit = true
        }
    }

    private fun storeBlob(db: Connection, body: BurpByteArray, hash: String, contentType: String?) {
        val size = body.length()
        val external = size > INLINE_BLOB_LIMIT
        val relativePath = if (external) "raw/resources/mcp-server/blobs/$hash.bin" else null
        db.prepareStatement("INSERT OR IGNORE INTO packet_blobs(hash,size,data,file_path) VALUES(?,?,?,?)").use { st ->
            st.setString(1, hash); st.setInt(2, size)
            st.setBytes(3, if (external) null else body.bytes)
            st.setString(4, relativePath)
            val inserted = st.executeUpdate() > 0
            if (inserted && external) writeExternalBlob(body, blobPath(hash))
            val needsIndex = inserted || db.prepareStatement(
                "SELECT 1 FROM packet_body_fts WHERE rowid=(SELECT rowid FROM packet_blobs WHERE hash=?) LIMIT 1"
            ).use { check ->
                check.setString(1, hash)
                check.executeQuery().use { !it.next() }
            }
            if (needsIndex) {
                val indexBytes = if (size == 0) byteArrayOf() else body.subArray(0, size.coerceAtMost(FTS_PREFIX_LIMIT)).bytes
                val searchText = searchableText(indexBytes, contentType)
                if (searchText != null) {
                    db.prepareStatement("INSERT INTO packet_body_fts(rowid,body_text) SELECT rowid,? FROM packet_blobs WHERE hash=? AND NOT EXISTS (SELECT 1 FROM packet_body_fts WHERE rowid=packet_blobs.rowid)").use { fts ->
                        fts.setString(1, searchText); fts.setString(2, hash); fts.executeUpdate()
                    }
                }
            }
        }
    }

    private fun writeExternalBlob(body: BurpByteArray, destination: Path) {
        Files.createDirectories(destination.parent)
        ensureResourceManifest()
        if (Files.exists(destination)) {
            require(Files.size(destination) == body.length().toLong()) { "Existing blob has unexpected size: $destination" }
            return
        }
        val temp = Files.createTempFile(destination.parent, ".packet-", ".tmp")
        try {
            Files.newOutputStream(temp).use { stream ->
                var offset = 0
                while (offset < body.length()) {
                    val end = (offset + COPY_CHUNK).coerceAtMost(body.length())
                    stream.write(body.subArray(offset, end).bytes)
                    offset = end
                }
            }
            try { moveIntoPlace(temp, destination) }
            catch (_: java.nio.file.FileAlreadyExistsException) { /* another completed copy won */ }
        } finally { Files.deleteIfExists(temp) }
    }

    private fun ensureResourceManifest() {
        val resources = requireNotNull(dbPath).parent.resolve("raw/resources")
        Files.createDirectories(resources)
        val manifest = resources.resolve("manifest.json")
        val current = if (Files.exists(manifest)) Json.parseToJsonElement(Files.readString(manifest)) as JsonObject
        else JsonObject(emptyMap())
        if ("mcp-server" in current) return
        val updated = JsonObject(current + ("mcp-server" to JsonObject(mapOf(
            "regenerable" to JsonPrimitive(false),
            "producer" to JsonPrimitive("mcp-server"),
            "note" to JsonPrimitive("Content-addressed full HTTP bodies larger than 16 MiB"),
        ))))
        val temp = Files.createTempFile(resources, ".manifest-", ".tmp")
        try {
            Files.writeString(temp, Json.encodeToString(JsonObject.serializer(), updated))
            Files.move(temp, manifest, StandardCopyOption.REPLACE_EXISTING)
        } finally { Files.deleteIfExists(temp) }
    }

    private fun initialize(db: Connection) {
        db.createStatement().use { st ->
            st.execute("""
                CREATE TABLE IF NOT EXISTS packet_blobs(
                    hash TEXT PRIMARY KEY,size INTEGER NOT NULL,data BLOB,file_path TEXT,
                    CHECK ((data IS NULL) != (file_path IS NULL))
                )
            """)
            st.execute("""
                CREATE TABLE IF NOT EXISTS burp_packets(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,fingerprint TEXT NOT NULL UNIQUE,
                    burp_id INTEGER,host TEXT NOT NULL,port INTEGER NOT NULL,uses_https INTEGER NOT NULL,
                    method TEXT NOT NULL,url TEXT NOT NULL,path TEXT NOT NULL,status_code INTEGER,
                    is_sent_from_mcp INTEGER NOT NULL,request_head BLOB NOT NULL,response_head BLOB,
                    request_body_hash TEXT NOT NULL REFERENCES packet_blobs(hash),
                    response_body_hash TEXT REFERENCES packet_blobs(hash),referer TEXT,captured_at TEXT NOT NULL
                )
            """)
            st.execute("CREATE INDEX IF NOT EXISTS idx_packets_host ON burp_packets(host)")
            st.execute("CREATE INDEX IF NOT EXISTS idx_packets_host_id ON burp_packets(host,id DESC)")
            st.execute("CREATE INDEX IF NOT EXISTS idx_packets_url ON burp_packets(url)")
            st.execute("CREATE INDEX IF NOT EXISTS idx_packets_referer ON burp_packets(referer)")
            val oldHistoryRefs = st.executeQuery("SELECT sql FROM sqlite_master WHERE type='table' AND name='packet_history_refs'").use { rs ->
                if (rs.next()) rs.getString(1) else null
            }
            if (oldHistoryRefs?.contains("history_id INTEGER PRIMARY KEY") == true) {
                st.execute("CREATE TABLE packet_history_refs_new(history_id INTEGER NOT NULL,packet_id INTEGER NOT NULL REFERENCES burp_packets(id),PRIMARY KEY(history_id,packet_id))")
                st.execute("INSERT OR IGNORE INTO packet_history_refs_new SELECT history_id,packet_id FROM packet_history_refs")
                st.execute("DROP TABLE packet_history_refs")
                st.execute("ALTER TABLE packet_history_refs_new RENAME TO packet_history_refs")
            }
            st.execute("CREATE TABLE IF NOT EXISTS packet_history_refs(history_id INTEGER NOT NULL,packet_id INTEGER NOT NULL REFERENCES burp_packets(id),PRIMARY KEY(history_id,packet_id))")
            st.execute("CREATE INDEX IF NOT EXISTS idx_history_refs_packet ON packet_history_refs(packet_id)")
            st.execute("INSERT OR IGNORE INTO packet_history_refs(history_id,packet_id) SELECT burp_id,id FROM burp_packets WHERE burp_id IS NOT NULL")
            st.execute("CREATE VIRTUAL TABLE IF NOT EXISTS packet_body_fts USING fts5(body_text,tokenize='trigram')")
            st.execute("CREATE TABLE IF NOT EXISTS capture_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            // The former Python collector left this INSERT trigger on some databases after
            // their packet table was migrated. It references columns absent from this schema
            // and makes every new Proxy response fail to save.
            st.execute("DROP TRIGGER IF EXISTS burp_fts_ai")
            db.prepareStatement("INSERT OR IGNORE INTO capture_metadata(key,value) VALUES('database_id',?)").use { insert ->
                insert.setString(1, UUID.randomUUID().toString())
                insert.executeUpdate()
            }
        }
        initializeTagSchema(db)
        initializeInventory(db)
        initializePacketChanges(db)
    }

    private fun initializeTagSchema(db: Connection) {
        db.autoCommit = false
        try {
            db.createStatement().use { st ->
                fun columns(table: String): Set<String> = st.executeQuery("PRAGMA table_info($table)").use { rows ->
                    buildSet { while (rows.next()) add(rows.getString("name")) }
                }
                val oldColumns = columns("endpoint_inspection_tags")
                val tagTableSql = st.executeQuery("SELECT sql FROM sqlite_master WHERE type='table' AND name='endpoint_inspection_tags'").use { rows ->
                    if (rows.next()) rows.getString(1) else null
                }
                if (oldColumns.isNotEmpty() && ("server_url" !in oldColumns || "'SUSPECT'" !in tagTableSql.orEmpty())) {
                    st.execute("ALTER TABLE endpoint_inspection_tags RENAME TO endpoint_inspection_tags_legacy")
                }
                st.execute("""
                    CREATE TABLE IF NOT EXISTS endpoint_inspection_tags(
                        host TEXT NOT NULL,server_url TEXT NOT NULL,method TEXT NOT NULL,path TEXT NOT NULL,
                        tag TEXT NOT NULL CHECK(tag IN ('VULN','SUSPECT','SAFE')),
                        source TEXT NOT NULL CHECK(source IN ('agent','human')),
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY(host,server_url,method,path)
                    )
                """)
                val legacyColumns = columns("endpoint_inspection_tags_legacy")
                if (legacyColumns.isNotEmpty()) {
                    val urlColumn = when {
                        "server_url" in legacyColumns -> "server_url"
                        "server_origin" in legacyColumns -> "server_origin"
                        else -> "''"
                    }
                    st.execute("""
                        INSERT OR IGNORE INTO endpoint_inspection_tags(host,server_url,method,path,tag,source,updated_at)
                        SELECT host,$urlColumn,method,path,tag,source,updated_at FROM endpoint_inspection_tags_legacy
                    """)
                    st.execute("DROP TABLE endpoint_inspection_tags_legacy")
                }
                val hasEvents = columns("endpoint_inspection_tag_events").isNotEmpty()
                st.execute("""
                    CREATE TABLE IF NOT EXISTS endpoint_inspection_tag_events(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        host TEXT NOT NULL,server_url TEXT NOT NULL,method TEXT NOT NULL,path TEXT NOT NULL,
                        old_tag TEXT,new_tag TEXT,source TEXT NOT NULL,updated_at TEXT NOT NULL
                    )
                """)
                st.execute("CREATE INDEX IF NOT EXISTS idx_tag_events_key ON endpoint_inspection_tag_events(host,server_url,method,path,id DESC)")
                if (!hasEvents) st.execute("""
                    INSERT INTO endpoint_inspection_tag_events(host,server_url,method,path,old_tag,new_tag,source,updated_at)
                    SELECT host,server_url,method,path,NULL,tag,source,updated_at FROM endpoint_inspection_tags
                """)
            }
            db.commit()
        } catch (error: Exception) {
            db.rollback()
            throw error
        } finally {
            db.autoCommit = true
        }
    }

    private fun saveHistoryReference(db: Connection, historyId: Int, packetId: Long) {
        db.prepareStatement("INSERT OR IGNORE INTO packet_history_refs(history_id,packet_id) VALUES(?,?)").use { st ->
            st.setInt(1, historyId)
            st.setLong(2, packetId)
            st.executeUpdate()
        }
    }
}

private fun normalizeTagHost(host: String): String {
    val normalized = host.trim().lowercase()
    require(normalized.length in 1..253 && normalized.matches(Regex("[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?"))) { "Invalid host" }
    return normalized
}

private fun normalizeTagServerUrl(serverUrl: String): String {
    val uri = runCatching { java.net.URI(serverUrl.trim()) }.getOrNull()
        ?: throw IllegalArgumentException("Invalid serverUrl")
    val scheme = uri.scheme?.lowercase()
    require(scheme in setOf("http", "https") && uri.host != null && uri.userInfo == null &&
        uri.rawQuery == null && uri.rawFragment == null) { "Invalid serverUrl" }
    require(uri.port == -1 || uri.port in 1..65535) { "Invalid serverUrl port" }
    val port = uri.port.takeIf { it in 1..65535 } ?: if (scheme == "https") 443 else 80
    val basePath = uri.path.orEmpty().trimEnd('/')
    return "$scheme://${uri.host.lowercase()}:$port$basePath"
}

private fun ResultSet.intOrNull(column: String): Int? = getInt(column).let { if (wasNull()) null else it }
private fun boundedMetadata(value: String): String =
    if (value.length > METADATA_TEXT_LIMIT) value.take(METADATA_TEXT_LIMIT) + "…" else value
private fun ResultSet.summary() = PacketSummary(
    getLong("id"), getString("host"), getString("method"), getString("url"), intOrNull("status_code"),
    getInt("request_size"), intOrNull("response_size"), getInt("is_sent_from_mcp") != 0,
    getString("snippet"), getInt("similar_count")
)
private fun harBodyText(rs: ResultSet, kind: String, maxBodyBytes: Int, project: Path): String? {
    val size = rs.intOrNull("${kind}_size") ?: return null
    if (size == 0 || size > maxBodyBytes) return null
    val inline = rs.getBytes("${kind}_data")
    val relative = rs.getString("${kind}_file")
    val bytes = inline ?: relative?.let { Files.readAllBytes(project.resolve(it)) } ?: return null
    require(bytes.size == size) { "Stored $kind body size does not match packet_blobs.size" }
    return try {
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString().takeIf { '\u0000' !in it }
    } catch (_: CharacterCodingException) { null }
}
private fun harHeaderLines(head: ByteArray): List<String> =
    String(head, StandardCharsets.ISO_8859_1).split(Regex("\\r?\\n")).drop(1)

private fun harHeaders(head: ByteArray) = buildJsonArray {
    harHeaderLines(head).forEach { line ->
        val separator = line.indexOf(':')
        if (separator > 0) add(buildJsonObject {
            put("name", line.substring(0, separator))
            put("value", line.substring(separator + 1).trim())
        })
    }
}
private fun harMimeType(head: ByteArray): String = harHeaderLines(head)
    .firstOrNull { it.startsWith("Content-Type:", ignoreCase = true) }
    ?.substringAfter(':')?.trim()?.substringBefore(';') ?: "application/octet-stream"

private fun responseMimeType(head: ByteArray?): String? = head?.let { bytes ->
    harHeaderLines(bytes).firstOrNull { it.startsWith("Content-Type:", ignoreCase = true) }
        ?.substringAfter(':')?.trim()?.substringBefore(';')?.takeIf(String::isNotBlank)
}

private fun harStatusText(head: ByteArray): String = String(head, StandardCharsets.ISO_8859_1)
    .lineSequence().firstOrNull()?.trimEnd('\r')?.split(' ', limit = 3)?.getOrNull(2) ?: ""

private fun ByteArray.takeBytes(max: Int) = copyOfRange(0, size.coerceAtMost(max))
private fun ByteArray.base64(): String = java.util.Base64.getEncoder().encodeToString(this)
private fun escapeLike(value: String) = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
private fun headBytes(raw: BurpByteArray, bodyOffset: Int): ByteArray {
    require(bodyOffset in 0..raw.length()) { "Invalid HTTP body offset: $bodyOffset" }
    val separatorLength = when {
        bodyOffset >= 4 && raw.subArray(bodyOffset - 4, bodyOffset).bytes.contentEquals("\r\n\r\n".toByteArray()) -> 4
        bodyOffset >= 2 && raw.subArray(bodyOffset - 2, bodyOffset).bytes.contentEquals("\n\n".toByteArray()) -> 2
        else -> 0
    }
    return raw.subArray(0, bodyOffset - separatorLength).bytes
}
private fun hashBody(body: BurpByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256")
    var offset = 0
    while (offset < body.length()) {
        val end = (offset + COPY_CHUNK).coerceAtMost(body.length())
        digest.update(body.subArray(offset, end).bytes)
        offset = end
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}
private fun packetHash(
    host: String, port: Int, secure: Boolean,
    requestHead: ByteArray, requestBodyHash: String,
    responseHead: ByteArray?, responseBodyHash: String?,
): String {
    val digest = MessageDigest.getInstance("SHA-256")
    listOf(
        host.lowercase().toByteArray(), ByteBuffer.allocate(4).putInt(port).array(),
        byteArrayOf(if (secure) 1 else 0), requestHead, requestBodyHash.toByteArray(),
        responseHead ?: byteArrayOf(), responseBodyHash?.toByteArray() ?: byteArrayOf(),
    ).forEach { part ->
        digest.update(ByteBuffer.allocate(4).putInt(part.size).array()); digest.update(part)
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}
private fun searchableText(bytes: ByteArray, contentType: String?): String? {
    if (bytes.isEmpty()) return null
    val type = contentType?.substringBefore(';')?.lowercase()?.trim()
    if (type != null && !(type.startsWith("text/") || type.contains("json") || type.contains("xml") || type.contains("javascript") || type.contains("ecmascript"))) return null
    // A bounded prefix can end in the middle of a UTF-8 code point.
    for (trim in 0..minOf(3, bytes.size - 1)) {
        try {
            val text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes, 0, bytes.size - trim)).toString()
            return if ('\u0000' in text) null else text
        } catch (_: CharacterCodingException) { /* Try without an incomplete trailing character. */ }
    }
    return null
}

private fun moveIntoPlace(source: Path, destination: Path) {
    try { Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE) }
    catch (_: java.nio.file.AtomicMoveNotSupportedException) { Files.move(source, destination) }
}
