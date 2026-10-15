package net.portswigger.mcp.packet

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
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
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

private const val DATABASE_FILE = "packets.sqlite3"
private const val INLINE_BLOB_LIMIT = 16 * 1024 * 1024
private const val FTS_PREFIX_LIMIT = 4 * 1024 * 1024
private const val COPY_CHUNK = 262_144

@Serializable
data class CaptureStatus(
    val databasePath: String?,
    val collecting: Boolean,
    val packetCount: Long,
    val historyPosition: Int,
    val scanned: Int = 0,
    val inserted: Int = 0,
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

@Serializable
data class PacketDetail(
    val id: Long,
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

/** One database connection and one collector belong to the Burp extension, not to an MCP client. */
class PacketRepository(private val api: MontoyaApi) : AutoCloseable {
    private val executor = Executors.newSingleThreadScheduledExecutor { work ->
        Thread(work, "burp-mcp-packet-collector").apply { isDaemon = true }
    }
    private var future: ScheduledFuture<*>? = null
    private var connection: Connection? = null
    private var dbPath: Path? = null
    private var historyPosition = 0
    private var lastHistoryId: Int? = null
    private val pendingResponsePositions = mutableSetOf<Int>()

    @Synchronized
    fun start(projectPath: String): CaptureStatus {
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
            // Every connection deliberately scans Burp history from the beginning.
            val scanned = syncHistory()
            future = executor.scheduleWithFixedDelay({
                try { synchronized(this) { if (connection != null) syncHistory() } }
                catch (error: Exception) { api.logging().logToError(error) }
            }, 5, 5, TimeUnit.SECONDS)
            return status(scanned.first, scanned.second)
        } catch (error: Exception) {
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
                historyPosition = 0
                lastHistoryId = null
                pendingResponsePositions.clear()
            }
        }
    }

    @Synchronized
    fun status(scanned: Int = 0, inserted: Int = 0): CaptureStatus = CaptureStatus(
        dbPath?.toString(), future?.isCancelled == false, count(), historyPosition, scanned, inserted
    )

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
        val tables = listOf("burp_packets", "packet_blobs", "packet_body_fts").associateWith { name ->
            db.createStatement().use { st ->
                st.executeQuery("PRAGMA table_info($name)").use { rs ->
                    buildList { while (rs.next()) add(rs.getString("name")) }
                }
            }
        }
        return DatabaseInfo(status(), tables)
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
    fun hosts(): List<String> {
        val db = requireDb()
        db.createStatement().use { st ->
            st.executeQuery("SELECT DISTINCT host FROM burp_packets ORDER BY host").use { rs ->
                return buildList { while (rs.next()) add(rs.getString(1)) }
            }
        }
    }

    @Synchronized
    fun search(
        query: String, targets: List<String>, hosts: List<String>, url: String?, method: String?,
        statusCode: Int?, excludeMcpSent: Boolean, groupSimilar: Boolean, limit: Int, offset: Int,
    ): List<PacketSummary> {
        require(query.isNotBlank()) { "ftsSearchQuery is required" }
        require(targets.isNotEmpty() && targets.all { it == "request_body" || it == "response_body" }) {
            "targets must contain request_body or response_body"
        }
        require(limit in 1..500 && offset >= 0) { "limit must be 1..500 and offset non-negative" }
        val db = requireDb()
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
        db.prepareStatement(sql).use { st ->
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

    @Synchronized
    fun querySelect(query: String, maxRows: Int): List<Map<String, String?>> {
        require(maxRows in 1..500) { "maxRows must be between 1 and 500" }
        require(Regex("(?is)^\\s*select\\b").containsMatchIn(query) && !query.contains(';')) {
            "Only a single SELECT statement is allowed"
        }
        val path = dbPath ?: error("Packet database is not connected")
        DriverManager.getConnection("jdbc:sqlite:file:${path.toUri().rawPath}?mode=ro").use { reader ->
            reader.createStatement().use { st ->
                st.queryTimeout = 5
                st.maxRows = maxRows
                st.maxFieldSize = 4096
                st.executeQuery(query).use { rs ->
                    val metadata = rs.metaData
                    return buildList {
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
                }
            }
        }
    }

    @Synchronized
    fun savePackets(ids: List<Long>, directory: String): List<Map<String, String>> {
        require(ids.isNotEmpty() && ids.size <= 100) { "packetIds must contain 1..100 ids" }
        val target = Path.of(directory).toAbsolutePath().normalize()
        Files.createDirectories(target)
        val db = requireDb()
        return ids.map { id ->
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
                    writeMessage(requestFile, rs.getBytes("request_head"), rs.getBytes("request_body"), rs.getString("request_body_path"))
                    val responseFile = rs.getBytes("response_head")?.let { head ->
                        target.resolve("$id.response.raw").also {
                            writeMessage(it, head, rs.getBytes("response_body"), rs.getString("response_body_path"))
                        }
                    }
                    mapOf("packetId" to id.toString(), "requestPath" to requestFile.toString(), "responsePath" to (responseFile?.toString() ?: ""))
                }
            }
        }
    }

    @Synchronized
    override fun close() {
        stopCollection()
        connection?.close()
        connection = null
        dbPath = null
        executor.shutdownNow()
    }

    private fun stopCollection() { future?.cancel(false); future = null }
    private fun requireDb(): Connection = connection ?: error("Packet database is not connected; call start_packet_capture first")

    private fun blobPath(hash: String): Path = requireNotNull(dbPath).parent.resolve("raw/resources/mcp-server/blobs/$hash.bin")

    private fun readBlobPrefix(inline: ByteArray?, relativePath: String?, limit: Int): ByteArray = when {
        inline != null -> inline.takeBytes(limit)
        relativePath != null -> Files.newInputStream(requireNotNull(dbPath).parent.resolve(relativePath)).use { it.readNBytes(limit) }
        else -> error("Stored body has neither inline data nor a file")
    }

    private fun writeMessage(output: Path, head: ByteArray, inline: ByteArray?, relativePath: String?) {
        Files.newOutputStream(output, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING).use { stream ->
            stream.write(head)
            stream.write("\r\n\r\n".toByteArray())
            when {
                inline != null -> stream.write(inline)
                relativePath != null -> Files.newInputStream(requireNotNull(dbPath).parent.resolve(relativePath)).use { it.copyTo(stream) }
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
        db.prepareStatement("SELECT id FROM burp_packets WHERE fingerprint=?").use { st ->
            st.setString(1, fingerprint)
            st.executeQuery().use { rs -> if (rs.next()) {
                // A request sent through MCP may later be observed in Proxy. Keep the observed origin.
                if (!sent) db.prepareStatement("UPDATE burp_packets SET is_sent_from_mcp=0,burp_id=COALESCE(burp_id,?) WHERE id=?").use { update ->
                    if (burpId == null) update.setNull(1, java.sql.Types.INTEGER) else update.setInt(1, burpId)
                    update.setLong(2, rs.getLong(1))
                    update.executeUpdate()
                }
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
                db.commit()
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
            st.execute("CREATE INDEX IF NOT EXISTS idx_packets_url ON burp_packets(url)")
            st.execute("CREATE INDEX IF NOT EXISTS idx_packets_referer ON burp_packets(referer)")
            st.execute("CREATE VIRTUAL TABLE IF NOT EXISTS packet_body_fts USING fts5(body_text,tokenize='trigram')")
        }
    }
}

private fun ResultSet.intOrNull(column: String): Int? = getInt(column).let { if (wasNull()) null else it }
private fun ResultSet.summary() = PacketSummary(
    getLong("id"), getString("host"), getString("method"), getString("url"), intOrNull("status_code"),
    getInt("request_size"), intOrNull("response_size"), getInt("is_sent_from_mcp") != 0,
    getString("snippet"), getInt("similar_count")
)
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
