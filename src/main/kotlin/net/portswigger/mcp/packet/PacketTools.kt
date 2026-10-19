package net.portswigger.mcp.packet

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.ProjectStorageConfig
import net.portswigger.mcp.openapi.OpenApiStore
import net.portswigger.mcp.tools.mcpTool
import java.nio.file.Files
import java.nio.file.Path

fun Server.registerPacketTools(packets: PacketRepository, storage: ProjectStorageConfig, config: McpConfig, openApiStore: OpenApiStore) {
    mcpTool<LoadProjectConfig>(
        "Load storage.db_dir and storage.openapi_dir from config.yaml. Relative paths use the config file's directory. " +
            "The Swagger viewer scans openapi_dir for host-named YAML files."
    ) {
        val loaded = storage.load(configPath)
        val connected = packets.status().databasePath
        if (connected != null && Path.of(connected).parent != loaded.databaseDirectory) packets.stop(closeDatabase = true)
        config.projectConfigPath = loaded.configPath
        Json.encodeToString(loaded)
    }
    mcpTool("get_project_storage", "Return effective DB and OpenAPI directories, config source, and capture state even when config.yaml is not loaded.") {
        val configured = storage.current()
        val capture = packets.status()
        val dbDir = configured?.dbDir ?: capture.databasePath?.let { Path.of(it).parent.toString() }
        val openapiDir = openApiStore.directoryPath()?.toString()
        Json.encodeToString(ProjectStorageStatus(
            source = when {
                configured != null -> "config.yaml"
                dbDir != null -> "projectPath"
                else -> "unconfigured"
            },
            configPath = configured?.configPath,
            dbDir = dbDir,
            openapiDir = openapiDir,
            openapiDirExists = openapiDir?.let { Files.isDirectory(Path.of(it)) } ?: false,
            databasePath = capture.databasePath,
            collecting = capture.collecting,
        ))
    }
    mcpTool<StartPacketCapture>(
        "Open or create packets.sqlite3 in the configured storage.db_dir, or in projectPath if no config is loaded. " +
            "Begin a background scan of the entire Burp proxy history, then collect new responses through Burp events. " +
            "Use get_db_info for historyScanPhase, historyScanProcessed, historyScanTotal and capture error counters. " +
            "Exact duplicate packets and identical request/response bodies are stored once."
    ) {
        val configured = storage.current()?.databaseDirectory
        val requested = projectPath?.let { Path.of(it).toRealPath() }
        require(configured == null || requested == null || configured.toRealPath() == requested) {
            "projectPath differs from storage.db_dir in config.yaml"
        }
        Json.encodeToString(packets.start((configured ?: requested
            ?: error("Load config.yaml or provide projectPath")).toString(), backgroundScan = true))
    }

    mcpTool<StopPacketCapture>(
        "Finish collecting Burp history. Stored packets remain queryable unless closeDatabase is true."
    ) { Json.encodeToString(packets.stop(closeDatabase)) }

    mcpTool("get_db_info", "Return the connected packet database path, collection state, and table columns.") {
        Json.encodeToString(packets.info())
    }
    mcpTool("get_db_schema", "Return CREATE TABLE statements for packets, blobs, full-text search, and the incrementally maintained API inventory, including body storage details.") {
        Json.encodeToString(packets.schema())
    }
    mcpTool("get_packet_count", "Return the number of unique saved HTTP packets.") {
        packets.count().toString()
    }
    mcpTool("get_all_hosts_by_db", "List distinct hosts observed in the connected packet database.") {
        Json.encodeToString(packets.hosts())
    }
    mcpTool<GetPacketDelta>(
        "Return saved packet metadata. For lossless filtered incremental reads, pass afterChangeSeq=0 initially " +
            "and then the returned lastChangeSeq on each call; this includes packets later promoted from MCP-sent " +
            "to Proxy-observed. afterId/lastId remain for legacy insertion-only readers. " +
            "Pass databaseId as expectedDatabaseId to detect a replaced DB. " +
            "Optional exact host and excludeMcpSent filters; use get_packet for bodies."
    ) { Json.encodeToString(packets.packetDelta(afterId, limit, host, excludeMcpSent, expectedDatabaseId, afterChangeSeq)) }
    mcpTool<GetApiInventory>(
        "Return a paged inventory of exact observed METHOD + path routes for one host. " +
            "Includes counts, status codes, body/query flags, sample MIME and URL, and source packet database IDs. " +
            "When writing OpenAPI, put at most 20 representative database IDs in each operation's x-burp-packet-ids, newest ID first. " +
            "Pass nextCursor unchanged for the next page; the cursor fixes route discovery to a DB packet ID and its filters. " +
            "Counts and status summaries for already discovered routes reflect the latest saved packets. " +
            "Paths are not guessed or merged into templates."
    ) { Json.encodeToString(packets.apiInventory(host, limit, cursor, excludeMcpSent)) }

    mcpTool<SearchPacket>(
        "Search saved request and response bodies with SQLite FTS5. Returns packet metadata and short snippets; " +
            "use get_packet or save_packets for complete bodies. targets: request_body, response_body."
    ) {
        Json.encodeToString(packets.search(ftsSearchQuery, targets, hosts, url, httpMethod, statusCode,
            excludeMcpSent, groupSimilar, limit, offset))
    }

    mcpTool<GetPacket>(
        "Get a saved packet by database id. Headers are returned as text and bounded bodies as base64; " +
            "use save_packets to export complete bodies."
    ) { Json.encodeToString(packets.getPacket(packetId, maxBodyBytes)) }

    mcpTool<SavePackets>(
        "Export complete saved HTTP request and response messages as raw files under saveDir. " +
            "Files are named by packet database id."
    ) { Json.encodeToString(packets.savePackets(packetIds, saveDir)) }

    mcpTool<ExportPacketsHar>(
        "Export a bounded page of stored packets to a local HAR file compatible with mitmproxy2swagger. " +
            "Filter by exact host and continue with lastId as afterId while hasMore is true. " +
            "Bodies larger than maxBodyBytes or invalid UTF-8 are omitted, and counters report omissions. " +
            "The HAR can contain credentials and personal data; keep it local and review before sharing."
    ) { Json.encodeToString(packets.exportHar(outputPath, host, afterId, limit, maxBodyBytes, excludeMcpSent)) }

    mcpTool<GetRefererOf>("Find Referer page URLs for saved requests whose URL contains url.") {
        Json.encodeToString(packets.referersOf(url, distinct, limit))
    }
    mcpTool<FindPacketsByReferer>("Find saved endpoints called by a page, matched against the request Referer header.") {
        Json.encodeToString(packets.packetsByReferer(referer, match, distinct, limit))
    }
    mcpTool<QueryBurpDatabase>(
        "Execute a single read-only SELECT query on the connected SQLite packet database. " +
            "Results are paginated by maxRows and offset; the response includes hasMore and nextOffset. " +
            "Use a stable ORDER BY (for example, ORDER BY id) when fetching multiple pages. " +
            "Rows, field lengths, and execution time are bounded; BLOB values are represented as strings."
    ) { Json.encodeToString(packets.querySelect(query, maxRows, offset)) }
}

@Serializable data class LoadProjectConfig(val configPath: String)
@Serializable data class ProjectStorageStatus(
    val source: String,
    val configPath: String?,
    val dbDir: String?,
    val openapiDir: String?,
    val openapiDirExists: Boolean,
    val databasePath: String?,
    val collecting: Boolean,
)
@Serializable data class StartPacketCapture(val projectPath: String? = null)
@Serializable data class StopPacketCapture(val closeDatabase: Boolean = false)
@Serializable data class GetPacketDelta(
    val afterId: Long = 0,
    val afterChangeSeq: Long? = null,
    val limit: Int = 100,
    val host: String? = null,
    val excludeMcpSent: Boolean = false,
    val expectedDatabaseId: String? = null,
)
@Serializable data class GetApiInventory(
    val host: String,
    val limit: Int = 100,
    val cursor: String? = null,
    val excludeMcpSent: Boolean = false,
)
@Serializable data class SearchPacket(
    val targets: List<String>,
    val ftsSearchQuery: String,
    val hosts: List<String> = emptyList(),
    val url: String? = null,
    val httpMethod: String? = null,
    val statusCode: Int? = null,
    val excludeMcpSent: Boolean = false,
    val groupSimilar: Boolean = true,
    val limit: Int = 30,
    val offset: Int = 0,
)
@Serializable data class GetPacket(val packetId: Long, val maxBodyBytes: Int = 65_536)
@Serializable data class SavePackets(val packetIds: List<Long>, val saveDir: String)
@Serializable data class ExportPacketsHar(
    val outputPath: String,
    val host: String? = null,
    val afterId: Long = 0,
    val limit: Int = 1000,
    val maxBodyBytes: Int = 1_048_576,
    val excludeMcpSent: Boolean = false,
)
@Serializable data class GetRefererOf(val url: String, val distinct: Boolean = true, val limit: Int = 100)
@Serializable data class FindPacketsByReferer(
    val referer: String, val match: String = "prefix", val distinct: Boolean = true, val limit: Int = 100,
)
@Serializable data class QueryBurpDatabase(val query: String, val maxRows: Int = 100, val offset: Int = 0)
