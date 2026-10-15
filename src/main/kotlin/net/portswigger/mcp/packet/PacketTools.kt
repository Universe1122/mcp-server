package net.portswigger.mcp.packet

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.tools.mcpTool

fun Server.registerPacketTools(packets: PacketRepository) {
    mcpTool<StartPacketCapture>(
        "Open or create packets.sqlite3 inside projectPath, rescan the entire current Burp proxy history, " +
            "then keep collecting new traffic. Exact duplicate packets and identical request/response bodies are stored once."
    ) { Json.encodeToString(packets.start(projectPath)) }

    mcpTool<StopPacketCapture>(
        "Finish collecting Burp history. Stored packets remain queryable unless closeDatabase is true."
    ) { Json.encodeToString(packets.stop(closeDatabase)) }

    mcpTool("get_db_info", "Return the connected packet database path, collection state, and table columns.") {
        Json.encodeToString(packets.info())
    }
    mcpTool("get_packet_count", "Return the number of unique saved HTTP packets.") {
        packets.count().toString()
    }
    mcpTool("get_all_hosts_by_db", "List distinct hosts observed in the connected packet database.") {
        Json.encodeToString(packets.hosts())
    }

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

    mcpTool<GetRefererOf>("Find Referer page URLs for saved requests whose URL contains url.") {
        Json.encodeToString(packets.referersOf(url, distinct, limit))
    }
    mcpTool<FindPacketsByReferer>("Find saved endpoints called by a page, matched against the request Referer header.") {
        Json.encodeToString(packets.packetsByReferer(referer, match, distinct, limit))
    }
    mcpTool<QueryBurpDatabase>(
        "Execute a single read-only SELECT query on the connected SQLite packet database. " +
            "Rows and execution time are bounded; BLOB values are represented as strings."
    ) { Json.encodeToString(packets.querySelect(query, maxRows)) }
}

@Serializable data class StartPacketCapture(val projectPath: String)
@Serializable data class StopPacketCapture(val closeDatabase: Boolean = false)
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
@Serializable data class GetRefererOf(val url: String, val distinct: Boolean = true, val limit: Int = 100)
@Serializable data class FindPacketsByReferer(
    val referer: String, val match: String = "prefix", val distinct: Boolean = true, val limit: Int = 100,
)
@Serializable data class QueryBurpDatabase(val query: String, val maxRows: Int = 100)
