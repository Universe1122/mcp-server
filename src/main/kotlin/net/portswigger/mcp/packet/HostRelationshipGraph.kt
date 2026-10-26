package net.portswigger.mcp.packet

import java.net.URI
import java.nio.charset.StandardCharsets
import java.sql.Connection

data class HostGraphNode(val origin: String, val packetCount: Int, val observed: Boolean)

data class HostGraphEdge(
    val source: String,
    val target: String,
    val kind: String,
    val packetCount: Int,
    val latestPacketId: Long,
)

data class HostGraphSnapshot(
    val nodes: List<HostGraphNode>,
    val edges: List<HostGraphEdge>,
    val sampledPackets: Int,
    val sampleLimit: Int,
    val demo: Boolean = false,
)

private data class EdgeKey(val source: String, val target: String, val kind: String)
private data class EdgeCount(var count: Int, var latestId: Long)

/** A bounded, passive preview of cross-origin relations in the saved traffic. */
internal fun readHostRelationshipGraph(db: Connection, sampleLimit: Int = 5_000): HostGraphSnapshot {
    require(sampleLimit in 1..20_000)
    val packetCounts = mutableMapOf<String, Int>()
    val edgeCounts = mutableMapOf<EdgeKey, EdgeCount>()
    var sampled = 0
    db.prepareStatement("""
        SELECT id,host,port,uses_https,url,referer,status_code,response_head
        FROM burp_packets ORDER BY id DESC LIMIT ?
    """).use { statement ->
        statement.setInt(1, sampleLimit)
        statement.executeQuery().use { rows ->
            while (rows.next()) {
                sampled++
                val origin = "${if (rows.getInt("uses_https") != 0) "https" else "http"}://${rows.getString("host").lowercase()}:${rows.getInt("port")}"
                packetCounts[origin] = packetCounts.getOrDefault(origin, 0) + 1
                val packetId = rows.getLong("id")
                fun add(source: String?, target: String?, kind: String) {
                    if (source == null || target == null || source == target) return
                    val key = EdgeKey(source, target, kind)
                    val value = edgeCounts.getOrPut(key) { EdgeCount(0, packetId) }
                    value.count++
                    value.latestId = maxOf(value.latestId, packetId)
                }
                add(httpOrigin(rows.getString("referer")), origin, "Referer")
                val status = rows.getInt("status_code")
                if (status in 300..399) {
                    val header = rows.getBytes("response_head")?.toString(StandardCharsets.ISO_8859_1)
                    val location = header?.lineSequence()?.firstOrNull { it.startsWith("Location:", ignoreCase = true) }
                        ?.substringAfter(':')?.trim()
                    val target = location?.let { value -> runCatching {
                        URI(rows.getString("url")).resolve(value).toString()
                    }.getOrNull() }
                    add(origin, httpOrigin(target), "Redirect")
                }
            }
        }
    }
    val degree = mutableMapOf<String, Int>()
    edgeCounts.forEach { (key, value) ->
        degree[key.source] = degree.getOrDefault(key.source, 0) + value.count
        degree[key.target] = degree.getOrDefault(key.target, 0) + value.count
    }
    val selected = (packetCounts.keys + degree.keys).distinct()
        .sortedWith(compareByDescending<String> { degree.getOrDefault(it, 0) }
            .thenByDescending { packetCounts.getOrDefault(it, 0) }.thenBy { it })
        .take(12).toSet()
    val nodes = selected.map { HostGraphNode(it, packetCounts.getOrDefault(it, 0), it in packetCounts) }
        .sortedWith(compareByDescending<HostGraphNode> { it.packetCount }.thenBy { it.origin })
    val edges = edgeCounts.entries.asSequence()
        .filter { it.key.source in selected && it.key.target in selected }
        .map { (key, value) -> HostGraphEdge(key.source, key.target, key.kind, value.count, value.latestId) }
        .sortedWith(compareByDescending<HostGraphEdge> { it.packetCount }.thenBy { it.source }.thenBy { it.target })
        .take(18).toList()
    return HostGraphSnapshot(nodes, edges, sampled, sampleLimit)
}

private fun httpOrigin(url: String?): String? {
    val uri = url?.let { runCatching { URI(it.trim()) }.getOrNull() } ?: return null
    val scheme = uri.scheme?.lowercase()
    if (scheme !in setOf("http", "https") || uri.host == null || uri.userInfo != null) return null
    val port = uri.port.takeIf { it in 1..65535 } ?: if (scheme == "https") 443 else 80
    return "$scheme://${uri.host.lowercase()}:$port"
}

internal fun demoHostRelationshipGraph(): HostGraphSnapshot = HostGraphSnapshot(
    nodes = listOf(
        HostGraphNode("https://shop.example.test:443", 248, true),
        HostGraphNode("https://api.example.test:443", 176, true),
        HostGraphNode("https://auth.example.test:443", 32, true),
        HostGraphNode("https://cdn.example.test:443", 84, true),
        HostGraphNode("https://search.example.test:443", 71, true),
        HostGraphNode("https://account.example.test:443", 53, true),
        HostGraphNode("https://static.example.test:443", 40, true),
        HostGraphNode("https://payments.example.test:443", 26, true),
    ),
    edges = listOf(
        HostGraphEdge("https://shop.example.test:443", "https://api.example.test:443", "Referer", 128, 114),
        HostGraphEdge("https://shop.example.test:443", "https://auth.example.test:443", "Redirect", 4, 87),
        HostGraphEdge("https://shop.example.test:443", "https://cdn.example.test:443", "Referer", 65, 102),
        HostGraphEdge("https://shop.example.test:443", "https://search.example.test:443", "Referer", 38, 121),
        HostGraphEdge("https://shop.example.test:443", "https://static.example.test:443", "Referer", 29, 105),
        HostGraphEdge("https://api.example.test:443", "https://account.example.test:443", "Referer", 31, 110),
        HostGraphEdge("https://api.example.test:443", "https://payments.example.test:443", "Redirect", 6, 92),
        HostGraphEdge("https://auth.example.test:443", "https://account.example.test:443", "Redirect", 8, 116),
        HostGraphEdge("https://cdn.example.test:443", "https://static.example.test:443", "Redirect", 3, 99),
        HostGraphEdge("https://search.example.test:443", "https://api.example.test:443", "Referer", 17, 119),
    ),
    sampledPackets = 730,
    sampleLimit = 5_000,
    demo = true,
)
