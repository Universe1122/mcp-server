package net.portswigger.mcp.packet

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.sql.DriverManager

class HostRelationshipGraphTest {
    @Test
    fun `saved referers and redirects create distinct evidenced origins`() {
        DriverManager.getConnection("jdbc:sqlite::memory:").use { db ->
            db.createStatement().use { it.execute("""
                CREATE TABLE burp_packets(
                    id INTEGER PRIMARY KEY,host TEXT,port INTEGER,uses_https INTEGER,url TEXT,
                    referer TEXT,status_code INTEGER,response_head BLOB
                )
            """) }
            fun insert(id: Int, host: String, url: String, referer: String?, status: Int, response: String?) {
                db.prepareStatement("INSERT INTO burp_packets VALUES(?,?,?,?,?,?,?,?)").use { st ->
                    st.setInt(1, id); st.setString(2, host); st.setInt(3, 443); st.setInt(4, 1)
                    st.setString(5, url); st.setString(6, referer); st.setInt(7, status)
                    st.setBytes(8, response?.toByteArray(StandardCharsets.ISO_8859_1))
                    st.executeUpdate()
                }
            }
            insert(1, "shop.example.test", "https://shop.example.test/login", null, 302,
                "HTTP/1.1 302 Found\r\nLocation: https://auth.example.test/signin\r\n")
            insert(2, "api.example.test", "https://api.example.test/items", "https://shop.example.test/home", 200, null)
            insert(3, "api.example.test", "https://api.example.test/items", "https://api.example.test/items", 200, null)
            val graph = readHostRelationshipGraph(db)
            assertEquals(3, graph.sampledPackets)
            assertEquals(3, graph.nodes.size)
            assertEquals(2, graph.edges.size)
            assertTrue(graph.edges.any { it.source == "https://shop.example.test:443" &&
                it.target == "https://api.example.test:443" && it.kind == "Referer" && it.latestPacketId == 2L })
            assertTrue(graph.edges.any { it.source == "https://shop.example.test:443" &&
                it.target == "https://auth.example.test:443" && it.kind == "Redirect" && it.latestPacketId == 1L })
            assertFalse(graph.edges.any { it.source == it.target })
        }
    }
}
