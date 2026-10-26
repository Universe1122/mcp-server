package net.portswigger.mcp.packet

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpBytes
import burp.api.montoya.core.Registration
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyResponseHandler
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.sql.DriverManager
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class PacketRepositoryTest {
    @Test
    fun `Swagger packet search finds URL headers and body with keyset paging`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns listOf(
            item(10, "X-Search: crimson\r\n", path = "/items?filter=needle"),
            item(11, "", path = "/alpha"),
        )
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            val url = packets.searchSwaggerPackets("example.com", "needle")
            assertEquals(listOf(10), url.hits.map { it.historyId })
            assertEquals("URL", url.hits.single().location)
            val header = packets.searchSwaggerPackets("example.com", "crimson").hits.single()
            assertEquals("Request headers", header.location)
            assertTrue(header.snippet.contains("X-Search: crimson"))
            val first = packets.searchSwaggerPackets("example.com", "alpha", limit = 1)
            assertEquals(11, first.hits.single().historyId)
            assertTrue(first.hasMore)
            val second = packets.searchSwaggerPackets("example.com", "alpha", beforeId = first.nextBeforeId!!, limit = 1)
            assertEquals(10, second.hits.single().historyId)
            assertEquals("Response body", second.hits.single().location)
            assertFalse(second.hasMore)
            assertTrue(packets.searchSwaggerPackets("other.example", "alpha").hits.isEmpty())
        }
    }

    @Test
    fun `Swagger search and endpoint tags distinguish ports`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns listOf(
            item(20, "X-Match: portneedle\r\n", path = "/items", port = 443),
            item(21, "X-Match: portneedle\r\n", path = "/items", port = 12345),
        )
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            assertEquals(listOf(20), packets.searchSwaggerPackets("example.com", "portneedle",
                port = 443, usesHttps = true).hits.mapNotNull { it.historyId })
            assertEquals(listOf(21), packets.searchSwaggerPackets("example.com", "portneedle",
                port = 12345, usesHttps = true).hits.mapNotNull { it.historyId })
            val packetIds = packets.searchSwaggerPackets("example.com", "portneedle").hits.map { it.packetId }
            assertEquals(1, packets.packetUrlsForServer(packetIds, "example.com", 12345, true).size)
            packets.setEndpointInspectionTag("example.com", "GET", "/items", "SAFE", "human", "https://example.com:443")
            packets.setEndpointInspectionTag("example.com", "GET", "/items", "VULN", "human", "https://example.com:12345")
            assertEquals("SAFE", packets.endpointInspectionTags("example.com", "https://example.com:443").single().tag)
            assertEquals("VULN", packets.endpointInspectionTags("example.com", "https://example.com:12345").single().tag)
            packets.setEndpointInspectionTag("example.com", "GET", "/items", "VULN", "agent", "https://example.com/v1")
            packets.setEndpointInspectionTag("example.com", "GET", "/items", "SAFE", "agent", "https://example.com/v2/")
            assertEquals("VULN", packets.endpointInspectionTags("example.com", "https://example.com:443/v1").single().tag)
            assertEquals("SAFE", packets.endpointInspectionTags("example.com", "https://example.com/v2").single().tag)
            assertEquals(4, packets.endpointInspectionTags("example.com").size)
        }
    }

    @Test
    fun `legacy endpoint tags migrate without losing decisions`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns emptyList()
        PacketRepository(api).use { it.start(project.toString()); it.stop(closeDatabase = true) }
        DriverManager.getConnection("jdbc:sqlite:${project.resolve("packets.sqlite3")}").use { db ->
            db.createStatement().use { st ->
                st.execute("DROP TABLE endpoint_inspection_tags")
                st.execute("DROP TABLE endpoint_inspection_tag_events")
                st.execute("CREATE TABLE endpoint_inspection_tags(host TEXT NOT NULL,method TEXT NOT NULL,path TEXT NOT NULL,tag TEXT NOT NULL,source TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(host,method,path))")
                st.execute("INSERT INTO endpoint_inspection_tags VALUES('example.com','GET','/items','SAFE','human','2026-01-01')")
            }
        }
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            val tag = packets.endpointInspectionTags("example.com").single()
            assertEquals("SAFE", tag.tag)
            assertEquals("", tag.serverUrl)
            assertTrue(packets.endpointInspectionTags("example.com", "https://example.com:12345").isEmpty())
        }
    }

    @Test
    fun `origin tags migrate to root server without applying to base paths`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns emptyList()
        PacketRepository(api).use { it.start(project.toString()); it.stop(closeDatabase = true) }
        DriverManager.getConnection("jdbc:sqlite:${project.resolve("packets.sqlite3")}").use { db ->
            db.createStatement().use { st ->
                st.execute("DROP TABLE endpoint_inspection_tags")
                st.execute("DROP TABLE endpoint_inspection_tag_events")
                st.execute("CREATE TABLE endpoint_inspection_tags(host TEXT NOT NULL,server_origin TEXT NOT NULL,method TEXT NOT NULL,path TEXT NOT NULL,tag TEXT NOT NULL,source TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(host,server_origin,method,path))")
                st.execute("INSERT INTO endpoint_inspection_tags VALUES('example.com','https://example.com:443','GET','/items','VULN','agent','2026-01-01')")
            }
        }
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            assertEquals("VULN", packets.endpointInspectionTags("example.com", "https://example.com").single().tag)
            assertTrue(packets.endpointInspectionTags("example.com", "https://example.com/v1").isEmpty())
            val baseline = packets.endpointTagHistory("example.com", "https://example.com", "GET", "/items").single()
            assertEquals(null, baseline.oldTag)
            assertEquals("VULN", baseline.newTag)
        }
    }

    @Test
    fun `two tag schema migrates and accepts SUSPECT without losing history`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns emptyList()
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            packets.setEndpointInspectionTag("example.com", "GET", "/items", "VULN", "agent", "https://example.com/v1")
            packets.stop(closeDatabase = true)
        }
        DriverManager.getConnection("jdbc:sqlite:${project.resolve("packets.sqlite3")}").use { db ->
            db.createStatement().use { st ->
                st.execute("ALTER TABLE endpoint_inspection_tags RENAME TO endpoint_inspection_tags_previous")
                st.execute("CREATE TABLE endpoint_inspection_tags(host TEXT NOT NULL,server_url TEXT NOT NULL,method TEXT NOT NULL,path TEXT NOT NULL,tag TEXT NOT NULL CHECK(tag IN ('VULN','SAFE')),source TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(host,server_url,method,path))")
                st.execute("INSERT INTO endpoint_inspection_tags SELECT * FROM endpoint_inspection_tags_previous")
                st.execute("DROP TABLE endpoint_inspection_tags_previous")
            }
        }
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            assertEquals("VULN", packets.endpointInspectionTags("example.com", "https://example.com/v1").single().tag)
            packets.setEndpointInspectionTag("example.com", "GET", "/items", "SUSPECT", "human", "https://example.com/v1")
            assertEquals("SUSPECT", packets.endpointInspectionTags("example.com", "https://example.com/v1").single().tag)
            assertEquals(listOf("VULN" to "SUSPECT", null to "VULN"),
                packets.endpointTagHistory("example.com", "https://example.com/v1", "GET", "/items").map { it.oldTag to it.newTag })
        }
    }

    @Test
    fun `endpoint inspection tags survive database reconnection and can be revised`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns emptyList()
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            val first = packets.setEndpointInspectionTag("Example.COM", "get", "/v1/users/{id}", "VULN", "agent", "https://example.com/v1")!!
            assertEquals("example.com", first.host)
            assertEquals("GET", first.method)
            packets.start(project.toString())
            assertEquals("VULN", packets.endpointInspectionTags("example.com").single().tag)
            packets.setEndpointInspectionTag("example.com", "GET", "/v1/users/{id}", "SUSPECT", "agent", "https://example.com/v1")
            assertEquals("SUSPECT", packets.endpointInspectionTags("example.com").single().tag)
            packets.setEndpointInspectionTag("example.com", "GET", "/v1/users/{id}", "SAFE", "human", "https://example.com/v1")
            assertEquals("human", packets.endpointInspectionTags("example.com").single().source)
            packets.setEndpointInspectionTag("example.com", "GET", "/v1/users/{id}", null, "human", "https://example.com/v1")
            assertTrue(packets.endpointInspectionTags("example.com").isEmpty())
            val events = packets.endpointTagHistory("example.com", "https://example.com/v1", "GET", "/v1/users/{id}")
            assertEquals(listOf("SAFE" to null, "SUSPECT" to "SAFE", "VULN" to "SUSPECT", null to "VULN"), events.map { it.oldTag to it.newTag })
            assertEquals(listOf("human", "human", "agent", "agent"), events.map { it.source })
        }
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            assertTrue(packets.endpointInspectionTags("example.com").isEmpty())
            assertTrue(packets.schema().createStatements.containsKey("endpoint_inspection_tags"))
            assertEquals(4, packets.endpointTagHistory("example.com", "https://example.com/v1", "GET", "/v1/users/{id}").size)
        }
    }

    @Test
    fun `schema and paged HAR export expose stored packets`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns listOf(item(10, ""), item(11, "X-Variant: second\r\n"))

        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            val schema = packets.schema()
            assertTrue(schema.createStatements.getValue("burp_packets").contains("request_body_hash"))
            assertTrue(schema.createStatements.getValue("packet_blobs").contains("file_path"))

            val firstPath = project.resolve("first.har")
            val first = packets.exportHar(firstPath.toString(), "example.com", 0, 1, 1024, false)
            assertEquals(1, first.exported)
            assertEquals(1L, first.lastId)
            assertTrue(first.hasMore)
            val entry = Json.parseToJsonElement(Files.readString(firstPath)).jsonObject
                .getValue("log").jsonObject.getValue("entries").jsonArray.single().jsonObject
            assertEquals("GET", entry.getValue("request").jsonObject.getValue("method").jsonPrimitive.content)
            assertEquals("{\"token\":\"alpha\"}", entry.getValue("response").jsonObject
                .getValue("content").jsonObject.getValue("text").jsonPrimitive.content)

            val second = packets.exportHar(project.resolve("second.har").toString(), null, first.lastId!!, 1, 0, false)
            assertEquals(1, second.exported)
            assertFalse(second.hasMore)
            assertEquals(1, second.skippedResponseBodies)
            assertThrows(IllegalArgumentException::class.java) {
                packets.exportHar(firstPath.toString(), null, 0, 1, 1024, false)
            }
        }
    }

    @Test
    fun `rescan skips exact packets and stores identical bodies once`(@TempDir project: Path) {
        val first = item(10, "")
        val second = item(11, "X-Variant: second\r\n")
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns listOf(first, second)

        PacketRepository(api).use { packets ->
            val firstStart = packets.start(project.toString())
            assertEquals(2, firstStart.scanned)
            assertEquals(2, firstStart.inserted)
            assertEquals(2, packets.count())
            assertEquals(2, packets.querySelect("SELECT count(*) AS n FROM packet_blobs", 10).rows.single().getValue("n")?.toInt())

            val firstPage = packets.querySelect("SELECT id, method FROM burp_packets ORDER BY id", 1)
            assertEquals(listOf("1"), firstPage.rows.map { it.getValue("id") })
            assertTrue(firstPage.hasMore)
            assertEquals(1, firstPage.nextOffset)

            val secondPage = packets.querySelect("SELECT id, method FROM burp_packets ORDER BY id", 1, firstPage.nextOffset!!)
            assertEquals(listOf("2"), secondPage.rows.map { it.getValue("id") })
            assertFalse(secondPage.hasMore)
            assertNull(secondPage.nextOffset)
            assertTrue(packets.querySelect("SELECT id FROM burp_packets ORDER BY id", 1, 2).rows.isEmpty())
            assertThrows(IllegalArgumentException::class.java) {
                packets.querySelect("SELECT id FROM burp_packets", 1, -1)
            }

            val matches = packets.search("alpha", listOf("response_body"), emptyList(), null, null, null, false, true, 30, 0)
            assertEquals(1, matches.size)
            assertEquals(2, matches.first().similarCount)
            assertTrue(matches.all { it.snippet?.contains("<<<") == true }, matches.toString())
            val detail = packets.getPacket(matches.first().id)
            assertNotNull(detail)
            assertEquals("{\"token\":\"alpha\"}", String(java.util.Base64.getDecoder().decode(detail!!.responseBodyBase64)))

            val secondStart = packets.start(project.toString())
            assertEquals(2, secondStart.scanned)
            assertEquals(0, secondStart.inserted)
            assertEquals(2, packets.count())
            assertEquals(2L, packets.apiInventory("example.com", 10, null, false).routes.single().packetCount)

            val exports = packets.savePackets(listOf(matches.first().id), project.resolve("export").toString())
            val savedResponse = Path.of(exports.first().getValue("responsePath"))
            assertArrayEquals(responseRaw, Files.readAllBytes(savedResponse))
        }
    }

    @Test
    fun `duplicate history entries retain distinct history references`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns listOf(item(0, ""), item(11, ""))
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            assertEquals(1, packets.count())
            assertEquals(1L, packets.getPacketByHistoryId(0, 1)?.id)
            assertEquals(11, packets.getPacketByHistoryId(11, 1)?.burpHistoryId)
            assertNull(packets.getPacketByHistoryId(0, 2))
            assertEquals(2, packets.querySelect("SELECT history_id FROM packet_history_refs ORDER BY history_id", 10).rows.size)
        }
    }

    @Test
    fun `reused Burp history number keeps both packet mappings`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns listOf(item(10, ""), item(10, "X-Variant: second\r\n"))
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            assertEquals(2, packets.count())
            assertEquals(1L, packets.getPacketByHistoryId(10, 1)?.id)
            assertEquals(2L, packets.getPacketByHistoryId(10, 2)?.id)
            assertEquals(2, packets.querySelect("SELECT packet_id FROM packet_history_refs WHERE history_id=10", 10).rows.size)
        }
    }

    @Test
    fun `switching database rescans history into the new project`(@TempDir root: Path) {
        val firstProject = Files.createDirectory(root.resolve("first"))
        val secondProject = Files.createDirectory(root.resolve("second"))
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns listOf(item(1, ""))

        PacketRepository(api).use { packets ->
            assertEquals(1, packets.start(firstProject.toString()).inserted)
            assertEquals(1, packets.start(secondProject.toString()).inserted)
            assertTrue(Files.exists(firstProject.resolve("packets.sqlite3")))
            assertTrue(Files.exists(secondProject.resolve("packets.sqlite3")))
        }
    }

    @Test
    fun `large body is stored once as an external content addressed file`(@TempDir project: Path) {
        val largeBody = ByteArray(16 * 1024 * 1024 + 1) { 'a'.code.toByte() }
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns listOf(item(1, "", largeBody), item(2, "", largeBody))

        PacketRepository(api).use { packets ->
            assertEquals(1, packets.start(project.toString()).inserted)
            val blobFiles = Files.list(project.resolve("raw/resources/mcp-server/blobs")).use { it.toList() }
            assertEquals(1, blobFiles.size)
            assertEquals(largeBody.size.toLong(), Files.size(blobFiles.single()))
            val detail = packets.getPacket(1, 4)!!
            assertEquals(largeBody.size, detail.responseBodySize)
            assertEquals("aaaa", String(java.util.Base64.getDecoder().decode(detail.responseBodyBase64)))
            assertTrue(detail.responseBodyTruncated)
            val exported = packets.savePackets(listOf(1), project.resolve("export").toString())
            val responseFile = Path.of(exported.single().getValue("responsePath"))
            assertArrayEquals(responseHead + largeBody, Files.readAllBytes(responseFile))
            assertTrue(Files.readString(project.resolve("raw/resources/manifest.json")).contains("\"regenerable\":false"))
        }
    }

    @Test
    fun `proxy observation upgrades an identical MCP sent packet`(@TempDir project: Path) {
        val observed = item(9, "")
        var history: List<ProxyHttpRequestResponse> = emptyList()
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } answers { history }

        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            assertNotNull(packets.saveSent(observed.request(), observed.response()))
            assertTrue(packets.getPacket(1)!!.isSentFromMcp)
            assertEquals(1L, packets.apiInventory("example.com", 10, null, false).routes.single().packetCount)
            assertTrue(packets.apiInventory("example.com", 10, null, true).routes.isEmpty())
            history = listOf(observed)
            assertEquals(0, packets.start(project.toString()).inserted)
            assertEquals(1, packets.count())
            assertFalse(packets.getPacket(1)!!.isSentFromMcp)
            assertEquals(1L, packets.apiInventory("example.com", 10, null, false).routes.single().packetCount)
            assertEquals(1L, packets.apiInventory("example.com", 10, null, true).routes.single().packetCount)
        }
    }

    @Test
    fun `change cursor reports a late proxy promotion behind the packet id cursor`(@TempDir project: Path) {
        val observed = item(9, "", path = "/promoted")
        val later = item(10, "X-Variant: later\r\n", path = "/later")
        var history: List<ProxyHttpRequestResponse> = emptyList()
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } answers { history }
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            packets.saveSent(observed.request(), observed.response())
            packets.saveSent(later.request(), later.response())
            val before = packets.packetDelta(0, 100, null, true, null, afterChangeSeq = 0)
            assertTrue(before.items.isEmpty())
            assertEquals(2L, before.lastChangeSeq)
            history = listOf(observed)
            packets.start(project.toString())
            val after = packets.packetDelta(0, 100, null, true, before.databaseId, before.lastChangeSeq)
            assertEquals(listOf(1L), after.items.map { it.id })
            assertEquals(listOf("proxy_observed"), after.items.map { it.changeKind })
            assertEquals(3L, after.lastChangeSeq)
            assertTrue(packets.packetDelta(0, 100, null, false, before.databaseId, 0).items.all {
                it.changeKind == "insert"
            })
        }
    }

    @Test
    fun `background history scan returns immediately and exposes progress`(@TempDir project: Path) {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } answers {
            entered.countDown()
            assertTrue(release.await(5, TimeUnit.SECONDS))
            listOf(item(1, ""))
        }
        PacketRepository(api).use { packets ->
            val started = packets.start(project.toString(), backgroundScan = true)
            assertEquals("loading_history", started.historyScanPhase)
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertEquals("loading_history", packets.status().historyScanPhase)
            release.countDown()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (packets.status().historyScanPhase != "complete" && System.nanoTime() < deadline) Thread.sleep(10)
            val complete = packets.status()
            assertEquals("complete", complete.historyScanPhase)
            assertEquals(1, complete.historyScanProcessed)
            assertEquals(1, complete.historyScanInserted)
            assertEquals(1L, complete.packetCount)
        }
    }

    @Test
    fun `existing database builds its route summary once and keeps it current`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        var history = listOf(item(1, "", path = "/a?page=1"), item(2, "X-Variant: second\r\n", path = "/a?page=2"))
        every { api.proxy().history() } answers { history }
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            packets.stop(closeDatabase = true)
        }
        DriverManager.getConnection("jdbc:sqlite:${project.resolve("packets.sqlite3")}").use { db ->
            db.createStatement().use { st ->
                st.execute("DROP TRIGGER trg_api_route_insert")
                st.execute("DROP TRIGGER trg_api_route_observed")
                st.execute("DROP TABLE api_route_summary")
                st.execute("DROP TABLE api_route_status_codes")
                st.execute("DELETE FROM capture_metadata WHERE key='api_inventory_version'")
            }
        }
        PacketRepository(api).use { packets ->
            assertEquals(0, packets.start(project.toString()).inserted)
            val restored = packets.apiInventory("example.com", 10, null, false).routes.single()
            assertEquals(2L, restored.packetCount)
            assertTrue(restored.hasQuery)
            assertEquals(listOf(200), restored.statusCodes)

            packets.stop(closeDatabase = true)
            history = history + item(3, "X-Variant: third\r\n", path = "/a?page=3")
            assertEquals(1, packets.start(project.toString()).inserted)
            assertEquals(3L, packets.apiInventory("example.com", 10, null, false).routes.single().packetCount)
            val stored = packets.querySelect(
                "SELECT packet_count FROM api_route_summary WHERE scope=0 AND host='example.com'",
                10,
            )
            assertEquals("3", stored.rows.single()["packet_count"])
        }
    }

    @Test
    fun `legacy Python FTS trigger is removed before new packets are saved`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        var history: List<ProxyHttpRequestResponse> = emptyList()
        every { api.proxy().history() } answers { history }
        PacketRepository(api).use { it.start(project.toString()) }
        DriverManager.getConnection("jdbc:sqlite:${project.resolve("packets.sqlite3")}").use { db ->
            db.createStatement().use { st ->
                st.execute("CREATE TABLE burp_fts(url TEXT,request_body TEXT,response_body TEXT)")
                st.execute("""
                    CREATE TRIGGER burp_fts_ai AFTER INSERT ON burp_packets BEGIN
                        INSERT INTO burp_fts(url,request_body,response_body)
                        VALUES(NEW.url,NEW.request_body,NEW.response_body);
                    END
                """)
            }
        }
        history = listOf(item(1, ""))
        PacketRepository(api).use { packets ->
            assertEquals(1, packets.start(project.toString()).inserted)
            assertEquals(1L, packets.count())
        }
    }

    @Test
    fun `response events store new packets without repeating the full history scan`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        val proxy = mockk<Proxy>(relaxed = true)
        every { api.proxy() } returns proxy
        every { proxy.history() } returns emptyList()
        val handler = slot<ProxyResponseHandler>()
        val registration = mockk<Registration>(relaxed = true)
        every { proxy.registerResponseHandler(capture(handler)) } returns registration
        val source = item(42, "", path = "/event")
        val savedResponse = source.response()
        val event = mockk<InterceptedResponse>()
        every { event.request() } returns source.request()
        every { event.messageId() } returns 42
        every { event.toByteArray() } returns savedResponse.toByteArray()
        every { event.bodyOffset() } returns savedResponse.bodyOffset()
        every { event.body() } returns savedResponse.body()
        every { event.statusCode() } returns 200
        every { event.headerValue("Content-Type") } returns "application/json"

        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            assertTrue(packets.status().collecting)
            // The standalone API jar has no Burp ObjectFactory for continueWith().
            val callbackFailure = runCatching { handler.captured.handleResponseToBeSent(event) }.exceptionOrNull()
            if (callbackFailure != null) {
                assertTrue(callbackFailure is NullPointerException && callbackFailure.message?.contains("FACTORY") == true)
            }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (packets.count() == 0L && System.nanoTime() < deadline) Thread.sleep(10)
            assertEquals(1L, packets.count())
            assertEquals("/event", packets.apiInventory("example.com", 10, null, false).routes.single().path)
            verify(exactly = 1) { proxy.history() }
            packets.stop(closeDatabase = true)
            assertFalse(packets.status().collecting)
            verify(exactly = 1) { registration.deregister() }
        }
    }

    @Test
    fun `packet delta resumes across reconnect and rejects another database`(@TempDir root: Path) {
        val project = Files.createDirectory(root.resolve("first"))
        val other = Files.createDirectory(root.resolve("other"))
        val api = mockk<MontoyaApi>(relaxed = true)
        var history = listOf(item(1, "", path = "/a"), item(2, "", path = "/b"))
        every { api.proxy().history() } answers { history }
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            val first = packets.packetDelta(0, 1, "example.com", false, null)
            assertEquals(listOf(1L), first.items.map { it.id })
            assertTrue(first.hasMore)
            val second = packets.packetDelta(first.lastId, 1, "example.com", false, first.databaseId)
            assertEquals(listOf(2L), second.items.map { it.id })
            assertFalse(second.hasMore)
            val noMatch = packets.packetDelta(0, 10, "other.example", false, first.databaseId)
            assertTrue(noMatch.items.isEmpty())
            assertEquals(2L, noMatch.lastId)

            history = history + item(3, "", path = "/c")
            packets.start(project.toString())
            val resumed = packets.packetDelta(second.lastId, 10, null, false, first.databaseId)
            assertEquals(listOf(3L), resumed.items.map { it.id })
            assertEquals(first.databaseId, resumed.databaseId)

            packets.start(other.toString())
            assertThrows(IllegalArgumentException::class.java) {
                packets.packetDelta(3, 10, null, false, first.databaseId)
            }
        }
    }

    @Test
    fun `database identity persists across repository instances`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.proxy().history() } returns listOf(item(1, ""))
        val firstId = PacketRepository(api).use { packets ->
            packets.start(project.toString())
            packets.packetDelta(0, 10, null, false, null).databaseId
        }
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            val resumed = packets.packetDelta(1, 10, null, false, firstId)
            assertEquals(firstId, resumed.databaseId)
            assertTrue(resumed.items.isEmpty())
            assertEquals(1L, resumed.lastId)
        }
    }

    @Test
    fun `API inventory groups query variants and keeps a stable paged snapshot`(@TempDir project: Path) {
        val api = mockk<MontoyaApi>(relaxed = true)
        var history = listOf(
            item(1, "", path = "/api/items/1?page=1"),
            item(2, "", path = "/api/items/1?page=2"),
            item(3, "", path = "/api/items/2"),
        )
        every { api.proxy().history() } answers { history }
        PacketRepository(api).use { packets ->
            packets.start(project.toString())
            val first = packets.apiInventory("example.com", 1, null, false)
            assertEquals(3L, first.snapshotMaxId)
            assertEquals("/api/items/1", first.routes.single().path)
            assertEquals(2L, first.routes.single().packetCount)
            assertEquals(listOf(200), first.routes.single().statusCodes)
            assertTrue(first.routes.single().hasQuery)
            assertEquals("application/json", first.routes.single().sampleResponseMimeType)
            assertTrue(first.hasMore)

            history = history + item(4, "", path = "/api/earlier")
            packets.start(project.toString())
            val second = packets.apiInventory("example.com", 1, first.nextCursor, false)
            assertEquals(first.snapshotMaxId, second.snapshotMaxId)
            assertEquals("/api/items/2", second.routes.single().path)
            assertFalse(second.hasMore)
            assertThrows(IllegalArgumentException::class.java) {
                packets.apiInventory("another.example", 1, first.nextCursor, false)
            }

            val refreshed = packets.apiInventory("example.com", 10, null, false)
            assertEquals(listOf("/api/items/1", "/api/items/2", "/api/earlier"),
                refreshed.routes.map { it.path })
        }
    }

    private fun item(id: Int, extraHeader: String, body: ByteArray = responseBody, path: String = "/a",
                     port: Int = 443): ProxyHttpRequestResponse {
        val service = mockk<HttpService>()
        every { service.host() } returns "example.com"
        every { service.port() } returns port
        every { service.secure() } returns true

        val request = mockk<HttpRequest>()
        val requestRaw = "GET $path HTTP/1.1\r\nHost: example.com\r\n${extraHeader}\r\n".toByteArray()
        every { request.httpService() } returns service
        every { request.toByteArray() } returns burpBytes(requestRaw)
        every { request.bodyOffset() } returns requestRaw.size
        every { request.body() } returns burpBytes(byteArrayOf())
        every { request.method() } returns "GET"
        every { request.url() } returns "https://example.com${if (port == 443) "" else ":$port"}$path"
        every { request.path() } returns path
        every { request.headerValue("Content-Type") } returns null
        every { request.headerValue("Referer") } returns "https://example.com/page"

        val response = mockk<HttpResponse>()
        val rawResponse = responseHead + body
        every { response.toByteArray() } returns burpBytes(rawResponse)
        every { response.bodyOffset() } returns responseHead.size
        every { response.body() } returns burpBytes(body)
        every { response.statusCode() } returns 200
        every { response.headerValue("Content-Type") } returns "application/json"

        val item = mockk<ProxyHttpRequestResponse>()
        every { item.id() } returns id
        every { item.request() } returns request
        every { item.response() } returns response
        return item
    }

    private fun burpBytes(bytes: ByteArray): BurpBytes = mockk<BurpBytes>().also {
        every { it.bytes } returns bytes
        every { it.length() } returns bytes.size
        every { it.subArray(any(), any()) } answers {
            val start = firstArg<Int>()
            val end = secondArg<Int>()
            require(start < end) { "Montoya does not guarantee an empty subArray result" }
            burpBytes(bytes.copyOfRange(start, end))
        }
    }

    companion object {
        private val responseBody = "{\"token\":\"alpha\"}".toByteArray()
        private val responseHead = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n".toByteArray()
        private val responseRaw = responseHead + responseBody
    }
}
