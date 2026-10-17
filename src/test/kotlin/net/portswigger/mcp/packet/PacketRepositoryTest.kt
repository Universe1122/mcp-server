package net.portswigger.mcp.packet

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpBytes
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.mockk.every
import io.mockk.mockk
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class PacketRepositoryTest {
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

            val exports = packets.savePackets(listOf(matches.first().id), project.resolve("export").toString())
            val savedResponse = Path.of(exports.first().getValue("responsePath"))
            assertArrayEquals(responseRaw, Files.readAllBytes(savedResponse))
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
            history = listOf(observed)
            assertEquals(0, packets.start(project.toString()).inserted)
            assertEquals(1, packets.count())
            assertFalse(packets.getPacket(1)!!.isSentFromMcp)
        }
    }

    private fun item(id: Int, extraHeader: String, body: ByteArray = responseBody): ProxyHttpRequestResponse {
        val service = mockk<HttpService>()
        every { service.host() } returns "example.com"
        every { service.port() } returns 443
        every { service.secure() } returns true

        val request = mockk<HttpRequest>()
        val requestRaw = "GET /a HTTP/1.1\r\nHost: example.com\r\n${extraHeader}\r\n".toByteArray()
        every { request.httpService() } returns service
        every { request.toByteArray() } returns burpBytes(requestRaw)
        every { request.bodyOffset() } returns requestRaw.size
        every { request.body() } returns burpBytes(byteArrayOf())
        every { request.method() } returns "GET"
        every { request.url() } returns "https://example.com/a"
        every { request.path() } returns "/a"
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
