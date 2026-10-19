package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.net.ServerSocket
import java.nio.file.Files
import java.nio.file.Path

class McpServerIntegrationTest {
    private val client = TestSseMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private val persistedObject = mockk<PersistedObject>()
    @Volatile private var serverStarted = false

    init {
        every { persistedObject.getBoolean(any()) } returns true
        every { persistedObject.getString(any()) } returns "127.0.0.1"
        every { persistedObject.getString("projectConfigPath") } returns ""
        every { persistedObject.getInteger("port") } returns testPort
        every { persistedObject.setBoolean(any(), any()) } returns Unit
        every { persistedObject.setString(any(), any()) } returns Unit
        every { persistedObject.setInteger(any(), any()) } returns Unit
        every { api.proxy().history() } returns emptyList()
    }

    private val mockLogging = mockk<Logging>().apply {
        every { logToError(any<String>()) } returns Unit
        every { logToOutput(any<String>()) } returns Unit
    }

    private val config = McpConfig(persistedObject, mockLogging)

    @BeforeEach
    fun setup() {
        serverStarted = false
        serverManager.start(config) { state ->
            if (state is ServerState.Running) {
                serverStarted = true
            }
        }
        
        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 50) {
                delay(100)
                attempts++
            }
            
            if (!serverStarted) {
                throw IllegalStateException("Server failed to start after timeout")
            }
        }
    }

    private fun findAvailablePort(): Int {
        return ServerSocket(0).use { it.localPort }
    }

    @AfterEach
    fun tearDown() {
        runBlocking {
            if (client.isConnected()) {
                client.close()
            }
        }
        serverManager.stop {}
    }

    @Test
    fun `server should accept connections and list tools`() = runBlocking {
        try {
            client.connectToServer("http://127.0.0.1:${testPort}")
            assertTrue(client.isConnected(), "Client should be connected to server")
            
            val tools = client.listTools()
            assertFalse(tools.isEmpty(), "Server should have registered tools")
            
            val toolNames = tools.map { it.name }
            assertTrue(toolNames.contains("output_project_options"), "Server should have output_project_options tool")
            assertTrue(toolNames.contains("output_user_options"), "Server should have output_user_options tool")
            assertTrue(toolNames.containsAll(listOf("start_packet_capture", "search_packet", "get_packet", "save_packets", "get_db_info", "get_db_schema", "export_packets_har", "get_packet_delta", "get_api_inventory")))
            assertTrue(toolNames.containsAll(listOf("load_project_config", "get_project_storage", "list_openapi_specs", "get_openapi_spec", "validate_openapi_spec")))
            assertFalse(toolNames.contains("send_http1_request"))
            assertFalse(toolNames.contains("send_http2_request"))
            assertFalse(toolNames.contains("put_openapi_spec"))
            assertTrue(client.listResourceUris().contains("burp-mcp://skills/openapi-from-packets"))
            val methodology = client.readResource("burp-mcp://skills/openapi-from-packets")
            assertTrue(methodology.contains("cafe.naver.com"))
            assertTrue(methodology.contains("x-burp-packet-ids"))
            assertTrue(client.listPromptNames().contains("build_openapi_from_packets"))
            
            val pingResult = client.ping()
            assertNotNull(pingResult, "Ping should return a result")
        } catch (e: Exception) {
            fail("Connection failed: ${e.message}")
        }
    }

    @Test
    fun `packet capture can be started through MCP`(@TempDir project: Path) = runBlocking {
        client.connectToServer("http://127.0.0.1:${testPort}")
        val specDir = project.resolve("custom-openapi")
        Files.writeString(project.resolve("config.yaml"),
            "storage:\n  db_dir: .\n  openapi_dir: custom-openapi\n")
        val loadedConfig = client.callTool("load_project_config", mapOf("configPath" to project.resolve("config.yaml").toString()))
        assertFalse(loadedConfig?.isError ?: true)
        val storageResult = client.callTool("get_project_storage", emptyMap())
        assertFalse(storageResult?.isError ?: true)
        val storage = Json.parseToJsonElement((storageResult!!.content.single() as TextContent).text).jsonObject
        assertEquals("config.yaml", storage.getValue("source").jsonPrimitive.content)
        assertEquals(specDir.toString(), storage.getValue("openapiDir").jsonPrimitive.content)
        val started = client.callTool("start_packet_capture", emptyMap())
        assertFalse(started?.isError ?: true)
        val payload = (started!!.content.single() as TextContent).text
        val status = Json.parseToJsonElement(payload).jsonObject
        assertEquals("0", status.getValue("packetCount").jsonPrimitive.content)
        assertTrue(Files.exists(project.resolve("packets.sqlite3")))

        val deltaResult = client.callTool("get_packet_delta", mapOf("afterId" to 0, "limit" to 10))
        assertFalse(deltaResult?.isError ?: true)
        val delta = Json.parseToJsonElement((deltaResult!!.content.single() as TextContent).text).jsonObject
        assertTrue(delta.getValue("items").jsonArray.isEmpty())
        assertEquals("0", delta.getValue("lastId").jsonPrimitive.content)
        assertTrue(delta.getValue("databaseId").jsonPrimitive.content.isNotBlank())

        val inventoryResult = client.callTool("get_api_inventory", mapOf("host" to "cafe.naver.com"))
        assertFalse(inventoryResult?.isError ?: true)
        val inventory = Json.parseToJsonElement((inventoryResult!!.content.single() as TextContent).text).jsonObject
        assertTrue(inventory.getValue("routes").jsonArray.isEmpty())

        val schemaResult = client.callTool("get_db_schema", emptyMap())
        assertFalse(schemaResult?.isError ?: true)
        val schema = Json.parseToJsonElement((schemaResult!!.content.single() as TextContent).text).jsonObject
        assertTrue(schema.getValue("createStatements").jsonObject.containsKey("burp_packets"))

        val harPath = project.resolve("empty.har")
        val harResult = client.callTool("export_packets_har", mapOf("outputPath" to harPath.toString()))
        assertFalse(harResult?.isError ?: true)
        val har = Json.parseToJsonElement((harResult!!.content.single() as TextContent).text).jsonObject
        assertEquals("0", har.getValue("exported").jsonPrimitive.content)
        assertTrue(Files.exists(harPath))

        val document = "openapi: 3.0.3\ninfo:\n  title: Cafe packet example\n  version: '1.0'\npaths: {}\n"
        Files.createDirectories(specDir)
        val specPath = specDir.resolve("cafe.naver.com.yaml")
        Files.writeString(specPath, document)
        val readSpec = client.callTool("get_openapi_spec", mapOf("host" to "cafe.naver.com"))
        assertFalse(readSpec?.isError ?: true)
        val readSpecJson = Json.parseToJsonElement((readSpec!!.content.single() as TextContent).text).jsonObject
        assertEquals(document, readSpecJson.getValue("text").jsonPrimitive.content)

        val listedSpecs = client.callTool("list_openapi_specs", emptyMap())
        assertFalse(listedSpecs?.isError ?: true)
        val listed = Json.parseToJsonElement((listedSpecs!!.content.single() as TextContent).text).jsonArray
        assertEquals(1, listed.size)
        assertEquals(specPath.toString(), listed.single().jsonObject.getValue("path").jsonPrimitive.content)
        val validationResult = client.callTool("validate_openapi_spec", mapOf("host" to "cafe.naver.com"))
        assertFalse(validationResult?.isError ?: true)
        val validation = Json.parseToJsonElement((validationResult!!.content.single() as TextContent).text).jsonObject
        assertEquals("true", validation.getValue("valid").jsonPrimitive.content)

        val query = "SELECT 1 AS n UNION ALL SELECT 2 AS n ORDER BY n"
        val firstPage = client.callTool("query_burp_database", mapOf("query" to query, "maxRows" to 1))
        assertFalse(firstPage?.isError ?: true)
        val first = Json.parseToJsonElement((firstPage!!.content.single() as TextContent).text).jsonObject
        assertEquals("1", first.getValue("rows").jsonArray.single().jsonObject.getValue("n").jsonPrimitive.content)
        assertEquals("true", first.getValue("hasMore").jsonPrimitive.content)
        assertEquals("1", first.getValue("nextOffset").jsonPrimitive.content)

        val secondPage = client.callTool("query_burp_database", mapOf("query" to query, "maxRows" to 1, "offset" to 1))
        assertFalse(secondPage?.isError ?: true)
        val second = Json.parseToJsonElement((secondPage!!.content.single() as TextContent).text).jsonObject
        assertEquals("2", second.getValue("rows").jsonArray.single().jsonObject.getValue("n").jsonPrimitive.content)
        assertEquals("false", second.getValue("hasMore").jsonPrimitive.content)

        val stopped = client.callTool("stop_packet_capture", mapOf("closeDatabase" to true))
        assertFalse(stopped?.isError ?: true)
    }

    @Test
    fun `storage status reports legacy project path`(@TempDir project: Path) = runBlocking {
        client.connectToServer("http://127.0.0.1:${testPort}")
        val started = client.callTool("start_packet_capture", mapOf("projectPath" to project.toString()))
        assertFalse(started?.isError ?: true)
        val result = client.callTool("get_project_storage", emptyMap())
        assertFalse(result?.isError ?: true)
        val status = Json.parseToJsonElement((result!!.content.single() as TextContent).text).jsonObject
        assertEquals("projectPath", status.getValue("source").jsonPrimitive.content)
        assertEquals(project.toRealPath().resolve("raw/resources/mcp-server/openapi").toString(),
            status.getValue("openapiDir").jsonPrimitive.content)
        assertEquals(project.toRealPath().resolve("packets.sqlite3").toString(),
            status.getValue("databasePath").jsonPrimitive.content)
    }
}
