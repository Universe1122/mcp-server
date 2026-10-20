package net.portswigger.mcp.openapi

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class OpenApiStoreTest {
    @Test
    fun `loads and refreshes an agent-written host spec`(@TempDir project: Path) {
        val store = OpenApiStore({ project })
        val spec = project.resolve("raw/resources/mcp-server/openapi/cafe.naver.com.yaml")
        Files.createDirectories(spec.parent)
        Files.writeString(spec, SAMPLE_SPEC)
        val first = store.list().single()
        assertEquals("cafe.naver.com", first.host)
        assertEquals(1, first.operationCount)
        assertEquals(spec.toString(), first.path)
        assertEquals("GET", store.load("cafe.naver.com").operations.single().method)
        assertTrue(store.load("cafe.naver.com").operations.single().details.contains("Responses"))
        assertEquals("https://cafe.naver.com", store.load("cafe.naver.com").servers.single())
        val operation = store.load("cafe.naver.com").operations.single()
        assertEquals(listOf(OpenApiHistoryRef(42, 100), OpenApiHistoryRef(17, 101)), operation.historyRefs)
        assertEquals("id", operation.parameters.single()["name"])
        assertEquals("string", (operation.parameters.single()["schema"] as Map<*, *>)["type"])
        assertEquals("200", operation.responses.keys.single().toString())
        assertTrue(store.validate("cafe.naver.com").valid)

        val page = store.read("cafe.naver.com", 0, 20)
        assertEquals(first.sha256, page.sha256)
        assertNotNull(page.nextOffset)
        assertEquals(1, store.list().size)
        Files.writeString(spec, SAMPLE_SPEC.replace("version: '1.0'", "version: '1.1'"))
        val second = store.list().single()
        assertNotEquals(first.sha256, second.sha256)
        assertEquals("1.1", second.version)
        assertThrows(IllegalArgumentException::class.java) { store.load("../outside") }
    }

    @Test
    fun `configured folder discovers direct YAML writes`(@TempDir root: Path) {
        val project = Files.createDirectory(root.resolve("project"))
        val configured = Files.createDirectory(root.resolve("specs"))
        val store = OpenApiStore({ project }, { configured })
        assertTrue(store.list().isEmpty())
        val spec = configured.resolve("cafe.naver.com.yml")
        Files.writeString(spec, SAMPLE_SPEC)
        assertEquals(spec.toString(), store.list().single().path)
        assertEquals(SAMPLE_SPEC, store.read("cafe.naver.com").text)
        Files.writeString(spec, "openapi: 3.0.3\ninfo: {}\npaths: {}")
        assertNotNull(store.list().single().error)
        assertFalse(store.validate("cafe.naver.com").valid)
        assertFalse(store.validate("missing.example").valid)
    }

    @Test
    fun `validation catches missing responses and undeclared path parameters`(@TempDir project: Path) {
        val directory = Files.createDirectories(project.resolve("raw/resources/mcp-server/openapi"))
        Files.writeString(directory.resolve("example.com.yaml"), """
            openapi: 3.0.3
            info:
              title: Test
              version: '1'
            paths:
              /items/{itemId}:
                get:
                  summary: Item
        """.trimIndent())
        val report = OpenApiStore({ project }).validate("example.com")
        assertFalse(report.valid)
        assertTrue(report.errors.any { "responses" in it })
        assertTrue(report.errors.any { "itemId" in it })
    }

    @Test
    fun `validation rejects ambiguous bare history references`(@TempDir project: Path) {
        val directory = Files.createDirectories(project.resolve("raw/resources/mcp-server/openapi"))
        Files.writeString(directory.resolve("example.com.yaml"), """
            openapi: 3.0.3
            info:
              title: Test
              version: '1'
            paths:
              /items:
                get:
                  x-burp-history-ids: [10]
                  responses:
                    '200':
                      description: OK
        """.trimIndent())
        val report = OpenApiStore({ project }).validate("example.com")
        assertFalse(report.valid)
        assertTrue(report.errors.any { "x-burp-history-refs" in it })
    }

    @Test
    fun `component parameter references appear in validation and Repeater drafts`(@TempDir project: Path) {
        val directory = Files.createDirectories(project.resolve("raw/resources/mcp-server/openapi"))
        Files.writeString(directory.resolve("example.com.yaml"), """
            openapi: 3.0.3
            info:
              title: Referenced parameters
              version: '1'
            servers:
              - url: https://example.com
            components:
              parameters:
                ItemId:
                  name: itemId
                  in: path
                  required: true
                  schema:
                    type: string
                Locale:
                  name: locale
                  in: query
                  schema:
                    type: string
            paths:
              /items/{itemId}:
                parameters:
                  - ${'$'}ref: '#/components/parameters/ItemId'
                get:
                  parameters:
                    - ${'$'}ref: '#/components/parameters/Locale'
                  responses:
                    '200':
                      description: OK
        """.trimIndent())
        val store = OpenApiStore({ project })
        assertTrue(store.validate("example.com").valid)
        val document = store.load("example.com")
        val operation = document.operations.single()
        assertEquals(setOf("itemId", "locale"), operation.parameters.map { it["name"] }.toSet())
        val draft = OpenApiRequestBuilder.build(document, operation,
            mapOf("path:itemId" to "a b", "query:locale" to "ko-KR"))
        assertTrue(draft.rawRequest.startsWith("GET /items/a%20b?locale=ko-KR HTTP/1.1"))
    }

    private companion object {
        private val SAMPLE_SPEC = """
            openapi: 3.0.3
            info:
              title: Cafe packet example
              version: '1.0'
            servers:
              - url: https://cafe.naver.com
            paths:
              /sample/{id}:
                parameters:
                  - name: id
                    in: path
                    required: true
                    schema:
                      type: integer
                get:
                  summary: Synthetic test operation
                  x-burp-history-refs:
                    - historyId: 42
                      packetId: 100
                    - historyId: 17
                      packetId: 101
                  parameters:
                    - name: id
                      in: path
                      required: true
                      schema:
                        type: string
                  responses:
                    '200':
                      description: OK
        """.trimIndent()
    }
}
