package net.portswigger.mcp.openapi

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class OpenApiRequestBuilderTest {
    @Test
    fun `builds an editable repeater request with server, parameters and JSON body`() {
        val operation = OpenApiOperation(
            method = "POST", path = "/items/{id}", summary = "Create item",
            description = "", tags = emptyList(), details = "",
            parameters = listOf(
                mapOf("name" to "id", "in" to "path", "required" to true),
                mapOf("name" to "page", "in" to "query", "required" to true),
                mapOf("name" to "optional", "in" to "query", "required" to false),
                mapOf("name" to "X-Trace", "in" to "header", "required" to true),
            ),
            requestBody = mapOf("content" to mapOf("application/json" to mapOf(
                "schema" to mapOf("type" to "object", "properties" to mapOf(
                    "name" to mapOf("type" to "string"),
                )),
            ))),
            responses = mapOf("200" to mapOf("content" to mapOf("application/json" to emptyMap<String, Any>()))),
        )
        val document = OpenApiDocument(
            info = OpenApiSpecInfo("api.example.com", "", "", "Example", "1", 1, ""),
            operations = listOf(operation),
            servers = listOf("https://api.example.com:8443/v1"),
        )

        val draft = OpenApiRequestBuilder.build(document, operation)
        assertEquals("api.example.com", draft.host)
        assertEquals(8443, draft.port)
        assertTrue(draft.usesHttps)
        assertTrue(draft.rawRequest.startsWith("POST /v1/items/{id}?page={page} HTTP/1.1\r\n"))
        assertTrue(draft.rawRequest.contains("Host: api.example.com:8443\r\n"))
        assertTrue(draft.rawRequest.contains("X-Trace: {X-Trace}\r\n"))
        assertTrue(draft.rawRequest.contains("Content-Type: application/json\r\n"))
        assertFalse(draft.rawRequest.contains("\"name\": \"string\""))
        assertTrue(draft.rawRequest.endsWith("\r\n\r\n"))
        assertFalse(draft.rawRequest.contains("optional="))
    }

    @Test
    fun `falls back to spec host when server has unresolved variables`() {
        val operation = OpenApiOperation("GET", "/status", "", "", emptyList(), "")
        val document = OpenApiDocument(
            OpenApiSpecInfo("api.example.com", "", "", "Example", "1", 1, ""),
            listOf(operation), servers = listOf("https://{server}/v1"),
        )
        val draft = OpenApiRequestBuilder.build(document, operation)
        assertEquals("api.example.com", draft.host)
        assertEquals(443, draft.port)
        assertTrue(draft.rawRequest.startsWith("GET /status HTTP/1.1\r\n"))
    }

    @Test
    fun `editable examples fill path and query in repeater draft`() {
        val operation = OpenApiOperation(
            method = "GET", path = "/articles/{id}", summary = "", description = "", tags = emptyList(), details = "",
            parameters = listOf(
                mapOf("name" to "id", "in" to "path", "required" to true, "example" to "09620"),
                mapOf("name" to "search", "in" to "query", "required" to false),
            ),
        )
        val document = OpenApiDocument(
            OpenApiSpecInfo("api.example.com", "", "", "Example", "1", 1, ""), listOf(operation),
        )
        assertEquals("09620", OpenApiRequestBuilder.parameterSample(operation.parameters[0]))
        val draft = OpenApiRequestBuilder.build(document, operation,
            mapOf("path:id" to "09620", "query:search" to "hello world"))
        assertTrue(draft.rawRequest.startsWith("GET /articles/09620?search=hello%20world HTTP/1.1\r\n"))
    }
}
