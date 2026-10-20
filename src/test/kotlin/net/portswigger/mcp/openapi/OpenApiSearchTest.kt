package net.portswigger.mcp.openapi

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class OpenApiSearchTest {
    @Test
    fun `search includes parameters schemas descriptions and inspection status`() {
        val operation = OpenApiOperation("GET", "/items/{itemId}", "항목 조회", "등록된 상품을 조회합니다", emptyList(), "",
            parameters = listOf(mapOf("name" to "itemId", "schema" to mapOf("type" to "integer"))),
            responses = mapOf("200" to mapOf("description" to "성공", "schema" to mapOf("stockCount" to "integer"))))
        assertTrue(matchesOpenApiSearch(operation, null, "itemId"))
        assertTrue(matchesOpenApiSearch(operation, null, "stockCount"))
        assertTrue(matchesOpenApiSearch(operation, null, "등록된"))
        assertTrue(matchesOpenApiSearch(operation, "VULN", "vuln"))
        assertFalse(matchesOpenApiSearch(operation, null, "vuln"))
        val referenced = operation.copy(responses = mapOf("200" to mapOf("schema" to mapOf(
            "\$ref" to "#/components/schemas/Item"))))
        assertTrue(matchesOpenApiSearch(referenced, null, "stockCount", mapOf("Item" to mapOf(
            "properties" to mapOf("stockCount" to mapOf("type" to "integer"))))))
    }

    @Test
    fun `packet matching prefers literal path over a variable route`() {
        val dynamic = OpenApiOperation("GET", "/items/{itemId}", "", "", emptyList(), "")
        val literal = OpenApiOperation("GET", "/items/stats", "", "", emptyList(), "")
        assertEquals(literal, matchingOpenApiOperation(listOf(dynamic, literal), "GET", "https://example.com/items/stats?q=1"))
        assertEquals(dynamic, matchingOpenApiOperation(listOf(dynamic, literal), "GET", "https://example.com/items/42"))
        assertNull(matchingOpenApiOperation(listOf(dynamic, literal), "POST", "https://example.com/items/42"))
    }
}
