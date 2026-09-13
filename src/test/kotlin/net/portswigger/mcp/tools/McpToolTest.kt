package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class McpToolTest {
    @Test
    fun `page character budget returns complete items and leaves the rest for the next offset`() {
        val items = listOf("aaaa", "bbbb", "cccc")

        val firstPage = buildPaginatedText(items, offset = 0, count = 3, maxOutputChars = 7) { it }
        val secondPage = buildPaginatedText(items, offset = 1, count = 3, maxOutputChars = 7) { it }

        assertEquals("aaaa", firstPage)
        assertEquals("bbbb", secondPage)
    }
}
