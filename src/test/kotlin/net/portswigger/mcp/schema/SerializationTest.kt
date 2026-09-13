package net.portswigger.mcp.schema

import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SerializationTest {
    @Test
    fun `proxy history truncates bodies before converting complete messages to strings`() {
        val requestBody = mockk<ByteArray>()
        val requestPrefix = mockk<ByteArray>()
        every { requestBody.length() } returns 10
        every { requestBody.subArray(0, 4) } returns requestPrefix
        every { requestPrefix.toString() } returns "REQ!"

        val responseBody = mockk<ByteArray>()
        val responsePrefix = mockk<ByteArray>()
        every { responseBody.length() } returns 20
        every { responseBody.subArray(0, 5) } returns responsePrefix
        every { responsePrefix.toString() } returns "RESP!"

        val requestHeader = mockk<HttpHeader>()
        every { requestHeader.name() } returns "Host"
        every { requestHeader.value() } returns "example.com"

        val responseHeader = mockk<HttpHeader>()
        every { responseHeader.name() } returns "Content-Type"
        every { responseHeader.value() } returns "application/octet-stream"

        val request = mockk<HttpRequest>()
        every { request.method() } returns "GET"
        every { request.path() } returns "/download"
        every { request.fileExtension() } returns "bin"
        every { request.httpVersion() } returns "HTTP/1.1"
        every { request.headers() } returns listOf(requestHeader)
        every { request.body() } returns requestBody

        val response = mockk<HttpResponse>()
        every { response.httpVersion() } returns "HTTP/1.1"
        every { response.statusCode() } returns 200
        every { response.reasonPhrase() } returns "OK"
        every { response.headers() } returns listOf(responseHeader)
        every { response.body() } returns responseBody
        every { response.headerValue("Content-Type") } returns "application/octet-stream"
        every { response.headerValue("Content-Disposition") } returns null
        every { response.statedMimeType() } returns MimeType.APPLICATION_UNKNOWN
        every { response.inferredMimeType() } returns MimeType.APPLICATION_UNKNOWN

        val item = mockk<ProxyHttpRequestResponse>()
        every { item.request() } returns request
        every { item.response() } returns response
        every { item.annotations().notes() } returns null

        val result = item.toSerializableForm(maxRequestBodyBytes = 4, maxResponseBodyBytes = 5)

        assertTrue(result.request!!.endsWith("REQ![truncated request body: stored 4 of 10 bytes]"))
        assertTrue(result.response!!.endsWith("RESP![truncated response body: stored 5 of 20 bytes]"))
        assertEquals(10, result.requestBodySize)
        assertEquals(20, result.responseBodySize)
        assertTrue(result.requestBodyTruncated)
        assertTrue(result.responseBodyTruncated)
        verify(exactly = 0) { request.toString() }
        verify(exactly = 0) { response.toString() }
    }

    @Test
    fun `javascript response body is externalized without converting any body bytes to text`() {
        val requestBody = mockk<ByteArray>()
        every { requestBody.length() } returns 0

        val responseBody = mockk<ByteArray>()
        every { responseBody.length() } returns 500_000_000

        val request = mockk<HttpRequest>()
        every { request.method() } returns "GET"
        every { request.path() } returns "/assets/app.js?v=1"
        every { request.fileExtension() } returns "js"
        every { request.httpVersion() } returns "HTTP/1.1"
        every { request.headers() } returns emptyList()
        every { request.body() } returns requestBody

        val response = mockk<HttpResponse>()
        every { response.httpVersion() } returns "HTTP/1.1"
        every { response.statusCode() } returns 200
        every { response.reasonPhrase() } returns "OK"
        every { response.headers() } returns emptyList()
        every { response.body() } returns responseBody

        val item = mockk<ProxyHttpRequestResponse>()
        every { item.request() } returns request
        every { item.response() } returns response
        every { item.annotations().notes() } returns null

        val result = item.toSerializableForm()

        assertTrue(result.responseIsJavaScript)
        assertEquals(500_000_000, result.responseBodySize)
        assertTrue(result.responseBodyTruncated)
        assertTrue(result.response!!.endsWith("[truncated response body: stored 0 of 500000000 bytes]"))
        verify(exactly = 0) { responseBody.subArray(any(), any()) }
        verify(exactly = 0) { responseBody.toString() }
    }
}
