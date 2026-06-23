package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable

object RepeaterCaptureStore {
    @Volatile
    var lastCapturedItem: CapturedRepeaterItem? = null
}

@Serializable
data class CapturedRepeaterItem(
    val request: String?,
    val response: String?,
    val capturedAt: String
)
