package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable

object RepeaterCaptureStore {
    const val SLOT_COUNT = 3

    private val slots = arrayOfNulls<CapturedRepeaterItem>(SLOT_COUNT)

    fun isValidSlot(slot: Int): Boolean = slot in 1..SLOT_COUNT

    fun set(slot: Int, item: CapturedRepeaterItem) {
        require(isValidSlot(slot)) { "slot must be between 1 and $SLOT_COUNT" }
        synchronized(slots) { slots[slot - 1] = item }
    }

    fun get(slot: Int): CapturedRepeaterItem? {
        if (!isValidSlot(slot)) return null
        return synchronized(slots) { slots[slot - 1] }
    }

    fun all(): List<CapturedRepeaterSlot> = synchronized(slots) {
        slots.mapIndexedNotNull { index, item ->
            item?.let { CapturedRepeaterSlot(index + 1, it) }
        }
    }

    fun clear() = synchronized(slots) { slots.fill(null) }
}

@Serializable
data class CapturedRepeaterItem(
    val request: String?,
    val response: String?,
    val capturedAt: String
)

@Serializable
data class CapturedRepeaterSlot(
    val slot: Int,
    val item: CapturedRepeaterItem
)
