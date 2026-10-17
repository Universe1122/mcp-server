package net.portswigger.mcp.openapi

import java.awt.Dimension
import java.awt.event.MouseEvent
import java.awt.event.MouseWheelEvent
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JLabel
import javax.swing.SwingUtilities
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DetailWheelRouterTest {
    @Test
    fun `wheel over nested response pane scrolls outer document`() {
        SwingUtilities.invokeAndWait {
            val page = JPanel().apply { preferredSize = Dimension(300, 2000) }
            val outer = JScrollPane(page).apply {
                setSize(300, 300)
                doLayout()
            }
            val response = JTextArea("response\n".repeat(100))
            val nested = JScrollPane(response).apply {
                setSize(200, 100)
                doLayout()
            }
            DetailWheelRouter.install(nested, outer)
            wheel(response, 1)
            assertEquals(3, outer.verticalScrollBar.value)
            assertEquals(0, nested.verticalScrollBar.value)
        }
    }

    @Test
    fun `ordinary detail content uses the outer native wheel handler`() {
        SwingUtilities.invokeAndWait {
            val page = JPanel().apply { preferredSize = Dimension(300, 2000) }
            val outer = JScrollPane(page).apply {
                setSize(300, 300)
                doLayout()
            }
            val label = JLabel("parameter name")
            val detail = JPanel().apply { add(label) }
            page.add(detail)
            DetailWheelRouter.install(detail, outer)
            assertTrue(outer.isWheelScrollingEnabled)
            assertEquals(0, detail.mouseWheelListeners.size)
            assertEquals(0, label.mouseWheelListeners.size)
            wheel(outer, 1)
            assertTrue(outer.verticalScrollBar.value > 0)
        }
    }

    @Test
    fun `nested response wheel stops at document bottom and can reverse`() {
        SwingUtilities.invokeAndWait {
            val page = JPanel().apply { preferredSize = Dimension(300, 2000) }
            val outer = JScrollPane(page).apply {
                setSize(300, 300)
                doLayout()
            }
            val response = JTextArea("response\n".repeat(100))
            DetailWheelRouter.install(JScrollPane(response), outer)
            val bar = outer.verticalScrollBar
            bar.value = bar.maximum - bar.visibleAmount
            val end = bar.value
            repeat(10) { wheel(response, 1) }
            assertEquals(end, bar.value)
            wheel(response, -1)
            assertTrue(bar.value < end)
        }
    }

    private fun wheel(source: java.awt.Component, rotation: Int) {
        source.dispatchEvent(MouseWheelEvent(source, MouseEvent.MOUSE_WHEEL,
            System.currentTimeMillis(), 0, 20, 20, 0, false,
            MouseWheelEvent.WHEEL_UNIT_SCROLL, 3, rotation))
    }
}
