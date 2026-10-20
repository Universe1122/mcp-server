package net.portswigger.mcp.openapi

import net.portswigger.mcp.packet.PacketDetail
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import javax.swing.AbstractAction
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.KeyStroke
import javax.swing.SwingConstants

/** DB-backed packet reader embedded beside the OpenAPI operation list. */
internal class PacketDetailPanel(
    private val sendToRepeater: (PacketDetail) -> Unit,
    private val createRequestEditor: (PacketDetail) -> Component,
    private val createResponseEditor: (PacketDetail) -> Component,
    private val close: () -> Unit,
) : JPanel(BorderLayout(0, 14)) {
    private data class Colors(
        val background: Color, val card: Color, val text: Color, val muted: Color,
        val accent: Color,
    )
    private val light = Colors(Color(247, 250, 253), Color.WHITE, Color(35, 46, 63),
        Color(91, 107, 125), Color(37, 112, 189))
    private val dark = Colors(Color(28, 34, 41), Color(38, 46, 55), Color(232, 238, 245),
        Color(168, 183, 198), Color(101, 172, 242))
    private var colors = light
    private var packet: PacketDetail? = null
    private var requestedId: Long? = null
    private val idLabel = JLabel("PACKET")
    private val closeButton = JButton("×")
    private val heading = JLabel("Select a packet")
    private val url = JTextArea()
    private val meta = JLabel("Click a packet ID in an endpoint to inspect its stored request and response.")
    private val repeater = JButton("Send to Repeater")
    private val copyUrl = JButton("Copy URL")
    private val messageTabs = JTabbedPane()
    private val header = JPanel(BorderLayout(0, 12))
    private val titleBar = JPanel(BorderLayout())
    private val actions = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))

    init {
        preferredSize = Dimension(620, 640)
        minimumSize = Dimension(400, 300)
        border = BorderFactory.createEmptyBorder(18, 18, 18, 18)
        idLabel.font = idLabel.font.deriveFont(Font.BOLD, 11f)
        heading.font = heading.font.deriveFont(Font.BOLD, 19f)
        url.isEditable = false
        url.isOpaque = false
        url.lineWrap = true
        url.wrapStyleWord = true
        url.rows = 2
        url.border = BorderFactory.createEmptyBorder()
        closeButton.toolTipText = "Close packet details (Esc)"
        closeButton.addActionListener { close() }
        val closeAction = "closePacketDetails"
        val escape = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0)
        getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(escape, closeAction)
        actionMap.put(closeAction, object : AbstractAction() {
            override fun actionPerformed(event: ActionEvent) = close()
        })
        repeater.addActionListener {
            packet?.let { current ->
                runCatching { sendToRepeater(current) }
                    .onFailure { meta.text = "Could not create Repeater tab: ${it.message}" }
            }
        }
        copyUrl.addActionListener {
            packet?.let { current ->
                runCatching { Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(current.url), null) }
                    .onFailure { meta.text = "Could not copy URL: ${it.message}" }
            }
        }
        titleBar.add(idLabel, BorderLayout.WEST)
        titleBar.add(closeButton, BorderLayout.EAST)
        header.add(titleBar, BorderLayout.NORTH)
        header.add(JPanel(BorderLayout(0, 7)).apply {
            add(heading, BorderLayout.NORTH)
            add(url, BorderLayout.CENTER)
            add(meta, BorderLayout.SOUTH)
        }, BorderLayout.CENTER)
        actions.add(repeater)
        actions.add(copyUrl)
        header.add(actions, BorderLayout.SOUTH)
        add(header, BorderLayout.NORTH)
        add(messageTabs, BorderLayout.CENTER)
        showLoading(null)
    }

    fun setDarkTheme(darkTheme: Boolean) {
        colors = if (darkTheme) dark else light
        background = colors.background
        header.background = colors.background
        titleBar.background = colors.background
        actions.background = colors.background
        (header.getComponent(1) as JPanel).background = colors.background
        idLabel.foreground = colors.accent
        heading.foreground = colors.text
        url.foreground = colors.text
        meta.foreground = colors.muted
        messageTabs.background = colors.card
        messageTabs.foreground = colors.text
        packet?.let { render(it) } ?: showPlaceholder(
            if (requestedId == null) "Select a packet ID" else "Loading packet #$requestedId…"
        )
    }

    fun showLoading(id: Long?) {
        packet = null
        requestedId = id
        idLabel.text = id?.let { "BURP HISTORY #$it" } ?: "PACKET"
        heading.text = if (id == null) "Select a packet" else "Loading packet…"
        url.text = ""
        meta.text = if (id == null) "Click a packet ID in an endpoint to inspect its stored request and response."
            else "Reading the saved request and response from the packet database."
        repeater.isEnabled = false
        copyUrl.isEnabled = false
        showPlaceholder(if (id == null) "Select a packet ID" else "Loading packet #$id…")
    }

    fun showError(id: Long, message: String) {
        showLoading(id)
        heading.text = "Packet unavailable"
        meta.text = message
        showPlaceholder(message)
    }

    fun showPacket(value: PacketDetail) {
        packet = value
        requestedId = value.id
        runCatching { render(value) }
            .onFailure { showError(value.id, "Could not display packet: ${it.message}") }
    }

    private fun render(value: PacketDetail) {
        val selectedTab = messageTabs.selectedIndex
        idLabel.text = value.burpHistoryId?.let { "BURP HISTORY #$it · DB #${value.id}" }
            ?: "DATABASE PACKET #${value.id}"
        heading.text = "${value.method}  ${value.statusCode ?: "No response"}"
        url.text = value.url
        meta.text = "${value.host}:${value.port}  ·  ${if (value.usesHttps) "HTTPS" else "HTTP"}  ·  " +
            "Request ${formatBytes(value.requestBodySize)}  ·  Response ${value.responseBodySize?.let(::formatBytes) ?: "none"}"
        repeater.isEnabled = !value.requestBodyTruncated
        repeater.toolTipText = if (value.requestBodyTruncated)
            "The stored request exceeds the preview limit; a partial request cannot be sent to Repeater"
        else "Create a Repeater tab from this saved request without sending it"
        copyUrl.isEnabled = true
        messageTabs.removeAll()
        messageTabs.addTab("Request", editorPanel(createRequestEditor(value), value.requestBodySize,
            value.requestBodyTruncated))
        if (value.responseHeaders != null) {
            messageTabs.addTab("Response", editorPanel(createResponseEditor(value),
                value.responseBodySize ?: 0, value.responseBodyTruncated))
        } else messageTabs.addTab("Response", placeholder("No response was saved for this packet."))
        if (selectedTab in 0 until messageTabs.tabCount) messageTabs.selectedIndex = selectedTab
        revalidate()
        repaint()
    }

    private fun editorPanel(editor: Component, bodySize: Int, truncated: Boolean): JPanel =
        JPanel(BorderLayout(0, 8)).apply {
            background = colors.card
            border = BorderFactory.createEmptyBorder(10, 10, 10, 10)
            add(editor, BorderLayout.CENTER)
            val notice = if (truncated) "Body preview limited to the first 1 MB of ${formatBytes(bodySize)}."
                else "${formatBytes(bodySize)} stored body"
            add(JLabel(notice).apply { foreground = colors.muted }, BorderLayout.SOUTH)
        }

    private fun showPlaceholder(message: String) {
        messageTabs.removeAll()
        messageTabs.addTab("Details", placeholder(message))
    }

    private fun placeholder(message: String): JPanel = JPanel(BorderLayout()).apply {
        background = colors.card
        border = BorderFactory.createEmptyBorder(24, 20, 24, 20)
        add(JLabel(message, SwingConstants.CENTER).apply { foreground = colors.muted }, BorderLayout.CENTER)
    }

    private fun formatBytes(size: Int): String = when {
        size < 1024 -> "$size B"
        size < 1024 * 1024 -> "%.1f KB".format(size / 1024.0)
        else -> "%.1f MB".format(size / (1024.0 * 1024.0))
    }
}
