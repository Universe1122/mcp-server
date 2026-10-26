package net.portswigger.mcp.packet

import java.awt.BasicStroke
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.geom.Point2D
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.BorderFactory
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.SwingWorker
import javax.swing.Timer
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.ln
import kotlin.math.min
import kotlin.math.sin

/** Interactive preview of relationships backed by the connected packet database. */
class HostRelationshipViewer(private val packets: PacketRepository) : JPanel(BorderLayout(0, 12)) {
    private val ink = Color(40, 54, 72)
    private val muted = Color(105, 121, 139)
    private val blue = Color(45, 115, 198)
    private val backgroundColor = Color(246, 249, 253)
    private val demoToggle = JCheckBox("Demo preview")
    private val localToggle = JCheckBox("Local graph")
    private val status = JLabel("Loading host relationships…")
    private val summary = JLabel("Hosts 0  ·  Relationships 0")
    private val hostModel = DefaultListModel<String>()
    private val hostList = JList(hostModel)
    private val detailTitle = JLabel("Select a host or connection")
    private val detailText = JTextArea("Click a node or line to inspect its packet evidence.")
    private val packetButton = JButton("Open source packet")
    private val graph = GraphCanvas(::selectNode, ::selectEdge)
    private val busy = AtomicBoolean(false)
    private var pending = false
    private var snapshot = demoHostRelationshipGraph()
    private var selectedEdge: HostGraphEdge? = null
    private var shownRevision: Pair<String, Long>? = null
    private val refreshDebounce = Timer(500) {
        if (isShowing && !demoToggle.isSelected) reload(onlyIfChanged = true)
    }.apply { isRepeats = false }
    private val inventorySubscription = packets.addInventoryListener {
        SwingUtilities.invokeLater { refreshDebounce.restart() }
    }

    init {
        background = backgroundColor
        border = BorderFactory.createEmptyBorder(16, 18, 16, 18)
        val heading = JLabel("Host relationships").apply {
            font = font.deriveFont(Font.BOLD, 23f)
            foreground = ink
        }
        val subtitle = JLabel("Observed connections between origins, with saved packets as evidence.").apply {
            foreground = muted
        }
        val top = JPanel(BorderLayout(0, 8)).apply {
            background = backgroundColor
            add(JPanel(BorderLayout()).apply {
                background = backgroundColor
                add(heading, BorderLayout.NORTH)
                add(subtitle, BorderLayout.SOUTH)
            }, BorderLayout.WEST)
            add(JPanel().apply {
                background = backgroundColor
                add(localToggle)
                add(demoToggle)
                add(JButton("Reset view").apply { addActionListener { graph.resetView() } })
                add(JButton("Refresh").apply { addActionListener { reload() } })
            }, BorderLayout.EAST)
        }
        demoToggle.background = backgroundColor
        demoToggle.foreground = ink
        demoToggle.addActionListener { reload() }
        localToggle.background = backgroundColor
        localToggle.foreground = ink
        localToggle.toolTipText = "Show only the selected host and its direct neighbors"
        localToggle.addActionListener { graph.localMode = localToggle.isSelected }
        val overview = JPanel(BorderLayout()).apply {
            background = Color.WHITE
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color(224, 232, 241)),
                BorderFactory.createEmptyBorder(10, 14, 10, 14),
            )
            summary.font = summary.font.deriveFont(Font.BOLD, 13f)
            summary.foreground = ink
            status.foreground = muted
            add(summary, BorderLayout.WEST)
            add(status, BorderLayout.EAST)
        }
        add(JPanel(BorderLayout(0, 10)).apply {
            background = backgroundColor
            add(top, BorderLayout.NORTH)
            add(overview, BorderLayout.SOUTH)
        }, BorderLayout.NORTH)

        hostList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        hostList.fixedCellHeight = 38
        hostList.background = Color.WHITE
        hostList.foreground = ink
        hostList.selectionBackground = Color(225, 239, 255)
        hostList.selectionForeground = ink
        hostList.cellRenderer = object : DefaultListCellRenderer() {
            override fun getListCellRendererComponent(
                list: JList<*>?, value: Any?, index: Int, isSelected: Boolean, cellHasFocus: Boolean,
            ): Component {
                val label = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus) as JLabel
                label.text = value?.toString()?.substringAfter("://") ?: ""
                label.toolTipText = value?.toString()
                label.border = BorderFactory.createEmptyBorder(0, 10, 0, 10)
                label.background = if (isSelected) Color(225, 239, 255) else Color.WHITE
                label.foreground = ink
                return label
            }
        }
        hostList.addListSelectionListener {
            if (!it.valueIsAdjusting) hostList.selectedValue?.let(::selectNode)
        }
        val left = card("HOSTS", JScrollPane(hostList)).apply { preferredSize = Dimension(230, 540) }
        graph.preferredSize = Dimension(720, 540)
        val middle = card("RELATIONSHIP MAP  ·  scroll to zoom  ·  drag background to pan  ·  drag a node to move", graph)
        detailTitle.foreground = ink
        detailTitle.font = detailTitle.font.deriveFont(Font.BOLD, 15f)
        detailText.isEditable = false
        detailText.lineWrap = true
        detailText.wrapStyleWord = true
        detailText.foreground = ink
        detailText.background = Color.WHITE
        detailText.border = BorderFactory.createEmptyBorder(12, 3, 10, 3)
        packetButton.isEnabled = false
        packetButton.addActionListener { selectedEdge?.takeIf { !snapshot.demo }?.let { openPacket(it.latestPacketId) } }
        val rightContent = JPanel(BorderLayout(0, 8)).apply {
            background = Color.WHITE
            border = BorderFactory.createEmptyBorder(8, 12, 12, 12)
            add(detailTitle, BorderLayout.NORTH)
            add(JScrollPane(detailText).apply { border = BorderFactory.createEmptyBorder() }, BorderLayout.CENTER)
            add(packetButton, BorderLayout.SOUTH)
        }
        val right = card("EVIDENCE", rightContent).apply { preferredSize = Dimension(265, 540) }
        val inner = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, middle, right).apply {
            resizeWeight = 1.0
            dividerSize = 6
            border = BorderFactory.createEmptyBorder()
        }
        add(JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, inner).apply {
            resizeWeight = 0.0
            dividerSize = 6
            border = BorderFactory.createEmptyBorder()
        }, BorderLayout.CENTER)
        preferredSize = Dimension(1180, 660)
        addHierarchyListener { event ->
            if (event.changeFlags and java.awt.event.HierarchyEvent.SHOWING_CHANGED.toLong() != 0L && isShowing) reload(onlyIfChanged = true)
        }
        reload()
    }

    fun close() { refreshDebounce.stop(); inventorySubscription.close() }

    private fun card(title: String, content: JComponent): JPanel = JPanel(BorderLayout(0, 7)).apply {
        background = Color.WHITE
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(224, 232, 241)),
            BorderFactory.createEmptyBorder(12, 12, 12, 12),
        )
        add(JLabel(title).apply {
            font = font.deriveFont(Font.BOLD, 11f)
            foreground = muted
        }, BorderLayout.NORTH)
        add(content, BorderLayout.CENTER)
    }

    private fun reload(onlyIfChanged: Boolean = false) {
        if (!busy.compareAndSet(false, true)) { pending = true; return }
        val demoRequested = demoToggle.isSelected
        val previousRevision = shownRevision
        object : SwingWorker<Pair<HostGraphSnapshot, Pair<String, Long>?>?, Unit>() {
            override fun doInBackground(): Pair<HostGraphSnapshot, Pair<String, Long>?>? {
                if (demoRequested) return demoHostRelationshipGraph() to null
                val revision = packets.inventoryRevision()
                if (onlyIfChanged && revision == previousRevision) return null
                val live = packets.hostRelationshipGraph()
                return (live?.takeIf { it.nodes.isNotEmpty() } ?: demoHostRelationshipGraph()) to revision
            }

            override fun done() {
                try {
                    val result = get()
                    if (result != null && demoRequested == demoToggle.isSelected) showSnapshot(result.first, result.second)
                    else if (demoRequested != demoToggle.isSelected) pending = true
                } catch (error: Exception) {
                    status.text = "Could not load graph: ${error.cause?.message ?: error.message}"
                } finally {
                    busy.set(false)
                    if (pending) { pending = false; reload() }
                }
            }
        }.execute()
    }

    private fun showSnapshot(value: HostGraphSnapshot, revision: Pair<String, Long>?) {
        snapshot = value
        shownRevision = revision
        selectedEdge = null
        packetButton.isEnabled = false
        hostModel.clear()
        value.nodes.forEach { hostModel.addElement(it.origin) }
        graph.show(value)
        summary.text = "Hosts ${value.nodes.size}  ·  Relationships ${value.edges.size}  ·  Sampled packets ${value.sampledPackets}"
        status.text = when {
            value.demo && demoToggle.isSelected -> "DEMO · illustrative data"
            value.demo -> "DEMO · no connected packets yet"
            value.sampledPackets >= value.sampleLimit -> "LIVE DB · latest ${value.sampleLimit} packets"
            else -> "LIVE DB · saved traffic"
        }
        detailTitle.text = "Select a host or connection"
        detailText.text = if (value.demo) "Example data only. Select a node or line to preview the layout." else
            "Select a node or line to inspect the relationship and its saved packet evidence."
    }

    private fun selectNode(origin: String) {
        val node = snapshot.nodes.firstOrNull { it.origin == origin } ?: return
        selectedEdge = null
        packetButton.isEnabled = false
        graph.selectNode(origin)
        if (hostList.selectedValue != origin) hostList.setSelectedValue(origin, true)
        val incoming = snapshot.edges.count { it.target == origin }
        val outgoing = snapshot.edges.count { it.source == origin }
        detailTitle.text = origin.substringAfter("://")
        detailText.text = buildString {
            appendLine(origin)
            appendLine()
            appendLine("Saved packets in view: ${node.packetCount}")
            appendLine("Incoming relations: $incoming")
            appendLine("Outgoing relations: $outgoing")
            if (!node.observed) appendLine("This origin appears in a reference but has no saved request in the current view.")
            if (snapshot.demo) appendLine("\nIllustrative demo data")
        }
    }

    private fun selectEdge(edge: HostGraphEdge) {
        selectedEdge = edge
        hostList.clearSelection()
        graph.selectEdge(edge)
        detailTitle.text = "${edge.kind} relationship"
        detailText.text = buildString {
            appendLine("FROM  ${edge.source}")
            appendLine("TO    ${edge.target}")
            appendLine()
            appendLine("Observed packets: ${edge.packetCount}")
            appendLine("Latest source: DB #${edge.latestPacketId}")
            appendLine()
            appendLine(when (edge.kind) {
                "Redirect" -> "A captured 3xx response points to the target origin through its Location header."
                else -> "A captured request to the target origin carries a Referer from the source origin."
            })
            if (snapshot.demo) appendLine("\nIllustrative demo data; packet IDs cannot be opened.")
        }
        packetButton.isEnabled = !snapshot.demo
    }

    private fun openPacket(id: Long) {
        packetButton.isEnabled = false
        object : SwingWorker<PacketDetail?, Unit>() {
            override fun doInBackground() = packets.getPacket(id, 65_536)
            override fun done() {
                packetButton.isEnabled = true
                try {
                    val packet = get() ?: throw IllegalStateException("Saved packet is unavailable")
                    val tabs = JTabbedPane().apply {
                        addTab("Request", messageText(packet.requestHeaders, packet.requestBodyBase64))
                        addTab("Response", messageText(packet.responseHeaders ?: "No saved response", packet.responseBodyBase64))
                    }
                    tabs.preferredSize = Dimension(780, 520)
                    JOptionPane.showMessageDialog(this@HostRelationshipViewer, tabs,
                        "DB #${packet.id} · ${packet.method} ${packet.url}", JOptionPane.PLAIN_MESSAGE)
                } catch (error: Exception) {
                    detailText.text = "Could not open DB #$id: ${error.cause?.message ?: error.message}"
                }
            }
        }.execute()
    }

    private fun messageText(headers: String, bodyBase64: String?): JScrollPane {
        val body = bodyBase64?.let { runCatching {
            String(Base64.getDecoder().decode(it), StandardCharsets.UTF_8)
        }.getOrNull() }
        val area = JTextArea(headers + if (body != null) "\n\n$body" else "").apply {
            isEditable = false
            font = Font(Font.MONOSPACED, Font.PLAIN, 12)
            caretPosition = 0
        }
        return JScrollPane(area)
    }

    private class GraphCanvas(
        private val onNode: (String) -> Unit,
        private val onEdge: (HostGraphEdge) -> Unit,
    ) : JPanel() {
        private var snapshot = demoHostRelationshipGraph()
        private var selectedNode: String? = null
        private var selectedEdge: HostGraphEdge? = null
        private var hoveredNode: String? = null
        private val positions = mutableMapOf<String, Point2D.Double>()
        private var zoom = 1.0
        private var panX = 0.0
        private var panY = 0.0
        private var draggingNode: String? = null
        private var lastMouseX = 0
        private var lastMouseY = 0
        private var moved = false
        var localMode = false
            set(value) { field = value; repaint() }

        init {
            background = Color.WHITE
            val mouse = object : MouseAdapter() {
                override fun mousePressed(event: MouseEvent) {
                    lastMouseX = event.x
                    lastMouseY = event.y
                    draggingNode = nodeAt(event.x, event.y)
                    moved = false
                }

                override fun mouseDragged(event: MouseEvent) {
                    val dx = event.x - lastMouseX
                    val dy = event.y - lastMouseY
                    if (dx != 0 || dy != 0) moved = true
                    draggingNode?.let { origin ->
                        positions[origin]?.let { point ->
                            point.x += dx / zoom
                            point.y += dy / zoom
                        }
                    } ?: run {
                        panX += dx
                        panY += dy
                    }
                    lastMouseX = event.x
                    lastMouseY = event.y
                    repaint()
                }

                override fun mouseReleased(event: MouseEvent) {
                    if (!moved) {
                        val node = nodeAt(event.x, event.y)
                        if (node != null) onNode(node)
                        else edgeAt(event.x, event.y)?.let(onEdge)
                    }
                    draggingNode = null
                }

                override fun mouseClicked(event: MouseEvent) {
                    if (event.clickCount == 2 && nodeAt(event.x, event.y) == null) resetView()
                }

                override fun mouseMoved(event: MouseEvent) {
                    val hovered = nodeAt(event.x, event.y)
                    if (hoveredNode != hovered) { hoveredNode = hovered; repaint() }
                    cursor = java.awt.Cursor.getPredefinedCursor(
                        if (hovered != null || edgeAt(event.x, event.y) != null)
                            java.awt.Cursor.HAND_CURSOR else java.awt.Cursor.MOVE_CURSOR,
                    )
                }
            }
            addMouseListener(mouse)
            addMouseMotionListener(mouse)
            addMouseWheelListener { event ->
                val before = screenToWorld(event.x, event.y)
                zoom = (zoom * Math.pow(1.13, -event.preciseWheelRotation)).coerceIn(0.35, 3.5)
                panX = event.x - width / 2.0 - before.x * zoom
                panY = event.y - height / 2.0 - before.y * zoom
                repaint()
            }
            layoutNodes()
        }

        fun show(value: HostGraphSnapshot) {
            snapshot = value
            selectedNode = null
            selectedEdge = null
            hoveredNode = null
            layoutNodes()
            resetView()
        }
        fun selectNode(origin: String) { selectedNode = origin; selectedEdge = null; repaint() }
        fun selectEdge(edge: HostGraphEdge) { selectedEdge = edge; selectedNode = null; repaint() }
        fun resetView() { zoom = 1.0; panX = 0.0; panY = 0.0; repaint() }

        private fun layoutNodes() {
            positions.clear()
            val ids = snapshot.nodes.map { it.origin }
            ids.forEachIndexed { index, origin ->
                val angle = -PI / 2 + 2 * PI * index / ids.size.coerceAtLeast(1)
                positions[origin] = Point2D.Double(260 * cos(angle), 260 * sin(angle))
            }
            if (ids.size < 2) return
            repeat(240) { iteration ->
                val forces = ids.associateWith { Point2D.Double() }
                for (i in ids.indices) for (j in i + 1 until ids.size) {
                    val a = positions.getValue(ids[i]); val b = positions.getValue(ids[j])
                    val dx = a.x - b.x; val dy = a.y - b.y
                    val distanceSquared = (dx * dx + dy * dy).coerceAtLeast(100.0)
                    val force = 20_000.0 / distanceSquared
                    val distance = kotlin.math.sqrt(distanceSquared)
                    forces.getValue(ids[i]).apply { x += dx / distance * force; y += dy / distance * force }
                    forces.getValue(ids[j]).apply { x -= dx / distance * force; y -= dy / distance * force }
                }
                snapshot.edges.forEach { edge ->
                    val a = positions[edge.source] ?: return@forEach
                    val b = positions[edge.target] ?: return@forEach
                    val dx = b.x - a.x; val dy = b.y - a.y
                    val distance = hypot(dx, dy).coerceAtLeast(1.0)
                    val force = (distance - 185) * 0.025
                    forces.getValue(edge.source).apply { x += dx / distance * force; y += dy / distance * force }
                    forces.getValue(edge.target).apply { x -= dx / distance * force; y -= dy / distance * force }
                }
                val cooling = 0.45 * (1.0 - iteration / 300.0)
                ids.forEach { id ->
                    val point = positions.getValue(id); val force = forces.getValue(id)
                    point.x = (point.x + (force.x - point.x * 0.004) * cooling).coerceIn(-550.0, 550.0)
                    point.y = (point.y + (force.y - point.y * 0.004) * cooling).coerceIn(-420.0, 420.0)
                }
            }
            val minX = positions.values.minOf { it.x }; val maxX = positions.values.maxOf { it.x }
            val minY = positions.values.minOf { it.y }; val maxY = positions.values.maxOf { it.y }
            val centerX = (minX + maxX) / 2; val centerY = (minY + maxY) / 2
            val scaleX = 370.0 / ((maxX - minX) / 2).coerceAtLeast(1.0)
            val scaleY = 180.0 / ((maxY - minY) / 2).coerceAtLeast(1.0)
            positions.values.forEach { point ->
                point.x = (point.x - centerX) * scaleX
                point.y = (point.y - centerY) * scaleY
            }
        }

        override fun paintComponent(graphics: Graphics) {
            super.paintComponent(graphics)
            val g = graphics.create() as Graphics2D
            try {
                g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                val visible = visibleOrigins()
                val original = g.transform
                g.translate(width / 2.0 + panX, height / 2.0 + panY)
                g.scale(zoom, zoom)
                snapshot.edges.filter { it.source in visible && it.target in visible }.forEach { edge ->
                    val a = positions[edge.source] ?: return@forEach
                    val b = positions[edge.target] ?: return@forEach
                    val selected = edge == selectedEdge
                    val highlighted = hoveredNode == edge.source || hoveredNode == edge.target ||
                        selectedNode == edge.source || selectedNode == edge.target
                    val base = if (edge.kind == "Redirect") Color(232, 141, 65) else Color(58, 132, 215)
                    val alpha = if (selected || highlighted) 230 else 105
                    g.color = Color(base.red, base.green, base.blue, alpha)
                    g.stroke = BasicStroke(if (selected) 3.6f else if (highlighted) 2.6f else 1.6f)
                    val dx = b.x - a.x; val dy = b.y - a.y
                    val distance = hypot(dx, dy).coerceAtLeast(1.0)
                    val ux = dx / distance; val uy = dy / distance
                    val endX = b.x - ux * (radius(edge.target) + 3)
                    val endY = b.y - uy * (radius(edge.target) + 3)
                    g.drawLine(a.x.toInt(), a.y.toInt(), endX.toInt(), endY.toInt())
                    g.drawLine((endX - 9 * cos(kotlin.math.atan2(uy, ux) - 0.5)).toInt(),
                        (endY - 9 * sin(kotlin.math.atan2(uy, ux) - 0.5)).toInt(), endX.toInt(), endY.toInt())
                    g.drawLine((endX - 9 * cos(kotlin.math.atan2(uy, ux) + 0.5)).toInt(),
                        (endY - 9 * sin(kotlin.math.atan2(uy, ux) + 0.5)).toInt(), endX.toInt(), endY.toInt())
                    if (selected) {
                        val label = "${edge.kind} · ${edge.packetCount}"
                        g.font = g.font.deriveFont(Font.BOLD, 12f)
                        val lx = ((a.x + b.x) / 2).toInt(); val ly = ((a.y + b.y) / 2).toInt()
                        val w = g.fontMetrics.stringWidth(label) + 16
                        g.color = Color.WHITE
                        g.fillRoundRect(lx - w / 2, ly - 15, w, 23, 12, 12)
                        g.color = base
                        g.drawString(label, lx - w / 2 + 8, ly + 1)
                    }
                }
                snapshot.nodes.filter { it.origin in visible }.forEach { node ->
                    val point = positions[node.origin] ?: return@forEach
                    val r = radius(node.origin)
                    val active = node.origin == selectedNode || node.origin == hoveredNode
                    val fill = if (active) Color(38, 113, 197) else if (node.observed) Color(85, 156, 226) else Color(180, 190, 202)
                    g.color = Color(fill.red, fill.green, fill.blue, 40)
                    g.fillOval((point.x - r - 8).toInt(), (point.y - r - 8).toInt(), (2 * r + 16).toInt(), (2 * r + 16).toInt())
                    g.color = fill
                    g.fillOval((point.x - r).toInt(), (point.y - r).toInt(), (2 * r).toInt(), (2 * r).toInt())
                    g.color = Color.WHITE
                    g.font = g.font.deriveFont(Font.BOLD, 12f)
                    val count = node.packetCount.toString()
                    g.drawString(count, (point.x - g.fontMetrics.stringWidth(count) / 2).toInt(), (point.y + 4).toInt())
                    val host = node.origin.substringAfter("://").substringBeforeLast(':')
                    val label = if (host.length > 25) host.take(23) + "…" else host
                    g.color = Color(40, 54, 72)
                    g.font = g.font.deriveFont(Font.BOLD, 12f)
                    g.drawString(label, (point.x - g.fontMetrics.stringWidth(label) / 2).toInt(), (point.y + r + 22).toInt())
                }
                g.transform = original
                g.font = g.font.deriveFont(Font.PLAIN, 12f)
                g.color = Color(58, 132, 215); g.fillOval(18, 18, 10, 10)
                g.color = Color(78, 94, 111); g.drawString("Referer", 34, 28)
                g.color = Color(232, 141, 65); g.fillOval(111, 18, 10, 10)
                g.color = Color(78, 94, 111); g.drawString("Redirect", 127, 28)
                if (localMode && selectedNode == null) g.drawString("Select a host for its local graph", 18, 51)
            } finally { g.dispose() }
        }

        private fun visibleOrigins(): Set<String> {
            val focus = selectedNode
            if (!localMode || focus == null) return snapshot.nodes.map { it.origin }.toSet()
            return snapshot.edges.asSequence().filter { it.source == focus || it.target == focus }
                .flatMap { sequenceOf(it.source, it.target) }.toSet() + focus
        }

        private fun radius(origin: String): Double {
            val packets = snapshot.nodes.firstOrNull { it.origin == origin }?.packetCount ?: 0
            return min(29.0, 14.0 + ln(packets + 1.0) * 2.2)
        }

        private fun screenToWorld(x: Int, y: Int) = Point2D.Double(
            (x - width / 2.0 - panX) / zoom, (y - height / 2.0 - panY) / zoom,
        )

        private fun nodeAt(x: Int, y: Int): String? {
            val point = screenToWorld(x, y)
            return visibleOrigins().firstOrNull { origin ->
                positions[origin]?.let { hypot(it.x - point.x, it.y - point.y) <= radius(origin) + 5 } == true
            }
        }

        private fun edgeAt(x: Int, y: Int): HostGraphEdge? {
            val point = screenToWorld(x, y)
            return snapshot.edges.asSequence()
                .filter { it.source in visibleOrigins() && it.target in visibleOrigins() }
                .map { it to distanceToEdge(it, point) }
                .minByOrNull { it.second }
                ?.takeIf { it.second < 10 / zoom }?.first
        }

        private fun distanceToEdge(edge: HostGraphEdge, point: Point2D.Double): Double {
            val a = positions[edge.source] ?: return Double.MAX_VALUE
            val b = positions[edge.target] ?: return Double.MAX_VALUE
            val dx = b.x - a.x; val dy = b.y - a.y
            val t = (((point.x - a.x) * dx + (point.y - a.y) * dy) / (dx * dx + dy * dy).coerceAtLeast(1.0)).coerceIn(0.0, 1.0)
            return hypot(point.x - (a.x + t * dx), point.y - (a.y + t * dy))
        }
    }
}
