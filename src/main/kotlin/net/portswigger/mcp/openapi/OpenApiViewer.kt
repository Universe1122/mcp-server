package net.portswigger.mcp.openapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import net.portswigger.mcp.packet.PacketDetail
import net.portswigger.mcp.packet.PacketRepository
import net.portswigger.mcp.packet.EndpointInspectionTag
import net.portswigger.mcp.packet.SwaggerPacketSearchHit
import net.portswigger.mcp.packet.SwaggerPacketSearchPage
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Cursor
import java.awt.Dimension
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.KeyEventDispatcher
import java.awt.KeyboardFocusManager
import java.awt.Rectangle
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.event.MouseWheelEvent
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.BorderFactory
import javax.swing.ButtonGroup
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JMenuItem
import javax.swing.JPopupMenu
import javax.swing.MenuSelectionManager
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.Scrollable
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.JTree
import javax.swing.JToggleButton
import javax.swing.KeyStroke
import javax.swing.SwingConstants
import javax.swing.SwingWorker
import javax.swing.SwingUtilities
import javax.swing.Timer
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.tree.DefaultMutableTreeNode

private const val MAX_VISIBLE_PACKET_IDS = 20

/** Read-only, Burp-native OpenAPI explorer for the connected packet project. */
class OpenApiViewer(
    private val store: OpenApiStore,
    private val tagStore: PacketRepository,
    private val createRepeaterTab: (RepeaterDraft) -> Unit,
    private val loadPacket: (Int, Long) -> PacketDetail?,
    sendPacketToRepeater: (PacketDetail) -> Unit,
    createPacketRequestEditor: (PacketDetail) -> Component,
    createPacketResponseEditor: (PacketDetail) -> Component,
) : JPanel(BorderLayout()) {
    private val projectLabel = JLabel("Connect a packet project with start_packet_capture")
    private val serverModel = DefaultListModel<OpenApiServer>()
    private val serverList = JList(serverModel)
    private val search = JTextField(24)
    private val includePackets = JCheckBox("Include packets")
    private val searchStatus = JLabel()
    private val whiteTheme = JToggleButton("White", true)
    private val darkTheme = JToggleButton("Dark")
    private val themeGroup = ButtonGroup().apply { add(whiteTheme); add(darkTheme) }
    private val status = JLabel("No OpenAPI files loaded")
    private val title = JLabel("OpenAPI")
    private val description = JTextArea()
    private val operationsPanel = JPanel()
    private val heading = JPanel(BorderLayout())
    private val page = object : JPanel(BorderLayout(0, 12)), Scrollable {
        override fun getPreferredScrollableViewportSize(): Dimension = preferredSize
        override fun getScrollableUnitIncrement(visibleRect: Rectangle, orientation: Int, direction: Int): Int = 18
        override fun getScrollableBlockIncrement(visibleRect: Rectangle, orientation: Int, direction: Int): Int =
            (visibleRect.height - 18).coerceAtLeast(18)
        override fun getScrollableTracksViewportWidth(): Boolean = true
        override fun getScrollableTracksViewportHeight(): Boolean = false
    }
    private val viewerScroll = JScrollPane(page)
    private val center = JPanel(BorderLayout())
    private val endpointPane = JPanel(BorderLayout())
    private val contentHost = JPanel(BorderLayout())
    private val packetPanel = PacketDetailPanel(
        sendToRepeater = sendPacketToRepeater,
        createRequestEditor = createPacketRequestEditor,
        createResponseEditor = createPacketResponseEditor,
        close = { closePacket() },
    )
    private var detailSplit: JSplitPane? = null
    private var packetOperationKey: String? = null
    private var packetLoadGeneration = 0
    private val packetEscapeDispatcher = KeyEventDispatcher { event ->
        if (event.id != KeyEvent.KEY_PRESSED || event.keyCode != KeyEvent.VK_ESCAPE ||
            detailSplit == null || !isShowing
        ) {
            false
        } else {
            val viewerWindow = SwingUtilities.getWindowAncestor(this)
            if (viewerWindow?.isActive == true && MenuSelectionManager.defaultManager().selectedPath.isEmpty()) {
                event.consume()
                closePacket()
                true
            } else false
        }
    }
    private val busy = AtomicBoolean(false)
    private var reloadPending = false
    private val expanded = mutableSetOf<String>()
    private var selectedServer: OpenApiServer? = null
    private var updatingServers = false
    private var document: OpenApiDocument? = null
    private var inspectionTags: Map<String, EndpointInspectionTag> = emptyMap()
    private var shownProject: String? = null
    private var signature: String? = null
    private val packetSearchDebounce = Timer(350) { loadPacketSearchPage() }.apply { isRepeats = false }
    private var packetSearchGeneration = 0L
    private var packetSearchBusy = false
    private var packetSearchError: String? = null
    private var packetMatches = emptyList<Pair<String, SwaggerPacketSearchHit>>()
    private var packetNextBeforeId: Long? = Long.MAX_VALUE
    private var packetHasMore = false
    private val timer = Timer(3000) { reload() }
    private data class Palette(
        val page: Color, val detail: Color, val ink: Color, val rule: Color,
        val tableHeader: Color, val field: Color, val code: Color, val codeInk: Color,
    )
    private val lightPalette = Palette(Color.WHITE, Color(236, 247, 255), Color(36, 47, 65),
        Color(190, 205, 219), Color(224, 238, 250), Color.WHITE, Color(45, 47, 51), Color(239, 242, 248))
    private val darkPalette = Palette(Color(33, 37, 43), Color(40, 54, 66), Color(232, 238, 245),
        Color(84, 108, 126), Color(48, 67, 82), Color(30, 38, 46), Color(24, 28, 33), Color(239, 242, 248))
    private val palette: Palette get() = if (darkTheme.isSelected) darkPalette else lightPalette
    private val pageColor: Color get() = palette.page
    private val ink: Color get() = palette.ink
    private val paleBlue: Color get() = palette.detail
    private val rule: Color get() = palette.rule

    init {
        border = BorderFactory.createEmptyBorder(10, 12, 10, 12)
        val controls = JPanel(BorderLayout(8, 8))
        controls.add(projectLabel, BorderLayout.NORTH)
        controls.add(JPanel().apply {
            add(JLabel("Search:"))
            add(search)
            add(includePackets)
            add(searchStatus)
            add(JLabel("Theme:"))
            add(whiteTheme)
            add(darkTheme)
            add(JButton("Reload").apply { addActionListener { signature = null; schedulePacketSearch(); reload() } })
        }, BorderLayout.CENTER)
        controls.add(status, BorderLayout.SOUTH)
        add(controls, BorderLayout.NORTH)

        title.font = title.font.deriveFont(Font.BOLD, 20f)
        title.foreground = ink
        description.isEditable = false
        description.background = pageColor
        description.foreground = ink
        description.lineWrap = true
        description.wrapStyleWord = true
        description.border = BorderFactory.createEmptyBorder(4, 0, 8, 0)
        operationsPanel.layout = BoxLayout(operationsPanel, BoxLayout.Y_AXIS)
        operationsPanel.background = pageColor
        heading.add(title, BorderLayout.NORTH)
        heading.add(description, BorderLayout.CENTER)
        page.border = BorderFactory.createEmptyBorder(12, 14, 20, 14)
        page.add(heading, BorderLayout.NORTH)
        page.add(operationsPanel, BorderLayout.CENTER)
        viewerScroll.apply {
            border = BorderFactory.createEmptyBorder()
            viewport.background = pageColor
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            verticalScrollBar.unitIncrement = 18
        }
        serverList.cellRenderer = object : DefaultListCellRenderer() {
            override fun getListCellRendererComponent(list: JList<*>?, value: Any?, index: Int,
                                                       isSelected: Boolean, cellHasFocus: Boolean): Component {
                val colors = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus) as JLabel
                val server = value as? OpenApiServer
                val row = JPanel(BorderLayout(0, 2)).apply {
                    background = colors.background
                    border = BorderFactory.createEmptyBorder(7, 10, 7, 10)
                }
                val main = JLabel(server?.url.orEmpty()).apply {
                    font = font.deriveFont(Font.BOLD)
                    foreground = colors.foreground
                }
                val source = JLabel(server?.let { "${it.specHost}.yaml" }.orEmpty()).apply {
                    font = font.deriveFont(font.size2D - 1f)
                    foreground = if (isSelected) colors.foreground else Color(110, 120, 135)
                }
                row.add(main, BorderLayout.NORTH)
                row.add(source, BorderLayout.SOUTH)
                row.toolTipText = server?.let { "${it.url}  ·  ${it.specHost}.yaml" }
                return row
            }
        }
        serverList.selectionMode = javax.swing.ListSelectionModel.SINGLE_SELECTION
        serverList.accessibleContext.accessibleName = "OpenAPI servers"
        val serverPane = JPanel(BorderLayout(0, 8)).apply {
            border = BorderFactory.createEmptyBorder(8, 4, 8, 6)
            add(JLabel("Servers"), BorderLayout.NORTH)
            add(JScrollPane(serverList).apply {
                horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            }, BorderLayout.CENTER)
            preferredSize = Dimension(245, 600)
            minimumSize = Dimension(170, 200)
        }
        endpointPane.add(JLabel("Endpoints").apply {
            border = BorderFactory.createEmptyBorder(8, 12, 5, 0)
        }, BorderLayout.NORTH)
        endpointPane.add(viewerScroll, BorderLayout.CENTER)
        contentHost.add(endpointPane, BorderLayout.CENTER)
        val serverSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, serverPane, contentHost).apply {
            resizeWeight = 0.0
            dividerSize = 6
            border = BorderFactory.createEmptyBorder()
        }
        center.add(serverSplit, BorderLayout.CENTER)
        add(center, BorderLayout.CENTER)
        SwingUtilities.invokeLater {
            serverSplit.dividerLocation = 245
        }
        whiteTheme.addActionListener { applyTheme() }
        darkTheme.addActionListener { applyTheme() }
        applyTheme()

        serverList.addListSelectionListener { event ->
            if (!event.valueIsAdjusting && !updatingServers) {
                val choice = serverList.selectedValue
                if (choice != selectedServer) {
                    selectedServer = choice
                    expanded.clear()
                    closePacket()
                    signature = null
                    schedulePacketSearch()
                    reload()
                }
            }
        }
        search.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(event: DocumentEvent) = schedulePacketSearch()
            override fun removeUpdate(event: DocumentEvent) = schedulePacketSearch()
            override fun changedUpdate(event: DocumentEvent) = schedulePacketSearch()
        })
        includePackets.addActionListener { schedulePacketSearch() }
        timer.start()
        reload()
    }

    fun close() {
        timer.stop()
        packetSearchDebounce.stop()
        packetSearchGeneration++
        KeyboardFocusManager.getCurrentKeyboardFocusManager().removeKeyEventDispatcher(packetEscapeDispatcher)
    }

    private fun applyTheme() {
        page.background = pageColor
        heading.background = pageColor
        operationsPanel.background = pageColor
        title.foreground = ink
        description.background = pageColor
        description.foreground = ink
        viewerScroll.viewport.background = pageColor
        serverList.background = pageColor
        serverList.foreground = ink
        packetPanel.setDarkTheme(darkTheme.isSelected)
        renderOperations()
    }

    private fun reload() {
        if (!busy.compareAndSet(false, true)) { reloadPending = true; return }
        val requestedServer = selectedServer
        object : SwingWorker<Snapshot, Unit>() {
            override fun doInBackground(): Snapshot {
                val project = store.projectPath()
                val specs = store.list()
                val servers = specs.flatMap { spec ->
                    spec.servers.ifEmpty { listOf("https://${spec.host}") }
                        .mapNotNull { parseOpenApiServer(spec.host, it) }
                }.distinctBy { Triple(it.specHost, it.origin, it.basePath) }
                val selected = requestedServer?.takeIf { it in servers } ?: servers.firstOrNull()
                val host = selected?.specHost
                val loaded = host?.let { runCatching { store.load(it) }.getOrNull() }
                val tags = selected?.let { runCatching {
                    tagStore.endpointInspectionTags(it.specHost, it.canonicalUrl)
                }.getOrDefault(emptyList()) }
                    ?: emptyList()
                return Snapshot(project?.toString(), specs, servers, selected, loaded, tags, tagStore.inspectionTagRevision())
            }

            override fun done() {
                try { showSnapshot(get()) }
                catch (error: Exception) { status.text = "OpenAPI reload failed: ${error.cause?.message ?: error.message}" }
                finally {
                    busy.set(false)
                    if (reloadPending) { reloadPending = false; reload() }
                }
            }
        }.execute()
    }

    private fun showSnapshot(snapshot: Snapshot) {
        if (selectedServer != null && selectedServer != snapshot.selectedServer && selectedServer in snapshot.servers) {
            reloadPending = true
            return
        }
        val documentChanged = shownProject != snapshot.project || document?.info?.sha256 != snapshot.document?.info?.sha256 ||
            document?.info?.host != snapshot.selectedServer?.specHost || selectedServer != snapshot.selectedServer
        if (shownProject != snapshot.project || selectedServer != snapshot.selectedServer) {
            closePacket()
            expanded.clear()
        }
        shownProject = snapshot.project
        projectLabel.text = snapshot.project?.let { "Project: $it" }
            ?: "Connect a packet project with start_packet_capture"
        val newSignature = listOf(snapshot.project, snapshot.selectedServer?.specHost, snapshot.selectedServer?.url,
            snapshot.specs.joinToString { "${it.host}:${it.sha256}:${it.error}" },
            snapshot.tagRevision).joinToString("|")
        if (signature == newSignature) return
        signature = newSignature
        updatingServers = true
        serverModel.clear()
        snapshot.servers.forEach(serverModel::addElement)
        selectedServer = snapshot.selectedServer
        serverList.selectedIndex = snapshot.servers.indexOf(snapshot.selectedServer)
        updatingServers = false
        document = snapshot.document
        inspectionTags = snapshot.tags.associateBy { "${it.method} ${it.path}" }
        if (documentChanged) schedulePacketSearch()
        val selected = snapshot.specs.firstOrNull { it.host == snapshot.selectedServer?.specHost }
        val serverOperationCount = snapshot.document?.operations?.count { operation ->
            snapshot.selectedServer?.let { supportsServer(snapshot.document, operation, it) } == true
        } ?: 0
        status.text = when {
            snapshot.project == null -> "No packet project connected"
            selected == null && snapshot.specs.isEmpty() -> "No OpenAPI YAML files in the configured folder yet."
            selected == null -> "No valid HTTP server URL found in OpenAPI files."
            selected.error != null -> "${selected.host}: ${selected.error}"
            else -> "${snapshot.selectedServer?.url} · $serverOperationCount operations · ${selected.path}"
        }
        val loaded = snapshot.document
        title.text = loaded?.let { "${it.info.title}  ·  ${it.info.version}" } ?: "OpenAPI"
        description.text = loaded?.let {
            listOf(it.description, snapshot.selectedServer?.url.orEmpty()).filter(String::isNotBlank).joinToString("\n")
        } ?: "Select a host with an OpenAPI document."
        description.rows = description.text.lines().size.coerceIn(1, 5)
        renderOperations()
    }

    private fun renderOperations() {
        operationsPanel.removeAll()
        val loaded = document
        val server = selectedServer
        val term = search.text.trim()
        val packetHits = if (includePackets.isSelected && term.length >= 3)
            packetMatches.groupBy({ it.first }, { it.second }) else emptyMap()
        val matches = loaded?.operations?.filter { operation ->
            val key = "${operation.method} ${operation.path}"
            server != null && supportsServer(loaded, operation, server) &&
                (matchesOpenApiSearch(operation, inspectionTags[key]?.tag, term, loaded.schemas) ||
                    packetHits[key]?.isNotEmpty() == true)
        } ?: emptyList()
        if (matches.isEmpty()) {
            val message = when {
                loaded == null -> "No OpenAPI document loaded."
                packetSearchBusy -> "Searching saved packets…"
                else -> "No matching operations."
            }
            operationsPanel.add(JLabel(message).apply {
                foreground = ink
            })
        } else {
            matches.forEach { operation ->
                operationsPanel.add(operationCard(operation, loaded!!, packetHits["${operation.method} ${operation.path}"].orEmpty()))
                operationsPanel.add(Box.createVerticalStrut(7))
            }
        }
        if (includePackets.isSelected && packetHasMore && term.length >= 3) {
            operationsPanel.add(JButton("Load more packet matches").apply {
                alignmentX = LEFT_ALIGNMENT
                isEnabled = !packetSearchBusy
                addActionListener { loadPacketSearchPage() }
            })
        }
        searchStatus.text = when {
            !includePackets.isSelected -> ""
            term.length < 3 -> "3+ characters for packet search"
            packetSearchBusy -> "Searching packets…"
            packetSearchError != null -> "Packet search failed: $packetSearchError"
            else -> "${packetMatches.size} matching packets loaded${if (packetHasMore) " · more available" else ""}"
        }
        operationsPanel.revalidate()
        operationsPanel.repaint()
    }

    private fun schedulePacketSearch() {
        packetSearchDebounce.stop()
        packetSearchGeneration++
        packetSearchBusy = false
        packetSearchError = null
        packetMatches = emptyList()
        packetNextBeforeId = Long.MAX_VALUE
        packetHasMore = false
        renderOperations()
        if (includePackets.isSelected && search.text.trim().length >= 3 && document != null)
            packetSearchDebounce.restart()
    }

    private fun loadPacketSearchPage() {
        val loaded = document ?: return
        val server = selectedServer ?: return
        val query = search.text.trim()
        val beforeId = packetNextBeforeId ?: return
        if (!includePackets.isSelected || query.length < 3 || packetSearchBusy) return
        val generation = packetSearchGeneration
        val host = loaded.info.host
        packetSearchBusy = true
        renderOperations()
        object : SwingWorker<SwaggerPacketSearchPage, Unit>() {
            override fun doInBackground(): SwaggerPacketSearchPage =
                tagStore.searchSwaggerPackets(server.host, query, beforeId, 100, server.port, server.usesHttps)

            override fun done() {
                if (generation != packetSearchGeneration || document?.info?.host != host || selectedServer != server ||
                    search.text.trim() != query || !includePackets.isSelected) return
                packetSearchBusy = false
                runCatching { get() }.onSuccess { result ->
                    packetMatches = packetMatches + result.hits.mapNotNull { hit ->
                        matchingOpenApiOperation(loaded.operations, hit.method, hit.url, server)?.let { operation ->
                            "${operation.method} ${operation.path}" to hit
                        }
                    }
                    packetHasMore = result.hasMore
                    packetNextBeforeId = result.nextBeforeId
                }.onFailure { error ->
                    packetHasMore = false
                    packetNextBeforeId = null
                    packetSearchError = error.cause?.message ?: error.message ?: "Unknown error"
                }
                renderOperations()
            }
        }.execute()
    }

    private fun packetSearchPreview(hits: List<SwaggerPacketSearchHit>, operation: OpenApiOperation,
                                    loaded: OpenApiDocument): JPanel = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        background = paleBlue
        border = BorderFactory.createEmptyBorder(6, 16, 8, 16)
        add(JLabel("Packet matches · ${hits.size} loaded").apply {
            foreground = ink
            font = font.deriveFont(Font.BOLD)
            alignmentX = LEFT_ALIGNMENT
        })
        hits.take(3).forEach { hit ->
            val reference = hit.historyId?.let { "History #$it" } ?: "DB #${hit.packetId}"
            val excerpt = hit.snippet.replace(Regex("\\s+"), " ").take(80)
            add(JButton("$reference · ${hit.location} · $excerpt").apply {
                horizontalAlignment = SwingConstants.LEFT
                alignmentX = LEFT_ALIGNMENT
                toolTipText = "Open stored packet #${hit.packetId}"
                addActionListener { openSearchPacket(hit, operation, loaded) }
            })
        }
        if (hits.size > 3) add(JLabel("${hits.size - 3} more loaded matches").apply {
            foreground = ink
            alignmentX = LEFT_ALIGNMENT
        })
    }

    private fun operationCard(operation: OpenApiOperation, loaded: OpenApiDocument,
                              hits: List<SwaggerPacketSearchHit>): JPanel {
        val key = "${operation.method} ${operation.path}"
        val accent = methodColor(operation.method)
        val card = JPanel(BorderLayout())
        card.alignmentX = LEFT_ALIGNMENT
        card.border = BorderFactory.createLineBorder(accent, 1)
        val header = JPanel(BorderLayout(10, 0))
        header.background = paleBlue
        header.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        val method = JLabel(operation.method, SwingConstants.CENTER)
        method.isOpaque = true
        method.background = accent
        method.foreground = Color.WHITE
        method.font = method.font.deriveFont(Font.BOLD)
        method.preferredSize = Dimension(86, 44)
        header.add(method, BorderLayout.WEST)
        header.add(JPanel(BorderLayout(12, 0)).apply {
            isOpaque = false
            add(JPanel(GridBagLayout()).apply {
                isOpaque = false
                add(JLabel(operation.path).apply {
                    font = font.deriveFont(Font.BOLD)
                    foreground = ink
                }, GridBagConstraints().apply {
                    gridx = 0
                    anchor = GridBagConstraints.WEST
                    insets = Insets(0, 0, 0, 8)
                })
                inspectionTags[key]?.let { saved ->
                    add(inspectionBadge(saved.tag), GridBagConstraints().apply {
                        gridx = 1
                        anchor = GridBagConstraints.WEST
                    })
                }
                add(Box.createHorizontalGlue(), GridBagConstraints().apply {
                    gridx = 2
                    weightx = 1.0
                    fill = GridBagConstraints.HORIZONTAL
                })
            }, BorderLayout.CENTER)
            add(JLabel(operation.summary.ifBlank { operation.tags.joinToString() }).apply {
                foreground = ink
            }, BorderLayout.EAST)
        }, BorderLayout.CENTER)
        val chevron = JLabel(if (key in expanded) "▾" else "▸", SwingConstants.CENTER).apply {
            preferredSize = Dimension(42, 44)
            foreground = ink
        }
        header.add(chevron, BorderLayout.EAST)
        val body = JPanel(BorderLayout()).apply { background = paleBlue }
        if (hits.isNotEmpty()) body.add(packetSearchPreview(hits, operation, loaded), BorderLayout.NORTH)
        var detail: JPanel? = null
        if (key in expanded) {
            detail = operationDetails(operation, loaded)
            routeDetailWheel(detail)
            body.add(detail, BorderLayout.CENTER)
        }
        fun toggle() {
            if (detail == null) {
                detail = operationDetails(operation, loaded)
                routeDetailWheel(detail!!)
                body.add(detail, BorderLayout.CENTER)
                expanded.add(key)
                chevron.text = "▾"
            } else {
                if (packetOperationKey == key) closePacket()
                body.remove(detail)
                detail = null
                expanded.remove(key)
                chevron.text = "▸"
            }
            card.maximumSize = Dimension(Int.MAX_VALUE, card.preferredSize.height)
            card.revalidate()
            card.repaint()
        }
        val popup = JPopupMenu().apply {
            listOf("VULN" to "Mark VULN", "SUSPECT" to "Mark SUSPECT", "SAFE" to "Mark SAFE", null to "Clear tag").forEach { (tag, title) ->
                add(JMenuItem(title).apply { addActionListener { updateInspectionTag(loaded.info.host, operation, tag) } })
            }
            addSeparator()
            add(JMenuItem("Tag history").apply {
                addActionListener { showInspectionTagHistory(loaded.info.host, operation) }
            })
        }
        val click = object : MouseAdapter() {
            override fun mousePressed(event: MouseEvent) = showPopup(event)
            override fun mouseReleased(event: MouseEvent) = showPopup(event)
            override fun mouseClicked(event: MouseEvent) {
                if (SwingUtilities.isLeftMouseButton(event)) toggle()
            }
            private fun showPopup(event: MouseEvent) {
                if (event.isPopupTrigger) popup.show(event.component, event.x, event.y)
            }
        }
        bindHeaderClick(header, click)
        header.isFocusable = true
        header.accessibleContext.accessibleName = "${operation.method} ${operation.path}. Expand or collapse"
        header.getInputMap(WHEN_FOCUSED).put(KeyStroke.getKeyStroke("SPACE"), "toggle")
        header.actionMap.put("toggle", object : javax.swing.AbstractAction() {
            override fun actionPerformed(event: java.awt.event.ActionEvent) = toggle()
        })
        card.add(header, BorderLayout.NORTH)
        card.add(body, BorderLayout.CENTER)
        card.maximumSize = Dimension(Int.MAX_VALUE, card.preferredSize.height)
        return card
    }

    private fun bindHeaderClick(component: Component, click: MouseAdapter) {
        component.addMouseListener(click)
        if (component is java.awt.Container) component.components.forEach { bindHeaderClick(it, click) }
    }

    private fun inspectionBadge(tag: String): JLabel = JLabel(tag).apply {
        isOpaque = true
        background = when (tag) {
            "VULN" -> Color(174, 45, 55)
            "SUSPECT" -> Color(155, 105, 0)
            else -> Color(36, 125, 75)
        }
        foreground = Color.WHITE
        font = font.deriveFont(Font.BOLD, 10f)
        border = BorderFactory.createEmptyBorder(3, 7, 3, 7)
        toolTipText = when (tag) {
            "VULN" -> "Confirmed vulnerability"
            "SUSPECT" -> "Potential issue; not yet confirmed"
            else -> "Reviewed: no issue identified"
        }
    }

    private fun updateInspectionTag(host: String, operation: OpenApiOperation, tag: String?) {
        val serverUrl = selectedServer?.canonicalUrl ?: return
        object : SwingWorker<Unit, Unit>() {
            override fun doInBackground() {
                tagStore.setEndpointInspectionTag(host, operation.method, operation.path, tag, "human", serverUrl)
            }
            override fun done() {
                try {
                    get()
                    signature = null
                    reload()
                } catch (error: Exception) {
                    status.text = "Could not save endpoint tag: ${error.cause?.message ?: error.message}"
                }
            }
        }.execute()
    }

    private fun showInspectionTagHistory(host: String, operation: OpenApiOperation) {
        val serverUrl = selectedServer?.canonicalUrl ?: return
        object : SwingWorker<List<net.portswigger.mcp.packet.EndpointTagChange>, Unit>() {
            override fun doInBackground() = tagStore.endpointTagHistory(host, serverUrl, operation.method, operation.path)
            override fun done() {
                try {
                    val history = get()
                    val message = if (history.isEmpty()) "No tag changes recorded." else history.joinToString("\n") {
                        "${it.updatedAt}  ${it.source}: ${it.oldTag ?: "none"} → ${it.newTag ?: "none"}"
                    }
                    javax.swing.JOptionPane.showMessageDialog(page, message, "Tag history: ${operation.method} ${operation.path}",
                        javax.swing.JOptionPane.INFORMATION_MESSAGE)
                } catch (error: Exception) {
                    status.text = "Could not load tag history: ${error.cause?.message ?: error.message}"
                }
            }
        }.execute()
    }

    private fun routeDetailWheel(component: Component) {
        DetailWheelRouter.install(component, viewerScroll)
    }

    private fun operationDetails(operation: OpenApiOperation, loaded: OpenApiDocument): JPanel {
        val content = JPanel()
        content.layout = BoxLayout(content, BoxLayout.Y_AXIS)
        content.background = paleBlue
        content.border = BorderFactory.createEmptyBorder(8, 16, 12, 16)
        val overview = buildString {
            if (operation.description.isNotBlank()) appendLine(operation.description)
            operation.operationId?.let { appendLine("Operation ID: $it") }
            if (operation.tags.isNotEmpty()) appendLine("Tags: ${operation.tags.joinToString()}")
        }.trim()
        if (overview.isNotBlank()) content.add(sectionBody(textPane(overview, 90)))
        val server = selectedServer
        val candidateRefs = operation.historyRefs.distinct().sortedWith(
            compareByDescending<OpenApiHistoryRef> { it.packetId }.thenByDescending { it.historyId })
        val packetUrls = if (server == null) emptyMap() else runCatching {
            tagStore.packetUrlsForServer(candidateRefs.take(100).map { it.packetId }, server.host, server.port, server.usesHttps)
        }.getOrDefault(emptyMap())
        val packetRefs = candidateRefs.filter { ref ->
            val url = packetUrls[ref.packetId]
            url != null && server != null && matchingOpenApiOperation(listOf(operation), operation.method, url, server) != null
        }
        if (packetRefs.isNotEmpty()) {
            val visibleRefs = packetRefs.take(MAX_VISIBLE_PACKET_IDS)
            val heading = if (packetRefs.size > visibleRefs.size) {
                "Source packets · latest ${visibleRefs.size} of ${packetRefs.size}"
            } else "Source packets"
            content.add(sectionHeading(heading))
            content.add(sectionBody(JPanel(GridBagLayout()).apply {
                background = paleBlue
                visibleRefs.forEachIndexed { index, ref ->
                    add(JButton("History #${ref.historyId}  ↗").apply {
                        margin = Insets(2, 8, 2, 8)
                        toolTipText = "Inspect Burp History #${ref.historyId} (stored packet #${ref.packetId})"
                        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                        addActionListener { openPacket(ref, operation, loaded) }
                    }, GridBagConstraints().apply {
                        gridx = index % 4
                        gridy = index / 4
                        anchor = GridBagConstraints.WEST
                        insets = Insets(0, 0, 6, 8)
                    })
                }
                add(Box.createHorizontalGlue(), GridBagConstraints().apply {
                    gridx = 4
                    gridy = 0
                    weightx = 1.0
                    fill = GridBagConstraints.HORIZONTAL
                })
            }))
        }
        val parameterInputs = linkedMapOf<String, JTextField>()
        val parameterPanel = parametersPanel(operation.parameters, parameterInputs)
        val tryOut = JButton("Send to Repeater")
        tryOut.toolTipText = "Create an editable request in Repeater without sending it"
        tryOut.addActionListener {
            runCatching {
                val values = parameterInputs.mapValues { (_, field) -> field.text }
                val draft = OpenApiRequestBuilder.build(loaded, operation, values, selectedServer?.url)
                createRepeaterTab(draft)
                status.text = "Created Repeater tab: ${draft.tabName}  ·  ${draft.host}:${draft.port}"
            }.onFailure { error ->
                status.text = "Could not create Repeater tab: ${error.message}"
            }
        }
        content.add(sectionHeading("Parameters", tryOut))
        content.add(sectionBody(parameterPanel))
        if (operation.requestBody != null) {
            content.add(sectionHeading("Request body"))
            content.add(sectionBody(contentPanel(operation.requestBody, loaded, operation)))
        }
        content.add(sectionHeading("Responses"))
        content.add(sectionBody(responsesPanel(operation.responses, loaded, operation)))
        return content
    }

    private fun parametersPanel(parameters: List<Map<*, *>>, inputs: MutableMap<String, JTextField>): JPanel {
        if (parameters.isEmpty()) return messagePanel("No parameters documented.")
        val columns = arrayOf("Name", "In", "Required", "Type", "Description", "Example (editable)")
        val weights = doubleArrayOf(0.13, 0.09, 0.08, 0.09, 0.39, 0.22)
        val rows = JPanel(GridBagLayout())
        rows.background = paleBlue
        addParameterRow(rows, columns.map { JLabel(it) }, weights, 0, header = true)
        parameters.forEachIndexed { row, parameter ->
            val schema = parameter["schema"] as? Map<*, *>
            val name = parameter["name"]?.toString().orEmpty()
            val location = parameter["in"]?.toString().orEmpty()
            val field = JTextField(OpenApiRequestBuilder.parameterSample(parameter), 12).apply {
                toolTipText = "Editable sample used in the Repeater request draft"
                background = palette.field
                foreground = ink
                caretColor = ink
            }
            inputs["$location:$name"] = field
            addParameterRow(rows, listOf(
                JLabel(name), JLabel(location), JLabel((parameter["required"] ?: false).toString()),
                JLabel(schemaType(schema)), JLabel(parameter["description"]?.toString().orEmpty()), field,
            ), weights, row + 1)
        }
        return JPanel(BorderLayout()).apply {
            background = paleBlue
            add(rows, BorderLayout.CENTER)
            add(JLabel("Sample values populate Repeater drafts; edit them before sending.").apply {
                foreground = ink
                border = BorderFactory.createEmptyBorder(8, 4, 0, 0)
            }, BorderLayout.SOUTH)
            preferredSize = Dimension(500, 34 + parameters.size * 40 + 28)
        }
    }

    private fun addParameterRow(
        rows: JPanel, cells: List<Component>, weights: DoubleArray, row: Int, header: Boolean = false,
    ) {
        val columnWidths = intArrayOf(65, 45, 80, 55, 220, 145)
        cells.forEachIndexed { index, component ->
            if (component is JLabel) {
                component.foreground = ink
                component.toolTipText = component.text
            }
            val cell = JPanel(BorderLayout()).apply {
                background = if (header) palette.tableHeader else paleBlue
                border = BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 0, 1, 0, rule),
                    BorderFactory.createEmptyBorder(3, 5, 3, 5),
                )
                preferredSize = Dimension(columnWidths[index], if (header) 34 else 40)
                add(component, BorderLayout.CENTER)
            }
            rows.add(cell, GridBagConstraints().apply {
                gridx = index
                gridy = row
                weightx = weights[index]
                fill = GridBagConstraints.BOTH
            })
        }
    }

    private fun contentPanel(body: Map<*, *>?, loaded: OpenApiDocument, operation: OpenApiOperation): JPanel {
        if (body == null) return messagePanel("No request body documented.")
        val panel = JPanel(BorderLayout(0, 6))
        panel.background = paleBlue
        val description = listOfNotNull(body["description"]?.toString(),
            if (body["required"] == true) "Required" else null).joinToString("  ·  ")
        if (description.isNotBlank()) panel.add(JLabel(description).apply { foreground = ink }, BorderLayout.NORTH)
        panel.add(mediaTypesPanel(body["content"] as? Map<*, *>, loaded, operation), BorderLayout.CENTER)
        return panel
    }

    private fun responsesPanel(responses: Map<*, *>, loaded: OpenApiDocument, operation: OpenApiOperation): JPanel {
        if (responses.isEmpty()) return messagePanel("No responses documented.")
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.background = paleBlue
        panel.add(JPanel(BorderLayout()).apply {
            background = paleBlue
            add(JLabel("Code").apply { foreground = ink; preferredSize = Dimension(92, 28) }, BorderLayout.WEST)
            add(JLabel("Description").apply { foreground = ink }, BorderLayout.CENTER)
            add(JLabel("Links").apply { foreground = ink }, BorderLayout.EAST)
            alignmentX = LEFT_ALIGNMENT
        })
        responses.forEach { (code, value) ->
            val response = value as? Map<*, *>
            val row = JPanel(BorderLayout(12, 0))
            row.background = paleBlue
            row.border = BorderFactory.createMatteBorder(1, 0, 0, 0, rule)
            row.alignmentX = LEFT_ALIGNMENT
            row.add(JLabel(code.toString()).apply {
                foreground = ink
                preferredSize = Dimension(80, 50)
            }, BorderLayout.WEST)
            val description = JPanel(BorderLayout(0, 7))
            description.background = paleBlue
            description.add(JLabel(response?.get("description")?.toString().orEmpty()).apply {
                foreground = ink
                font = font.deriveFont(Font.BOLD)
            }, BorderLayout.NORTH)
            description.add(mediaTypesPanel(response?.get("content") as? Map<*, *>, loaded, operation, code.toString()), BorderLayout.CENTER)
            row.add(description, BorderLayout.CENTER)
            row.add(JLabel(if (response?.get("links") is Map<*, *>) "Links" else "No links").apply {
                foreground = ink
                preferredSize = Dimension(70, 50)
            }, BorderLayout.EAST)
            panel.add(row)
            panel.add(Box.createVerticalStrut(10))
        }
        return panel
    }

    private fun mediaTypesPanel(content: Map<*, *>?, loaded: OpenApiDocument,
                                operation: OpenApiOperation, responseCode: String? = null): JPanel {
        if (content.isNullOrEmpty()) return messagePanel("No content schema documented.")
        val panel = JPanel(BorderLayout(0, 7))
        panel.background = paleBlue
        val selector = JComboBox(content.keys.map { it.toString() }.toTypedArray())
        val schemaContainer = JPanel(BorderLayout())
        schemaContainer.background = paleBlue
        var previewGeneration = 0
        fun showSchema() {
            val generation = ++previewGeneration
            schemaContainer.removeAll()
            val media = content[selector.selectedItem] as? Map<*, *>
            val schema = media?.get("schema")
            val example = media?.get("example") ?: (media?.get("examples") as? Map<*, *>)
                ?.values?.firstOrNull()?.let { (it as? Map<*, *>)?.get("value") }
            val preview = if (example == null) "No observed example is documented."
                else OpenApiRequestBuilder.exampleJson(mapOf("example" to example), loaded.schemas)
            val tabs = JTabbedPane()
            val previewText = JTextArea(preview).apply {
                isEditable = false
                font = Font(Font.MONOSPACED, Font.PLAIN, 12)
                background = palette.code
                foreground = palette.codeInk
                caretPosition = 0
            }
            tabs.addTab("Example Value", JScrollPane(previewText).apply { preferredSize = Dimension(500, 190) })
            tabs.addTab("Schema", schemaTree(schema, loaded.schemas))
            routeDetailWheel(tabs)
            schemaContainer.add(tabs, BorderLayout.CENTER)
            schemaContainer.revalidate()
            schemaContainer.repaint()
            if (example == null && responseCode != null) {
                val mime = selector.selectedItem.toString().substringBefore(';').trim().lowercase()
                object : SwingWorker<String?, Unit>() {
                    override fun doInBackground(): String? = observedResponseExample(loaded, operation, responseCode, mime)
                    override fun done() {
                        if (generation != previewGeneration) return
                        runCatching { get() }.getOrNull()?.let {
                            previewText.text = it
                            previewText.caretPosition = 0
                        }
                    }
                }.execute()
            }
        }
        selector.addActionListener { showSchema() }
        panel.add(JPanel(BorderLayout()).apply {
            background = paleBlue
            add(JLabel("Media type: ").apply { foreground = ink }, BorderLayout.WEST)
            add(selector, BorderLayout.CENTER)
        }, BorderLayout.NORTH)
        panel.add(schemaContainer, BorderLayout.CENTER)
        showSchema()
        return panel
    }

    private fun observedResponseExample(loaded: OpenApiDocument, operation: OpenApiOperation,
                                        responseCode: String, mime: String): String? {
        if (!(mime.startsWith("text/") || mime.contains("json") || mime.contains("xml") ||
                    mime == "application/x-www-form-urlencoded")) return null
        for (ref in operation.historyRefs.sortedByDescending { it.packetId }.take(MAX_VISIBLE_PACKET_IDS)) {
            val packet = loadPacket(ref.historyId, ref.packetId) ?: continue
            if (!matchesOperation(loaded, operation, packet)) continue
            if (packet.statusCode?.toString() != responseCode || packet.responseBodyTruncated) continue
            val actualMime = packet.responseHeaders?.lineSequence()?.firstOrNull {
                it.startsWith("Content-Type:", ignoreCase = true)
            }?.substringAfter(':')?.trim()?.substringBefore(';')?.lowercase()
            if (actualMime != null && actualMime != mime) continue
            val bytes = packet.responseBodyBase64?.let { java.util.Base64.getDecoder().decode(it) } ?: continue
            if (bytes.isEmpty()) continue
            val text = bytes.toString(Charsets.UTF_8)
            if ('\u0000' in text) continue
            val formatted = if (mime.contains("json")) runCatching {
                Json { prettyPrint = true }.encodeToString(JsonElement.serializer(), Json.parseToJsonElement(text))
            }.getOrDefault(text) else text
            val displayed = if (formatted.length > 32_000) formatted.take(32_000) + "\n… (preview truncated)" else formatted
            return "Observed response · History #${ref.historyId}\n\n$displayed"
        }
        return null
    }

    private fun sectionHeading(label: String, action: JButton? = null): JPanel =
        JPanel(BorderLayout()).apply {
            background = pageColor
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, rule),
                BorderFactory.createEmptyBorder(9, 8, 9, 8),
            )
            add(JLabel(label).apply {
                foreground = ink
                font = font.deriveFont(Font.BOLD, 15f)
            }, BorderLayout.WEST)
            if (action != null) add(action, BorderLayout.EAST)
            alignmentX = LEFT_ALIGNMENT
            maximumSize = Dimension(Int.MAX_VALUE, 52)
        }

    private fun sectionBody(body: JPanel): JPanel = JPanel(BorderLayout()).apply {
        background = paleBlue
        border = BorderFactory.createEmptyBorder(12, 12, 16, 12)
        add(body, BorderLayout.CENTER)
        alignmentX = LEFT_ALIGNMENT
        maximumSize = Dimension(Int.MAX_VALUE, body.preferredSize.height + 28)
    }

    private fun schemaTree(schema: Any?, components: Map<*, *>): JScrollPane {
        val root = DefaultMutableTreeNode("Schema")
        addSchemaNodes(root, schema, components, 0, emptySet())
        val tree = JTree(root)
        tree.isRootVisible = false
        tree.showsRootHandles = true
        tree.background = paleBlue
        tree.foreground = ink
        tree.cellRenderer = object : javax.swing.tree.DefaultTreeCellRenderer() {
            override fun getTreeCellRendererComponent(
                tree: JTree, value: Any?, selected: Boolean, expanded: Boolean,
                leaf: Boolean, row: Int, hasFocus: Boolean,
            ): Component {
                textNonSelectionColor = ink
                backgroundNonSelectionColor = paleBlue
                textSelectionColor = palette.codeInk
                backgroundSelectionColor = palette.tableHeader
                return super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus)
            }
        }
        for (row in 0 until tree.rowCount.coerceAtMost(4)) tree.expandRow(row)
        return JScrollPane(tree).apply {
            viewport.background = paleBlue
            preferredSize = Dimension(500, 190)
        }
    }

    private fun addSchemaNodes(
        parent: DefaultMutableTreeNode, raw: Any?, components: Map<*, *>,
        depth: Int, visited: Set<String>,
    ) {
        if (depth > 16) { parent.add(DefaultMutableTreeNode("…")); return }
        val schema = raw as? Map<*, *> ?: run {
            parent.add(DefaultMutableTreeNode(if (raw == null) "Schema not specified" else raw.toString()))
            return
        }
        val ref = schema["\$ref"]?.toString()
        if (ref != null) {
            val node = parent.addNode(ref)
            val name = ref.removePrefix("#/components/schemas/")
            if (name != ref && ref !in visited) addSchemaNodes(node, components[name], components, depth + 1, visited + ref)
            return
        }
        val type = schemaType(schema)
        if (type.isNotBlank()) parent.addNode("type: $type")
        for (field in listOf("description", "format", "default", "example", "enum")) {
            schema[field]?.let { parent.addNode("$field: $it") }
        }
        val required = (schema["required"] as? List<*>)?.map { it.toString() }?.toSet() ?: emptySet()
        (schema["properties"] as? Map<*, *>)?.forEach { (name, value) ->
            val label = "$name${if (name.toString() in required) " *" else ""}: ${schemaType(value as? Map<*, *>)}"
            addSchemaNodes(parent.addNode(label), value, components, depth + 1, visited)
        }
        schema["items"]?.let { addSchemaNodes(parent.addNode("items"), it, components, depth + 1, visited) }
        for (composition in listOf("allOf", "oneOf", "anyOf")) {
            (schema[composition] as? List<*>)?.forEachIndexed { index, value ->
                addSchemaNodes(parent.addNode("$composition #${index + 1}"), value, components, depth + 1, visited)
            }
        }
        schema["additionalProperties"]?.let {
            if (it is Map<*, *>) addSchemaNodes(parent.addNode("additionalProperties"), it, components, depth + 1, visited)
        }
    }

    private fun DefaultMutableTreeNode.addNode(label: String): DefaultMutableTreeNode =
        DefaultMutableTreeNode(label).also { add(it) }

    private fun schemaType(schema: Map<*, *>?): String = when {
        schema == null -> ""
        schema["type"] != null -> schema["type"].toString()
        schema["\$ref"] != null -> schema["\$ref"].toString().substringAfterLast('/')
        schema["properties"] != null -> "object"
        else -> ""
    }

    private fun textPane(value: String, height: Int, code: Boolean = false): JPanel = JPanel(BorderLayout()).apply {
        background = if (code) palette.code else paleBlue
        val text = JTextArea(value)
        text.isEditable = false
        text.lineWrap = true
        text.wrapStyleWord = true
        text.background = if (code) palette.code else paleBlue
        text.foreground = if (code) palette.codeInk else ink
        if (code) text.font = Font(Font.MONOSPACED, Font.PLAIN, 12)
        text.border = BorderFactory.createEmptyBorder(4, 4, 4, 4)
        add(JScrollPane(text), BorderLayout.CENTER)
        preferredSize = Dimension(500, height)
    }

    private fun messagePanel(message: String): JPanel = JPanel(BorderLayout()).apply {
        background = paleBlue
        add(JLabel(message).apply { foreground = ink }, BorderLayout.NORTH)
        preferredSize = Dimension(500, 50)
    }

    private fun matchesOperation(loaded: OpenApiDocument, operation: OpenApiOperation,
                                 packet: PacketDetail): Boolean {
        val server = selectedServer ?: return false
        if (!supportsServer(loaded, operation, server) ||
            !packetMatchesServer(packet.url, packet.port, packet.usesHttps, server) ||
            !packet.method.equals(operation.method, ignoreCase = true)) return false
        val actualPath = operationPathForServer(packet.url, server) ?: return false
        val expected = operation.path.split('/')
        val actual = actualPath.split('/')
        return expected.size == actual.size && expected.zip(actual).all { (template, segment) ->
            (template.startsWith('{') && template.endsWith('}') && segment.isNotEmpty()) || template == segment
        }
    }

    private fun openPacket(ref: OpenApiHistoryRef, operation: OpenApiOperation, loaded: OpenApiDocument) {
        openPacketDetail(ref.historyId.toLong(), operation, loaded) { loadPacket(ref.historyId, ref.packetId) }
    }

    private fun openSearchPacket(hit: SwaggerPacketSearchHit, operation: OpenApiOperation, loaded: OpenApiDocument) {
        openPacketDetail(hit.historyId?.toLong() ?: hit.packetId, operation, loaded) {
            if (hit.historyId != null) loadPacket(hit.historyId, hit.packetId)
            else tagStore.getPacket(hit.packetId, 1_048_576)
        }
    }

    private fun openPacketDetail(id: Long, operation: OpenApiOperation, loaded: OpenApiDocument,
                                 fetch: () -> PacketDetail?) {
        val generation = ++packetLoadGeneration
        packetOperationKey = "${operation.method} ${operation.path}"
        if (detailSplit == null) {
            val scrollPosition = viewerScroll.verticalScrollBar.value
            contentHost.remove(endpointPane)
            val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, endpointPane, packetPanel).apply {
                resizeWeight = 1.0
                dividerSize = 7
                border = BorderFactory.createEmptyBorder()
            }
            detailSplit = split
            contentHost.add(split, BorderLayout.CENTER)
            KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(packetEscapeDispatcher)
            contentHost.revalidate()
            SwingUtilities.invokeLater {
                split.dividerLocation = (split.width - packetPanel.preferredSize.width).coerceAtLeast(350)
                viewerScroll.verticalScrollBar.value = scrollPosition
            }
        }
        packetPanel.showLoading(id)
        object : SwingWorker<PacketDetail?, Unit>() {
            override fun doInBackground(): PacketDetail? = fetch()
            override fun done() {
                if (generation != packetLoadGeneration || detailSplit == null) return
                runCatching { get() }.onSuccess { packet ->
                    if (packet == null || !matchesOperation(loaded, operation, packet))
                        packetPanel.showError(id, "Saved packet #$id does not match this endpoint in the connected database.")
                    else packetPanel.showPacket(packet)
                }.onFailure { error ->
                    packetPanel.showError(id, error.cause?.message ?: error.message ?: "Could not load packet")
                }
            }
        }.execute()
    }

    private fun closePacket() {
        ++packetLoadGeneration
        val split = detailSplit ?: return
        KeyboardFocusManager.getCurrentKeyboardFocusManager().removeKeyEventDispatcher(packetEscapeDispatcher)
        val scrollPosition = viewerScroll.verticalScrollBar.value
        contentHost.remove(split)
        split.leftComponent = null
        split.rightComponent = null
        contentHost.add(endpointPane, BorderLayout.CENTER)
        detailSplit = null
        packetOperationKey = null
        contentHost.revalidate()
        contentHost.repaint()
        SwingUtilities.invokeLater { viewerScroll.verticalScrollBar.value = scrollPosition }
    }

    private fun methodColor(method: String): Color = when (method) {
        "GET" -> Color(37, 112, 189)
        "POST" -> Color(47, 150, 88)
        "PUT" -> Color(196, 130, 29)
        "PATCH" -> Color(138, 89, 174)
        "DELETE" -> Color(190, 65, 65)
        else -> Color(91, 103, 115)
    }

    private fun escapeLabel(value: String): String = value.replace("&", "&amp;")
        .replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    private data class Snapshot(
        val project: String?, val specs: List<OpenApiSpecInfo>,
        val servers: List<OpenApiServer>, val selectedServer: OpenApiServer?, val document: OpenApiDocument?,
        val tags: List<EndpointInspectionTag>, val tagRevision: Long,
    )

}

/** Keep ordinary detail content on the outer scroll pane's native wheel path. */
internal object DetailWheelRouter {
    fun install(component: Component, outer: JScrollPane) {
        if (component is JScrollPane) {
            installNested(component, outer)
        } else if (component is java.awt.Container) {
            component.components.forEach { install(it, outer) }
        }
    }

    private fun installNested(component: Component, outer: JScrollPane) {
        if (component is JComponent && component.getClientProperty("openapiWheelRouted") == true) return
        if (component is JComponent) component.putClientProperty("openapiWheelRouted", true)
        if (component is JScrollPane) component.isWheelScrollingEnabled = false
        component.addMouseWheelListener { event -> forward(event, outer) }
        if (component is java.awt.Container) component.components.forEach { installNested(it, outer) }
    }

    private fun forward(event: MouseWheelEvent, outer: JScrollPane) {
        val bar = outer.verticalScrollBar
        val rotation = event.preciseWheelRotation.takeIf { it != 0.0 } ?: event.wheelRotation.toDouble()
        val end = (bar.maximum - bar.visibleAmount).coerceAtLeast(bar.minimum)
        if (!((rotation > 0 && bar.value >= end) || (rotation < 0 && bar.value <= bar.minimum))) {
            outer.dispatchEvent(MouseWheelEvent(outer, event.id, event.`when`, event.modifiersEx,
                event.x, event.y, event.xOnScreen, event.yOnScreen, event.clickCount,
                event.isPopupTrigger, event.scrollType, event.scrollAmount,
                event.wheelRotation, event.preciseWheelRotation))
        }
        event.consume()
    }
}
