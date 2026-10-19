package net.portswigger.mcp.openapi

import net.portswigger.mcp.packet.PacketDetail
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Cursor
import java.awt.Dimension
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.GridLayout
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
import javax.swing.JComponent
import javax.swing.JLabel
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
    private val createRepeaterTab: (RepeaterDraft) -> Unit,
    private val loadPacket: (Long) -> PacketDetail?,
    sendPacketToRepeater: (PacketDetail) -> Unit,
    createPacketRequestEditor: (PacketDetail) -> Component,
    createPacketResponseEditor: (PacketDetail) -> Component,
) : JPanel(BorderLayout()) {
    private val projectLabel = JLabel("Connect a packet project with start_packet_capture")
    private val hostSelector = JComboBox<String>()
    private val search = JTextField(24)
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
    private val packetPanel = PacketDetailPanel(
        sendToRepeater = sendPacketToRepeater,
        createRequestEditor = createPacketRequestEditor,
        createResponseEditor = createPacketResponseEditor,
        close = { closePacket() },
    )
    private var detailSplit: JSplitPane? = null
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
    private val expanded = mutableSetOf<String>()
    private var updatingHost = false
    private var document: OpenApiDocument? = null
    private var shownProject: String? = null
    private var signature: String? = null
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
            add(JLabel("Host:"))
            add(hostSelector)
            add(JLabel("Search:"))
            add(search)
            add(JLabel("Theme:"))
            add(whiteTheme)
            add(darkTheme)
            add(JButton("Reload").apply { addActionListener { signature = null; reload() } })
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
        center.add(viewerScroll, BorderLayout.CENTER)
        add(center, BorderLayout.CENTER)
        whiteTheme.addActionListener { applyTheme() }
        darkTheme.addActionListener { applyTheme() }
        applyTheme()

        hostSelector.addActionListener {
            if (!updatingHost) { closePacket(); signature = null; expanded.clear(); reload() }
        }
        search.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(event: DocumentEvent) = renderOperations()
            override fun removeUpdate(event: DocumentEvent) = renderOperations()
            override fun changedUpdate(event: DocumentEvent) = renderOperations()
        })
        timer.start()
        reload()
    }

    fun close() {
        timer.stop()
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
        packetPanel.setDarkTheme(darkTheme.isSelected)
        renderOperations()
    }

    private fun reload() {
        if (!busy.compareAndSet(false, true)) return
        val requestedHost = hostSelector.selectedItem as? String
        object : SwingWorker<Snapshot, Unit>() {
            override fun doInBackground(): Snapshot {
                val project = store.projectPath()
                val specs = store.list()
                val host = requestedHost?.takeIf { selected -> specs.any { it.host == selected } }
                    ?: specs.firstOrNull()?.host
                val loaded = host?.let { runCatching { store.load(it) }.getOrNull() }
                return Snapshot(project?.toString(), specs, host, loaded)
            }

            override fun done() {
                try { showSnapshot(get()) }
                catch (error: Exception) { status.text = "OpenAPI reload failed: ${error.cause?.message ?: error.message}" }
                finally { busy.set(false) }
            }
        }.execute()
    }

    private fun showSnapshot(snapshot: Snapshot) {
        if (shownProject != snapshot.project || document?.info?.host != snapshot.host) closePacket()
        shownProject = snapshot.project
        projectLabel.text = snapshot.project?.let { "Project: $it" }
            ?: "Connect a packet project with start_packet_capture"
        val newSignature = listOf(snapshot.project, snapshot.host,
            snapshot.specs.joinToString { "${it.host}:${it.sha256}:${it.error}" }).joinToString("|")
        if (signature == newSignature) return
        signature = newSignature
        updatingHost = true
        hostSelector.removeAllItems()
        snapshot.specs.forEach { hostSelector.addItem(it.host) }
        hostSelector.selectedItem = snapshot.host
        updatingHost = false
        document = snapshot.document
        val selected = snapshot.specs.firstOrNull { it.host == snapshot.host }
        status.text = when {
            snapshot.project == null -> "No packet project connected"
            selected == null -> "No OpenAPI YAML files in the configured folder yet."
            selected.error != null -> "${selected.host}: ${selected.error}"
            else -> "${selected.host} · ${selected.operationCount} operations · ${selected.path}"
        }
        val loaded = snapshot.document
        title.text = loaded?.let { "${it.info.title}  ·  ${it.info.version}" } ?: "OpenAPI"
        description.text = loaded?.let {
            listOf(it.description, it.servers.joinToString("  ·  ")).filter(String::isNotBlank).joinToString("\n")
        } ?: "Select a host with an OpenAPI document."
        description.rows = description.text.lines().size.coerceIn(1, 5)
        renderOperations()
    }

    private fun renderOperations() {
        operationsPanel.removeAll()
        val loaded = document
        val term = search.text.trim().lowercase()
        val matches = loaded?.operations?.filter { operation ->
            term.isEmpty() || listOf(operation.method, operation.path, operation.summary,
                operation.operationId.orEmpty(), operation.tags.joinToString()).any { term in it.lowercase() }
        } ?: emptyList()
        if (matches.isEmpty()) {
            operationsPanel.add(JLabel(if (loaded == null) "No OpenAPI document loaded." else "No matching operations.").apply {
                foreground = ink
            })
        } else {
            matches.forEach { operation ->
                operationsPanel.add(operationCard(operation, loaded!!))
                operationsPanel.add(Box.createVerticalStrut(7))
            }
        }
        operationsPanel.revalidate()
        operationsPanel.repaint()
    }

    private fun operationCard(operation: OpenApiOperation, loaded: OpenApiDocument): JPanel {
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
            add(JLabel(operation.path).apply {
                font = font.deriveFont(Font.BOLD)
                foreground = ink
            }, BorderLayout.CENTER)
            add(JLabel(operation.summary.ifBlank { operation.tags.joinToString() }).apply {
                foreground = ink
            }, BorderLayout.EAST)
        }, BorderLayout.CENTER)
        val chevron = JLabel("▾", SwingConstants.CENTER).apply {
            preferredSize = Dimension(42, 44)
            foreground = ink
        }
        header.add(chevron, BorderLayout.EAST)
        var detail: JPanel? = null
        if (key in expanded) {
            detail = operationDetails(operation, loaded)
            routeDetailWheel(detail)
            card.add(detail, BorderLayout.CENTER)
        } else chevron.text = "▸"
        fun toggle() {
            if (detail == null) {
                detail = operationDetails(operation, loaded)
                routeDetailWheel(detail!!)
                card.add(detail, BorderLayout.CENTER)
                expanded.add(key)
                chevron.text = "▾"
            } else {
                card.remove(detail)
                detail = null
                expanded.remove(key)
                chevron.text = "▸"
            }
            card.maximumSize = Dimension(Int.MAX_VALUE, card.preferredSize.height)
            card.revalidate()
            card.repaint()
        }
        val click = object : MouseAdapter() {
            override fun mouseClicked(event: MouseEvent) = toggle()
        }
        bindHeaderClick(header, click)
        header.isFocusable = true
        header.accessibleContext.accessibleName = "${operation.method} ${operation.path}. Expand or collapse"
        header.getInputMap(WHEN_FOCUSED).put(KeyStroke.getKeyStroke("SPACE"), "toggle")
        header.actionMap.put("toggle", object : javax.swing.AbstractAction() {
            override fun actionPerformed(event: java.awt.event.ActionEvent) = toggle()
        })
        card.add(header, BorderLayout.NORTH)
        card.maximumSize = Dimension(Int.MAX_VALUE, card.preferredSize.height)
        return card
    }

    private fun bindHeaderClick(component: Component, click: MouseAdapter) {
        component.addMouseListener(click)
        if (component is java.awt.Container) component.components.forEach { bindHeaderClick(it, click) }
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
        val packetIds = operation.packetIds.mapNotNull { it.toLongOrNull()?.takeIf { id -> id > 0 } }
            .distinct().sortedDescending()
        if (packetIds.isNotEmpty()) {
            val visibleIds = packetIds.take(MAX_VISIBLE_PACKET_IDS)
            val heading = if (packetIds.size > visibleIds.size) {
                "Source packets · latest ${visibleIds.size} of ${packetIds.size}"
            } else "Source packets"
            content.add(sectionHeading(heading))
            content.add(sectionBody(JPanel(GridLayout(0, 4, 8, 6)).apply {
                background = paleBlue
                visibleIds.forEach { id ->
                    add(JButton("DB #$id  ↗").apply {
                        toolTipText = "Inspect stored packet #$id"
                        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                        addActionListener { openPacket(id) }
                    })
                }
            }))
        }
        val parameterInputs = linkedMapOf<String, JTextField>()
        val parameterPanel = parametersPanel(operation.parameters, parameterInputs)
        val tryOut = JButton("Send to Repeater")
        tryOut.toolTipText = "Create an editable request in Repeater without sending it"
        tryOut.addActionListener {
            runCatching {
                val values = parameterInputs.mapValues { (_, field) -> field.text }
                val draft = OpenApiRequestBuilder.build(loaded, operation, values)
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
            content.add(sectionBody(contentPanel(operation.requestBody, loaded)))
        }
        content.add(sectionHeading("Responses"))
        content.add(sectionBody(responsesPanel(operation.responses, loaded)))
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
                preferredSize = Dimension(component.preferredSize.width + 10, if (header) 34 else 40)
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

    private fun contentPanel(body: Map<*, *>?, loaded: OpenApiDocument): JPanel {
        if (body == null) return messagePanel("No request body documented.")
        val panel = JPanel(BorderLayout(0, 6))
        panel.background = paleBlue
        val description = listOfNotNull(body["description"]?.toString(),
            if (body["required"] == true) "Required" else null).joinToString("  ·  ")
        if (description.isNotBlank()) panel.add(JLabel(description).apply { foreground = ink }, BorderLayout.NORTH)
        panel.add(mediaTypesPanel(body["content"] as? Map<*, *>, loaded), BorderLayout.CENTER)
        return panel
    }

    private fun responsesPanel(responses: Map<*, *>, loaded: OpenApiDocument): JPanel {
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
            description.add(mediaTypesPanel(response?.get("content") as? Map<*, *>, loaded), BorderLayout.CENTER)
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

    private fun mediaTypesPanel(content: Map<*, *>?, loaded: OpenApiDocument): JPanel {
        if (content.isNullOrEmpty()) return messagePanel("No content schema documented.")
        val panel = JPanel(BorderLayout(0, 7))
        panel.background = paleBlue
        val selector = JComboBox(content.keys.map { it.toString() }.toTypedArray())
        val schemaContainer = JPanel(BorderLayout())
        schemaContainer.background = paleBlue
        fun showSchema() {
            schemaContainer.removeAll()
            val media = content[selector.selectedItem] as? Map<*, *>
            val schema = media?.get("schema")
            val example = media?.get("example") ?: (media?.get("examples") as? Map<*, *>)
                ?.values?.firstOrNull()?.let { (it as? Map<*, *>)?.get("value") }
            val preview = if (example == null) OpenApiRequestBuilder.exampleJson(schema, loaded.schemas)
                else OpenApiRequestBuilder.exampleJson(mapOf("example" to example), loaded.schemas)
            val tabs = JTabbedPane()
            tabs.addTab(if (example == null) "Example Value (generated)" else "Example Value",
                textPane(preview, 190, code = true))
            tabs.addTab("Schema", schemaTree(schema, loaded.schemas))
            routeDetailWheel(tabs)
            schemaContainer.add(tabs, BorderLayout.CENTER)
            schemaContainer.revalidate()
            schemaContainer.repaint()
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

    private fun openPacket(id: Long) {
        val generation = ++packetLoadGeneration
        if (detailSplit == null) {
            val scrollPosition = viewerScroll.verticalScrollBar.value
            center.remove(viewerScroll)
            val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, viewerScroll, packetPanel).apply {
                resizeWeight = 1.0
                border = BorderFactory.createEmptyBorder()
                dividerSize = 7
            }
            detailSplit = split
            center.add(split, BorderLayout.CENTER)
            KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(packetEscapeDispatcher)
            center.revalidate()
            SwingUtilities.invokeLater {
                split.dividerLocation = (split.width - packetPanel.preferredSize.width).coerceAtLeast(350)
                viewerScroll.verticalScrollBar.value = scrollPosition
            }
        }
        packetPanel.showLoading(id)
        object : SwingWorker<PacketDetail?, Unit>() {
            override fun doInBackground(): PacketDetail? = loadPacket(id)
            override fun done() {
                if (generation != packetLoadGeneration || detailSplit == null) return
                runCatching { get() }.onSuccess { packet ->
                    if (packet == null) packetPanel.showError(id, "Packet #$id was not found in the connected database.")
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
        center.remove(split)
        split.leftComponent = null
        split.rightComponent = null
        center.add(viewerScroll, BorderLayout.CENTER)
        detailSplit = null
        center.revalidate()
        center.repaint()
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

    private data class Snapshot(
        val project: String?, val specs: List<OpenApiSpecInfo>,
        val host: String?, val document: OpenApiDocument?,
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
