package net.portswigger.mcp.packet

import java.awt.BorderLayout
import java.awt.Dimension
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.SwingWorker
import javax.swing.Timer
import javax.swing.table.DefaultTableModel

/** Passive, DB-backed view of exact observed routes. */
class ApiInventoryViewer(private val packets: PacketRepository) : JPanel(BorderLayout(0, 8)) {
    private val hostSelector = JComboBox<String>()
    private val status = JLabel("Connect a packet database to see observed APIs")
    private val details = JTextArea("Select a route to see its source packet IDs.")
    private val model = object : DefaultTableModel(
        arrayOf("Method", "Path", "Packets", "Status", "Response MIME", "Query", "Body", "First ID", "Last ID"), 0
    ) {
        override fun isCellEditable(row: Int, column: Int): Boolean = false
    }
    private val table = JTable(model)
    private val previous = JButton("Previous")
    private val next = JButton("Next")
    private val busy = AtomicBoolean(false)
    private val refreshQueued = AtomicBoolean(false)
    private val previousCursors = mutableListOf<String?>()
    private var cursor: String? = null
    private var nextCursor: String? = null
    private var selectedHost: String? = null
    private var routes: List<ApiRouteSummary> = emptyList()
    private var updatingHosts = false
    private var refreshPending = false
    private var shownRevision: Pair<String, Long>? = null
    private val refreshDebounce = Timer(300) {
        if (isShowing && previousCursors.isEmpty()) reload(onlyIfChanged = true)
    }.apply { isRepeats = false }
    private val inventorySubscription = packets.addInventoryListener {
        if (refreshQueued.compareAndSet(false, true)) javax.swing.SwingUtilities.invokeLater {
            refreshQueued.set(false)
            refreshDebounce.restart()
        }
    }

    init {
        border = BorderFactory.createEmptyBorder(10, 12, 10, 12)
        val toolbar = JPanel(BorderLayout(8, 6))
        toolbar.add(JPanel().apply {
            add(JLabel("Host:"))
            add(hostSelector)
            add(JButton("Refresh").apply { addActionListener { resetPage(); reload() } })
            add(previous)
            add(next)
        }, BorderLayout.NORTH)
        toolbar.add(status, BorderLayout.SOUTH)
        add(toolbar, BorderLayout.NORTH)

        table.autoResizeMode = JTable.AUTO_RESIZE_OFF
        table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION)
        table.rowHeight = 26
        val widths = intArrayOf(80, 450, 75, 115, 170, 65, 65, 80, 80)
        widths.forEachIndexed { index, width -> table.columnModel.getColumn(index).preferredWidth = width }
        table.selectionModel.addListSelectionListener { event -> if (!event.valueIsAdjusting) showSelectedRoute() }
        details.isEditable = false
        details.lineWrap = true
        details.wrapStyleWord = true
        details.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(table), JScrollPane(details)).apply {
            resizeWeight = 0.8
            dividerLocation = 460
        }
        add(split, BorderLayout.CENTER)
        preferredSize = Dimension(850, 620)

        hostSelector.addActionListener {
            if (!updatingHosts) {
                selectedHost = hostSelector.selectedItem as? String
                resetPage()
                reload()
            }
        }
        previous.addActionListener {
            if (previousCursors.isNotEmpty()) {
                cursor = previousCursors.removeAt(previousCursors.lastIndex)
                reload()
            }
        }
        next.addActionListener {
            nextCursor?.let {
                previousCursors.add(cursor)
                cursor = it
                reload()
            }
        }
        updateButtons()
        addHierarchyListener { event ->
            if (event.changeFlags and java.awt.event.HierarchyEvent.SHOWING_CHANGED.toLong() != 0L && isShowing) reload(onlyIfChanged = true)
        }
        reload()
    }

    fun close() { refreshDebounce.stop(); inventorySubscription.close() }

    private fun resetPage() {
        cursor = null
        nextCursor = null
        previousCursors.clear()
        updateButtons()
    }

    private fun reload(onlyIfChanged: Boolean = false) {
        if (!busy.compareAndSet(false, true)) { refreshPending = true; return }
        val requestedHost = selectedHost
        val requestedCursor = cursor
        val displayedRevision = shownRevision
        object : SwingWorker<Snapshot?, Unit>() {
            override fun doInBackground(): Snapshot? {
                val revision = packets.inventoryRevision()
                if (onlyIfChanged && revision == displayedRevision) return null
                val hosts = if (revision == null) emptyList() else packets.hosts()
                val host = requestedHost?.takeIf { it in hosts } ?: hosts.firstOrNull()
                val page = host?.let { packets.apiInventory(it, 100, requestedCursor, false) }
                return Snapshot(hosts, host, page, revision)
            }

            override fun done() {
                try {
                    val snapshot = get()
                    if (snapshot != null) {
                        val visibleHost = hostSelector.selectedItem as? String
                        if (visibleHost == requestedHost && cursor == requestedCursor) showSnapshot(snapshot)
                        else {
                            selectedHost = visibleHost
                            refreshPending = true
                        }
                    }
                }
                catch (error: Exception) {
                    status.text = "Inventory unavailable: ${error.cause?.message ?: error.message}"
                    clearRows()
                } finally {
                    busy.set(false)
                    if (refreshPending) { refreshPending = false; reload() }
                }
            }
        }.execute()
    }

    private fun showSnapshot(snapshot: Snapshot) {
        shownRevision = snapshot.revision
        updatingHosts = true
        hostSelector.removeAllItems()
        snapshot.hosts.forEach(hostSelector::addItem)
        hostSelector.selectedItem = snapshot.host
        updatingHosts = false
        selectedHost = snapshot.host
        val page = snapshot.page
        nextCursor = page?.nextCursor
        routes = page?.routes ?: emptyList()
        model.rowCount = 0
        routes.forEach { route ->
            model.addRow(arrayOf<Any>(
                route.method, route.path, route.packetCount, route.statusCodes.joinToString(", "),
                route.sampleResponseMimeType.orEmpty(), if (route.hasQuery) "Yes" else "",
                if (route.hasRequestBody) "Yes" else "", route.firstPacketId, route.lastPacketId,
            ))
        }
        status.text = when {
            snapshot.revision == null -> "Connect a packet database to see observed APIs"
            snapshot.hosts.isEmpty() -> "No packets stored yet"
            page == null -> "Select a host"
            else -> "${page.host} · ${routes.size} observed routes on this page · DB snapshot through packet #${page.snapshotMaxId}"
        }
        details.text = "Select a route to see its source packet IDs."
        updateButtons()
    }

    private fun showSelectedRoute() {
        val route = routes.getOrNull(table.selectedRow) ?: return
        details.text = buildString {
            appendLine("${route.method} ${route.path}")
            appendLine("Observed packets: ${route.packetCount}")
            appendLine("Source packet IDs: ${route.firstPacketId} … ${route.lastPacketId}")
            appendLine("First saved: ${route.firstSeen}")
            appendLine("Last saved: ${route.lastSeen}")
            appendLine("Status codes: ${route.statusCodes.joinToString(", ").ifBlank { "none" }}")
            appendLine("Sample response MIME: ${route.sampleResponseMimeType ?: "unknown"}")
            appendLine("Sample URL: ${route.sampleUrl}")
        }
        details.caretPosition = 0
    }

    private fun clearRows() {
        routes = emptyList()
        model.rowCount = 0
        details.text = ""
        nextCursor = null
        updateButtons()
    }

    private fun updateButtons() {
        previous.isEnabled = previousCursors.isNotEmpty()
        next.isEnabled = nextCursor != null
    }

    private data class Snapshot(
        val hosts: List<String>, val host: String?, val page: ApiInventoryPage?,
        val revision: Pair<String, Long>?,
    )
}
