package net.portswigger.mcp.config

import java.awt.BorderLayout
import java.awt.Font
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingWorker

/** Explicit file editor in Settings; reading and saving happen only on user action. */
internal class ProjectConfigEditor(private val config: McpConfig) : JPanel(BorderLayout(8, 8)) {
    private val file = ProjectConfigFile()
    private val path = JTextField(config.projectConfigPath, 35)
    private val text = JTextArea(18, 58).apply { font = Font(Font.MONOSPACED, Font.PLAIN, 12) }
    private val status = JLabel("Select config.yaml and click Load")
    private val load = JButton("Load")
    private val save = JButton("Save")
    private var loaded: ProjectConfigFile.Loaded? = null

    init {
        border = BorderFactory.createTitledBorder("Project config.yaml")
        val row = JPanel(BorderLayout(6, 0))
        row.add(path, BorderLayout.CENTER)
        row.add(JPanel().apply {
            add(JButton("Browse…").apply {
                addActionListener {
                    val chooser = JFileChooser().apply {
                        selectedFile = runCatching { java.io.File(path.text) }.getOrNull()
                    }
                    if (chooser.showOpenDialog(this@ProjectConfigEditor) == JFileChooser.APPROVE_OPTION) {
                        path.text = chooser.selectedFile.absolutePath
                    }
                }
            })
            add(load)
            add(save)
        }, BorderLayout.EAST)
        add(row, BorderLayout.NORTH)
        add(JScrollPane(text), BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
        text.isEditable = false
        save.isEnabled = false
        load.addActionListener {
            val selectedPath = path.text
            runFileTask("Loading", { file.open(selectedPath) }) { result ->
            loaded = result
            path.text = result.path.toString()
            text.text = result.text
            text.caretPosition = 0
            text.isEditable = true
            save.isEnabled = true
            config.projectConfigPath = result.path.toString()
            status.text = "Loaded ${result.path}"
            }
        }
        save.addActionListener {
            val current = loaded ?: return@addActionListener
            if (path.text != current.path.toString()) {
                status.text = "Path changed. Load that file before saving."
                return@addActionListener
            }
            val value = text.text
            runFileTask("Saving", { file.save(current, value) }) { result ->
                loaded = result
                status.text = if (result.storageReady)
                    "Saved. Run load_project_config and start_packet_capture to apply storage changes."
                else "Saved. Add storage.db_dir and storage.openapi_dir before loading this config through MCP."
            }
        }
    }

    private fun runFileTask(label: String, work: () -> ProjectConfigFile.Loaded,
                            done: (ProjectConfigFile.Loaded) -> Unit) {
        load.isEnabled = false
        save.isEnabled = false
        status.text = "$label config.yaml…"
        object : SwingWorker<ProjectConfigFile.Loaded, Unit>() {
            override fun doInBackground(): ProjectConfigFile.Loaded = work()
            override fun done() {
                load.isEnabled = true
                save.isEnabled = loaded != null
                runCatching { get() }.onSuccess(done).onFailure {
                    status.text = "${label} failed: ${it.cause?.message ?: it.message}"
                }
            }
        }.execute()
    }
}
