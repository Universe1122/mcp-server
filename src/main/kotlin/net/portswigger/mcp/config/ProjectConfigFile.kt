package net.portswigger.mcp.config

import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/** Human-edited YAML file. Keep its text intact and reject stale or invalid saves. */
internal class ProjectConfigFile(private val storage: ProjectStorageConfig = ProjectStorageConfig()) {
    data class Loaded(val path: Path, val text: String, val sha256: String, val storageReady: Boolean)

    fun open(rawPath: String): Loaded {
        val path = checkedPath(rawPath)
        val bytes = Files.readAllBytes(path)
        require(bytes.size <= 1_048_576) { "config.yaml is too large" }
        val text = String(bytes, StandardCharsets.UTF_8)
        return Loaded(path, text, digest(bytes), storageReady = false)
    }

    fun save(loaded: Loaded, newText: String): Loaded {
        val path = checkedPath(loaded.path.toString())
        val bytes = newText.toByteArray(StandardCharsets.UTF_8)
        require(bytes.size <= 1_048_576) { "config.yaml is too large" }
        val settings = LoadSettings.builder().setAllowDuplicateKeys(false).setMaxAliasesForCollections(20)
            .setCodePointLimit(1_048_576).build()
        val root = Load(settings).loadFromString(newText) as? Map<*, *>
            ?: throw IllegalArgumentException("config.yaml must be a YAML object")
        val storageReady = if ("storage" in root) {
            storage.validateText(path, newText)
            true
        } else false
        require(digest(Files.readAllBytes(path)) == loaded.sha256) {
            "config.yaml changed outside this editor. Reload before saving."
        }
        val temp = Files.createTempFile(path.parent, ".config-", ".yaml")
        try {
            Files.write(temp, bytes)
            try {
                Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(temp)
        }
        return Loaded(path, newText, digest(bytes), storageReady)
    }

    private fun checkedPath(rawPath: String): Path {
        val path = Path.of(rawPath).toAbsolutePath().normalize()
        require(path.fileName.toString() == "config.yaml") { "Select an existing config.yaml file" }
        require(Files.isRegularFile(path) && !Files.isSymbolicLink(path)) { "config.yaml does not exist: $path" }
        return path
    }

    private fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
}
