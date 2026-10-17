package net.portswigger.mcp.config

import kotlinx.serialization.Serializable
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.nio.file.Files
import java.nio.file.Path

@Serializable data class ProjectStoragePaths(val configPath: String, val dbDir: String, val openapiDir: String) {
    val databaseDirectory: Path get() = Path.of(dbDir)
    val openApiDirectory: Path get() = Path.of(openapiDir)
}

/** Loads only the storage paths; unrelated config.yaml fields remain owned by their consumers. */
class ProjectStorageConfig {
    @Volatile private var paths: ProjectStoragePaths? = null

    fun current(): ProjectStoragePaths? = paths

    @Synchronized fun load(configPath: String): ProjectStoragePaths {
        val file = Path.of(configPath).toAbsolutePath().normalize()
        require(file.fileName.toString() == "config.yaml") { "configPath must name config.yaml" }
        require(Files.isRegularFile(file) && !Files.isSymbolicLink(file)) { "config.yaml does not exist: $file" }
        require(Files.size(file) <= 1_048_576) { "config.yaml is too large" }
        val settings = LoadSettings.builder().setAllowDuplicateKeys(false).setMaxAliasesForCollections(20)
            .setCodePointLimit(1_048_576).build()
        val root = Load(settings).loadFromString(Files.readString(file)) as? Map<*, *>
            ?: throw IllegalArgumentException("config.yaml must be a YAML object")
        val storage = root["storage"] as? Map<*, *>
            ?: throw IllegalArgumentException("config.yaml requires storage.db_dir and storage.openapi_dir")
        fun directory(key: String, mustExist: Boolean): Path {
            val value = (storage[key] as? String)?.takeIf(String::isNotBlank)
                ?: throw IllegalArgumentException("storage.$key must be a directory path")
            val candidate = Path.of(value)
            val resolved = (if (candidate.isAbsolute) candidate else file.parent.resolve(candidate)).normalize()
            if (mustExist) require(Files.isDirectory(resolved)) { "storage.$key must be an existing directory: $resolved" }
            else require(!Files.exists(resolved) || Files.isDirectory(resolved)) { "storage.$key must be a directory: $resolved" }
            return if (Files.exists(resolved)) resolved.toRealPath() else resolved
        }
        val db = directory("db_dir", true)
        val openapi = directory("openapi_dir", false)
        return ProjectStoragePaths(file.toString(), db.toString(), openapi.toString()).also { paths = it }
    }
}
