package net.portswigger.mcp.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class ProjectStorageConfigTest {
    @Test
    fun `resolves folders relative to config file and supports an absolute OpenAPI folder`(@TempDir root: Path) {
        val project = Files.createDirectory(root.resolve("project"))
        val specDirectory = root.resolve("shared-specs")
        val file = project.resolve("config.yaml")
        Files.writeString(file, "storage:\n  db_dir: .\n  openapi_dir: ${specDirectory}\n")

        val loaded = ProjectStorageConfig().load(file.toString())
        assertEquals(project.toRealPath(), loaded.databaseDirectory)
        assertEquals(specDirectory, loaded.openApiDirectory)
        assertEquals(file.toString(), loaded.configPath)
    }

    @Test
    fun `rejects missing storage paths without changing current configuration`(@TempDir root: Path) {
        val file = root.resolve("config.yaml")
        Files.writeString(file, "storage:\n  db_dir: .\n  openapi_dir: specs\n")
        val config = ProjectStorageConfig()
        val first = config.load(file.toString())
        Files.writeString(file, "storage:\n  db_dir: missing\n  openapi_dir: specs\n")
        assertThrows(IllegalArgumentException::class.java) { config.load(file.toString()) }
        assertEquals(first, config.current())
    }
}
