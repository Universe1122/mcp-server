package net.portswigger.mcp.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class ProjectConfigFileTest {
    @Test
    fun `saves valid config and rejects outside changes`(@TempDir root: Path) {
        val path = root.resolve("config.yaml")
        Files.writeString(path, "storage:\n  db_dir: .\n  openapi_dir: specs\n")
        val editor = ProjectConfigFile()
        val loaded = editor.open(path.toString())
        val updated = editor.save(loaded, loaded.text + "note: retained\n")
        assertEquals(updated.text, Files.readString(path))
        Files.writeString(path, updated.text + "external: true\n")
        assertThrows(IllegalArgumentException::class.java) { editor.save(updated, updated.text + "another: true\n") }
        assertThrows(IllegalArgumentException::class.java) { editor.save(editor.open(path.toString()), "storage: [invalid]\n") }
    }

    @Test
    fun `loads an invalid config so a person can repair it`(@TempDir root: Path) {
        val path = root.resolve("config.yaml")
        Files.writeString(path, "legacy: true\n")
        val editor = ProjectConfigFile()
        val loaded = editor.open(path.toString())
        assertEquals("legacy: true\n", loaded.text)
        val stillLegacy = editor.save(loaded, loaded.text)
        assertEquals(false, stillLegacy.storageReady)
        assertEquals(true, editor.save(stillLegacy, "storage:\n  db_dir: .\n  openapi_dir: specs\n").storageReady)
    }
}
