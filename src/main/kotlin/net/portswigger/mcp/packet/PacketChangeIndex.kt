package net.portswigger.mcp.packet

import java.sql.Connection

/** A durable cursor for inserts and later MCP-to-Proxy origin promotions. */
internal fun initializePacketChanges(db: Connection) {
    db.autoCommit = false
    try {
        db.createStatement().use { st ->
            st.execute("""
                CREATE TABLE IF NOT EXISTS packet_changes(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    packet_id INTEGER NOT NULL REFERENCES burp_packets(id),
                    kind TEXT NOT NULL CHECK(kind IN ('insert','proxy_observed')),
                    is_sent_from_mcp INTEGER NOT NULL
                )
            """)
            st.execute("CREATE INDEX IF NOT EXISTS idx_packet_changes_packet ON packet_changes(packet_id)")
            val initialized = st.executeQuery(
                "SELECT 1 FROM capture_metadata WHERE key='packet_changes_version' AND value='1'"
            ).use { it.next() }
            if (!initialized) {
                st.executeUpdate("""
                    INSERT INTO packet_changes(packet_id,kind,is_sent_from_mcp)
                    SELECT id,'insert',is_sent_from_mcp FROM burp_packets ORDER BY id
                """)
                st.executeUpdate("INSERT OR REPLACE INTO capture_metadata(key,value) VALUES('packet_changes_version','1')")
            }
            st.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_packet_change_insert AFTER INSERT ON burp_packets BEGIN
                    INSERT INTO packet_changes(packet_id,kind,is_sent_from_mcp)
                    VALUES(NEW.id,'insert',NEW.is_sent_from_mcp);
                END
            """)
            st.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_packet_change_observed
                AFTER UPDATE OF is_sent_from_mcp ON burp_packets
                WHEN OLD.is_sent_from_mcp=1 AND NEW.is_sent_from_mcp=0 BEGIN
                    INSERT INTO packet_changes(packet_id,kind,is_sent_from_mcp)
                    VALUES(NEW.id,'proxy_observed',0);
                END
            """)
        }
        db.commit()
    } catch (error: Exception) {
        db.rollback()
        throw error
    } finally {
        db.autoCommit = true
    }
}
