package net.portswigger.mcp.packet

import java.sql.Connection

/**
 * Materialized route inventory. SQLite triggers update it in the same transaction as each packet.
 * scope=0 includes all saved packets; scope=1 excludes packets sent only through MCP.
 */
internal fun initializeInventory(db: Connection) {
    db.autoCommit = false
    try {
        db.createStatement().use { st ->
            st.execute("""
                CREATE TABLE IF NOT EXISTS api_route_summary(
                    scope INTEGER NOT NULL,host TEXT NOT NULL,method TEXT NOT NULL,route_path TEXT NOT NULL,
                    packet_count INTEGER NOT NULL,first_id INTEGER NOT NULL,last_id INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,
                    has_query INTEGER NOT NULL,has_request_body INTEGER NOT NULL,
                    PRIMARY KEY(scope,host,method,route_path)
                ) WITHOUT ROWID
            """)
            st.execute("CREATE INDEX IF NOT EXISTS idx_api_route_summary_page ON api_route_summary(host,scope,first_id)")
            st.execute("""
                CREATE TABLE IF NOT EXISTS api_route_status_codes(
                    scope INTEGER NOT NULL,host TEXT NOT NULL,method TEXT NOT NULL,
                    route_path TEXT NOT NULL,code INTEGER NOT NULL,
                    PRIMARY KEY(scope,host,method,route_path,code)
                ) WITHOUT ROWID
            """)
        }

        val initialized = db.prepareStatement(
            "SELECT 1 FROM capture_metadata WHERE key='api_inventory_version' AND value='1'"
        ).use { st -> st.executeQuery().use { it.next() } }
        if (!initialized) {
            // Existing databases are scanned once. Rows and marker commit together, so a failed
            // migration is retried without leaving a partially populated inventory.
            for (scope in 0..1) {
                val filter = if (scope == 1) "WHERE p.is_sent_from_mcp=0" else ""
                db.createStatement().use { st ->
                    st.executeUpdate("""
                        INSERT INTO api_route_summary
                          (scope,host,method,route_path,packet_count,first_id,last_id,
                           first_seen,last_seen,has_query,has_request_body)
                        SELECT $scope,p.host,p.method,
                               CASE WHEN instr(p.path,'?')>0 THEN substr(p.path,1,instr(p.path,'?')-1)
                                    ELSE p.path END AS route_path,
                               count(*),min(p.id),max(p.id),min(p.captured_at),max(p.captured_at),
                               max(instr(p.path,'?')>0),max(rq.size>0)
                        FROM burp_packets p JOIN packet_blobs rq ON rq.hash=p.request_body_hash
                        $filter
                        GROUP BY p.host,p.method,route_path
                    """)
                    st.executeUpdate("""
                        INSERT INTO api_route_status_codes(scope,host,method,route_path,code)
                        SELECT DISTINCT $scope,p.host,p.method,
                               CASE WHEN instr(p.path,'?')>0 THEN substr(p.path,1,instr(p.path,'?')-1)
                                    ELSE p.path END,p.status_code
                        FROM burp_packets p
                        WHERE p.status_code IS NOT NULL ${if (scope == 1) "AND p.is_sent_from_mcp=0" else ""}
                    """)
                }
            }
            db.createStatement().use { st ->
                st.executeUpdate("INSERT OR REPLACE INTO capture_metadata(key,value) VALUES('api_inventory_version','1')")
            }
        }

        db.createStatement().use { st ->
            st.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_api_route_insert AFTER INSERT ON burp_packets BEGIN
                    ${summaryUpsert(0, "1")}
                    ${statusInsert(0, "1")}
                    ${summaryUpsert(1, "NEW.is_sent_from_mcp=0")}
                    ${statusInsert(1, "NEW.is_sent_from_mcp=0")}
                END
            """)
            st.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_api_route_observed
                AFTER UPDATE OF is_sent_from_mcp ON burp_packets
                WHEN OLD.is_sent_from_mcp=1 AND NEW.is_sent_from_mcp=0 BEGIN
                    ${summaryUpsert(1, "1")}
                    ${statusInsert(1, "1")}
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

private fun summaryUpsert(scope: Int, condition: String): String = """
    INSERT INTO api_route_summary
      (scope,host,method,route_path,packet_count,first_id,last_id,
       first_seen,last_seen,has_query,has_request_body)
    SELECT $scope,NEW.host,NEW.method,
           CASE WHEN instr(NEW.path,'?')>0 THEN substr(NEW.path,1,instr(NEW.path,'?')-1)
                ELSE NEW.path END,
           1,NEW.id,NEW.id,NEW.captured_at,NEW.captured_at,
           instr(NEW.path,'?')>0,
           (SELECT size>0 FROM packet_blobs WHERE hash=NEW.request_body_hash)
    WHERE $condition
    ON CONFLICT(scope,host,method,route_path) DO UPDATE SET
        packet_count=packet_count+1,
        first_id=min(first_id,excluded.first_id),last_id=max(last_id,excluded.last_id),
        first_seen=min(first_seen,excluded.first_seen),last_seen=max(last_seen,excluded.last_seen),
        has_query=max(has_query,excluded.has_query),
        has_request_body=max(has_request_body,excluded.has_request_body);
"""

private fun statusInsert(scope: Int, condition: String): String = """
    INSERT OR IGNORE INTO api_route_status_codes(scope,host,method,route_path,code)
    SELECT $scope,NEW.host,NEW.method,
           CASE WHEN instr(NEW.path,'?')>0 THEN substr(NEW.path,1,instr(NEW.path,'?')-1)
                ELSE NEW.path END,NEW.status_code
    WHERE $condition AND NEW.status_code IS NOT NULL;
"""
