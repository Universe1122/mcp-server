# Burp Suite MCP Server Extension

## Overview

Integrate Burp Suite with AI Clients using the Model Context Protocol (MCP).

For more information about the protocol visit: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

## Features

- Connect Burp Suite to AI clients through MCP
- Automatic installation for Claude Desktop
- Comes with packaged Stdio MCP proxy server

## Usage

- Install the extension in Burp Suite
- Configure your Burp MCP server in the extension settings
- Configure your MCP client to use the Burp SSE MCP server or stdio proxy
- Interact with Burp through your client!

## Installation

### Prerequisites

Ensure that the following prerequisites are met before building and installing the extension:

1. **Java**: Java must be installed and available in your system's PATH. You can verify this by running `java --version` in your terminal.
2. **jar Command**: The `jar` command must be executable and available in your system's PATH. You can verify this by running `jar --version` in your terminal. This is required for building and installing the extension.

### Building the Extension

1. **Clone the Repository**: Obtain the source code for the MCP Server Extension.
   ```
   git clone https://github.com/PortSwigger/mcp-server.git
   ```

2. **Navigate to the Project Directory**: Move into the project's root directory.
   ```
   cd mcp-server
   ```

3. **Build the JAR File**: Use Gradle to build the extension.
   ```
   ./gradlew embedProxyJar
   ```

   This command compiles the source code and packages it into a JAR file located in `build/libs/burp-mcp-all.jar`.

### Loading the Extension into Burp Suite

1. **Open Burp Suite**: Launch your Burp Suite application.
2. **Access the Extensions Tab**: Navigate to the `Extensions` tab.
3. **Add the Extension**:
    - Click on `Add`.
    - Set `Extension Type` to `Java`.
    - Click `Select file ...` and choose the JAR file built in the previous step.
    - Click `Next` to load the extension.

Upon successful loading, the MCP Server Extension will be active within Burp Suite.

## Configuration

### Configuring the Extension
Configuration for the extension is done through the Burp Suite UI in the `MCP` tab.
- **Toggle the MCP Server**: The `Enabled` checkbox controls whether the MCP server is active.
- **Enable config editing**: The `Enable tools that can edit your config` checkbox allows the MCP server to expose tools which can edit Burp configuration files.
- **Advanced options**: You can configure the port and host for the MCP server. By default, it listens on `http://127.0.0.1:9876`.

### Claude Desktop Client

To fully utilize the MCP Server Extension with Claude, you need to configure your Claude client settings appropriately.
The extension has an installer which will automatically configure the client settings for you.

1. Currently, Claude Desktop only support STDIO MCP Servers
   for the service it needs.
   This approach isn't ideal for desktop apps like Burp, so instead, Claude will start a proxy server that points to the
   Burp instance,  
   which hosts a web server at a known port (`localhost:9876`).

2. **Configure Claude to use the Burp MCP server**  
   You can do this in one of two ways:

    - **Option 1: Run the installer from the extension**
      This will add the Burp MCP server to the Claude Desktop config.

    - **Option 2: Manually edit the config file**  
      Open the file located at `~/Library/Application Support/Claude/claude_desktop_config.json`,
      and replace or update it with the following:
      ```json
      {
        "mcpServers": {
          "burp": {
            "command": "<path to Java executable packaged with Burp>",
            "args": [
                "-jar",
                "/path/to/mcp/proxy/jar/mcp-proxy-all.jar",
                "--sse-url",
                "<your Burp MCP server URL configured in the extension>"
            ]
          }
        }
      }
      ```

3. **Restart Claude Desktop** - assuming Burp is running with the extension loaded.

## Persistent packet database

Call `start_packet_capture` with an existing project directory. The extension opens or creates
`packets.sqlite3` there, scans the current Burp Proxy HTTP history from the beginning, and then
collects new completed exchanges every five seconds. Reconnecting to the same directory rescans
history but does not insert exact duplicate exchanges. Switching directories creates a separate
database and imports the current history into it. `stop_packet_capture` stops collection; by default
the database remains available for queries. The extension must be running for its MCP tools to work.

Packet request and response bodies are deduplicated by their raw SHA-256 hash for every MIME type.
Bodies over 16 MiB are kept in `raw/resources/mcp-server/blobs/` under the project directory and
referenced by the database; the resource manifest marks these files as non-regenerable. FTS5 indexes
UTF-8 text bodies, using the first 4 MiB of a larger body. Export complete messages with
`save_packets` when searching beyond that indexed prefix. `search_packet` groups similar results by
default; set `groupSimilar=false` to see every distinct exchange. Packet IDs remain stable within a
database. The database schema differs from the former Python wrapper's schema, and existing wrapper
databases are not automatically migrated.

Use `get_db_info`, `get_db_schema`, `get_packet_count`, `get_all_hosts_by_db`, `search_packet`, `get_packet`,
`get_referer_of`, `find_packets_by_referer`, `query_burp_database`, and `save_packets` to inspect the
stored data. `query_burp_database` accepts a single read-only `SELECT` and returns a page with
`rows`, `hasMore`, and `nextOffset`. Set `maxRows` (1–500) and pass `nextOffset` as the next call's
`offset` until `hasMore` is false. Use a stable `ORDER BY`, such as `ORDER BY id`, when paging
through packets. Field lengths and query execution time remain bounded. Requests sent through this
MCP server's HTTP tools are also stored when a database is
connected; search can exclude them with `excludeMcpSent=true`.

For incremental ingestion, call `get_packet_delta` with `afterChangeSeq=0` and a page `limit`
(1–500). Process the returned metadata, then persist `lastChangeSeq` and `databaseId` in the
agent's project state. Pass `lastChangeSeq` as the next `afterChangeSeq` and `databaseId` as
`expectedDatabaseId`. A changed database ID causes an explicit error so a stale cursor cannot
silently skip a new database. The cursor advances past nonmatching packets when an exact `host`
or `excludeMcpSent` filter has no more matches. Use `get_packet` only for representative bodies;
the delta never returns body content.

`get_api_inventory` returns a page of exact observed `METHOD + path` routes for one host, with
unique packet counts, status codes, query/body presence, a representative response MIME and URL,
and first/last source packet IDs. It removes query strings from route keys but does not guess path
parameters or merge string segments. Pass `nextCursor` unchanged to read the next page. The cursor
fixes which routes were discovered by a packet ID, plus the host and filter; counts and status
summaries for those routes can grow as new packets are saved. Start again without a cursor to see
newly captured routes. Routes appear in first-observed packet order. Long paths and URLs are shortened to 4096
characters in MCP results, with truncation flags; use the source packet ID for the full value.
The Burp **MCP → Inventory** tab shows the same inventory with a host selector and
Previous/Next controls. Its selected route displays the representative URL and source packet IDs.
The inventory is maintained when unique packets are saved. Existing databases are indexed once
on first connection after upgrading; the viewer refreshes when the repository reports a change.
`start_packet_capture` starts the Burp History scan in the background. `get_db_info` reports
`historyScanPhase`, `historyScanProcessed`, `historyScanTotal`, `historyScanInserted`, queue overflows,
save failures, catch-up scans, and the last capture error. New Proxy responses are saved through
Burp response events. A bounded event queue triggers a History catch-up scan if it fills, and
stopping capture reconciles History once more.

This change cursor survives Burp restarts and includes a packet originally sent through MCP if it
is later observed in Proxy. `afterId` and `lastId` remain for older insertion-only clients; they
cannot report a later origin change behind the packet ID cursor.

`get_db_schema` returns the actual SQLite `CREATE TABLE` statements for `burp_packets`,
`packet_blobs`, `packet_body_fts`, `api_route_summary`, `api_route_status_codes`, and `packet_changes`.
Packet heads are stored in `burp_packets`; body hashes join
to `packet_blobs`. When `packet_blobs.file_path` is set, resolve it relative to the directory
containing `packets.sqlite3`.

Use `export_packets_har` to write a local HAR file for tools such as
[mitmproxy2swagger](https://github.com/alufers/mitmproxy2swagger). Set `host` to an exact hostname,
`outputPath` to a new file, and optionally `afterId`, `limit`, and `maxBodyBytes`. The result returns
`lastId` and `hasMore`; use `lastId` as the next call's `afterId` and a different output file until
`hasMore` is false. Only packets with responses are exported. Bodies exceeding `maxBodyBytes`
(default 1 MiB) or lacking valid UTF-8 are omitted, with counts in the result. The HAR contains
captured headers and any included bodies, so it may contain credentials or personal data. Keep it
local and review it before sharing. The extension exports traffic; an agent or external tool can
build or update the OpenAPI spec from the HAR and an existing spec.
For mitmproxy2swagger, run:

```sh
mitmproxy2swagger -i export.har -o openapi.yaml -p https://api.example.com -f har
```

Review the generated `x-path-templates`, remove `ignore:` from accepted paths, then run the
same command again. Reuse the existing `openapi.yaml` for
subsequent exports; review changes because the tool preserves existing endpoint descriptions.

## Agent-authored OpenAPI and Swagger tab

The extension does not infer OpenAPI from traffic. The agent reads saved packets and any existing
spec, writes OpenAPI 3.x YAML, and saves `<host>.yaml` directly in the folder selected by
`storage.openapi_dir` in the project's `config.yaml`. The Burp **MCP → Swagger** tab lists those files by
host, shows a read-only Swagger-style API explorer, and reloads changed files. Click anywhere on an
operation row to expand its description, source packet IDs, parameters, request body, response
examples, and schemas. The viewer has White and Dark themes, and the expanded detail scrolls with
the main page even when the pointer is over a parameter or response example. Search filters paths,
methods, summaries, tags, and operation IDs. Schema
trees resolve local `#/components/schemas/` references with a recursion limit. **Try it out →
Repeater** creates an editable request tab from the documented server, path, required parameters,
and request body. Editable example values in the Parameters section populate the Repeater draft;
the agent can supply observed values with OpenAPI `example`, and the viewer uses temporary sample
values where the spec has none. Review these values before sending. Creating the tab does not
transmit the request. The Swing viewer works without a browser engine.

For example, the project can contain:

```yaml
storage:
  db_dir: .
  openapi_dir: raw/resources/mcp-server/openapi
```

Paths may also be absolute; relative paths are resolved from `config.yaml`. After the user provides
that file and authorizes `cafe.naver.com` as the host to document, the agent calls
`load_project_config` with its path and then `start_packet_capture`. The extension remembers the
config path for Swagger after a Burp restart. The agent then pages
through a metadata query such as:

```sql
SELECT id, method, url, path, status_code, request_body_hash, response_body_hash
FROM burp_packets WHERE host = 'cafe.naver.com' ORDER BY id
```

Use `get_packet` for representative request and response bodies, and
`list_openapi_specs` / `get_openapi_spec` to read an existing spec. Save the finished document as
`<storage.openapi_dir>/cafe.naver.com.yaml`, ideally using a temporary file and atomic rename.
Use `get_project_storage` to confirm the effective directory, including when packet capture was
started with the legacy `projectPath` argument. After writing, call `validate_openapi_spec` for
read-only structural checks; it reports parse errors, missing responses, and undeclared path
parameters. It is not a complete OpenAPI schema validator.
The OpenAPI Resource
`burp-mcp://skills/openapi-from-packets` and prompt `build_openapi_from_packets` carry the method
to other MCP clients, although a client must choose to read them. The example does not collect
traffic or make requests to `cafe.naver.com` on its own.

## Manual installations
If you want to install the MCP server manually you can either use the extension's SSE server directly or the packaged
Stdio proxy server.

### SSE MCP Server
To use the SSE server directly, provide the configured server URL to your MCP client:
```
http://127.0.0.1:9876
```

### Stdio MCP Proxy Server
The source code for the proxy server can be found here: [MCP Proxy Server](https://github.com/PortSwigger/mcp-proxy)

In order to support MCP Clients which only support Stdio MCP Servers, the extension comes packaged with a proxy server for
passing requests to the SSE MCP server extension.

If you want to use the Stdio proxy server you can use the extension's installer option to extract the proxy server jar.
Once you have the jar you can add the following command and args to your client configuration:
```
/path/to/packaged/burp/java -jar /path/to/proxy/jar/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```

If you modify the proxy source, rebuild and copy it into this project before packaging the extension:
```bash
# From mcp-proxy
./gradlew shadowJar
cp build/libs/mcp-proxy-all.jar /path/to/mcp-server/libs/mcp-proxy-all.jar

# From mcp-server
./gradlew embedProxyJar
```

### Creating / modifying tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`. To define new tools, create a new serializable
data class with the required parameters which will come from the LLM.

The tool name is auto-derived from its parameters data class. A description is also needed for the LLM. You can return
a string or a `List<ContentBlock>` to provide data back to the LLM.

Extend the Paginated interface to add auto-pagination support.
