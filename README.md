# Port Forward Manager

A loopback-only dashboard and Codex plugin for inspecting and managing SSH local port forwards on macOS.

## Features

- Shows persistent launchd forwards and temporary forwards created by Codex or VS Code.
- Hides VS Code internal and automatically restored listeners.
- Creates, edits, starts, stops, and removes persistent forwards.
- Converts temporary Codex/VS Code forwards into persistent launchd profiles.
- Detects webpage titles and provides direct links.
- Reports `Running`, `Error`, and `Stopped` health states.
- Provides Chinese and English UI modes.
- Exposes the same backend through Codex MCP tools.

## Run locally

Requires macOS, Python 3.9+, OpenSSH, `launchctl`, and `lsof`.

```bash
/usr/bin/python3 server.py
```

Open <http://localhost:56800>.

The service listens only on `127.0.0.1`. Persistent forwards are also restricted to loopback addresses. A per-user token protects mutations made through MCP.

## Codex plugin

The plugin manifest is in `.codex-plugin/plugin.json`; `.mcp.json` starts the local MCP bridge from the plugin directory.

## Privacy

Runtime SSH hosts, forwarded ports, detected webpage titles, process IDs, and authentication tokens are discovered locally and are never stored in this repository.
