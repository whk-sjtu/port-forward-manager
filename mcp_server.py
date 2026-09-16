#!/usr/bin/env python3
"""MCP bridge to the shared Port Forward Manager backend."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

BASE_URL = "http://localhost:56800"
TOKEN_FILE = Path.home() / ".config" / "port-forward-manager" / "token"


def backend(path: str, method: str = "GET", payload: Optional[dict] = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Accept": "application/json"}
    if method != "GET":
        if not TOKEN_FILE.exists():
            raise RuntimeError("Port Forward Manager 后端尚未启动，找不到本地认证令牌")
        headers.update({"Authorization": f"Bearer {TOKEN_FILE.read_text().strip()}", "Content-Type": "application/json"})
    request = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc).get("error", exc.reason)
        except Exception:
            detail = exc.reason
        raise RuntimeError(str(detail)) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"无法连接本地管理后端 {BASE_URL}: {exc.reason}") from exc


TOOLS = [
    {
        "name": "list_port_forwards",
        "description": "列出当前固定、Codex、VS Code 和普通 SSH port forwarding，包括端口、目标、PID、运行中/异常/已停止状态、异常详情，以及可用于固化临时转发的 suggestedFixedPort。",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "open_port_forward_dashboard",
        "description": "返回本地 Port Forward Manager 网页入口。",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "create_fixed_port_forward",
        "description": "创建并启动一个由 launchd 保活的固定 SSH 本地端口转发。仅允许绑定回环地址。",
        "inputSchema": {
            "type": "object",
            "required": ["name", "sshHost", "localPort", "remotePort"],
            "properties": {
                "name": {"type": "string"}, "sshHost": {"type": "string"},
                "localPort": {"type": "integer", "minimum": 1024, "maximum": 65535},
                "remoteHost": {"type": "string", "default": "127.0.0.1"},
                "remotePort": {"type": "integer", "minimum": 1, "maximum": 65535},
            }, "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "update_fixed_port_forward",
        "description": "编辑并重新启动现有固定 SSH 转发。",
        "inputSchema": {
            "type": "object", "required": ["id", "name", "sshHost", "localPort", "remotePort"],
            "properties": {
                "id": {"type": "string"}, "name": {"type": "string"}, "sshHost": {"type": "string"},
                "localPort": {"type": "integer"}, "remoteHost": {"type": "string", "default": "127.0.0.1"},
                "remotePort": {"type": "integer"},
            }, "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "set_fixed_port_forward_state",
        "description": "启动或停止一个固定 SSH 转发。",
        "inputSchema": {"type": "object", "required": ["id", "running"], "properties": {"id": {"type": "string"}, "running": {"type": "boolean"}}, "additionalProperties": False},
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "stop_temporary_port_forward",
        "description": "停止 Codex、VS Code 或普通 SSH 临时转发对应的本地进程。同一进程维护的其他连接也可能中断。",
        "inputSchema": {"type": "object", "required": ["pid", "localPort"], "properties": {"pid": {"type": "integer"}, "localPort": {"type": "integer"}}, "additionalProperties": False},
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    },
    {
        "name": "solidify_temporary_port_forward",
        "description": "把 Codex 或 VS Code 临时转发创建为 launchd 固定转发；固定转发成功启动后自动停止原临时转发。",
        "inputSchema": {
            "type": "object", "required": ["pid", "localPort", "name"],
            "properties": {
                "pid": {"type": "integer"},
                "localPort": {"type": "integer", "description": "原临时转发的本地端口"},
                "name": {"type": "string"},
                "fixedLocalPort": {"type": "integer", "minimum": 1024, "maximum": 65535},
            }, "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    },
    {
        "name": "delete_fixed_port_forward",
        "description": "停止并删除固定 SSH 转发；配置文件会移入 macOS 废纸篓，可恢复。",
        "inputSchema": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}, "additionalProperties": False},
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    },
]


def call_tool(name: str, arguments: dict) -> dict:
    if name == "list_port_forwards":
        result = backend("/api/forwards")
    elif name == "open_port_forward_dashboard":
        result = {"url": BASE_URL, "message": "在浏览器打开本地 Port Forward Manager"}
    elif name == "create_fixed_port_forward":
        result = backend("/api/profiles", "POST", {**arguments, "bindAddress": "127.0.0.1"})
    elif name == "update_fixed_port_forward":
        profile_id = urllib.parse.quote(arguments.pop("id"), safe="")
        result = backend(f"/api/profiles/{profile_id}", "PUT", {**arguments, "bindAddress": "127.0.0.1"})
    elif name == "set_fixed_port_forward_state":
        profile_id = urllib.parse.quote(arguments["id"], safe="")
        action = "start" if arguments["running"] else "stop"
        result = backend(f"/api/profiles/{profile_id}/{action}", "POST", {})
    elif name == "stop_temporary_port_forward":
        result = backend(f"/api/live/{int(arguments['pid'])}/{int(arguments['localPort'])}/stop", "POST", {})
    elif name == "solidify_temporary_port_forward":
        current = backend("/api/forwards")
        source = next((item for item in current["forwards"] if item.get("pid") == int(arguments["pid"]) and item.get("localPort") == int(arguments["localPort"])), None)
        if not source or source.get("source") not in {"codex", "vscode"}:
            raise RuntimeError("找不到可固化的 Codex/VS Code 临时转发")
        payload = {
            "name": arguments["name"], "sshHost": source["sshHost"],
            "localPort": int(arguments.get("fixedLocalPort") or source["suggestedFixedPort"]),
            "remoteHost": source["remoteHost"], "remotePort": source["remotePort"],
            "bindAddress": "127.0.0.1",
        }
        result = backend(f"/api/live/{int(arguments['pid'])}/{int(arguments['localPort'])}/solidify", "POST", payload)
    elif name == "delete_fixed_port_forward":
        profile_id = urllib.parse.quote(arguments["id"], safe="")
        result = backend(f"/api/profiles/{profile_id}", "DELETE", {})
    else:
        raise RuntimeError(f"未知工具：{name}")
    return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}], "structuredContent": result}


def respond(message: dict) -> Optional[dict]:
    method = message.get("method")
    if method == "initialize":
        return {"protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "port-forward-manager", "version": "0.1.0"}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        params = message.get("params", {})
        return call_tool(params.get("name", ""), dict(params.get("arguments") or {}))
    if method and method.startswith("notifications/"):
        return None
    raise RuntimeError(f"不支持的 MCP 方法：{method}")


for line in sys.stdin:
    try:
        request = json.loads(line)
        result = respond(request)
        if result is not None and "id" in request:
            print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}, ensure_ascii=False), flush=True)
    except Exception as exc:
        request_id = request.get("id") if isinstance(locals().get("request"), dict) else None
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(exc)}}, ensure_ascii=False), flush=True)
