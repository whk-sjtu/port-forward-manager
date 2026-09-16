#!/usr/bin/env python3
"""Shared loopback-only SSH port-forward backend for macOS and Codex."""

from __future__ import annotations

import html
import http.client
import json
import os
import plistlib
import re
import secrets
import select
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse
from typing import Optional, Tuple

APP_DIR = Path(__file__).resolve().parent
INDEX_FILE = APP_DIR / "index.html"
ICON_FILE = APP_DIR / "icon.svg"
LAUNCH_AGENTS = Path.home() / "Library" / "LaunchAgents"
LABEL_PREFIX = "io.github.port-forward-manager."
TOKEN_FILE = Path.home() / ".config" / "port-forward-manager" / "token"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(os.environ.get("PORT_FORWARD_MANAGER_PORT", "56800"))
TITLE_CACHE: dict[int, tuple[float, Optional[dict]]] = {}
WEB_PORTS: set[int] = set()


def auth_token() -> str:
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not TOKEN_FILE.exists():
        TOKEN_FILE.write_text(secrets.token_urlsafe(32))
        TOKEN_FILE.chmod(0o600)
    return TOKEN_FILE.read_text().strip()


def run(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=15)


def process_table() -> dict[int, dict]:
    result: dict[int, dict] = {}
    output = run("/bin/ps", "-axo", "pid=,ppid=,comm=,args=").stdout
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)", line)
        if match:
            pid, ppid, comm, args = match.groups()
            result[int(pid)] = {"pid": int(pid), "ppid": int(ppid), "comm": comm, "args": args}
    return result


def listeners() -> list[dict]:
    proc = run("/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn")
    rows: list[dict] = []
    pid = None
    command = ""
    for line in proc.stdout.splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("c"):
            command = line[1:]
        elif line.startswith("n") and pid is not None:
            address = line[1:]
            match = re.search(r"(?:\[([^]]+)\]|([^:]+)):(\d+)$", address)
            if match:
                rows.append({
                    "pid": pid,
                    "command": command,
                    "localHost": match.group(1) or match.group(2),
                    "localPort": int(match.group(3)),
                })
    return rows


def ancestry_text(pid: int, processes: dict[int, dict]) -> str:
    parts: list[str] = []
    seen: set[int] = set()
    while pid in processes and pid not in seen and len(parts) < 12:
        seen.add(pid)
        item = processes[pid]
        parts.append(item["args"])
        pid = item["ppid"]
    return "\n".join(parts)


@dataclass(frozen=True)
class ForwardSpec:
    bind: str
    local_port: int
    remote_host: str
    remote_port: int


def parse_forward(value: str) -> Optional[ForwardSpec]:
    parts = value.rsplit(":", 3)
    try:
        if len(parts) == 3:
            local_port, remote_host, remote_port = parts
            return ForwardSpec("127.0.0.1", int(local_port), remote_host, int(remote_port))
        if len(parts) == 4:
            bind, local_port, remote_host, remote_port = parts
            return ForwardSpec(bind.strip("[]"), int(local_port), remote_host, int(remote_port))
    except ValueError:
        return None
    return None


def ssh_details(command: str) -> Tuple[Optional[str], list[ForwardSpec]]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None, []
    if not tokens:
        return None, []
    forwards: list[ForwardSpec] = []
    host: Optional[str] = None
    consumes = {"-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-P", "-p", "-Q", "-R", "-S", "-W", "-w"}
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token == "-L" and i + 1 < len(tokens):
            spec = parse_forward(tokens[i + 1])
            if spec:
                forwards.append(spec)
            i += 2
            continue
        if token.startswith("-L") and len(token) > 2:
            spec = parse_forward(token[2:])
            if spec:
                forwards.append(spec)
            i += 1
            continue
        if token in consumes:
            i += 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        if host is None:
            host = token
        i += 1
    return host, forwards


def vscode_tunnels() -> dict[int, dict]:
    database = Path.home() / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "state.vscdb"
    if not database.exists():
        return {}
    result: dict[int, dict] = {}
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=1)
        rows = connection.execute(
            "SELECT key, value FROM ItemTable WHERE key LIKE 'remote.tunnels.toRestore.ssh-remote+%'"
        ).fetchall()
        connection.close()
    except sqlite3.Error:
        return {}
    for key, value in rows:
        match = re.match(r"remote\.tunnels\.toRestore\.ssh-remote\+([^.]+)", key)
        ssh_host = match.group(1) if match else None
        try:
            items = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            continue
        for item in items if isinstance(items, list) else []:
            source = item.get("source") if isinstance(item, dict) else None
            # VS Code stores auto/restored listeners beside explicit forwards. In this
            # setup, explicit entries are "User Forwarded" with localhost as the target.
            if (
                not isinstance(source, dict)
                or source.get("description") != "User Forwarded"
                or str(item.get("remoteHost", "")).lower() != "localhost"
            ):
                continue
            try:
                local_port = int(item["localPort"])
                remote_port = int(item["remotePort"])
            except (KeyError, TypeError, ValueError):
                continue
            result[local_port] = {
                "sshHost": ssh_host,
                "remoteHost": item.get("remoteHost") or "127.0.0.1",
                "remotePort": remote_port,
            }
    return result


def profile_from_plist(path: Path) -> Optional[dict]:
    try:
        with path.open("rb") as handle:
            data = plistlib.load(handle)
        args = [str(value) for value in data.get("ProgramArguments", [])]
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    if not args or Path(args[0]).name != "ssh":
        return None
    host, specs = ssh_details(" ".join(shlex.quote(arg) for arg in args))
    if not host or len(specs) != 1:
        return None
    spec = specs[0]
    label = str(data.get("Label", path.stem))
    return {
        "id": label,
        "name": str(data.get("PortForwardManagerName") or label.removeprefix(LABEL_PREFIX).replace("-", " ")),
        "label": label,
        "path": str(path),
        "bindAddress": spec.bind,
        "localPort": spec.local_port,
        "sshHost": host,
        "remoteHost": spec.remote_host,
        "remotePort": spec.remote_port,
        "editable": True,
    }


def profiles() -> list[dict]:
    LAUNCH_AGENTS.mkdir(parents=True, exist_ok=True)
    items = []
    for path in sorted(LAUNCH_AGENTS.glob("*.plist")):
        profile = profile_from_plist(path)
        if profile:
            items.append(profile)
    return items


def concrete_ssh_hosts() -> list[str]:
    config = Path.home() / ".ssh" / "config"
    if not config.exists():
        return []
    found: list[str] = []
    for line in config.read_text(errors="replace").splitlines():
        match = re.match(r"\s*Host\s+(.+)$", line, re.I)
        if not match:
            continue
        for host in match.group(1).split():
            if not any(char in host for char in "*?!") and host not in found:
                found.append(host)
    return found


def classify(text: str, command: str) -> tuple[str, str]:
    low = text.lower()
    if "chatgpt.app" in low or "contents/resources/codex" in low:
        return "codex", "Codex"
    if "remote-ssh" in low or "visual studio code" in low or "code helper" in low:
        return "vscode", "VS Code"
    if Path(command).name == "ssh" or " ssh " in f" {low} ":
        return "ssh", "SSH"
    return "other", "其他"


def probe_web(local_port: int) -> Optional[dict]:
    now = time.monotonic()
    cached = TITLE_CACHE.get(local_port)
    if cached and now - cached[0] < 55:
        return cached[1]

    result: Optional[dict] = None
    path = "/"
    try:
        for attempt in range(2):
            connection = http.client.HTTPConnection("127.0.0.1", local_port, timeout=1.5)
            connection.request(
                "GET",
                path,
                headers={"Host": f"localhost:{local_port}", "User-Agent": "Port Forward Manager"},
            )
            response = connection.getresponse()
            result = {"httpStatus": response.status}
            if response.status in {301, 302, 303, 307, 308} and attempt == 0:
                location = response.getheader("Location")
                response.read(1024)
                connection.close()
                if not location:
                    break
                redirect = urlparse(urljoin(f"http://localhost:{local_port}{path}", location))
                redirect_port = redirect.port or 80
                if redirect.hostname not in {"localhost", "127.0.0.1", "::1"} or redirect_port != local_port:
                    break
                path = redirect.path or "/"
                if redirect.query:
                    path += "?" + redirect.query
                continue
            content_type = response.getheader("Content-Type", "")
            body = response.read(131072)
            connection.close()
            if "text/html" not in content_type.lower():
                break
            WEB_PORTS.add(local_port)
            charset_match = re.search(r"charset=([^;\s]+)", content_type, re.I)
            charset = charset_match.group(1).strip('"\'') if charset_match else "utf-8"
            page = body.decode(charset, errors="replace")
            title_match = re.search(r"<title(?:\s[^>]*)?>(.*?)</title>", page, re.I | re.S)
            if title_match:
                title = re.sub(r"\s+", " ", html.unescape(title_match.group(1))).strip()
                if title:
                    result.update({"title": title[:160], "url": f"http://localhost:{local_port}{path}"})
            break
    except (OSError, ValueError, LookupError, http.client.HTTPException):
        result = None
    TITLE_CACHE[local_port] = (now, result)
    return result


def endpoint_health(local_port: int, website: Optional[dict]) -> tuple[bool, Optional[str]]:
    if website is not None:
        status = int(website.get("httpStatus", 0))
        if status >= 500:
            return False, f"HTTP {status}"
        return True, None
    if local_port in WEB_PORTS:
        return False, "HTTP 请求失败"
    try:
        with socket.create_connection((LISTEN_HOST, local_port), timeout=0.8) as probe:
            readable, _, _ = select.select([probe], [], [], 0.8)
            if readable:
                try:
                    if probe.recv(1, socket.MSG_PEEK) == b"":
                        return False, "远程端口不可达"
                except (ConnectionResetError, OSError):
                    return False, "远程连接失败"
        return True, None
    except OSError:
        return False, "远程连接失败"


def suggested_fixed_port(local_port: int, reserved: set[int]) -> Optional[int]:
    """Pick a nearby free loopback port without disturbing the live forwarding."""
    for candidates in (range(local_port + 1, 65536), range(20000, local_port)):
        for candidate in candidates:
            if candidate in reserved:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.bind((LISTEN_HOST, candidate))
                reserved.add(candidate)
                return candidate
            except OSError:
                continue
    return None


def snapshot() -> dict:
    processes = process_table()
    unique_listeners: dict[tuple[int, int], dict] = {}
    for item in listeners():
        key = (item["pid"], item["localPort"])
        if key not in unique_listeners or item["localHost"] == "127.0.0.1":
            unique_listeners[key] = item
    live_listeners = list(unique_listeners.values())
    vscode = vscode_tunnels()
    saved = profiles()
    rows: list[dict] = []
    claimed: set[tuple[int, int]] = set()

    for profile in saved:
        live = next((item for item in live_listeners if item["localPort"] == profile["localPort"] and item["command"] == "ssh"), None)
        rows.append({
            **profile,
            "source": "fixed",
            "sourceLabel": "固定",
            "status": "running" if live else "stopped",
            "listening": bool(live),
            "pid": live["pid"] if live else None,
        })
        if live:
            claimed.add((live["pid"], live["localPort"]))

    for item in live_listeners:
        key = (item["pid"], item["localPort"])
        if key in claimed:
            continue
        proc = processes.get(item["pid"], {})
        text = ancestry_text(item["pid"], processes)
        source, source_label = classify(text, item["command"])
        is_ssh = Path(proc.get("comm", "")).name == "ssh" or item["command"] == "ssh"
        host, specs = ssh_details(proc.get("args", "")) if is_ssh else (None, [])
        matching = next((spec for spec in specs if spec.local_port == item["localPort"]), None)
        vscode_match = vscode.get(item["localPort"]) if source == "vscode" else None
        if source == "vscode" and not vscode_match:
            continue
        if source in {"codex", "ssh"} and not matching:
            continue
        if not matching and source not in {"vscode"}:
            continue
        rows.append({
            "id": f"live-{item['pid']}-{item['localPort']}",
            "name": source_label,
            "label": None,
            "bindAddress": matching.bind if matching else item["localHost"],
            "localPort": item["localPort"],
            "sshHost": host or (vscode_match or {}).get("sshHost"),
            "remoteHost": matching.remote_host if matching else (vscode_match or {}).get("remoteHost"),
            "remotePort": matching.remote_port if matching else (vscode_match or {}).get("remotePort"),
            "source": source,
            "sourceLabel": source_label,
            "status": "running",
            "listening": True,
            "pid": item["pid"],
            "editable": False,
            "stoppable": True,
        })
    order = {"fixed": 0, "codex": 1, "vscode": 2, "ssh": 3}
    rows.sort(key=lambda row: (order.get(row["source"], 9), row["localPort"]))
    reserved_ports = {item["localPort"] for item in live_listeners}
    reserved_ports.update(row["localPort"] for row in rows)
    for row in rows:
        row["suggestedFixedPort"] = (
            suggested_fixed_port(row["localPort"], reserved_ports)
            if row["source"] in {"codex", "vscode"}
            else None
        )
    with ThreadPoolExecutor(max_workers=min(6, max(1, len(rows)))) as pool:
        websites = list(pool.map(lambda row: probe_web(row["localPort"]) if row["listening"] else None, rows))
    for row, website in zip(rows, websites):
        row["webTitle"] = website.get("title") if website else None
        row["webUrl"] = website.get("url") if website else None
        if row["listening"]:
            healthy, detail = endpoint_health(row["localPort"], website)
            if not healthy:
                row["status"] = "error"
            row["statusDetail"] = detail
        else:
            row["statusDetail"] = "本地监听不存在"
    return {"forwards": rows, "sshHosts": concrete_ssh_hosts(), "updatedAt": int(time.time())}


def stop_temporary(pid: int, local_port: int) -> dict:
    match = next(
        (
            item
            for item in snapshot()["forwards"]
            if item.get("pid") == pid
            and item.get("localPort") == local_port
            and item.get("source") in {"codex", "vscode", "ssh"}
            and not item.get("editable")
        ),
        None,
    )
    if not match:
        raise ValueError("该临时转发已结束，或不属于可停止的 SSH/Codex/VS Code 进程")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError as exc:
        raise ValueError("进程已经结束") from exc
    except PermissionError as exc:
        raise ValueError("没有权限停止该进程") from exc
    return {"ok": True, "pid": pid, "note": "所属应用可能按需重新建立转发"}


def solidify_temporary(pid: int, local_port: int, payload: dict) -> dict:
    match = next(
        (
            item
            for item in snapshot()["forwards"]
            if item.get("pid") == pid
            and item.get("localPort") == local_port
            and item.get("source") in {"codex", "vscode"}
            and not item.get("editable")
        ),
        None,
    )
    if not match:
        raise ValueError("该 Codex/VS Code 临时转发已结束，无法固化")

    result = save_profile(payload)
    try:
        os.kill(pid, signal.SIGTERM)
        result.update({"solidified": True, "stoppedPid": pid})
    except ProcessLookupError:
        result.update({"solidified": True, "stoppedPid": pid, "note": "原临时转发已经结束"})
    except PermissionError:
        result.update({"solidified": True, "stoppedPid": None, "warning": "固定转发已建立，但没有权限停止原临时转发"})
    return result


def validate_payload(payload: dict) -> dict:
    name = str(payload.get("name", "")).strip()
    ssh_host = str(payload.get("sshHost", "")).strip()
    remote_host = str(payload.get("remoteHost", "127.0.0.1")).strip()
    bind = str(payload.get("bindAddress", "127.0.0.1")).strip()
    if not name or len(name) > 60:
        raise ValueError("名称不能为空，且不能超过 60 个字符")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", ssh_host):
        raise ValueError("SSH 主机必须是 ~/.ssh/config 中的安全别名")
    if bind not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("为安全起见，只允许绑定本机回环地址")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", remote_host):
        raise ValueError("远端地址格式不合法")
    try:
        local_port = int(payload["localPort"])
        remote_port = int(payload["remotePort"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("端口必须是整数") from exc
    if not (1024 <= local_port <= 65535 and 1 <= remote_port <= 65535):
        raise ValueError("本地端口需为 1024–65535，远端端口需为 1–65535")
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or f"forward-{local_port}"
    return {"name": name, "slug": slug[:48], "sshHost": ssh_host, "remoteHost": remote_host, "bindAddress": bind, "localPort": local_port, "remotePort": remote_port}


def make_plist(values: dict, label: str) -> bytes:
    args = [
        "/usr/bin/ssh", "-N", "-T", "-L",
        f"{values['bindAddress']}:{values['localPort']}:{values['remoteHost']}:{values['remotePort']}",
        "-o", "ExitOnForwardFailure=yes", "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4", values["sshHost"],
    ]
    data = {
        "Label": label,
        "PortForwardManagerName": values["name"],
        "ProgramArguments": args,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "StandardOutPath": f"/tmp/{label}.log",
        "StandardErrorPath": f"/tmp/{label}.log",
    }
    return plistlib.dumps(data, fmt=plistlib.FMT_XML, sort_keys=False)


def domain() -> str:
    return f"gui/{os.getuid()}"


def bootout(label: str) -> None:
    run("/bin/launchctl", "bootout", f"{domain()}/{label}")


def bootstrap(path: Path) -> None:
    result = run("/bin/launchctl", "bootstrap", domain(), str(path))
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "launchctl bootstrap 失败")


def save_profile(payload: dict, old_id: Optional[str] = None) -> dict:
    values = validate_payload(payload)
    existing = {item["id"]: item for item in profiles()}
    if old_id:
        if old_id not in existing:
            raise ValueError("找不到要编辑的固定转发")
        label = old_id
        path = Path(existing[old_id]["path"])
        bootout(label)
    else:
        label = LABEL_PREFIX + values["slug"]
        path = LAUNCH_AGENTS / f"{label}.plist"
        if path.exists():
            raise ValueError("同名固定转发已经存在")
    data = make_plist(values, label)
    with tempfile.NamedTemporaryFile(dir=LAUNCH_AGENTS, prefix=path.name, delete=False) as handle:
        handle.write(data)
        temp_path = Path(handle.name)
    os.replace(temp_path, path)
    bootstrap(path)
    return {"ok": True, "id": label}


def delete_profile(profile_id: str) -> dict:
    existing = {item["id"]: item for item in profiles()}
    if profile_id not in existing:
        raise ValueError("找不到固定转发")
    path = Path(existing[profile_id]["path"])
    bootout(profile_id)
    trash = Path.home() / ".Trash"
    trash.mkdir(exist_ok=True)
    destination = trash / f"{path.name}.{int(time.time())}"
    shutil.move(path, destination)
    return {"ok": True, "recoverableFrom": str(destination)}


class Handler(BaseHTTPRequestHandler):
    server_version = "PortForwardManager/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}", flush=True)

    def send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def allowed_host(self) -> bool:
        host = self.headers.get("Host", "").split(":", 1)[0]
        return host in {"localhost", "127.0.0.1", "[::1]"}

    def mutation_allowed(self) -> bool:
        origin = self.headers.get("Origin", "")
        parsed = urlparse(origin) if origin else None
        browser_request = (
            self.allowed_host()
            and self.headers.get("X-Port-Forward-Manager") == "1"
            and parsed is not None
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            and parsed.port == LISTEN_PORT
        )
        plugin_request = (
            self.allowed_host()
            and self.headers.get("Authorization", "") == f"Bearer {auth_token()}"
        )
        return browser_request or plugin_request

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 16384:
            raise ValueError("请求过大")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self) -> None:
        if not self.allowed_host():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        path = urlparse(self.path).path
        if path == "/api/forwards":
            self.send_json(snapshot())
            return
        if path in {"/", "/index.html"}:
            body = INDEX_FILE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/icon.svg":
            body = ICON_FILE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if not self.mutation_allowed():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        path = urlparse(self.path).path
        try:
            payload = self.read_json()
            if path == "/api/profiles":
                self.send_json(save_profile(payload), 201)
                return
            match = re.fullmatch(r"/api/profiles/([^/]+)/(start|stop)", path)
            if match:
                profile_id, action = unquote(match.group(1)), match.group(2)
                existing = {item["id"]: item for item in profiles()}
                if profile_id not in existing:
                    raise ValueError("找不到固定转发")
                if action == "start":
                    bootstrap(Path(existing[profile_id]["path"]))
                else:
                    bootout(profile_id)
                self.send_json({"ok": True})
                return
            match = re.fullmatch(r"/api/live/(\d+)/(\d+)/stop", path)
            if match:
                self.send_json(stop_temporary(int(match.group(1)), int(match.group(2))))
                return
            match = re.fullmatch(r"/api/live/(\d+)/(\d+)/solidify", path)
            if match:
                self.send_json(solidify_temporary(int(match.group(1)), int(match.group(2)), payload), 201)
                return
        except (ValueError, RuntimeError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
            return
        self.send_error(404)

    def do_PUT(self) -> None:
        if not self.mutation_allowed():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        match = re.fullmatch(r"/api/profiles/([^/]+)", urlparse(self.path).path)
        if not match:
            self.send_error(404)
            return
        try:
            self.send_json(save_profile(self.read_json(), unquote(match.group(1))))
        except (ValueError, RuntimeError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)

    def do_DELETE(self) -> None:
        if not self.mutation_allowed():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        match = re.fullmatch(r"/api/profiles/([^/]+)", urlparse(self.path).path)
        if not match:
            self.send_error(404)
            return
        try:
            self.send_json(delete_profile(unquote(match.group(1))))
        except ValueError as exc:
            self.send_json({"error": str(exc)}, 400)


if __name__ == "__main__":
    auth_token()
    print(f"Port Forward Manager: http://localhost:{LISTEN_PORT}", flush=True)
    ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()
