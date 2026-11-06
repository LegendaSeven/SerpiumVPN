#!/usr/bin/env python3
"""Serpium server preparation and deployment. Python 3.10+, no pip packages.

Private state is deliberately separate from the application/release directory.
Only `apply` and `stop` affect a running Linux Docker server.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import csv
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import uuid
from urllib.parse import quote, urlencode

HERE = Path(__file__).resolve().parent
MAX_USERS = 100
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}\Z")
REVISION = re.compile(r"[0-9a-f]{32}\Z")
PRIVATE_NETWORKS = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15",
                    "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"]


class ServerError(Exception):
    """Messages contain no keys, process output or server configuration."""


def run(command: list[str], timeout: int = 40) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ServerError("Could not run the required tool, or it timed out.") from error
    if result.returncode != 0:
        raise ServerError("Tool rejected the operation. Existing deployment has not been confirmed changed.")
    if len(result.stdout) > 1_000_000:
        raise ServerError("Unexpected tool response.")
    return result.stdout


def hostname(value: str, public: bool = True) -> str:
    value = value.strip().rstrip('.').strip('[]')
    try:
        address = ipaddress.ip_address(value)
        if public and not address.is_global:
            raise ServerError("Use a public server address.")
        return str(address)
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ServerError("Invalid server hostname.") from error
    if len(value) > 253 or '.' not in value or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split('.')):
        raise ServerError("Use a hostname or public IP, without a URL, path or port.")
    if value.endswith((".local", ".localhost", ".internal")):
        raise ServerError("Use a public server hostname.")
    return value


def user_name(value: str) -> str:
    if not NAME.fullmatch(value):
        raise ServerError("User name must contain 1-32 ASCII letters, digits, underscores or hyphens.")
    return value


def atomic_text(path: Path, text: str, mode: int = 0o600) -> None:
    if path.is_symlink():
        raise ServerError("Refusing to write through a symbolic link.")
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        os.chmod(temporary, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path: Path) -> dict:
    if path.is_symlink() or path.stat().st_size > 2_000_000:
        raise ServerError("Invalid state file.")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def json_text(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def secure_root(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    # A recognizable directory name is excluded by Git and the application's publish rules.
    if path.name != ".serpium-server":
        raise ServerError("The private state directory must be named .serpium-server.")
    for parent in (path, *path.parents):
        if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
            raise ServerError("Private state must not use linked directories.")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name == "nt":
        sid = next(csv.reader(run(["whoami", "/user", "/fo", "csv", "/nh"]).splitlines()))[1]
        if not re.fullmatch(r"S-1-[0-9-]+", sid):
            raise ServerError("Unable to identify the current Windows account.")
        run(["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"])
    else:
        if path.stat().st_uid != os.getuid():
            raise ServerError("Private state belongs to another account.")
        path.chmod(0o700)
    return path


@contextlib.contextmanager
def state_lock(root: Path):
    lock = root / ".lock"
    if lock.is_symlink():
        raise ServerError("Invalid state lock.")
    with open(lock, "a+b") as stream:
        os.chmod(lock, 0o600)
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            stream.write(b"0")
            stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise ServerError("Another server operation is running.") from error
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise ServerError("Another server operation is running.") from error
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def pinned_engine(engine: str) -> dict:
    item = read_json(HERE / "images.lock.json")[engine]
    repository = {"sing-box": "sagernet/sing-box", "xray": "xtls/xray-core"}[engine]
    if not re.fullmatch(r"ghcr\.io/" + repository + r"@sha256:[0-9a-f]{64}", item["image"]):
        raise ServerError("A digest-pinned official image is required.")
    return item


class Engine:
    def __init__(self, engine: str, binary: str | None = None):
        self.engine = engine
        self.binary = str(Path(binary).resolve(strict=True)) if binary else None
        self.pin = pinned_engine(engine)
        if self.binary:
            version = run([self.binary, "version"])
            if not re.search(r"(?<![\d.])" + re.escape(self.pin["version"]) + r"(?![\d.])", version):
                raise ServerError("Local engine version differs from the server lock file.")

    def command(self, args: list[str], directory: Path | None = None) -> list[str]:
        if self.binary:
            return [self.binary, *args]
        command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
                   "--security-opt=no-new-privileges:true"]
        if directory:
            command += ["--mount", f"type=bind,source={(directory / 'config.json').resolve()},target=/input.json,readonly"]
        return [*command, self.pin["image"], *args]

    def keys(self) -> tuple[str, str]:
        output = run(self.command(["x25519"]), timeout=180)
        values = dict(line.split(":", 1) for line in output.splitlines() if ":" in line)
        private = values.get("PrivateKey", "").strip()
        public = values.get("Password (PublicKey)", values.get("PublicKey", "")).strip()
        if not all(re.fullmatch(r"[A-Za-z0-9_-]{43}", value) for value in (private, public)):
            raise ServerError("Engine did not return a supported REALITY key pair.")
        return private, public

    def check(self, directory: Path) -> None:
        config = str(directory / "config.json") if self.binary else "/input.json"
        arguments = ["check", "-c", config] if self.engine == "sing-box" else ["run", "-test", "-config", config]
        run(self.command(arguments, directory), timeout=180)


def new_state(mode: str, host: str, port: int, target: str | None, engine: Engine) -> dict:
    if mode not in ("outline", "reality") or not 1 <= port <= 65535:
        raise ServerError("Unsupported mode or port.")
    state = {"schema": 1, "project": "serpium-" + secrets.token_hex(4), "mode": mode,
             "host": hostname(host), "first_port": port, "users": {}}
    if mode == "reality":
        if not target:
            raise ServerError("REALITY needs --target: a suitable public TLS 1.3 hostname reachable from the VPS.")
        target = hostname(target)
        if ipaddress_like(target):
            raise ServerError("REALITY target must be a TLS hostname, not an IP address.")
        private, public = engine.keys()
        state["reality"] = {"target": target, "private_key": private, "public_key": public,
                            "short_id": secrets.token_hex(8)}
    return state


def ipaddress_like(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def add_user(state: dict, name: str) -> None:
    user_name(name)
    if name in state["users"] or len(state["users"]) >= MAX_USERS:
        raise ServerError("User already exists, or the 100-user limit was reached.")
    port = state["first_port"]
    if state["mode"] == "outline":
        occupied = {user["port"] for user in state["users"].values()}
        while port in occupied:
            port += 1
        if port > 65535:
            raise ServerError("No free port remains in the selected range.")
    internal = 20000
    occupied_internal = {user["internal_port"] for user in state["users"].values()}
    while internal in occupied_internal:
        internal += 1
    state["users"][name] = {"port": port, "internal_port": internal,
                            "password": secrets.token_urlsafe(32), "id": str(uuid.uuid4())}


def server_config(state: dict) -> dict:
    if state["mode"] == "outline":
        return {"log": {"disabled": True}, "dns": {
            "servers": [{"type": "udp", "tag": "resolver", "server": "1.1.1.1"}], "final": "resolver"}, "inbounds": [
            {"type": "shadowsocks", "tag": name, "listen": "0.0.0.0", "listen_port": user["internal_port"],
             "method": "chacha20-ietf-poly1305", "password": user["password"]}
            for name, user in state["users"].items()],
            "outbounds": [{"type": "direct", "tag": "internet"}],
            "route": {"rules": [{"action": "resolve"}, {"ip_cidr": PRIVATE_NETWORKS, "action": "reject"}], "final": "internet"}}
    reality = state["reality"]
    return {"log": {"loglevel": "none", "access": "none", "error": "none"}, "inbounds": [
        {"listen": "0.0.0.0", "port": 10443, "protocol": "vless",
         "settings": {"clients": [{"id": user["id"], "flow": "xtls-rprx-vision"} for user in state["users"].values()], "decryption": "none"},
         "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
             "show": False, "target": reality["target"] + ":443", "xver": 0,
             "serverNames": [reality["target"]], "privateKey": reality["private_key"],
             "shortIds": [reality["short_id"]]}}}],
        "outbounds": [{"protocol": "freedom", "tag": "internet"}, {"protocol": "blackhole", "tag": "block"}],
        "routing": {"domainStrategy": "IPOnDemand", "rules": [
            {"type": "field", "ip": PRIVATE_NETWORKS, "outboundTag": "block"}]}}


def client_key(state: dict, name: str) -> str:
    user_name(name)
    if name not in state["users"]:
        raise ServerError("User does not exist.")
    user = state["users"][name]
    host = state["host"]
    if ':' in host:
        host = '[' + host + ']'
    label = quote("Serpium " + name, safe="")
    if state["mode"] == "outline":
        credential = base64.urlsafe_b64encode(("chacha20-ietf-poly1305:" + user["password"]).encode()).decode().rstrip('=')
        return f"ss://{credential}@{host}:{user['port']}/?outline=1#{label}"
    reality = state["reality"]
    query = urlencode({"encryption": "none", "security": "reality", "type": "tcp", "flow": "xtls-rprx-vision",
                       "sni": reality["target"], "fp": "chrome", "pbk": reality["public_key"], "sid": reality["short_id"]})
    return f"vless://{user['id']}@{host}:{user['port']}?{query}#{label}"


def compose_config(state: dict) -> dict:
    engine = "sing-box" if state["mode"] == "outline" else "xray"
    ports = [f"{user['port']}:{user['internal_port']}/{proto}" for user in state["users"].values() for proto in ("tcp", "udp")] if engine == "sing-box" else [f"{state['first_port']}:10443/tcp"]
    return {"services": {"vpn": {
        "image": pinned_engine(engine)["image"], "restart": "unless-stopped",
        "user": "65532:65532", "read_only": True, "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"], "pids_limit": 128,
        "command": ["run", "-c" if engine == "sing-box" else "-config", "/etc/serpium/config.json"],
        "volumes": [{"type": "bind", "source": "./config.json", "target": "/etc/serpium/config.json", "read_only": True}],
        "ports": ports, "logging": {"driver": "local", "options": {"max-size": "1m", "max-file": "2"}}
    }}}


def current_revision(root: Path, pointer: str = "CURRENT") -> str | None:
    file = root / pointer
    if not file.exists():
        return None
    if file.is_symlink():
        raise ServerError("Invalid revision pointer.")
    value = file.read_text(encoding="ascii").strip()
    if not REVISION.fullmatch(value):
        raise ServerError("Invalid revision pointer.")
    return value


def load_state(root: Path) -> dict:
    revision = current_revision(root)
    if not revision:
        raise ServerError("Run init first.")
    state = read_json(root / "revisions" / revision / "state.json")
    if state.get("schema") != 1 or state.get("mode") not in ("outline", "reality") or not re.fullmatch(r"serpium-[0-9a-f]{8}", state.get("project", "")):
        raise ServerError("Unsupported server state.")
    return state


def prepare(root: Path, state: dict, engine: Engine) -> str:
    revision = uuid.uuid4().hex
    directory = root / "revisions" / revision
    directory.mkdir(parents=True, mode=0o700)
    atomic_text(directory / "state.json", json_text(state))
    # Parent directories are private. Only the single config file is mounted into the non-root container.
    atomic_text(directory / "config.json", json_text(server_config(state)), mode=0o644)
    atomic_text(directory / "compose.json", json_text(compose_config(state)))
    engine.check(directory)
    atomic_text(root / "CURRENT", revision + "\n")
    # Exports are generated on demand; remove stale copies after a key is rotated/revoked or the host changes.
    exports = root / "exports"
    if exports.exists():
        if exports.is_symlink():
            raise ServerError("Invalid export directory.")
        for file in exports.glob("*.txt"):
            if NAME.fullmatch(file.stem) and not file.is_symlink():
                file.unlink()
    return revision


def compose(root: Path, revision: str, args: list[str], timeout: int = 180) -> str:
    directory = root / "revisions" / revision
    state = read_json(directory / "state.json")
    return run(["docker", "compose", "-p", state["project"], "-f", str(directory / "compose.json"), *args], timeout)


def check_reality_target(state: dict) -> None:
    if state["mode"] != "reality":
        return
    target = hostname(state["reality"]["target"])
    try:
        addresses = socket.getaddrinfo(target, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
            raise ServerError("REALITY target must resolve only to public addresses.")
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["h2"])
        context.set_ecdh_curve("X25519")
        for family, socktype, proto, _, address in addresses[:2]:
            try:
                with socket.socket(family, socktype, proto) as connection:
                    connection.settimeout(6)
                    connection.connect(address)
                    with context.wrap_socket(connection, server_hostname=target) as secured:
                        if secured.version() == "TLSv1.3" and secured.selected_alpn_protocol() == "h2":
                            return
            except (OSError, ValueError):
                continue
    except (OSError, ValueError) as error:
        raise ServerError("Could not verify the REALITY target from this VPS.") from error
    raise ServerError("REALITY target did not confirm TLS 1.3, HTTP/2 and X25519. Choose a compatible target.")


def apply(root: Path) -> None:
    if not sys.platform.startswith("linux"):
        raise ServerError("Deployment is Linux-only. Prepare/check/export can also run on Windows.")
    revision = current_revision(root)
    if not revision:
        raise ServerError("Run init first.")
    previous = current_revision(root, "DEPLOYED")
    state = load_state(root)
    engine = Engine("sing-box" if state["mode"] == "outline" else "xray")
    engine.check(root / "revisions" / revision)
    check_reality_target(state)
    compose(root, revision, ["config", "--quiet"])
    try:
        compose(root, revision, ["up", "-d", "--force-recreate", "--wait", "--wait-timeout", "30"])
    except ServerError as original:
        try:
            if previous:
                compose(root, previous, ["up", "-d", "--force-recreate", "--wait", "--wait-timeout", "30"])
            else:
                compose(root, revision, ["down"])
        except ServerError as rollback:
            raise ServerError("Deployment failed and rollback failed. Server availability needs manual verification.") from rollback
        raise ServerError("Deployment failed. Previous deployment restored (or new deployment stopped).") from original
    atomic_text(root / "DEPLOYED", revision + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path.home() / ".serpium-server")
    parser.add_argument("--engine-binary", help="Exact-version local engine for preparation/tests; deployments always use pinned Docker images")
    commands = parser.add_subparsers(dest="command", required=True)
    initial = commands.add_parser("init")
    initial.add_argument("--mode", choices=["outline", "reality"], required=True)
    initial.add_argument("--host", required=True)
    initial.add_argument("--port", type=int)
    initial.add_argument("--target", help="REALITY TLS 1.3 hostname, e.g. a suitable endpoint you control")
    initial.add_argument("--user", default="owner")
    for name in ("add", "revoke", "rotate", "export"):
        command = commands.add_parser(name)
        command.add_argument("--user", required=True)
    endpoint = commands.add_parser("endpoint")
    endpoint.add_argument("--host", required=True)
    for name in ("apply", "stop", "check", "list"):
        commands.add_parser(name)
    args = parser.parse_args(argv)
    try:
        root = secure_root(args.state)
        with state_lock(root):
            if args.command == "init":
                if current_revision(root):
                    raise ServerError("Already initialized; existing keys were preserved.")
                engine = Engine("sing-box" if args.mode == "outline" else "xray", args.engine_binary)
                port = args.port if args.port is not None else (20000 if args.mode == "outline" else 443)
                state = new_state(args.mode, args.host, port, args.target, engine)
                add_user(state, args.user)
                prepare(root, state, engine)
            else:
                state = load_state(root)
                if args.command == "apply":
                    apply(root)
                    print("Server process started. Verify a client connection from the user's network before declaring it available.")
                    return 0
                if args.command == "stop":
                    if not sys.platform.startswith("linux"):
                        raise ServerError("Deployment operations are Linux-only.")
                    deployed = current_revision(root, "DEPLOYED")
                    if deployed:
                        compose(root, deployed, ["down"])
                        (root / "DEPLOYED").unlink()
                    print("Deployment stopped; private state preserved.")
                    return 0
                if args.command == "list":
                    print("Mode:", state["mode"], "Users:", len(state["users"]))
                    print("Configuration:", "applied" if current_revision(root) == current_revision(root, "DEPLOYED") else "pending apply")
                    for name, user in state["users"].items():
                        print(name, "port", user["port"])
                    return 0
                if args.command == "export":
                    key = client_key(state, args.user)
                    directory = root / "exports"
                    directory.mkdir(mode=0o700, exist_ok=True)
                    if directory.is_symlink():
                        raise ServerError("Invalid export directory.")
                    atomic_text(directory / (args.user + ".txt"), key + "\n")
                    print("Key saved in the private exports directory; paste its contents into Serpium. Do not share server state.")
                    return 0
                engine = Engine("sing-box" if state["mode"] == "outline" else "xray", args.engine_binary)
                if args.command == "check":
                    engine.check(root / "revisions" / current_revision(root))
                    print("Configuration compatible with the pinned engine. This is not a remote connectivity test.")
                    return 0
                if args.command == "add":
                    add_user(state, args.user)
                elif args.command in ("revoke", "rotate"):
                    user_name(args.user)
                    if args.user not in state["users"]:
                        raise ServerError("User does not exist.")
                    if args.command == "revoke":
                        del state["users"][args.user]
                    else:
                        user = state["users"][args.user]
                        user["password"], user["id"] = secrets.token_urlsafe(32), str(uuid.uuid4())
                elif args.command == "endpoint":
                    state["host"] = hostname(args.host)
                prepare(root, state, engine)
            print("Configuration checked and prepared. Run apply on the VPS to activate it. Existing running connections were not changed.")
        return 0
    except (ServerError, OSError, ValueError, KeyError, TypeError):
        # Do not echo raw keys, configs, subprocess output or exception messages from dependencies.
        error = sys.exc_info()[1]
        print(str(error) if isinstance(error, ServerError) else "Server preparation failed; check permissions, arguments and state format.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
