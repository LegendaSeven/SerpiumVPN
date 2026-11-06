"""Offline server-kit regression checks; no Docker deployment and no external server access."""
import copy
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

PROJECT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("server", PROJECT / "Server" / "serpium_server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)
OUTPUT = pathlib.Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else pathlib.Path(tempfile.mkdtemp())
OUTPUT.mkdir(parents=True, exist_ok=True)


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=OUTPUT)
        self.root = pathlib.Path(self.temporary.name) / ".serpium-server"
        self.root.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def engine(self, mode="outline"):
        name = "sing-box" if mode == "outline" else "xray"
        return server.Engine(name, str(PROJECT / "bin_files" / "relay" / (name + ".exe")))

    def state(self, mode="outline"):
        state = server.new_state(mode, "vpn.example.com", 443, "www.example.com", self.engine(mode))
        server.add_user(state, "alice")
        return state

    def test_both_configs_are_accepted_by_actual_pinned_engines(self):
        for mode in ("outline", "reality"):
            state = self.state(mode)
            revision = server.prepare(self.root, state, self.engine(mode))
            self.assertEqual(state, server.load_state(self.root))
            # Artificial credentials only; used by the C# client compatibility and loopback tests.
            fixture = OUTPUT / mode
            fixture.mkdir(exist_ok=True)
            (fixture / "config.json").write_text((self.root / "revisions" / revision / "config.json").read_text(), encoding="utf-8")
            (fixture / "key.txt").write_text(server.client_key(state, "alice"), encoding="utf-8")
            self.assertEqual(len(revision), 32)

    def test_individual_keys_and_ports(self):
        state = self.state()
        server.add_user(state, "bob")
        self.assertNotEqual(server.client_key(state, "alice"), server.client_key(state, "bob"))
        self.assertNotEqual(state["users"]["alice"]["password"], state["users"]["bob"]["password"])
        self.assertEqual([u["port"] for u in state["users"].values()], [443, 444])
        self.assertEqual([u["internal_port"] for u in state["users"].values()], [20000, 20001])
        self.assertIn("443:20000/udp", server.compose_config(state)["services"]["vpn"]["ports"])

    def test_reality_users_share_port_but_not_credentials(self):
        state = self.state("reality")
        server.add_user(state, "bob")
        self.assertEqual(state["users"]["alice"]["port"], state["users"]["bob"]["port"])
        self.assertNotEqual(state["users"]["alice"]["id"], state["users"]["bob"]["id"])
        self.assertNotIn(state["reality"]["private_key"], server.client_key(state, "alice"))

    def test_compose_has_no_admin_api_privileges_or_floating_images(self):
        for mode in ("outline", "reality"):
            service = server.compose_config(self.state(mode))["services"]["vpn"]
            self.assertIn("@sha256:", service["image"])
            self.assertNotIn("latest", service["image"])
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertTrue(service["read_only"])
            self.assertNotEqual(service["user"], "0")
            self.assertNotIn("network_mode", service)
            self.assertEqual(len(service["volumes"]), 1)
            self.assertNotIn("state.json", json.dumps(service))

    def test_server_blocks_private_network_destinations(self):
        outline = server.server_config(self.state())
        self.assertEqual(outline["route"]["rules"][0]["action"], "resolve")
        self.assertIn("169.254.0.0/16", outline["route"]["rules"][1]["ip_cidr"])
        reality = server.server_config(self.state("reality"))
        self.assertEqual(reality["routing"]["domainStrategy"], "IPOnDemand")
        self.assertIn("127.0.0.0/8", reality["routing"]["rules"][0]["ip"])

    def test_invalid_input(self):
        for value in ("../owner", "a/b", "a b", "", "a" * 33, "x\nTOKEN"):
            with self.subTest(value=value), self.assertRaises(server.ServerError):
                server.user_name(value)
        for host in ("127.0.0.1", "10.0.0.1", "::1", "https://example.com/", "x.local", "-bad.example.com", "host:443"):
            with self.subTest(host=host), self.assertRaises(server.ServerError):
                server.hostname(host)
        self.assertEqual(server.hostname("[2606:4700:4700::1111]"), "2606:4700:4700::1111")
        self.assertTrue(server.hostname("пример.рф").startswith("xn--"))

    def test_duplicates_limits_and_port_exhaustion(self):
        state = self.state()
        with self.assertRaises(server.ServerError):
            server.add_user(state, "alice")
        state["first_port"] = 65535
        server.add_user(state, "last")
        with self.assertRaises(server.ServerError):
            server.add_user(state, "overflow")

    def test_invalid_configuration_does_not_replace_current(self):
        state = self.state()
        original = server.prepare(self.root, state, self.engine())
        bad = copy.deepcopy(state)
        bad["users"]["alice"]["internal_port"] = 99999
        with self.assertRaises(server.ServerError):
            server.prepare(self.root, bad, self.engine())
        self.assertEqual(server.current_revision(self.root), original)

    def test_empty_server_after_last_revocation_is_valid(self):
        for mode in ("outline", "reality"):
            state = self.state(mode)
            state["users"] = {}
            server.prepare(self.root, state, self.engine(mode))
            with self.assertRaises(server.ServerError):
                server.client_key(state, "alice")

    def test_revisions_cannot_escape_private_directory(self):
        (self.root / "CURRENT").write_text("../../somewhere")
        with self.assertRaises(server.ServerError):
            server.current_revision(self.root)

    def test_key_export_ipv6_roundtrip(self):
        state = self.state()
        state["host"] = "2606:4700:4700::1111"
        self.assertIn("@[2606:4700:4700::1111]:443/", server.client_key(state, "alice"))

    def test_apply_rollback_and_no_success_pointer_on_failure(self):
        state = self.state()
        old = server.prepare(self.root, state, self.engine())
        (self.root / "DEPLOYED").write_text(old)
        server.add_user(state, "bob")
        new = server.prepare(self.root, state, self.engine())
        calls = []
        def fake_compose(root, revision, args):
            calls.append((revision, args[0]))
            if revision == new and args[0] == "up":
                raise server.ServerError("Synthetic failure")
        with patch.object(server.sys, "platform", "linux"), patch.object(server.Engine, "check"), patch.object(server, "compose", fake_compose):
            with self.assertRaisesRegex(server.ServerError, "restored"):
                server.apply(self.root)
        self.assertIn((old, "up"), calls)
        self.assertEqual(server.current_revision(self.root, "DEPLOYED"), old)

    def test_apply_success_records_exact_revision(self):
        revision = server.prepare(self.root, self.state(), self.engine())
        with patch.object(server.sys, "platform", "linux"), patch.object(server.Engine, "check"), patch.object(server, "compose") as compose:
            server.apply(self.root)
            self.assertIn("--force-recreate", compose.call_args.args[2])
        self.assertEqual(server.current_revision(self.root, "DEPLOYED"), revision)

    def test_cli_rotation_revocation_and_export_secrecy(self):
        state = self.state()
        server.prepare(self.root, state, self.engine())
        engine = str(PROJECT / "bin_files" / "relay" / "sing-box.exe")
        prefix = ["--state", str(self.root), "--engine-binary", engine]
        # Directory ACLs are exercised separately on the exported fixtures directory. Avoid locking out unittest cleanup.
        with patch.object(server, "secure_root", return_value=self.root), redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()):
            self.assertEqual(server.main([*prefix, "export", "--user", "alice"]), 0)
            old = (self.root / "exports" / "alice.txt").read_text()
            self.assertEqual(server.main([*prefix, "rotate", "--user", "alice"]), 0)
            self.assertFalse((self.root / "exports" / "alice.txt").exists())
            self.assertNotEqual(old.strip(), server.client_key(server.load_state(self.root), "alice"))
            self.assertEqual(server.main([*prefix, "revoke", "--user", "alice"]), 0)
            self.assertEqual(server.main([*prefix, "export", "--user", "alice"]), 1)
            self.assertNotIn("ss://", output.getvalue())
            self.assertNotIn(state["users"]["alice"]["password"], output.getvalue())

    def test_engine_version_must_match(self):
        with patch.object(server, "run", return_value="sing-box version 0.0.1"), self.assertRaises(server.ServerError):
            self.engine()

    def test_state_lock_excludes_concurrent_mutation(self):
        with server.state_lock(self.root):
            with self.assertRaises(server.ServerError), server.state_lock(self.root):
                pass

    def test_docker_check_mounts_only_configuration(self):
        command = server.Engine("xray").command(["run", "-test"], self.root)
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("target=/input.json,readonly", ' '.join(command))
        self.assertNotIn("state.json", ' '.join(command))

    def test_reality_preflight_rejects_private_dns(self):
        state = self.state("reality")
        import socket
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]
        with patch.object(server.socket, "getaddrinfo", return_value=answer), self.assertRaises(server.ServerError):
            server.check_reality_target(state)

    def test_first_deployment_failure_stops_partial_container(self):
        server.prepare(self.root, self.state(), self.engine())
        calls = []
        def fake_compose(root, revision, args):
            calls.append(args[0])
            if args[0] == "up":
                raise server.ServerError("Synthetic failure")
        with patch.object(server.sys, "platform", "linux"), patch.object(server.Engine, "check"), patch.object(server, "compose", fake_compose):
            with self.assertRaises(server.ServerError):
                server.apply(self.root)
        self.assertIn("down", calls)
        self.assertIsNone(server.current_revision(self.root, "DEPLOYED"))

    def test_failed_rollback_is_not_reported_as_success(self):
        old = server.prepare(self.root, self.state(), self.engine())
        (self.root / "DEPLOYED").write_text(old)
        def fake_compose(root, revision, args):
            if args[0] == "up":
                raise server.ServerError("Synthetic failure")
        with patch.object(server.sys, "platform", "linux"), patch.object(server.Engine, "check"), patch.object(server, "compose", fake_compose):
            with self.assertRaisesRegex(server.ServerError, "rollback failed"):
                server.apply(self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
