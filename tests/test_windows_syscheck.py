"""Windows listener/proxy observations, runnable with pytest or stdlib unittest."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from wmpf_mcp.core import syscheck


def completed(stdout="", returncode=0, stderr=""):
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


class WindowsListeners(unittest.TestCase):
    def setUp(self):
        self.platform = patch.object(syscheck.sys, "platform", "win32")
        self.platform.start()
        self.addCleanup(self.platform.stop)

    def test_native_listener_ownership_and_multiple_pids(self):
        own = os.getpid()
        external = own + 1
        output = json.dumps({"listeners": [{"LocalPort": 10000, "OwningProcess": pid}
                                           for pid in (external, own, external)]})
        with patch.object(syscheck.subprocess, "run", return_value=completed(output)) as run:
            result = syscheck.port_state(10000)
        self.assertEqual(result["state"], "busy")
        self.assertEqual(result["pids"], sorted([own, external]))
        self.assertEqual(result["ownership"], "mixed")
        self.assertEqual(result["owned_pids"], [own])
        self.assertEqual(result["external_pids"], [external])
        self.assertEqual(result["source"], "Get-NetTCPConnection")
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["powershell.exe", "-NoProfile", "-NonInteractive"])
        self.assertIn("Get-NetTCPConnection -State Listen -ErrorAction Stop", command[-1])
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_native_empty_snapshot_is_observation_only(self):
        with patch.object(syscheck.subprocess, "run", return_value=completed('{"listeners":[]}')):
            result = syscheck.port_state(10000)
        self.assertEqual((result["state"], result["pid"], result["ownership"]),
                         ("free", None, "not_observed"))
        self.assertIn("does not reserve", result["note"])

    def test_owned_and_external_are_distinct(self):
        for pid, expected in [(os.getpid(), "owned"), (os.getpid() + 1, "external")]:
            with self.subTest(expected=expected):
                output = json.dumps({"listeners": [{"LocalPort": 10000, "OwningProcess": pid}]})
                with patch.object(syscheck.subprocess, "run", return_value=completed(output)):
                    result = syscheck.port_state(10000)
                    self.assertEqual(result["ownership"], expected)
                    self.assertEqual(syscheck.port_busy_pid(10000), pid)

    def test_denied_primary_falls_back_to_ipv6_netstat(self):
        output = "  TCP    [::1]:10000     [::]:0     LISTENING     123\n"
        with patch.object(syscheck.subprocess, "run", side_effect=[
            completed(returncode=1, stderr="Access denied"), completed(output),
        ]) as run:
            result = syscheck.port_state(10000)
        self.assertEqual((result["state"], result["pid"], result["source"]), ("busy", 123, "netstat"))
        self.assertIn("Access denied", result["fallback_reason"])
        self.assertEqual(run.call_args.args[0], ["netstat.exe", "-ano"])

    def test_netstat_does_not_treat_established_connection_as_listener(self):
        output = ("Proto Local Address Foreign Address State PID\n"
                  " TCP 127.0.0.1:10000 127.0.0.1:50123 ESTABLISHED 123\n"
                  " TCP 0.0.0.0:10001 0.0.0.0:0 LISTENING 124\n")
        with patch.object(syscheck.subprocess, "run", side_effect=[FileNotFoundError(), completed(output)]):
            result = syscheck.port_state(10000)
        self.assertEqual(result["state"], "free")
        self.assertEqual(result["ownership"], "not_observed")

    def test_failed_or_incomplete_queries_remain_unknown(self):
        native_outputs = ["", "{}", '{"listeners":null}', '{"listeners":{}}',
                          '{"listeners":[{"LocalPort":10000}]}',
                          '{"listeners":[{"LocalPort":9999,"OwningProcess":1}]}',
                          '{"listeners":[{"LocalPort":10000,"OwningProcess":true}]}']
        for output in native_outputs:
            with self.subTest(output=output):
                with patch.object(syscheck.subprocess, "run", side_effect=[completed(output), completed("")]):
                    result = syscheck.port_state(10000)
                self.assertEqual((result["state"], result["pid"], result["ownership"]),
                                 ("unknown", None, "unknown"))

    def test_netstat_errors_and_malformed_rows_remain_unknown(self):
        outputs = [completed(returncode=1), completed("", stderr="denied"),
                   completed("TCP 0.0.0.0:10000 0.0.0.0:0 LISTENING 0"),
                   completed("TCP 0.0.0.0:10000 0.0.0.0:0 UNRECOGNIZED 123"),
                   completed("TCP 0.0.0.0:10000 missing LISTENING 123")]
        for output in outputs:
            with self.subTest(output=output):
                with patch.object(syscheck.subprocess, "run", side_effect=[FileNotFoundError(), output]):
                    self.assertEqual(syscheck.port_state(10000)["state"], "unknown")

    def test_native_timeout_and_fallback_failure_remain_unknown(self):
        with patch.object(syscheck.subprocess, "run", side_effect=[
            subprocess.TimeoutExpired("powershell.exe", 5), OSError("netstat unavailable"),
        ]):
            result = syscheck.port_state(10000)
        self.assertEqual(result["state"], "unknown")
        self.assertIn("netstat unavailable", result["reason"])

    def test_invalid_port_cannot_enter_command(self):
        for port in ["10000;exit", 0, 65536, True]:
            with self.subTest(port=port), patch.object(syscheck.subprocess, "run") as run:
                self.assertEqual(syscheck.port_state(port)["state"], "unknown")
                run.assert_not_called()


class WindowsProxy(unittest.TestCase):
    def test_sources_are_independent_and_environment_is_inherited(self):
        configs = {"wininet": {"checked": True, "enabled": False},
                   "winhttp": {"checked": True, "enabled": False}}
        with patch.object(syscheck.sys, "platform", "win32"), patch.dict(os.environ, {
            "HTTPS_PROXY": "http://name:password@127.0.0.1:8080", "NO_PROXY": "localhost,127.0.0.1",
        }, clear=True), patch.object(syscheck, "_windows_proxy_config", side_effect=configs.__getitem__):
            result = syscheck.proxy_state()
        self.assertTrue(result["checked"])
        self.assertTrue(result["enabled"])
        self.assertEqual(set(result["sources"]), {"env", "wininet", "winhttp"})
        env = result["sources"]["env"]
        self.assertEqual(env["variables"]["NO_PROXY"], "localhost,127.0.0.1")
        self.assertNotIn("password", env["variables"]["HTTPS_PROXY"])

    def test_query_failure_never_becomes_proxy_disabled(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(syscheck, "_windows_proxy_config", side_effect=[
            {"checked": False, "enabled": None, "reason": "denied"},
            {"checked": True, "enabled": False},
        ]):
            result = syscheck._windows_proxy_state()
        self.assertFalse(result["checked"])
        self.assertIsNone(result["enabled"])
        self.assertEqual(result["sources"]["wininet"]["reason"], "denied")

    def test_known_enabled_source_remains_visible_when_another_query_fails(self):
        with patch.dict(os.environ, {"all_proxy": "socks5://127.0.0.1:1080"}, clear=True), \
                patch.object(syscheck, "_windows_proxy_config", return_value={"checked": False, "enabled": None}):
            result = syscheck._windows_proxy_state()
        self.assertFalse(result["checked"])
        self.assertTrue(result["enabled"])

    def test_no_proxy_bypass_alone_does_not_enable_proxy(self):
        with patch.dict(os.environ, {"NO_PROXY": "*"}, clear=True), \
                patch.object(syscheck, "_windows_proxy_config", return_value={"checked": True, "enabled": False}):
            result = syscheck._windows_proxy_state()
        self.assertTrue(result["checked"])
        self.assertFalse(result["enabled"])

    def native_query(self, source, *, flag, server=None, bypass=None, pac=None, succeeds=True):
        buffers = {key: ctypes.create_unicode_buffer(value) for key, value in
                   {"server": server, "bypass": bypass, "pac": pac}.items() if value is not None}
        def fill(pointer):
            pointer._obj.flag = flag
            for key, buffer in buffers.items():
                setattr(pointer._obj, key, ctypes.addressof(buffer))
            return int(succeeds)
        query = Mock(side_effect=fill)
        free = Mock()
        winhttp = SimpleNamespace(WinHttpGetIEProxyConfigForCurrentUser=query,
                                  WinHttpGetDefaultProxyConfiguration=query)
        with patch.object(ctypes, "WinDLL", side_effect=[winhttp, SimpleNamespace(GlobalFree=free)], create=True), \
                patch.object(ctypes, "WinError", return_value=OSError("native query failed"), create=True), \
                patch.object(ctypes, "get_last_error", return_value=5, create=True):
            result = syscheck._windows_proxy_config(source)
        self.assertEqual({call.args[0] for call in free.call_args_list},
                         {ctypes.addressof(buffer) for buffer in buffers.values()})
        return result

    def test_wininet_reports_pac_wpad_and_bypass(self):
        result = self.native_query("wininet", flag=1, server="proxy:8080", bypass="<local>", pac="https://local/proxy.pac")
        self.assertTrue(result["checked"])
        self.assertTrue(result["enabled"])
        self.assertEqual(result["automatic"], {"pac": True, "discovery": True})
        self.assertEqual(result["bypass"], "<local>")

    def test_winhttp_named_proxy_and_direct_are_distinct(self):
        for flag, server, enabled in [(1, None, False), (3, "proxy:8080", True)]:
            with self.subTest(flag=flag):
                result = self.native_query("winhttp", flag=flag, server=server)
                self.assertTrue(result["checked"])
                self.assertEqual(result["enabled"], enabled)

    def test_winhttp_invalid_result_stays_unknown_and_releases_strings(self):
        result = self.native_query("winhttp", flag=0, server="proxy:8080")
        self.assertFalse(result["checked"])
        self.assertIsNone(result["enabled"])

    def test_native_api_failure_stays_unknown_and_releases_strings(self):
        result = self.native_query("wininet", flag=0, server="proxy:8080", succeeds=False)
        self.assertFalse(result["checked"])
        self.assertIsNone(result["enabled"])
        self.assertIn("native query failed", result["reason"])


if __name__ == "__main__":
    unittest.main()
