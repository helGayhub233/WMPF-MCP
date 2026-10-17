"""Relocated PE fixtures exercise Windows role analysis without version data."""

from __future__ import annotations

import copy
import json
import struct
from pathlib import Path

import pytest

from wmpf_mcp.offsets import windows
from wmpf_mcp.offsets.service import analysis_backend, static_checks


class _Code:
    def __init__(self, start):
        self.start = start
        self.data = bytearray()

    def emit(self, value):
        self.data.extend(bytes.fromhex(value))

    def relative(self, prefix, target):
        opcode = bytes.fromhex(prefix)
        next_address = self.start + len(self.data) + len(opcode) + 4
        self.data.extend(opcode + struct.pack("<i", target - next_address))


def pe_fixture(path: Path, *, base=0x1000, tag=6, return_out=True,
               span_abi=True, scene_branch=True, duplicate_filter=False,
               clobber_pointer=False, machine=0x8664, webview=True,
               webview_tag=6, duplicate_webview=False, webview_native=True,
               webview_separate_native=False,
               webview_source=b"..\\flue\\devtools_message_filter_webview.cc"):
    """No executable fixture is run; bytes describe role-positive/negative code."""
    load, helper, owner, decoy, native, decoder = [base + n for n in (0, 0x100, 0x200, 0x400, 0x500, 0x600)]
    rdata, pdata = base + 0x1000, base + 0x2000
    functions = []
    a = _Code(load)
    a.emit("4889ce")  # mov rsi,rcx
    a.relative("488d15", rdata + 2)  # pooled filename, not its fragment start
    a.relative("4c8d05", rdata + 0x100)
    a.emit("488b4628488b8880010000")
    a.relative("e8", helper)
    a.emit("c3")
    functions.append(a)

    a = _Code(helper)
    a.emit("4889ce488b4108488b8848020000488b4910")
    a.emit("81b9a00100004d040000")
    a.emit("7406" if scene_branch else "7506")
    a.emit("807e2901750290c3c3")
    functions.append(a)

    a = _Code(owner)
    a.emit("4c89c7")  # preserve the input span across an unrelated first call
    a.relative("e8", decoy)
    for _ in range(2 if duplicate_filter else 1):
        a.emit("488b174c8b4708488d5c24204889d9")
        a.relative("e8", native)
        a.emit("31db" if clobber_pointer else "488b1b")
        a.emit("4885db7404837b08" + f"{tag:02x}")
    a.relative("488d15", rdata + 0x200)
    a.relative("4c8d05", rdata + 0x300)
    a.emit("c3")
    functions.append(a)

    a = _Code(decoy)
    a.emit("c3")
    functions.append(a)
    for target in ([native, base + 0xA00] if webview_separate_native else [native]):
        a = _Code(target)
        a.emit("564883ec304889ce488d4c2420488911")
        a.emit("4c894108" if span_abi else "48895108")
        a.relative("e8", decoder)
        a.emit("488906")
        a.emit("4889f0" if return_out else "31c0")
        a.emit("4883c4305ec3")
        functions.append(a)
    a = _Code(decoder)
    a.emit("31c0c3")
    functions.append(a)

    roles = {}
    for role, start, source in (("webview", base + 0x700, rdata + 0x380),
                                ("worker", base + 0x800, rdata + 0x280),
                                ("unrelated", base + 0x900, rdata + 0x2D0)):
        if role == "webview" and not webview:
            continue
        a = _Code(start)
        a.emit("4c89c7488b174c8b4708488d5c24204889d9")
        call = start + len(a.data)
        target = native
        if role == "webview":
            if webview_separate_native:
                target = base + 0xA00
            elif not webview_native:
                target = decoy
        a.relative("e8", target)
        a.emit("488b1b4885db7404")
        compare = start + len(a.data)
        a.emit("837b08" + f"{webview_tag if role == 'webview' else 6:02x}")
        if role == "webview" and duplicate_webview:
            a.emit("488b174c8b4708488d5c24204889d9")
            a.relative("e8", native)
            a.emit("488b1b4885db7404837b0806")
        a.relative("488d15", source)
        a.emit("c3")
        functions.append(a)
        roles[role] = {"Role": role, "OwnerOffset": hex(start),
                       "CallOffset": hex(call), "TagCompareOffset": hex(compare)}

    data = bytearray(0x1800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 3, 0, 0, 0, 0xF0, 0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<Q", data, 0x98 + 24, 0x180000000)
    sections = [(b".text", base, 0x1000, 0x200, 0x60000020),
                (b".rdata", rdata, 0x400, 0x1200, 0x40000040),
                (b".pdata", pdata, 0x200, 0x1600, 0x40000040)]
    for index, (name, rva, size, raw, flags) in enumerate(sections):
        offset = 0x188 + index * 40
        struct.pack_into("<8sIIIIIIHHI", data, offset, name, size, rva, size, raw, 0, 0, 0, 0, flags)
    for index, code in enumerate(functions):
        offset = 0x200 + code.start - base
        data[offset:offset + len(code.data)] = code.data
        struct.pack_into("<III", data, 0x1600 + 12 * index, code.start,
                         code.start + len(code.data), pdata + 0x100)
    for offset, string in [(0x1200, b"..\\flue\\applet_index_container.cc\0"),
                           (0x1300, b"[Perf] AppletIndexContainer::OnLoadStart \0"),
                           (0x1400, b"SendToClientFilter\0"),
                           (0x1480, b"..\\flue\\devtools_message_filter_worker.cc\0"),
                           (0x14D0, b"..\\business\\document_parser.cc\0"),
                           (0x1500, b"..\\flue\\devtools_message_filter_applet_webview.cc\0"),
                           (0x1580, webview_source + b"\0")]:
        data[offset:offset + len(string)] = string
    path.write_bytes(data)
    return path, {"load": load, "helper": helper, "owner": owner, "native": native,
                  "decoy": decoy, **roles}


@pytest.mark.parametrize("base", [0x1000, 0x9000])
def test_pe_roles_are_derived_at_relocated_addresses(tmp_path, base):
    binary, addresses = pe_fixture(tmp_path / "flue.dll", base=base)
    result = windows.extract_offsets(binary, None)
    block = result.config["Arch"]["x86_64"]
    assert result.verified
    assert result.version is None
    assert "Version" not in result.config
    assert block["LoadStartHookOffset"] == hex(addresses["load"])
    assert block["CDPFilterHookOffset"] == hex(addresses["native"])
    assert block["CDPFilterHookOffset"] != hex(addresses["decoy"])
    assert block["SceneChain"] == [0x28, 0x180, 8, 0x248, 0x10, 0x1A0]
    assert block["SceneGuard"]["Operator"] == "or"
    assert block["SceneGuard"]["AlternativeChain"] == [0x28, 0x180, 0x29]
    assert block["FilterABI"] == {"OutArgument": 0, "DataArgument": 1,
        "LengthArgument": 2, "Return": "out-pointer", "TagOffset": 8,
        "MapTag": 6, "SuppressedTag": 0}
    assert block["FilterCallSites"] == [
        {"Role": "applet_webview", "OwnerOffset": block["FilterOwnerOffset"],
         "CallOffset": block["FilterCallOffset"], "TagCompareOffset": block["FilterTagCompareOffset"]},
        addresses["webview"],
    ]
    imported = json.loads(json.dumps(result.config))
    assert all(check.ok for check in windows.verify_config(binary, imported))


@pytest.mark.parametrize("change,stage", [
    ({"tag": 7}, "CDPFilterHookOffset"),
    ({"return_out": False}, "CDPFilterHookOffset"),
    ({"span_abi": False}, "CDPFilterHookOffset"),
    ({"clobber_pointer": True}, "CDPFilterHookOffset"),
    ({"duplicate_filter": True}, "CDPFilterHookOffset"),
    ({"scene_branch": False}, "SceneChain"),
])
def test_role_failures_do_not_fall_back_to_first_call(tmp_path, change, stage):
    binary, _ = pe_fixture(tmp_path / "flue.dll", **change)
    with pytest.raises(windows.ExtractionError) as caught:
        windows.extract_offsets(binary, 999999)
    assert caught.value.stage == stage
    assert caught.value.report[-1].found is False


@pytest.mark.parametrize("key,value", [
    ("CDPFilterHookOffset", "0x1400"), ("SceneChain", [1, 2, 3, 4]),
    ("FilterABI", {"Return": "direct-pointer"}), ("SceneGuard", {}),
])
def test_static_recheck_rejects_stale_roles(tmp_path, key, value):
    binary, _ = pe_fixture(tmp_path / "flue.dll")
    config = windows.extract_offsets(binary, 42).config
    config["Arch"]["x86_64"][key] = value
    failed = [check.key for check in windows.verify_config(binary, config) if not check.ok]
    assert failed == [key]


def test_static_recheck_reads_current_binary(tmp_path):
    binary, _ = pe_fixture(tmp_path / "flue.dll")
    config = windows.extract_offsets(binary, 42).config
    pe_fixture(binary, tag=7)
    checks = windows.verify_config(binary, config)
    assert any(not check.ok and check.key == "CDPFilterHookOffset" for check in checks)


def test_no_fallback_to_host_architecture_or_missing_unwind_table(tmp_path, monkeypatch):
    monkeypatch.setattr("platform.machine", lambda: "arm64")
    binary, _ = pe_fixture(tmp_path / "flue.dll")
    assert windows.extract_offsets(binary, None).arch == "x86_64"
    with pytest.raises(windows.ExtractionError, match="requested arm64"):
        windows.extract_offsets(binary, None, "arm64")
    raw = bytearray(binary.read_bytes())
    raw[0x1600:0x1800] = bytes(0x200)
    binary.write_bytes(raw)
    with pytest.raises(windows.ExtractionError, match="unwind function boundaries"):
        windows.extract_offsets(binary, None)


def test_shared_service_selects_windows_and_rechecks_imported_json(tmp_path):
    binary, _ = pe_fixture(tmp_path / "flue.dll")
    backend = analysis_backend(binary)
    assert backend is windows
    config = json.loads(json.dumps(backend.extract_offsets(binary, None).config))
    assert all(check["ok"] for check in static_checks(binary, config))
    wrong_isa = copy.deepcopy(config)
    wrong_isa["Arch"] = {"arm64": config["Arch"]["x86_64"]}
    assert any(not check["ok"] for check in static_checks(binary, wrong_isa))


def test_abi_numeric_fields_reject_boolean_substitutes(tmp_path):
    binary, _ = pe_fixture(tmp_path / "flue.dll")
    config = windows.extract_offsets(binary, None).config
    config["Arch"]["x86_64"]["FilterABI"]["OutArgument"] = False
    assert any(not check.ok and check.key == "FilterABI" for check in windows.verify_config(binary, config))


@pytest.mark.parametrize("change", [
    {"webview_tag": 7}, {"webview_native": False}, {"duplicate_webview": True},
    {"webview_separate_native": True},
])
def test_present_webview_source_requires_one_complete_role_proof(tmp_path, change):
    binary, _ = pe_fixture(tmp_path / "flue.dll", **change)
    with pytest.raises(windows.ExtractionError) as caught:
        windows.extract_offsets(binary, None)
    assert caught.value.stage == "FilterCallSites.webview"


def test_absent_webview_role_preserves_canonical_applet_site(tmp_path):
    binary, _ = pe_fixture(tmp_path / "flue.dll", webview=False)
    config = windows.extract_offsets(binary, None).config
    sites = config["Arch"]["x86_64"]["FilterCallSites"]
    assert [site["Role"] for site in sites] == ["applet_webview"]
    assert all(check.ok for check in windows.verify_config(binary, config))


@pytest.mark.parametrize("change", ["role", "owner", "call", "compare", "missing", "worker", "unrelated"])
def test_static_recheck_rejects_unproven_or_changed_call_sites(tmp_path, change):
    binary, addresses = pe_fixture(tmp_path / "flue.dll")
    config = windows.extract_offsets(binary, None).config
    sites = config["Arch"]["x86_64"]["FilterCallSites"]
    if change == "role":
        sites[1]["Role"] = "worker"
    elif change in ("owner", "call", "compare"):
        key = {"owner": "OwnerOffset", "call": "CallOffset", "compare": "TagCompareOffset"}[change]
        sites[1][key] = hex(int(sites[1][key], 0) + 1)
    elif change == "missing":
        sites.pop(0)
    else:
        sites.append(addresses[change])
    assert [check.key for check in windows.verify_config(binary, config) if not check.ok] == ["FilterCallSites"]


def test_non_cdp_source_does_not_establish_webview_role(tmp_path):
    binary, _ = pe_fixture(tmp_path / "flue.dll", webview_source=b"..\\business\\document_parser.cc")
    block = windows.extract_offsets(binary, None).config["Arch"]["x86_64"]
    assert [site["Role"] for site in block["FilterCallSites"]] == ["applet_webview"]


@pytest.mark.anyio
async def test_public_extract_import_recheck_and_failed_import_preserves_cache(tmp_path):
    from wmpf_mcp.server import build_server
    binary, _ = pe_fixture(tmp_path / "flue.dll")
    output = tmp_path / "derived.json"
    server = build_server()
    result = await server.call_tool("prepare_offsets", {"binary_path": str(binary), "output_path": str(output)})
    assert not result.is_error, result
    assert result.structured_content["data"]["verified"]
    imported = await server.call_tool("prepare_offsets", {"source": "import",
        "candidate_path": str(output), "binary_path": str(binary)})
    assert not imported.is_error, imported
    assert imported.structured_content["data"]["imported"]
    installed = Path(imported.structured_content["data"]["config_path"])
    saved = installed.read_bytes()
    checked = await server.call_tool("check_offsets", {"config_path": str(installed), "binary_path": str(binary)})
    assert checked.structured_content["data"]["ready"]
    pe_fixture(binary, tag=7)
    rejected = await server.call_tool("prepare_offsets", {"source": "import", "force": True,
        "candidate_path": str(output), "binary_path": str(binary)})
    assert rejected.is_error
    assert rejected.structured_content["error"]["code"] == "E_OFFSETS_VERIFY_FAILED"
    assert installed.read_bytes() == saved
