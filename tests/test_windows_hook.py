"""Exercise the Windows ABI at the JS/native boundary without a live hook."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from wmpf_mcp.injector.manager import InjectorManager, TEMPLATE_PATH


def windows_config():
    return {"Format": "PE", "ABI": "win64-legacy", "Module": "flue.dll", "Arch": {"x86_64": {
        "LoadStartHookOffset": "0x100", "CDPFilterHookOffset": "0x200", "FilterCallOffset": "0x300", "SceneChain": [16, 32],
        "FilterOwnerOffset": "0x280", "FilterTagCompareOffset": "0x310",
        "FilterCallSites": [
            {"Role": "applet_webview", "OwnerOffset": "0x280", "CallOffset": "0x300", "TagCompareOffset": "0x310"},
            {"Role": "webview", "OwnerOffset": "0x480", "CallOffset": "0x500", "TagCompareOffset": "0x510"},
        ],
        "FilterABI": {"OutArgument": 0, "DataArgument": 1, "LengthArgument": 2,
            "Return": "out-pointer", "TagOffset": 8, "MapTag": 6, "SuppressedTag": 0}}}}


@pytest.mark.parametrize("mode", ["success", "install_failure", "wrong_platform", "wrong_abi", "unverified_role", "missing_applet", "duplicate_role", "canonical_mismatch"])
def test_windows_abi_data_capture_scene_guard_and_rollback(mode):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required to exercise the Frida JS boundary")
    config = windows_config()
    if mode == "wrong_abi":
        config["Arch"]["x86_64"]["FilterABI"]["DataArgument"] = 0
    sites = config["Arch"]["x86_64"]["FilterCallSites"]
    if mode == "unverified_role":
        sites[1]["Role"] = "worker"
    elif mode == "missing_applet":
        sites.pop(0)
    elif mode == "duplicate_role":
        sites[1]["Role"] = "applet_webview"
    elif mode == "canonical_mismatch":
        sites[0]["CallOffset"] = "0x350"
    source = TEMPLATE_PATH.with_name("windows.js").read_text(encoding="utf-8").replace(
        "@@CONFIG@@", json.dumps(config))
    harness = r'''
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = require('node:fs').readFileSync(0, 'utf8');
const mode = process.argv[1];
const memory = new Map(), writes = [], frames = [], messages = [], listeners = [];
class Pointer {
  constructor(n) { this.n = BigInt(n); }
  add(n) { return ptr(this.n + ptr(n).n); }
  isNull() { return this.n === 0n; }
  toString() { return '0x' + this.n.toString(16); }
  toUInt32() { return Number(this.n & 0xffffffffn); }
  compare(p) { return this.n < p.n ? -1 : this.n > p.n ? 1 : 0; }
  and(p) { return ptr(this.n & ptr(p).n); }
  or(p) { return ptr(this.n | ptr(p).n); }
  readPointer() { return ptr(memory.get(this.toString()) || 0); }
  readInt() { return Number(memory.get(this.toString()) || 0); }
  readU32() { return this.readInt(); }
  writeInt(n) { writes.push([this.toString(), n]); memory.set(this.toString(), n); }
  writeU32(n) { this.writeInt(n); }
  readByteArray(n) { frames.push([this.toString(), n]); return new ArrayBuffer(n); }
}
function ptr(n) { return n instanceof Pointer ? n : new Pointer(n); }
vm.runInNewContext(source, {
  ptr, Process: {platform: mode === 'wrong_platform' ? 'darwin' : 'windows', arch:'x64', id:42,
    getCurrentThreadId:()=>7, findModuleByName:()=>({base:ptr(0x1000)})},
  send:(m,data)=>messages.push(m), Instruction:{parse:(address)=>({toString:()=> 'call decoder',next:address.add(5)})},
  Interceptor:{attach:(address, callbacks)=>{
    if(mode==='install_failure' && listeners.length===1) throw new Error('unable to intercept function');
    const item={address,callbacks,detached:false,detach(){this.detached=true;}};
    listeners.push(item); return item;
  }, flush:()=>{}}
});
if (mode !== 'success') {
  assert(!messages.some(m=>m.type==='armed'||m.type==='ready'));
  const error=messages.find(m=>m.type==='error'); assert(error); assert(error.rollback_complete);
  assert(listeners.every(l=>l.detached));
  if(mode==='install_failure') { assert.equal(error.role,'CDPFilterHookOffset'); assert.equal(error.address,'0x1200'); }
} else {
  assert.equal(messages.filter(m=>m.type==='armed').length,1);
  assert.equal(messages.at(-1).type,'armed'); assert.equal(messages.at(-1).hooks.length,2);
  const load=listeners[0].callbacks;
  memory.set('0x3010',0x4000); memory.set('0x4020',1256);
  const args=[ptr(0x3000),ptr(0xaabb00)]; load.onEnter(args);
  assert.equal(memory.get('0x4020'),1101); assert.equal(args[1].n,0xaabb01n);
  assert.deepEqual(writes,[['0x4020',1101]]); // No foreign mode or string layout writes.
  memory.set('0x4020',1000); writes.length=0; load.onEnter([ptr(0x3000),ptr(0)]);
  assert.equal(writes.length,0);
  const filter=listeners[1].callbacks, state={returnAddress:ptr(0x1305)};
  memory.set('0x5000',0x6000); memory.set('0x6008',6);
  filter.onEnter.call(state,[ptr(0x5000),ptr(0x7000),ptr(128)]);
  assert.deepEqual(frames,[['0x7000',128]]);
  filter.onLeave.call(state,ptr(0x5000)); assert.equal(memory.get('0x6008'),0);
  memory.set('0x6008',0); filter.onLeave.call(state,ptr(0x5000));
  assert.equal(memory.get('0x6008'),0); // Never promotes null/tag0 to map/tag6.
  writes.length=0; memory.set('0x6008',6);
  filter.onEnter.call(state,[ptr(0x5000),ptr(0x7000),ptr('0x100000001')]);
  filter.onLeave.call(state,ptr(0x5000)); assert.equal(writes.length,0);
  assert.equal(frames.length,1); // A 64-bit oversize cannot wrap to a short capture.
  state.returnAddress=ptr(0x1405); memory.set('0x6008',6);
  filter.onEnter.call(state,[ptr(0x5000),ptr(0x7000),ptr(128)]);
  filter.onLeave.call(state,ptr(0x5000));
  assert.equal(frames.length,1); assert.equal(memory.get('0x6008'),6);
  assert.equal(writes.length,0); // Other decoder callers retain their original map.
  state.returnAddress=ptr(0x1505);
  filter.onEnter.call(state,[ptr(0x5000),ptr(0x7000),ptr(128)]);
  filter.onLeave.call(state,ptr(0x5000));
  assert.equal(frames.length,2); assert.equal(memory.get('0x6008'),0);
  assert.deepEqual(writes,[['0x6008',0]]); // Independently verified generic WebView events.
}
'''
    subprocess.run([node, "-e", harness, mode], input=source, text=True,
                   capture_output=True, check=True, timeout=10)


def test_renderer_selects_windows_template_and_preserves_escaping(tmp_path):
    config = windows_config()
    config["Comment"] = "Chinese 中文, quote ', path C:\\a\\b"
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
    rendered = InjectorManager()._render_script(path)
    assert "win64-legacy" in rendered
    assert "length64" in rendered
    assert "this.context.x0" not in rendered
    assert "@@CONFIG@@" not in rendered
