// Windows x64 legacy WMPF backend. The PE extractor proves each role and ABI
// against the current flue.dll before this template may be loaded.
// Scene strategy informed by evi0s/WMPFDebugger (GPL-2.0):
// https://github.com/evi0s/WMPFDebugger/blob/main/frida/hook.js
'use strict';

var CONFIG = JSON.parse('@@CONFIG@@');
var MAX_CDP_MESSAGE_BYTES = 16 * 1024 * 1024;
var SCENE_WHITELIST = [1005, 1007, 1008, 1011, 1012, 1027, 1035, 1037,
  1053, 1074, 1145, 1178, 1256, 1260, 1302, 1308];
var _hits = {};

function report(hook, detail) {
  _hits[hook] = (_hits[hook] || 0) + 1;
  send({type: 'hook_hit', pid: Process.id, hook: hook, detail: detail, count: _hits[hook]});
}

function main() {
  var listeners = [];
  var installed = [];
  var installing = null;
  try {
    if (Process.platform !== 'windows' || Process.arch !== 'x64' ||
        CONFIG.Format !== 'PE' || CONFIG.ABI !== 'win64-legacy' || CONFIG.Module !== 'flue.dll') {
      throw new Error('This backend requires PE/windows/x64 and the verified win64-legacy ABI');
    }
    var mod = Process.findModuleByName(CONFIG.Module);
    if (!mod) { throw new Error('The verified flue.dll module is not loaded'); }
    var arch = CONFIG.Arch && CONFIG.Arch.x86_64;
    if (!arch || !arch.LoadStartHookOffset || !arch.CDPFilterHookOffset || !arch.FilterCallOffset ||
        !Array.isArray(arch.SceneChain) || arch.SceneChain.length < 2) {
      throw new Error('Complete load, filter and scene roles are required');
    }
    var abi = arch.FilterABI;
    if (!abi || abi.OutArgument !== 0 || abi.DataArgument !== 1 || abi.LengthArgument !== 2 ||
        abi.Return !== 'out-pointer' || abi.TagOffset !== 8 || abi.MapTag !== 6 || abi.SuppressedTag !== 0) {
      throw new Error('The filter ABI does not match the proven Windows legacy calling convention');
    }
    var base = mod.base;
    // The decoder has unrelated callers. Each permitted WebView call site is
    // independently proven by the PE backend; do not hook all parser users.
    var sites = arch.FilterCallSites;
    if (!Array.isArray(sites) || sites.length < 1 || sites.length > 2) {
      throw new Error('Verified WebView filter call sites are required');
    }
    var filterReturnAddresses = {};
    var roles = {};
    sites.forEach(function (site) {
      if (!site || (site.Role !== 'applet_webview' && site.Role !== 'webview') ||
          roles[site.Role] || !site.OwnerOffset || !site.CallOffset || !site.TagCompareOffset) {
        throw new Error('Invalid or duplicate WebView filter role');
      }
      if (site.Role === 'applet_webview' &&
          (site.OwnerOffset !== arch.FilterOwnerOffset || site.CallOffset !== arch.FilterCallOffset ||
           site.TagCompareOffset !== arch.FilterTagCompareOffset)) {
        throw new Error('The canonical applet filter must match its verified call site');
      }
      roles[site.Role] = true;
      var returnAddress = Instruction.parse(base.add(ptr(site.CallOffset))).next.toString();
      if (filterReturnAddresses[returnAddress]) { throw new Error('Duplicate filter return address'); }
      filterReturnAddresses[returnAddress] = site.Role;
    });
    if (!roles.applet_webview) { throw new Error('The canonical applet filter is required'); }
    function install(role, callbacks) {
      var target = base.add(ptr(arch[role]));
      installing = {role: role, offset: arch[role], address: target.toString()};
      listeners.push(Interceptor.attach(target, callbacks));
      installed.push(installing);
    }

    install('LoadStartHookOffset', {
      onEnter: function (args) {
        report('load_start', 'Windows x64 OnLoadStart');
        try {
          var object = args[0];
          var chain = arch.SceneChain;
          for (var i = 0; i < chain.length - 1; i++) {
            object = object.add(chain[i]).readPointer();
            if (object.isNull()) { report('scene_skip', 'null chain level ' + i); return; }
          }
          var sceneSlot = object.add(chain[chain.length - 1]);
          var scene = sceneSlot.readInt();
          if (SCENE_WHITELIST.indexOf(scene) < 0) {
            report('scene_skip', 'scene ' + scene + ' not in whitelist');
            return;
          }
          // Only input data is changed. The extracted legacy helper accepts
          // scene == 1101 OR its own debug byte; it supplies the default URL.
          sceneSlot.writeInt(1101);
          args[1] = args[1].and(ptr('0xffffffffffffff00')).or(1);
          report('scene_rewrite', 'scene ' + scene + ' -> 1101; debug flag -> 1');
        } catch (error) { report('scene_error', String(error)); }
      }
    });

    install('CDPFilterHookOffset', {
      onEnter: function (args) {
        this.cborCaptured = false;
        try {
          if (!filterReturnAddresses[this.returnAddress.toString()]) { return; }
          // Win64 return-by-out-pointer occupies RCX; input and length occupy
          // RDX and R8. They differ from the Darwin function's first two args.
          var input = args[abi.DataArgument];
          var length64 = args[abi.LengthArgument];
          if (input.isNull() || length64.isNull() || length64.compare(ptr(MAX_CDP_MESSAGE_BYTES)) > 0) {
            report('cdp_capture_skip', 'invalid or oversized native frame');
            return;
          }
          var length = length64.toUInt32();
          send({type: 'cbor_message', pid: Process.id,
            tid: Process.getCurrentThreadId(), size: length}, input.readByteArray(length));
          this.cborCaptured = true;
        } catch (error) { report('cdp_capture_error', String(error)); }
      },
      onLeave: function (retval) {
        try {
          // The caller loads *RAX before testing variant+8. Preserve that
          // indirection, the vtable and object storage; only map 6 -> null 0.
          if (!this.cborCaptured || retval.isNull()) { return; }
          var variant = retval.readPointer();
          if (!variant.isNull() && variant.add(abi.TagOffset).readU32() === abi.MapTag) {
            variant.add(abi.TagOffset).writeU32(abi.SuppressedTag);
          }
        } catch (error) { report('cdp_filter_error', String(error)); }
      }
    });
    installing = null;
    Interceptor.flush();
    send({type: 'ready', pid: Process.id});
    send({type: 'armed', pid: Process.id, version: CONFIG.Version,
      arch: Process.arch, base: base.toString(), hooks: installed});
  } catch (error) {
    var rollbackErrors = [];
    for (var j = listeners.length - 1; j >= 0; j--) {
      try { listeners[j].detach(); } catch (cleanupError) { rollbackErrors.push(String(cleanupError)); }
    }
    try { Interceptor.flush(); } catch (flushError) { rollbackErrors.push(String(flushError)); }
    var failure = {type: 'error', pid: Process.id, stage: 'install', detail: String(error),
      rollback_complete: rollbackErrors.length === 0};
    if (installing) {
      failure.role = installing.role;
      failure.offset = installing.offset;
      failure.address = installing.address;
      try { failure.instruction = Instruction.parse(ptr(installing.address)).toString(); } catch (_) {}
    }
    if (rollbackErrors.length) { failure.detail += '; rollback: ' + rollbackErrors.join('; '); }
    send(failure);
  }
}

main();
