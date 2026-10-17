// WMPF-MCP Frida hook template — rendered with `@@CONFIG@@`.
//
// Target: the WeChatAppEx process family (per-PID WeChatAppEx Framework base).
// Goal: make miniapps entering AppletIndexContainer::OnLoadStart pass the
// developer-tools (scene 1101) check, so the runtime dials ws://127.0.0.1:9421.
//
// Strategy (aligned with the verified WMPFDebugger approach): only DATA is
// rewritten at the function entry — never control flow, never registers of the
// internal checks. WeChat's own gate chain (remoteDebugMode == 1, scene == 1101,
// final guard) then passes naturally and the debug-start routine runs with its
// own consistent state. Forcing the checks by register override crashes the
// runtime (observed on 25800) and is deliberately NOT done here.
//
// Rewrites (guarded, whitelist-protected):
//   * 2nd argument low byte -> 1                (debug flag)
//   * scene field (chain end, +456)  -> 1101    (developer-tools scene)
//   * remoteDebugMode field (+724)   -> 1       (enables the debug path)
//
// Additional hooks:
//   * CDPFilterHookOffset — copy CBOR before the native output filter
//   * ResourceCachePolicyHookOffset — renderer cache policy retval -> 0
'use strict';

var CONFIG = JSON.parse('@@CONFIG@@');

// Scenes from which the 1101 rewrite is safe (WMPFDebugger's published list;
// 1000 is excluded on purpose — rewriting it crashes the process).
var SCENE_WHITELIST = [
  1005, 1007, 1008, 1011, 1012, 1027, 1035, 1037, 1053, 1074, 1145, 1178,
  1256, 1260, 1302, 1308,
];

var _probeEnter = 0;
var _probeLeave = 0;
var MAX_CDP_MESSAGE_BYTES = 16 * 1024 * 1024;

function findMainModule() {
  if (Process.platform === 'darwin') {
    return Process.findModuleByName('WeChatAppEx Framework');
  }
  return null; // Windows/Linux module layout lands in M5
}

function resolveArch(config) {
  var table = config.Arch || {};
  return Process.platform === 'darwin' && Process.arch === 'arm64'
    ? (table[Process.arch] || null) : null;
}

var _hits = {};

function report(hook, detail) {
  _hits[hook] = (_hits[hook] || 0) + 1;
  send({ type: 'hook_hit', pid: Process.id, hook: hook, detail: detail, count: _hits[hook] });
}

function main() {
  var mod = findMainModule();
  if (!mod) {
    send({ type: 'error', message: 'WeChatAppEx Framework module not found' });
    return;
  }
  var arch = resolveArch(CONFIG);
  if (!arch) {
    send({ type: 'error', message: 'no config for arch ' + Process.arch });
    return;
  }
  var base = mod.base;
  send({ type: 'config_echo', arch_keys: Object.keys(arch),
         cdp: arch.CDPFilterHookOffset, load: arch.LoadStartHookOffset,
         hasPtr: typeof ptr === 'function' });

  var listeners = [];
  var installed = [];
  var installing = null;
  function install(role, callbacks) {
    var target = base.add(ptr(arch[role]));
    installing = { role: role, offset: arch[role], address: target.toString() };
    listeners.push(Interceptor.attach(target, callbacks));
    installed.push(installing);
  }

  try {
    if (!arch.LoadStartHookOffset || !arch.CDPFilterHookOffset) {
      throw new Error('LoadStartHookOffset and CDPFilterHookOffset are required');
    }

    // 1) OnLoadStart entry: force the debug flag AND rewrite the launch-config
    //    data (scene + remote-debug mode) through the on-device verified chain.
    if (arch.LoadStartHookOffset) {
      install('LoadStartHookOffset', {
        onEnter: function () {
          var x1 = this.context.x1;
          if (x1.and(0xff).toInt32() !== 1) {
            this.context.x1 = x1.and(ptr('0xffffffffffffff00')).or(1);
            report('load_start', 'debug flag forced');
          } else {
            report('load_start', 'flag already set');
          }

          // Walk the extracted SceneChain from the launch object.
          var chain = arch.SceneChain;
          if (!chain || !chain.length) {
            return;
          }
          try {
            var p = this.context.x0;
            for (var i = 0; i < chain.length - 1; i++) {
              p = p.add(chain[i]).readPointer();
              if (p.isNull()) {
                report('scene_skip', 'chain level ' + i + ' is null');
                return;
              }
            }
            var scenePtr = p.add(chain[chain.length - 1]);
            var scene = scenePtr.readInt();
            if (SCENE_WHITELIST.indexOf(scene) < 0) {
              report('scene_skip', 'scene ' + scene + ' not in whitelist');
              return;
            }
            scenePtr.writeInt(1101);
            var detail = 'pid ' + Process.id + ' x9=' + p + ' scene ' + scene + ' -> 1101';
            if (arch.RemoteDebugModeOffset) {
              var modePtr = p.add(arch.RemoteDebugModeOffset);
              var mode = modePtr.readInt();
              if (mode !== 1) {
                modePtr.writeInt(1);
                detail += ', mode ' + mode + ' -> 1';
              }
            }
            // The debug-connect guard requires the websocket-URL std::string to
            // be non-empty; writing it satisfies the guard AND gives the runtime
            // the connect target (libc++ 24-byte layout: 23 inline + length/marker).
            if (arch.WebSocketURLStringOffset !== undefined) {
              var urlSlot = p.add(arch.WebSocketURLStringOffset);
              var url = arch.WebSocketURL || 'ws://127.0.0.1:9421';
              var marker = urlSlot.add(23).readS8();
              if (marker < 0) {
                // long representation: overwrite the heap buffer in place
                var dataPtr = urlSlot.readPointer();
                if (!dataPtr.isNull()) {
                  dataPtr.writeUtf8String(url);
                  urlSlot.add(8).writeU64(url.length);
                }
              } else {
                // short representation: 23 inline bytes + one length byte
                urlSlot.writeUtf8String(url);
                urlSlot.add(23).writeU8(url.length & 0x7f);
              }
              detail += ', url="' + url + '"';
            }
            report('scene_rewrite', detail);
          } catch (e) {
            report('scene_error', String(e));
          }
        },
      });
    }

    // 2) Observe the callee at its function entry. Attaching directly at the BL
    //    instruction needs a four-byte near redirect and can fail even when the
    //    instruction/config is valid. Keep BL as a verified caller reference only.
    var debugCallerReturn = arch.DebugStartBlOffset
      ? base.add(ptr(arch.DebugStartBlOffset)).add(4) : null;
    if (arch.DebugConnectOffset) {
      install('DebugConnectOffset', {
        onEnter: function (args) {
          if (debugCallerReturn && this.returnAddress.equals(debugCallerReturn)) {
            report('debug_bl', 'debug-connect caller verified at callee entry: ' + this.returnAddress);
          }
          // This callee's object ABI need not match the launch object's ABI.
          report('sub_enter', 'entry arg0=' + args[0]);
        },
      });
    }

    // 2) Recover both responses and events before the native filter. Promoting
    //    a null variant (0 -> 6) makes the native rewriter dereference invalid
    //    objects. Even real maps hit a null childFrames bug on Page.getFrameTree
    //    (25800, crash @ 0x93566d8). After copying CBOR, suppress native rewriting
    //    with the upstream legacy hook's 6 -> 0 direction. The native transport
    //    then emits "{}", which the engine drops; complete CDP travels via Frida.
    //    Python decodes the top-level CDP envelope: scanning bytes for "id"
    //    misclassifies events containing params.context.id, and truncating at
    //    64 KiB loses screenshots and large DOM responses.
    //    This filter also sees UTF-8 JSON shutdown notifications. The legacy
    //    cbor_message name is a capture channel, not a guarantee of wire format;
    //    Python identifies JSON objects before decoding CRDTP CBOR.
    send({ type: 'stage', at: 'before-filter-section' });
    if (arch.CDPFilterHookOffset) {
      send({ type: 'stage', at: 'filter-attach-call', target: base.add(ptr(arch.CDPFilterHookOffset)).toString() });
      install('CDPFilterHookOffset', {
        onEnter: function (args) {
          this.cborCaptured = false;
          try {
            var input = args[0];
            var len = args[1].toUInt32();
            if (_probeEnter < 12) {
              _probeEnter++;
              report('cdp_probe', 'enter len=' + len + ' caller=' + this.returnAddress);
            }
            if (input.isNull() || len === 0 || len > MAX_CDP_MESSAGE_BYTES) {
              report('cdp_capture_skip', 'len=' + len);
              return;
            }
            send({ type: 'cbor_message', pid: Process.id,
                   tid: Process.getCurrentThreadId(), size: len }, input.readByteArray(len));
            this.cborCaptured = true;
          } catch (e) {
            report('cdp_capture_error', String(e));
          }
        },
        onLeave: function (retval) {
          try {
            // Keep the real object's vtable and storage intact. Never promote
            // another variant to a map. This is the legacy WMPFDebugger bypass:
            // https://github.com/evi0s/WMPFDebugger/blob/main/frida/hook.js
            if (this.cborCaptured && !retval.isNull() && retval.add(8).readU32() === 6) {
              retval.add(8).writeU32(0);
            }
          } catch (e) {
            report('cdp_filter_error', String(e));
          }
          if (_probeLeave < 12) {
            _probeLeave++;
            try {
              report('cdp_probe', 'leave tag=' + (retval.isNull() ? 'null' : retval.add(8).readU32()));
            } catch (e) {
              report('cdp_probe', 'leave unreadable: ' + e);
            }
          }
        },
      });
    }

    send({ type: 'stage', at: 'after-filter-section' });

    // 3) Renderer cache policy: force the returned value to 0.
    if (arch.ResourceCachePolicyHookOffset) {
      install('ResourceCachePolicyHookOffset', {
        onLeave: function (retval) {
          report('cache_policy', 'retval ' + retval + ' -> 0');
          retval.replace(0);
        },
      });
    }

    installing = null;
    Interceptor.flush();
  } catch (error) {
    var rollbackErrors = [];
    for (var j = listeners.length - 1; j >= 0; j--) {
      try { listeners[j].detach(); } catch (cleanupError) { rollbackErrors.push(String(cleanupError)); }
    }
    try { Interceptor.flush(); } catch (flushError) { rollbackErrors.push(String(flushError)); }
    var failure = { type: 'error', pid: Process.id, stage: 'install',
      detail: String(error), rollback_complete: rollbackErrors.length === 0 };
    if (installing) {
      failure.role = installing.role;
      failure.offset = installing.offset;
      failure.address = installing.address;
      try { failure.instruction = Instruction.parse(ptr(installing.address)).toString(); } catch (_) {}
    }
    if (rollbackErrors.length) { failure.detail += '; rollback: ' + rollbackErrors.join('; '); }
    send(failure);
    return;
  }

  send({ type: 'ready', pid: Process.id });
  // This is the final initialization message, after all configured hooks have
  // installed and flushed. Python waits for this event before committing a PID.
  send({ type: 'armed', pid: Process.id, version: CONFIG.Version,
         arch: Process.arch, base: base.toString(), hooks: installed });
}

main();
