"""Hook installation is transactional; observation must not require a BL patch."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from wmpf_mcp.core.errors import ErrorCode, ToolError
from wmpf_mcp.injector.manager import InjectorManager, TEMPLATE_PATH


@pytest.mark.parametrize('failure', ['none', 'attach', 'flush', 'rollback'])
def test_template_installs_atomically_and_observes_the_callee(failure):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js unavailable')
    config = {'Arch': {'arm64': {
        'LoadStartHookOffset': '0x100', 'DebugConnectOffset': '0x200',
        'CDPFilterHookOffset': '0x300', 'ResourceCachePolicyHookOffset': '0x400',
        'DebugStartBlOffset': '0x500'}}}
    source = TEMPLATE_PATH.read_text().replace('@@CONFIG@@', json.dumps(config))
    harness = r'''
const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
const mode=process.argv[1],messages=[],listeners=[],events=[];
class Address{constructor(v){this.value=Number(v);}add(v){return new Address(this.value+Number(v.value??v));}toString(){return '0x'+this.value.toString(16);}equals(other){return this.value===other.value;}}
let flushed=0;
const sandbox={Process:{platform:'darwin',arch:'arm64',id:11,findModuleByName:()=>({base:new Address(0)})},
 ptr:x=>new Address(x),send:m=>{messages.push(m);events.push('send:'+m.type);},
 Instruction:{parse:()=>({toString:()=>'stp x29, x30, [sp, #-0x10]!'})},
 Interceptor:{attach(address,callbacks){
  events.push('attach:'+address);if((mode==='attach'||mode==='rollback')&&address.value===0x400)throw Error('unable to intercept function');
  const item={address,callbacks,detached:false,detach(){if(mode==='rollback'&&address.value===0x100)throw Error('detach refused');this.detached=true;}};listeners.push(item);return item;},
 flush(){events.push('flush');if(mode==='flush'&&flushed++===0)throw Error('flush refused');}}};
vm.runInNewContext(fs.readFileSync(0,'utf8'),sandbox);
assert(!listeners.some(item=>item.address.value===0x500));
if(mode==='none'){
 const armed=messages.at(-1);assert.equal(armed.type,'armed');assert.equal(armed.hooks.length,4);assert.equal(listeners.length,4);
 assert(events.indexOf('send:armed')>events.lastIndexOf('flush'));assert(!messages.some(m=>m.type==='error'));
 const callee=listeners.find(item=>item.address.value===0x200);
 callee.callbacks.onEnter.call({returnAddress:new Address(0x504)},['object']);
 callee.callbacks.onEnter.call({returnAddress:new Address(0x999)},['object']);
 assert.equal(messages.filter(m=>m.type==='hook_hit'&&m.hook==='debug_bl').length,1);
 assert.equal(messages.filter(m=>m.type==='hook_hit'&&m.hook==='sub_enter').length,2);
}else{
 assert(!messages.some(m=>m.type==='armed'||m.type==='ready'));
 const error=messages.find(m=>m.type==='error');assert.equal(error.stage,'install');
 assert.equal(error.rollback_complete,mode!=='rollback');
 assert(listeners.every(item=>item.detached||(mode==='rollback'&&item.address.value===0x100)));
 if(mode!=='flush'){assert.equal(error.role,'ResourceCachePolicyHookOffset');assert.equal(error.address,'0x400');assert(error.instruction);}
 else{assert(!('role' in error));}
}
'''
    subprocess.run([node, '-e', harness, failure], input=source, text=True,
                   capture_output=True, check=True, timeout=10)


def fake_manager(monkeypatch, fake_cancellable, outcomes, entered=None):
    manager = InjectorManager()
    manager.INITIALIZE_TIMEOUT_S = 0.02 if entered is None else 5
    sessions = []
    loop = asyncio.get_running_loop()

    class Script:
        unloaded = False
        def __init__(self, pid):
            self.pid = pid
        def on(self, _, callback):
            self.callback = callback
        def load(self):
            if entered:
                loop.call_soon_threadsafe(entered.set)
            outcome = outcomes[self.pid]
            if outcome in {'ready', 'premature'}:
                self.callback({'type': 'send', 'payload': {'type': 'armed', 'hooks': [
                    {'role': 'LoadStartHookOffset', 'address': '0x100', 'offset': '0x100'}]}}, None)
            if outcome in {'error', 'premature'}:
                self.callback({'type': 'send', 'payload': {'type': 'error', 'stage': 'install',
                    'role': 'DebugConnectOffset', 'address': '0x200', 'offset': '0x200',
                    'message': 'unable to intercept function', 'rollback_complete': True}}, None)
        def unload(self):
            self.unloaded = True

    class Session:
        is_detached = False
        def __init__(self, pid):
            self.pid = pid
            self.script = Script(pid)
        def create_script(self, _):
            return self.script
        def detach(self):
            self.is_detached = True

    def attach(pid):
        session = Session(pid)
        sessions.append(session)
        return session

    monkeypatch.setattr(manager, '_render_script', lambda _: 'fixture')
    monkeypatch.setattr(manager, '_load_frida', lambda: SimpleNamespace(Cancellable=fake_cancellable,
        get_local_device=lambda: SimpleNamespace(attach=attach)))
    return manager, sessions


@pytest.mark.anyio
@pytest.mark.parametrize('outcome', ['error', 'premature', 'missing', 'ready'])
async def test_load_return_is_not_complete_hook_initialization(monkeypatch, fake_cancellable, outcome):
    manager, sessions = fake_manager(monkeypatch, fake_cancellable, {11: outcome})
    if outcome == 'ready':
        result = await manager.start(Path('fixture'), [11])
        assert result['injected'][0]['ok']
        status = manager.status()
        assert status['armed_pids'] == [11]
        assert status['sessions'][0]['initialization'] == 'ready'
        assert status['sessions'][0]['installed_hooks'][0]['role'] == 'LoadStartHookOffset'
        await manager.stop()
    else:
        with pytest.raises(ToolError) as caught:
            await manager.start(Path('fixture'), [11])
        assert caught.value.code == (ErrorCode.HOOK_TIMEOUT if outcome == 'missing' else ErrorCode.INTERNAL)
        status = manager.status()
        assert not status['sessions'] and not status['armed_pids']
        failure = status['last_start_failures'][0]
        if outcome != 'missing':
            assert failure['hook_failure']['role'] == 'DebugConnectOffset'
            assert status['recent_errors'][-1]['detail'] == 'unable to intercept function'
        with pytest.raises(ToolError):
            await manager.wait_armed(0.1)
        await manager.stop()
        assert not manager.status()['last_start_failures']
    assert sessions[0].is_detached and sessions[0].script.unloaded


@pytest.mark.anyio
@pytest.mark.parametrize('cancel', [False, True])
async def test_initialization_wait_is_driven_by_callbacks_and_cancellation(monkeypatch, fake_cancellable, cancel):
    entered = asyncio.Event()
    manager, sessions = fake_manager(monkeypatch, fake_cancellable, {11: 'missing'}, entered)
    request = asyncio.create_task(manager.start(Path('fixture'), [11]))
    await asyncio.wait_for(entered.wait(), 1)
    assert not request.done()
    if cancel:
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(request, 1)
        assert sessions[0].is_detached and sessions[0].script.unloaded
        assert not manager.status()['sessions']
    else:
        await asyncio.to_thread(sessions[0].script.callback,
            {'type': 'send', 'payload': {'type': 'armed'}}, None)
        assert (await asyncio.wait_for(request, 1))['injected'][0]['ok']
        await manager.stop()


@pytest.mark.anyio
async def test_partial_pid_failure_blocks_public_start_and_can_resume(monkeypatch, fake_cancellable, tmp_path):
    from wmpf_mcp.core.state import Stage, get_state
    from wmpf_mcp.server import build_server
    from wmpf_mcp.tools import _injection
    from wmpf_mcp.core import envelope

    manager, sessions = fake_manager(monkeypatch, fake_cancellable, {11: 'ready', 12: 'error'})
    pids = [11, 12]
    config = tmp_path / 'offsets.json'
    config.write_text('{"Arch":{"arm64":{}}}')
    state = get_state()
    state.config_path = str(config)
    state.advance(Stage.OFFSETS_READY)
    monkeypatch.setattr(_injection, 'get_injector', lambda: manager)
    monkeypatch.setattr(_injection, 'get_adapter', lambda: SimpleNamespace(
        platform='darwin', main_module_path=lambda: str(tmp_path / 'module'), running_pids=lambda: list(pids)))
    monkeypatch.setattr(_injection, 'static_checks', lambda *_: [{'ok': True}])
    monkeypatch.setattr('wmpf_mcp.tools.runtime.collect_environment', lambda *_: {'environment_ready': True})
    async def checked(**_):
        return envelope.ok({'ready': True}, stage=get_state().stage.value)
    monkeypatch.setattr('wmpf_mcp.tools._offsets.execute', checked)
    server = build_server()
    reply = await server.call_tool('start_runtime', {'component': 'hooks', 'prompt_user': False})
    assert reply.is_error
    assert reply.structured_content['remedy_detail']['first_unmet'] == 'hooks'
    assert not reply.structured_content['remedy_detail']['awaiting_miniapp']
    assert manager.status()['armed_pids'] == [11] and sessions[1].is_detached
    inspected = await server.call_tool('inspect_runtime', {'component': 'hooks'})
    assert inspected.structured_content['data']['branch'] == 'hook_installation'
    probe = await server.call_tool('probe_runtime', {'layer': 'hooks'})
    assert probe.is_error
    pids[:] = [11]  # The failed helper has exited; no forced retry of it.
    resumed = await server.call_tool('start_runtime', {'component': 'hooks', 'prompt_user': False})
    assert resumed.structured_content['ok'] and not manager.status()['last_start_failures']
    assert len(sessions) == 2  # Reuses the already initialized PID without another attach.
    await manager.stop()
