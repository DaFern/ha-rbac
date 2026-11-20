"""Cross-project admission/execution tests with simulated transport authentication.

No real ESPHome connection, audio, model call, pipeline interception or hardware
is exercised. The session validator stands in for a future authenticated adapter.
"""

import asyncio
import sys
from dataclasses import replace
from importlib import import_module
from types import ModuleType, SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from homeassistant.components import stt, tts
from homeassistant.components.homeassistant.exposed_entities import async_expose_entity
from homeassistant.core import Context
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import llm
from homeassistant.setup import async_setup_component

from custom_components.ha_rbac import assist_policy, satellite_admission
from custom_components.ha_rbac.const import DATA_RBAC
from custom_components.ha_rbac.policy import Evaluator, default_roles
from custom_components.ha_rbac.satellite_admission import SatelliteAdmissionRegistry
from testsupport.ha_test import MockConfigEntry

IDS = ("light.guest", "light.child", "light.adult", "light.other")
DENIED = {"status": "denied", "completed": 0}


def role(name, ids):
    """Synthetic explicit grants, never household configuration."""
    grants = {eid: {"read": True, "control": True} for eid in ids}
    return {"id": name, "name": name, "allow": {"entities": {"entity_ids": grants}}}


@pytest.fixture
async def env(hass, monkeypatch):
    """Connect real registries, roles, paired handoff and native exact execution."""
    consumer = pytest.importorskip("custom_components.codex_assist.rbac_satellite")
    voices = pytest.importorskip("custom_components.codex_assist.voice_match")
    packets = pytest.importorskip("custom_components.codex_assist.speaker_packet")
    assert await async_setup_component(hass, "homeassistant", {})
    registry = er.async_get(hass)
    for eid in IDS:
        registry.async_get_or_create(
            "light", "test", eid, suggested_object_id=eid.partition(".")[2]
        )
        hass.states.async_set(eid, "off", {"friendly_name": f"PRIVATE {eid}"})
        async_expose_entity(hass, "conversation", eid, True)
    entry = MockConfigEntry(domain="esphome")
    entry.add_to_hass(hass)
    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={("esphome", "test-satellite")}
    )
    satellite = registry.async_get_or_create(
        "assist_satellite",
        "esphome",
        "test-satellite",
        config_entry=entry,
        device_id=device.id,
        suggested_object_id="test",
    )
    store = SimpleNamespace(
        roles={
            **default_roles(),
            "guest": role("guest", IDS[:1]),
            "child": role("child", IDS[:2]),
            "adult": role("adult", IDS[:3]),
        },
        bindings={"child": ["child"], "adult": ["adult"]},
        global_deny={},
    )
    evaluator = Evaluator(hass, store)
    hass.data[DATA_RBAC] = SimpleNamespace(store=store, evaluator=evaluator)
    users = {
        uid: SimpleNamespace(
            id=uid,
            is_active=True,
            is_owner=uid == "owner",
            is_admin=uid in {"adult", "owner"},
            system_generated=False,
            permissions=SimpleNamespace(check_entity=lambda *args: True),
        )
        for uid in ("child", "adult", "owner", "unbound")
    }

    async def get_user(uid):
        await asyncio.sleep(0)
        return users.get(uid)

    monkeypatch.setattr(hass.auth, "async_get_user", get_user)
    state = SimpleNamespace(key=Fernet.generate_key().decode(), guest_role="guest")
    runtime = voices.SpeakerRuntime()
    dispatcher = consumer.ProtectedSatelliteDispatcher(
        hass,
        runtime,
        key_provider=lambda: state.key,
        guest_role_provider=lambda: state.guest_role,
        candidate_entity_ids=IDS,
    )
    ingress = SatelliteAdmissionRegistry(
        hass, dispatcher, approved_satellite_ids=frozenset({satellite.entity_id})
    )
    session = SimpleNamespace(online=True)
    binding = ingress.register_transport(
        satellite.entity_id,
        session,
        connection_is_current=lambda actual: actual is session and session.online,
    )
    calls = []

    async def record(call):
        calls.append((call.domain, call.service, dict(call.data), call.context))

    for action in ("turn_on", "turn_off"):
        hass.services.async_register("light", action, record)
    yield SimpleNamespace(
        hass=hass,
        ingress=ingress,
        dispatcher=dispatcher,
        runtime=runtime,
        state=state,
        packets=packets,
        session=session,
        binding=binding,
        satellite=satellite,
        store=store,
        evaluator=evaluator,
        users=users,
        calls=calls,
    )
    await ingress.async_close()
    runtime.handoffs.clear()


@pytest.fixture
async def guest_tools_env(env):
    """Pair real guest domain rules/tools with the simulated transport admission."""
    if not hasattr(llm, "ToolResult"):
        pytest.skip("Guest tools require modern native tool results")
    pytest.importorskip("custom_components.codex_assist.guest_control")
    e = env
    targets = ("light.guest", "switch.guest", "fan.guest", "media_player.guest")
    music_entry = MockConfigEntry(domain="music_assistant")
    music_entry.add_to_hass(e.hass)
    for eid in targets[1:]:
        domain = eid.partition(".")[0]
        entry = er.async_get(e.hass).async_get_or_create(
            domain, "music_assistant" if domain == "media_player" else "test",
            eid, suggested_object_id="guest",
            **({"config_entry": music_entry} if domain == "media_player" else {}),
        )
        e.hass.states.async_set(entry.entity_id, "off", {"friendly_name": "Guest device"})
        async_expose_entity(e.hass, "conversation", entry.entity_id, True)
    e.store.roles["guest"] = {
        "id": "guest", "name": "Guest",
        "allow": {"entities": {"domains": {
            domain: {"read": True, "control": True}
            for domain in ("light", "switch", "fan", "media_player")
        }}},
        "deny": {},
    }
    e.evaluator.invalidate()
    e.dispatcher._candidates = targets  # Trusted adapter-owned candidate selection.

    async def record(call):
        e.calls.append((call.domain, call.service, dict(call.data), call.context))

    for domain, service in (
        ("switch", "turn_on"), ("fan", "turn_on"), ("media_player", "media_play"),
        ("music_assistant", "play_media"),
    ):
        e.hass.services.async_register(domain, service, record)
    return e


@pytest.mark.parametrize("domain", ["light", "switch", "fan", "media_player"])
async def test_guest_tools_real_domain_policy_native_admission_and_no_replay(
    guest_tools_env, domain
):
    """The paired neutral turn uses the current role, not a synthetic HA user."""
    e = guest_tools_env
    context = Context(user_id="original-kiosk")
    admission = e.binding.admit(context)
    text, _wire = transcript(e, speaker=None)
    held = []

    async def handle(payload, original):
        held.extend(payload["tools"])
        assert original is context
        tool = next(tool for tool in held if tool.name.endswith(
            "guest_music" if domain == "media_player" else "guest_on_off"
        ))
        args = (
            {"action": "resume", "speaker": "media_player.guest"}
            if domain == "media_player"
            else {"operation": "turn_on", "entity_ids": [f"{domain}.guest"]}
        )
        result = await tool.async_call(
            e.hass, llm.ToolInput(tool_name=tool.name, tool_args=args),
            llm.LLMContext(platform="codex_assist", context=original, language="en",
                           assistant="conversation", device_id=None),
        )
        assert not result.error
        return {"status": "completed", "completed": 1}

    result = await e.ingress.async_guest_turn(admission, transcript=text, handler=handle)
    assert result == {"status": "completed", "completed": 1}
    assert len(e.calls) == 1
    assert e.calls[0][3] is context
    assert context.user_id == "original-kiosk"
    assert await e.ingress.async_guest_turn(admission, transcript=text, handler=handle) == DENIED
    # Tools retained by a server handler lose authority as soon as the scope closes.
    tool = held[0]
    assert (await tool.async_call(
        e.hass, llm.ToolInput(tool_name=tool.name, tool_args={}),
        llm.LLMContext(platform="codex_assist", context=context, language="en",
                       assistant="conversation", device_id=None),
    )).error
    assert len(e.calls) == 1


@pytest.mark.parametrize("change", ["domain", "role", "disconnect", "caller", "key"])
async def test_guest_tools_recheck_changes_after_model_prompt(guest_tools_env, change):
    """Revocation after preparing tools is still checked before device admission."""
    e = guest_tools_env
    context = Context(user_id="original-kiosk")
    admission = e.binding.admit(context)
    text, _wire = transcript(e, speaker=None)

    async def handle(payload, original):
        if change == "domain":
            e.store.roles["guest"]["allow"]["entities"]["domains"].pop("switch")
            e.evaluator.invalidate()
        elif change == "role":
            e.state.guest_role = "child"
        elif change == "disconnect":
            e.session.online = False
        elif change == "caller":
            context.user_id = "forged-owner"
        else:
            e.state.key = Fernet.generate_key().decode()
        tool = next(tool for tool in payload["tools"] if tool.name.endswith("guest_on_off"))
        result = await tool.async_call(
            e.hass, llm.ToolInput(tool_name=tool.name, tool_args={
                "operation": "turn_on", "entity_ids": ["switch.guest"],
            }),
            llm.LLMContext(platform="codex_assist", context=original, language="en",
                           assistant="conversation", device_id=None),
        )
        assert result.error
        return DENIED

    assert await e.ingress.async_guest_turn(
        admission, transcript=text, handler=handle
    ) == DENIED
    assert e.calls == []


@pytest.mark.parametrize("kind", ["serialized", "recognised", "unbound"])
async def test_guest_tools_require_private_neutral_handoff(guest_tools_env, kind):
    """Neither supplied neutral strings nor an unresolved matched user become guests."""
    e = guest_tools_env
    context = Context(user_id="original-kiosk")
    admission = e.binding.admit(context)
    if kind == "serialized":
        text, _wire = transcript(e, speaker=None)
        text = str(text)
    elif kind == "recognised":
        text, _wire = transcript(e, speaker="child")
    else:
        wire = e.packets.encode(
            e.state.key, "Turn on the plug", voice="unbound", revision="a" * 32,
        )
        text = e.runtime.handoffs.issue(e.state.key, wire)

    async def forbidden(*args):
        pytest.fail("Invalid guest authority reached a server handler")

    assert await e.ingress.async_guest_turn(
        admission, transcript=text, handler=forbidden
    ) == DENIED
    assert e.calls == []


async def test_guest_handler_disconnect_cancels_and_revokes_held_tools(guest_tools_env):
    """Disconnect cannot leave a model request or its tool authority running."""
    e = guest_tools_env
    started = asyncio.Event()
    held = []
    context = Context(user_id="original-kiosk")

    async def handle(payload, original):
        held.extend(payload["tools"])
        started.set()
        await asyncio.Event().wait()

    async def run():
        lease = e.binding.admit(context)
        text, _wire = transcript(e, speaker=None)
        return await e.ingress.async_guest_turn(lease, transcript=text, handler=handle)

    task = asyncio.create_task(run())
    await started.wait()
    await e.binding.async_close()
    with pytest.raises(asyncio.CancelledError):
        await task
    tool = held[0]
    assert (await tool.async_call(
        e.hass, llm.ToolInput(tool_name=tool.name, tool_args={}),
        llm.LLMContext(platform="codex_assist", context=context, language="en",
                       assistant="conversation", device_id=None),
    )).error
    assert not e.dispatcher._scopes
    assert e.calls == []


def command(*ids, operation="turn_on"):
    """Only the operation and exact entity IDs are untrusted proposal data."""
    return {"operation": operation, "entity_ids": list(ids or IDS[:1])}


def transcript(env, speaker="child"):
    """Simulate paired STT on the same owning task as the transport admission."""
    wire = env.packets.encode(
        env.state.key,
        "Turn on the requested lamp",
        voice="profile" if speaker else None,
        revision="a" * 32 if speaker else None,
        ha_user_id=speaker,
    )
    return env.runtime.handoffs.issue(env.state.key, wire), wire


@pytest.mark.parametrize(
    ("speaker", "target", "allowed"),
    [(None, IDS[0], True), ("child", IDS[1], True), ("child", IDS[2], False),
     ("adult", IDS[2], True), ("owner", IDS[3], True), ("unbound", IDS[3], False)],
)
async def test_voice_tool_turn_uses_own_role_not_guest_or_original_caller(
    guest_tools_env, speaker, target, allowed,
):
    """Recognised voice actions check the speaker, never the transport caller."""
    e = guest_tools_env
    # Guest can control only its domain role here, while each matched account has
    # the separate explicit grant compiled in env. The caller is never replaced.
    e.dispatcher._candidates = IDS
    context = Context(user_id="original-kiosk")
    lease = e.binding.admit(context)
    text, _ = transcript(e, speaker)
    seen = []

    async def handle(payload, original):
        assert original is context
        tool = next(t for t in payload["tools"] if t.name.endswith("guest_on_off"))
        result = await tool.async_call(
            e.hass, llm.ToolInput(tool_name=tool.name, tool_args=command(target)),
            llm.LLMContext(platform="codex_assist", context=original,
                           language="en", assistant="conversation", device_id=None),
        )
        seen.append(result)
        return {"status": "denied" if result.error else "completed",
                "completed": 0 if result.error else 1}

    result = await e.ingress.async_voice_turn(lease, transcript=text, handler=handle)
    assert (result["status"] == "completed") is allowed
    assert len(e.calls) == int(allowed)
    if allowed:
        assert e.calls[0][3] is context
    assert context.user_id == "original-kiosk"


@pytest.fixture
async def native_voice(env, monkeypatch):
    """Real HA STT/TTS pipeline controllers, real RBAC and protected model loop.

    External audio recognition, TTS synthesis, model provider and network
    authentication remain simulated. This does not prove a physical Kiosk session.
    """
    prefix = "custom_components.codex_assist."
    if not import_module(prefix + "satellite_runtime").satellite_tools_supported():
        pytest.skip("Protected tools require modern HA")
    for name, attr in (("pymicro_vad", "MicroVad"), ("pyspeex_noise", "AudioProcessor")):
        module = ModuleType(name)
        setattr(module, attr, lambda *args, **kwargs: None)
        monkeypatch.setitem(sys.modules, name, module)
    assist_pipeline = import_module("homeassistant.components.assist_pipeline")
    processor = import_module(
        "homeassistant.components.assist_pipeline.default_pipeline",
    )._DefaultPipelineProcessor
    model = import_module(prefix + "protected_model")
    runner = import_module(prefix + "protected_pipeline")
    voices = import_module(prefix + "voice_match")
    adapter_type = import_module(prefix + "voice_match_stt").VoiceMatchSttAdapter
    client_types = import_module(prefix + "codex_client")

    e = env
    assert await async_setup_component(e.hass, "assist_pipeline", {})
    entry = MockConfigEntry(domain="codex_assist", options={
        "voice_match_pairing_key": e.state.key,
    })
    entry.add_to_hass(e.hass)
    e.runtime = voices.runtime_for_entry(entry)
    e.dispatcher._runtime = e.runtime
    state = SimpleNamespace(speaker=None, forged=False, error=False, model_calls=[],
                            target=IDS[0], tts=[], owner=None)

    async def recognise(metadata, stream):
        state.owner = asyncio.current_task()
        assert b"".join([part async for part in stream])
        wire = e.packets.encode(
            e.state.key, "Turn on the requested lamp",
            voice="profile" if state.speaker else None,
            revision="a" * 32 if state.speaker else None,
            ha_user_id=state.speaker,
        )
        return stt.SpeechResult(
            "Turn on the requested lamp" if state.forged else wire,
            stt.SpeechResultState.SUCCESS,
        )

    source = SimpleNamespace(
        supported_languages=["en"], supported_formats=[stt.AudioFormats.WAV],
        supported_codecs=[stt.AudioCodecs.PCM], supported_bit_rates=[stt.AudioBitRates.BITRATE_16],
        supported_sample_rates=[stt.AudioSampleRates.SAMPLERATE_16000],
        supported_channels=[stt.AudioChannels.CHANNEL_MONO],
        audio_processing=stt.SpeechAudioProcessing(False, False, False),
        async_process_audio_stream=recognise,
    )
    stt_adapter = adapter_type(entry, source)
    stt_adapter.hass = e.hass
    stt_adapter.entity_id = "stt.test_protected"
    monkeypatch.setattr(stt, "async_get_speech_to_text_engine", lambda *args: stt_adapter)
    stream = SimpleNamespace(
        engine="tts.test", media_source_id="media-source://tts/test", token="synthetic",
        url="/synthetic.wav", content_type="audio/wav",
        async_set_message=state.tts.append, delete=lambda: None, supports_streaming_input=False,
    )
    monkeypatch.setattr(tts, "async_create_stream", lambda **kwargs: stream)

    async def no_native_intent(*args, **kwargs):
        raise AssertionError("Native sentence/local-intent/conversation path was entered")

    monkeypatch.setattr(processor, "recognize_intent", no_native_intent)
    monkeypatch.setattr(processor, "prepare_recognize_intent", no_native_intent)
    profile = SimpleNamespace(model="synthetic", reasoning_effort="low",
                              reasoning_summary="auto", text_verbosity="low")

    class Model:
        async def stream_turn(self, **kwargs):
            state.model_calls.append(kwargs)
            yield client_types.CodexTextDelta("Premature unverified success must never be spoken.")
            yield client_types.CodexToolCallDelta(client_types.CodexToolCall(
                "call-1", "codex_assist__guest_on_off", command(state.target),
            ))
            if state.error:
                raise RuntimeError("Simulated incomplete provider response")

    async def handler(payload, context, text, language):
        assert state.owner is asyncio.current_task()
        return await model.async_fixed_tool_turn(
            e.hass, Model(), profile, payload, context, text, language,
        )

    pipeline = assist_pipeline.Pipeline(
        name="Synthetic protected pipeline", conversation_engine="never-enter",
        conversation_language="en", language="en", stt_engine=stt_adapter.entity_id,
        stt_language="en", tts_engine="tts.test", tts_language="en", tts_voice=None,
        wake_word_entity=None, wake_word_id=None,
    )

    async def run():
        events = []
        context = Context(user_id="original-kiosk")

        async def audio():
            yield b"\x01\x00" * 512

        await runner.async_run_protected_pipeline(
            e.hass, pipeline=pipeline, context=context, audio_stream=audio(),
            event_callback=events.append, binding=e.binding, ingress=e.ingress,
            handler=handler, device_id=e.satellite.device_id,
            satellite_id=e.satellite.entity_id,
        )
        return events, context

    yield SimpleNamespace(
        env=e, state=state, run=run, entry=entry, pipeline=pipeline,
        handler=handler, profile=profile, stt_adapter=stt_adapter,
    )
    e.runtime.handoffs.clear()


@pytest.fixture
async def hooked_voice(native_voice, monkeypatch):
    """Synthetic ESPHome object shapes at the real hook; not network auth evidence."""
    component_key = import_module("homeassistant.components.assist_satellite.const").DATA_COMPONENT
    kiosk_adapter = import_module("custom_components.codex_assist.kiosk_adapter")
    agent_type = import_module(
        "custom_components.codex_assist.conversation",
    ).CodexAssistConversationEntity

    n = native_voice
    e = n.env
    e.hass.config_entries.async_update_entry(n.entry, options={
        **n.entry.options, "guest_voice_role_id": "guest",
        "protected_satellite_ids": [e.satellite.entity_id],
    })
    stt_entry = er.async_get(e.hass).async_get_or_create(
        "stt", "codex_assist", "synthetic-protected", config_entry=n.entry,
        suggested_object_id="test_protected",
    )
    assert stt_entry.entity_id == n.stt_adapter.entity_id

    class Connection:
        is_connected = True

    class Client:
        is_connected = True
        noise_psk = "synthetic-not-a-credential"

        def __init__(self):
            self._connection = Connection()

    class Runtime:
        available = True

        def __init__(self):
            self.client = Client()
            self.disconnect_callbacks = set()

    runtime = Runtime()
    esphome_entry = e.hass.config_entries.async_get_entry(e.satellite.config_entry_id)
    esphome_entry.runtime_data = runtime
    events = []
    fallback = []

    class Satellite:
        available = True
        _ask_question_future = _wake_word_intercept_future = None
        tts_options = None
        registry_entry = e.satellite
        entity_id = e.satellite.entity_id
        config_entry = esphome_entry
        cli = runtime.client
        _entry_data = runtime

        async def async_accept_pipeline_from_satellite(self, *args, **kwargs):
            fallback.append(True)

        def _resolve_pipeline(self):
            return n.pipeline.id

        def _resolve_vad_sensitivity(self):
            return 0.7

        def async_set_context(self, context):
            self.context = context

        def _internal_on_pipeline_event(self, event):
            events.append(event)

    satellite = Satellite()
    monkeypatch.setattr(kiosk_adapter, "_native_types", lambda: (
        Satellite, Runtime, Client, Connection,
    ))
    monkeypatch.setitem(e.hass.data, component_key, SimpleNamespace(
        get_entity=lambda eid: satellite if eid == satellite.entity_id else None,
    ))
    monkeypatch.setattr(kiosk_adapter, "async_get_pipeline", lambda *args: n.pipeline)
    agent = agent_type(n.entry)
    monkeypatch.setattr(kiosk_adapter.conversation, "async_get_agent", lambda *args: agent)

    async def handle(_hass, entry, profile, payload, context, text, language):
        assert entry is n.entry
        return await n.handler(payload, context, text, language)

    monkeypatch.setattr(kiosk_adapter, "async_entry_voice_handler", handle)
    adapter = kiosk_adapter.KioskSatelliteAdapter(
        e.hass, n.entry, [satellite.entity_id],
    )
    adapter.install()

    async def run():
        async def audio():
            yield b"\x01\x00" * 512

        context = Context(user_id="original-kiosk")
        await satellite.async_accept_pipeline_from_satellite(audio(), context=context)
        return context

    yield SimpleNamespace(n=n, adapter=adapter, satellite=satellite, runtime=runtime,
                          events=events, fallback=fallback, run=run, module=kiosk_adapter,
                          agent=agent)
    await adapter.async_close()
    # Explicitly remove synthetic enrollment so no closed hook leaks between tests.
    e.hass.config_entries.async_update_entry(n.entry, options={})
    adapter.close()


@pytest.mark.parametrize(
    ("speaker", "target", "allowed"),
    [(None, IDS[0], True), (None, IDS[1], False), ("child", IDS[1], True),
     ("child", IDS[2], False), ("adult", IDS[2], True), ("owner", IDS[3], True)],
)
async def test_hook_to_native_stt_protected_tools_and_tts(hooked_voice, speaker, target, allowed):
    """The installed hook reaches native STT/TTS without the unrestricted path."""
    h = hooked_voice
    h.n.state.speaker, h.n.state.target = speaker, target
    context = await h.run()
    assert len(h.n.env.calls) == int(allowed)
    assert h.fallback == []
    assert h.n.state.tts == [
        "The command was sent." if allowed else "This voice request is not authorised.",
    ]
    assert h.satellite.context is context
    if allowed:
        assert h.n.env.calls[0][3] is context


@pytest.mark.parametrize("change", [
    "plaintext", "connection_not_ready", "client_not_ready", "runtime_unavailable",
    "replaced_client", "replaced_connection", "config_changed", "caller_options",
    "wrong_stt", "wrong_agent", "satellite_unavailable",
])
async def test_hook_refuses_unsupported_or_changed_session(hooked_voice, monkeypatch, change):
    """Transport/client/configuration changes never cause ordinary Assist fallback."""
    h = hooked_voice
    if change == "plaintext":
        h.runtime.client.noise_psk = None
    elif change == "connection_not_ready":
        h.runtime.client._connection.is_connected = False
    elif change == "client_not_ready":
        h.runtime.client.is_connected = False
    elif change == "runtime_unavailable":
        h.runtime.available = False
    elif change == "replaced_client":
        h.runtime.client = SimpleNamespace()
    elif change == "replaced_connection":
        h.runtime.client._connection = object()
    elif change == "config_changed":
        binding = h.adapter._binding(h.satellite)
        h.n.env.hass.config_entries.async_update_entry(h.satellite.config_entry, data={"new": True})
        assert binding.admit(Context()) is None
        return
    elif change == "caller_options":
        h.n.env.hass.config_entries.async_update_entry(h.n.entry, options={
            **h.n.entry.options, "guest_voice_role_id": "changed",
        })
    elif change == "wrong_stt":
        monkeypatch.setattr(h.module, "async_get_pipeline", lambda *args: replace(
            h.n.pipeline, stt_engine="stt.untrusted",
        ))
    elif change == "wrong_agent":
        monkeypatch.setattr(h.module.conversation, "async_get_agent", lambda *args: object())
    else:
        h.satellite.available = False
    await h.run()
    assert h.fallback == [] and h.n.env.calls == [] and h.n.state.model_calls == []


async def test_disconnect_cancels_native_stt_and_clears_pending_admission(hooked_voice, monkeypatch):
    """Losing the connection cancels pending STT, not just active model tools."""
    h = hooked_voice
    started = asyncio.Event()

    async def recognise(*args):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(h.n.stt_adapter, "async_process_audio_stream", recognise)
    task = asyncio.create_task(h.run())
    async with asyncio.timeout(5):
        await started.wait()
    h.runtime.available = False
    for callback in tuple(h.runtime.disconnect_callbacks):
        callback()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not h.adapter.ingress._pending and not h.adapter.ingress._active
    assert h.fallback == [] and h.n.env.calls == [] and h.n.state.tts == []


async def test_closed_hook_denies_during_reload_and_restores_only_after_deenrollment(hooked_voice):
    """Reload keeps a closed denial hook; deliberate de-enrollment restores native."""
    h = hooked_voice
    hook = h.satellite.async_accept_pipeline_from_satellite
    await h.adapter.async_close()
    assert h.satellite.async_accept_pipeline_from_satellite is hook
    await h.run()
    assert h.fallback == [] and h.n.env.calls == []
    replacement = h.module.KioskSatelliteAdapter(
        h.n.env.hass, h.n.entry, [h.satellite.entity_id],
    )
    replacement.install()
    assert h.satellite.async_accept_pipeline_from_satellite is not hook
    h.adapter.close()
    # The old owner may never overwrite the replacement's hook.
    assert h.satellite.async_accept_pipeline_from_satellite is not hook
    await replacement.async_close()
    h.n.env.hass.config_entries.async_update_entry(h.n.entry, options={})
    replacement.close()
    assert h.module.HOOK not in h.satellite.__dict__


async def test_disconnect_cancels_model_and_does_not_keep_tools_alive(hooked_voice, monkeypatch):
    """Disconnect cancellation propagates through the model handler and admission."""
    h = hooked_voice
    started = asyncio.Event()
    held = []

    async def wait(_hass, _entry, _profile, payload, *_args):
        held.extend(payload["tools"])
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(h.module, "async_entry_voice_handler", wait)
    task = asyncio.create_task(h.run())
    async with asyncio.timeout(5):
        await started.wait()
    h.runtime.available = False
    for callback in tuple(h.runtime.disconnect_callbacks):
        callback()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert held and not held[0]._auth.valid()
    assert not h.adapter.ingress._active and not h.adapter.ingress._pending
    assert h.n.env.calls == [] and h.n.state.tts == [] and h.fallback == []


async def test_reconnect_requires_new_connection_admission(hooked_voice):
    """A reconnected client never revives its old session or lease."""
    h = hooked_voice
    await h.run()
    connection, binding = h.adapter._bindings[h.satellite.entity_id]
    h.runtime.available = False
    connection.is_connected = False
    for callback in tuple(h.runtime.disconnect_callbacks):
        callback()
    h.runtime.disconnect_callbacks.clear()
    h.runtime.client._connection = type(connection)()
    h.runtime.available = True
    assert binding.admit(Context()) is None
    await h.run()
    assert len(h.n.env.calls) == 2 and h.fallback == []
    assert h.adapter._bindings[h.satellite.entity_id][0] is not connection


@pytest.fixture
async def native_esphome_voice(native_voice, monkeypatch):
    """Real ESPHome objects and audio entry point; socket authentication is simulated.

    USB discovery/serial proxy are unrelated import-only doubles. Native ESPHome
    entity/runtime/client/connection types and disconnect logic are not replaced.
    Outbound device event delivery, like external STT/model/TTS providers, is captured.
    """
    import base64  # noqa: PLC0415

    api = pytest.importorskip("aioesphomeapi")
    connection_module = import_module("aioesphomeapi.connection")
    usb = ModuleType("homeassistant.components.usb")
    for attr in ("SerialDevice", "USBDevice", "async_register_serial_port_scanner"):
        setattr(usb, attr, object)
    monkeypatch.setitem(sys.modules, usb.__name__, usb)
    serial = ModuleType("homeassistant.components.esphome.serial_proxy")
    serial.build_url = lambda *args: None
    monkeypatch.setitem(sys.modules, serial.__name__, serial)
    module = import_module("custom_components.codex_assist.kiosk_adapter")
    native_type, runtime_type, client_type, connection_type = module._native_types()
    n = native_voice
    e = n.env
    e.hass.config_entries.async_update_entry(n.entry, options={
        **n.entry.options, "guest_voice_role_id": "guest",
        "protected_satellite_ids": [e.satellite.entity_id],
    })
    er.async_get(e.hass).async_get_or_create(
        "stt", "codex_assist", "native-package-protected", config_entry=n.entry,
        suggested_object_id="test_protected",
    )
    esphome_entry = e.hass.config_entries.async_get_entry(e.satellite.config_entry_id)
    client = client_type(
        "192.0.2.1", 6053, noise_psk=base64.b64encode(bytes(range(32))).decode(),
    )

    def connection(ready=True):
        value = connection_type(client._params, None, False, "synthetic-test")
        # No socket/handshake is executed. Tests explicitly control real library
        # readiness fields; this does not establish cryptographic authentication.
        value.connection_state = (
            connection_module.ConnectionState.CONNECTED if ready
            else connection_module.ConnectionState.HANDSHAKE_COMPLETE
        )
        value.is_connected = ready
        return value

    client._connection = connection()
    runtime = runtime_type(
        entry_id=esphome_entry.entry_id, title="Synthetic native satellite",
        client=client, store=None, available=True,
        device_info=api.DeviceInfo(
            mac_address="02:00:00:00:00:01",
            voice_assistant_feature_flags=int(
                api.VoiceAssistantFeature.SPEAKER | api.VoiceAssistantFeature.API_AUDIO
            ),
        ),
        api_version=api.APIVersion(1, 10),
    )
    esphome_entry.runtime_data = runtime
    satellite = native_type(esphome_entry)
    satellite.hass = e.hass
    satellite.entity_id = e.satellite.entity_id
    e.satellite = er.async_get(e.hass).async_update_entity(
        e.satellite.entity_id, new_unique_id=satellite.unique_id,
    )
    satellite.registry_entry = e.satellite
    events = []
    monkeypatch.setattr(satellite, "async_write_ha_state", lambda: None)
    monkeypatch.setattr(satellite, "on_pipeline_event", events.append)
    component_key = import_module("homeassistant.components.assist_satellite.const").DATA_COMPONENT
    monkeypatch.setitem(e.hass.data, component_key, SimpleNamespace(
        get_entity=lambda eid: satellite if eid == satellite.entity_id else None,
    ))
    monkeypatch.setattr(module, "async_get_pipeline", lambda *args: n.pipeline)
    agent_type = import_module(
        "custom_components.codex_assist.conversation",
    ).CodexAssistConversationEntity
    agent = agent_type(n.entry)
    monkeypatch.setattr(module.conversation, "async_get_agent", lambda *args: agent)

    async def handler(_hass, _entry, _profile, payload, context, text, language):
        return await n.handler(payload, context, text, language)

    monkeypatch.setattr(module, "async_entry_voice_handler", handler)
    adapter = module.KioskSatelliteAdapter(e.hass, n.entry, [satellite.entity_id])
    adapter.install()

    async def run(entity=None):
        target = entity if entity is not None else satellite
        port = await target.handle_pipeline_start(
            "", 0, api.VoiceAssistantAudioSettings(), None,
        )
        assert port == 0
        await target.handle_audio(b"\x01\x00" * 512)
        await target.handle_pipeline_stop(abort=False)
        task = target._pipeline_task
        async with asyncio.timeout(5):
            await task
        return task

    def replace_entity():
        replacement = native_type(esphome_entry)
        # Protection is installed before HA assigns identity or adds the entity.
        assert module.HOOK in replacement.__dict__
        replacement.hass = e.hass
        replacement.entity_id = satellite.entity_id
        replacement.registry_entry = e.satellite
        monkeypatch.setattr(replacement, "async_write_ha_state", lambda: None)
        monkeypatch.setattr(replacement, "on_pipeline_event", events.append)
        monkeypatch.setitem(e.hass.data, component_key, SimpleNamespace(
            get_entity=lambda eid: replacement if eid == replacement.entity_id else None,
        ))
        return replacement

    yield SimpleNamespace(
        n=n, satellite=satellite, runtime=runtime, client=client,
        connection=connection, adapter=adapter, module=module, events=events, run=run,
        replace_entity=replace_entity, component_key=component_key,
    )
    await adapter.async_close()
    e.hass.config_entries.async_update_entry(n.entry, options={})
    adapter.close()


@pytest.mark.parametrize(
    ("speaker", "target", "allowed"),
    [(None, IDS[0], True), (None, IDS[1], False), ("child", IDS[1], True),
     ("child", IDS[2], False), ("adult", IDS[2], True), ("owner", IDS[3], True)],
)
async def test_real_esphome_audio_entry_reaches_protected_native_pipeline(
    native_esphome_voice, speaker, target, allowed,
):
    """The actual native audio callback resolves the installed per-instance hook."""
    h = native_esphome_voice
    h.n.state.speaker, h.n.state.target = speaker, target
    await h.run()
    assert len(h.n.env.calls) == int(allowed)
    assert h.n.state.tts == [
        "The command was sent." if allowed else "This voice request is not authorised.",
    ]
    if allowed:
        assert h.n.env.calls[0][3].user_id is None
    assert sum(event.type == "run-start" for event in h.events) == 1
    assert sum(event.type == "run-end" for event in h.events) == 1


@pytest.mark.parametrize("change", ["plaintext", "not_ready", "disconnect", "runtime_replaced"])
async def test_real_esphome_library_readiness_and_disconnect_are_required(
    native_esphome_voice, change,
):
    """Real connection state and HA disconnect callbacks revoke old admission."""
    h = native_esphome_voice
    binding = h.adapter._binding(h.satellite)
    if change == "plaintext":
        h.client.clear_noise_psk()
    elif change == "not_ready":
        h.client._connection = h.connection(ready=False)
    elif change == "disconnect":
        h.runtime.async_on_disconnect()
    else:
        h.satellite.config_entry.runtime_data = object()
    assert binding.admit(Context()) is None
    await h.run()
    assert h.n.env.calls == [] and h.n.state.model_calls == []


async def test_real_esphome_reconnect_requires_a_new_binding(native_esphome_voice):
    """Real runtime disconnect clears callbacks and revokes the old connection."""
    h = native_esphome_voice
    await h.run()
    old_connection, old_binding = h.adapter._bindings[h.satellite.entity_id]
    h.runtime.async_on_disconnect()
    assert not h.runtime.disconnect_callbacks
    h.client._connection = h.connection()
    h.runtime.async_on_connect(h.n.env.hass, h.runtime.device_info, h.runtime.api_version)
    assert old_binding.admit(Context()) is None
    await h.run()
    assert len(h.n.env.calls) == 2
    assert h.adapter._bindings[h.satellite.entity_id][0] is not old_connection


@pytest.mark.parametrize(
    ("speaker", "target", "allowed"),
    [(None, IDS[0], True), (None, IDS[1], False), ("child", IDS[1], True),
     ("child", IDS[2], False), ("adult", IDS[2], True), ("owner", IDS[3], True)],
)
async def test_replaced_native_entity_cannot_return_to_ordinary_pipeline(
    native_esphome_voice, monkeypatch, speaker, target, allowed,
):
    """A native entity replacement must not silently lose protected enrollment."""
    h = native_esphome_voice
    h.n.state.speaker, h.n.state.target = speaker, target
    native_module = import_module("homeassistant.components.assist_satellite.entity")
    api = import_module("aioesphomeapi")
    ordinary = []

    async def ordinary_pipeline(_self, *args, **kwargs):
        # Sentinel only: never execute an actual unrestricted intent in this test.
        ordinary.append(True)

    monkeypatch.setattr(
        native_module.AssistSatelliteEntity,
        "async_accept_pipeline_from_satellite", ordinary_pipeline,
    )
    replacement = type(h.satellite)(h.satellite.config_entry)
    assert h.module.HOOK in replacement.__dict__
    replacement.hass = h.n.env.hass
    replacement.entity_id = h.satellite.entity_id
    replacement.registry_entry = h.satellite.registry_entry
    monkeypatch.setattr(replacement, "async_write_ha_state", lambda: None)
    monkeypatch.setattr(replacement, "on_pipeline_event", h.events.append)
    component_key = import_module("homeassistant.components.assist_satellite.const").DATA_COMPONENT
    monkeypatch.setitem(h.n.env.hass.data, component_key, SimpleNamespace(
        get_entity=lambda eid: replacement if eid == replacement.entity_id else None,
    ))
    await replacement.handle_pipeline_start("", 0, api.VoiceAssistantAudioSettings(), None)
    await replacement.handle_audio(b"\x01\x00" * 512)
    await replacement.handle_pipeline_stop(abort=False)
    async with asyncio.timeout(5):
        await replacement._pipeline_task
    assert ordinary == [], "Replacing the entity lost the per-instance guard"
    assert len(h.n.env.calls) == int(allowed)
    assert h.n.state.tts == [
        "The command was sent." if allowed else "This voice request is not authorised.",
    ]


async def test_native_replacement_revokes_old_connection_and_retires_old_instance(native_esphome_voice):
    """Even a reused API connection needs fresh admission after entity replacement."""
    h = native_esphome_voice
    old_binding = h.adapter._binding(h.satellite)
    replacement = h.replace_entity()
    assert old_binding.admit(Context()) is None
    await h.run()
    assert h.n.env.calls == []
    await h.run(replacement)
    assert len(h.n.env.calls) == 1
    assert h.adapter._bindings[replacement.entity_id][1] is not old_binding


async def test_native_replacement_cancels_active_model_before_publishing_new_hook(
    native_esphome_voice, monkeypatch,
):
    """Constructing a new entity revokes and cancels active work on its predecessor."""
    h = native_esphome_voice
    started = asyncio.Event()
    held = []

    async def wait(_hass, _entry, _profile, payload, *_args):
        held.extend(payload["tools"])
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(h.module, "async_entry_voice_handler", wait)
    task = asyncio.create_task(h.run())
    async with asyncio.timeout(5):
        await started.wait()
    h.replace_entity()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert held and not held[0]._auth.valid()
    assert not h.adapter.ingress._active and not h.adapter.ingress._pending
    assert h.n.env.calls == [] and h.n.state.tts == []


async def test_native_replacement_with_changed_unique_identity_is_guarded_but_denied(
    native_esphome_voice,
):
    """A different device identity cannot evade enrollment by constructing a new entity."""
    h = native_esphome_voice
    h.runtime.device_info = replace(h.runtime.device_info, mac_address="02:00:00:00:00:02")
    replacement = h.replace_entity()
    await h.run(replacement)
    assert h.n.env.calls == [] and h.n.state.model_calls == [] and h.n.state.tts == []
    assert any(event.type == "error" for event in h.events)


async def test_native_closed_owner_guards_replacement_until_new_adapter_takes_over(
    native_esphome_voice,
):
    """Reload's closed owner still intercepts construction and never restores Assist."""
    h = native_esphome_voice
    await h.adapter.async_close()
    replacement = h.replace_entity()
    await h.run(replacement)
    assert h.n.env.calls == [] and h.n.state.model_calls == []
    new_owner = h.module.KioskSatelliteAdapter(
        h.n.env.hass, h.n.entry, [replacement.entity_id],
    )
    new_owner.install()
    try:
        h.adapter.close()
        await h.run(replacement)
        assert len(h.n.env.calls) == 1
    finally:
        h.n.env.hass.config_entries.async_update_entry(h.n.entry, options={})
        await new_owner.async_close()


async def test_native_lifecycle_guard_can_enroll_before_entity_construction(
    native_esphome_voice, monkeypatch,
):
    """Saved registry enrollment is guarded before a later platform constructs its entity."""
    h = native_esphome_voice
    await h.adapter.async_close()
    monkeypatch.setitem(h.n.env.hass.data, h.component_key, SimpleNamespace(
        get_entity=lambda eid: None,
    ))
    new_owner = h.module.KioskSatelliteAdapter(
        h.n.env.hass, h.n.entry, [h.satellite.entity_id],
    )
    new_owner.install()
    try:
        replacement = h.replace_entity()
        await h.run(replacement)
        assert len(h.n.env.calls) == 1
    finally:
        h.n.env.hass.config_entries.async_update_entry(h.n.entry, options={})
        await new_owner.async_close()


async def test_constructor_guard_leaves_unenrolled_esphome_entries_untouched(native_esphome_voice):
    """The class-wide interception does not install hooks on unrelated satellites."""
    h = native_esphome_voice
    other = MockConfigEntry(domain="esphome")
    other.add_to_hass(h.n.env.hass)
    other.runtime_data = replace(h.runtime, entry_id=other.entry_id)
    unrelated = type(h.satellite)(other)
    assert h.module.HOOK not in unrelated.__dict__


async def test_constructor_restoration_does_not_overwrite_a_newer_hook(native_esphome_voice):
    """Explicit de-enrollment restores only the exact constructor hook we installed."""
    h = native_esphome_voice
    native = type(h.satellite)
    original = h.adapter._constructor.original

    def newer(instance, *args, **kwargs):
        return original(instance, *args, **kwargs)

    native.__init__ = newer
    try:
        h.n.env.hass.config_entries.async_update_entry(h.n.entry, options={})
        await h.adapter.async_close()
        assert native.__init__ is newer
    finally:
        native.__init__ = original


async def test_constructor_guard_restores_only_after_last_owner_deenrolls(
    native_esphome_voice, monkeypatch,
):
    """Removing one owner must not remove constructor protection from another."""
    h = native_esphome_voice
    hass = h.n.env.hass
    native = type(h.satellite)
    original = h.adapter._constructor.original
    guarded = native.__init__
    other_esphome = MockConfigEntry(domain="esphome")
    other_esphome.add_to_hass(hass)
    other_esphome.runtime_data = replace(
        h.runtime, entry_id=other_esphome.entry_id,
        device_info=replace(h.runtime.device_info, mac_address="02:00:00:00:00:03"),
    )
    second = native(other_esphome)
    assert h.module.HOOK not in second.__dict__
    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=other_esphome.entry_id, identifiers={("esphome", "second-test")},
    )
    registered = er.async_get(hass).async_get_or_create(
        "assist_satellite", "esphome", second.unique_id,
        config_entry=other_esphome, device_id=device.id, suggested_object_id="second",
    )
    second.hass = hass
    second.entity_id = registered.entity_id
    second.registry_entry = registered
    other_codex = MockConfigEntry(domain="codex_assist", options={
        "protected_satellite_ids": [second.entity_id],
        "voice_match_pairing_key": h.n.env.state.key,
    })
    other_codex.add_to_hass(hass)
    entities = {h.satellite.entity_id: h.satellite, second.entity_id: second}
    monkeypatch.setitem(hass.data, h.component_key, SimpleNamespace(
        get_entity=entities.get,
    ))
    other_owner = h.module.KioskSatelliteAdapter(hass, other_codex, [second.entity_id])
    other_owner.install()
    try:
        hass.config_entries.async_update_entry(h.n.entry, options={})
        await h.adapter.async_close()
        assert native.__init__ is guarded
        assert h.module.HOOK not in native(h.satellite.config_entry).__dict__
        assert h.module.HOOK in native(other_esphome).__dict__
    finally:
        hass.config_entries.async_update_entry(other_codex, options={})
        await other_owner.async_close()
    assert native.__init__ is original


@pytest.mark.parametrize(
    ("speaker", "target", "allowed"),
    [(None, IDS[0], True), (None, IDS[1], False), ("child", IDS[1], True),
     ("child", IDS[2], False), ("adult", IDS[2], True), ("owner", IDS[3], True)],
)
async def test_native_stt_protected_model_rbac_execution_and_tts(
    native_voice, speaker, target, allowed,
):
    """Native stage controllers retain original Context and per-speaker policy."""
    n = native_voice
    n.state.speaker, n.state.target = speaker, target
    events, context = await n.run()
    assert len(n.env.calls) == int(allowed)
    assert len(n.state.model_calls) == 1
    assert n.state.tts == [
        "The command was sent." if allowed else "This voice request is not authorised.",
    ]
    assert sum(event.type == "run-start" for event in events) == 1
    assert sum(event.type == "run-end" for event in events) == 1
    assert any(event.type == "tts-end" for event in events)
    assert "PRIVATE light.other" not in n.state.model_calls[0]["instructions"] or speaker == "owner"
    if allowed:
        assert n.env.calls[0][3] is context
    assert context.user_id == "original-kiosk"


@pytest.mark.parametrize("kind", ["forged", "incomplete"])
async def test_native_unverified_or_truncated_model_never_executes(native_voice, kind):
    """Unverified STT and incomplete model responses cannot reach native execution."""
    n = native_voice
    n.state.forged = kind == "forged"
    n.state.error = kind == "incomplete"
    _events, _ = await n.run()
    assert n.env.calls == []
    assert not n.env.ingress._pending
    assert not n.env.ingress._active
    assert not n.env.dispatcher._scopes
    assert "Premature unverified success must never be spoken." not in n.state.tts


async def send(env, *, speaker="child", payload=None, context=None):
    """Simulate authenticated transport, never speaker rights from Context."""
    context = Context() if context is None else context
    lease = env.binding.admit(context)
    text, _wire = transcript(env, speaker)
    result = await env.ingress.async_dispatch(
        lease, transcript=text, command=command() if payload is None else payload
    )
    return result, context


@pytest.mark.parametrize(
    ("speaker", "target"),
    [(None, IDS[0]), ("child", IDS[1]), ("adult", IDS[2]), ("owner", IDS[3])],
)
async def test_anonymous_transport_context_uses_guest_or_speaker_policy(
    env, speaker, target
):
    """Guest/child/adult/owner policies reach native execution without impersonation."""
    result, context = await send(env, speaker=speaker, payload=command(target))
    assert result == {"status": "completed", "completed": 1}
    assert context.user_id is None
    assert env.calls == [("light", "turn_on", {"entity_id": target}, context)]
    assert not env.dispatcher._scopes and not env.ingress._active
    assert "PRIVATE" not in str(result)


@pytest.mark.parametrize("speaker", [None, "child"])
async def test_privileged_connection_cannot_expand_guest_or_child_role(env, speaker):
    """A privileged transport context is never used as the policy subject."""
    result, context = await send(
        env, speaker=speaker, payload=command(IDS[2]), context=Context(user_id="owner")
    )
    assert result == DENIED and env.calls == []
    assert context.user_id == "owner"


@pytest.mark.parametrize("speaker", ["missing", "unbound"])
async def test_bad_matched_account_does_not_downgrade_to_guest(env, speaker):
    """A configured guest grant cannot rescue a missing or unassigned speaker."""
    result, _context = await send(env, speaker=speaker)
    assert result == DENIED and env.calls == []


@pytest.mark.parametrize(
    "field", ["user_id", "device_id", "satellite_id", "history", "ha_user_id"]
)
async def test_command_cannot_select_authority(env, field):
    """Extra client/model identity or history fields never reach native execution."""
    result, _context = await send(env, payload={**command(), field: "owner"})
    assert result == DENIED and env.calls == []


@pytest.mark.parametrize("kind", ["raw", "serialized", "dictionary", "prepared"])
async def test_no_raw_or_serialized_identity_is_a_private_stt_handoff(env, kind):
    """Valid ciphertext alone is not proof of this task's authenticated audio."""
    lease = env.binding.admit(Context())
    text, wire = transcript(env)
    supplied = {
        "raw": wire,
        "serialized": str(text),
        "dictionary": {"verified": True, "ha_user_id": "owner"},
        "prepared": SimpleNamespace(verified=True, voice="profile", ha_user_id="owner"),
    }[kind]
    result = await env.ingress.async_dispatch(
        lease, transcript=supplied, command=command()
    )
    assert result == DENIED and env.calls == []


async def test_lease_copy_replay_and_packet_nonce_replay_are_denied(env):
    """Admission object, transcript carrier and shared nonce ledger are independent."""
    lease = env.binding.admit(Context())
    text, wire = transcript(env)
    result = await env.ingress.async_dispatch(
        replace(lease), transcript=text, command=command()
    )
    assert result == DENIED
    result = await env.ingress.async_dispatch(lease, transcript=text, command=command())
    assert result["completed"] == 1
    result = await env.ingress.async_dispatch(lease, transcript=text, command=command())
    assert result == DENIED
    next_lease = env.binding.admit(Context())
    replay = env.runtime.handoffs.issue(env.state.key, wire)
    result = await env.ingress.async_dispatch(
        next_lease, transcript=replay, command=command()
    )
    assert result == DENIED
    assert len(env.calls) == 1


async def test_forged_unregistered_and_closed_sources_are_denied(env):
    """A device ID or event-shaped object is not a registered transport binding."""
    fake = SimpleNamespace(context=Context(), owner=asyncio.current_task())
    result = await env.ingress.async_dispatch(
        fake, transcript="text", command=command()
    )
    assert result == DENIED
    with pytest.raises(ValueError):
        env.ingress.register_transport(
            "assist_satellite.unapproved",
            object(),
            connection_is_current=lambda _: True,
        )
    env.binding.close()
    assert env.binding.admit(Context()) is None
    result, _context = await send(env)
    assert result == DENIED and env.calls == []


async def test_admission_cannot_move_to_another_task(env):
    """The same source string and a real lease do not authorize another pipeline."""
    lease = env.binding.admit(Context())
    text, _wire = transcript(env)
    result = await asyncio.create_task(
        env.ingress.async_dispatch(lease, transcript=text, command=command())
    )
    assert result == DENIED and env.calls == []


async def test_stt_handoff_cannot_be_borrowed_from_another_task(env):
    """Authentication/admission and the clean STT carrier must share an owner."""
    ready, release = asyncio.Event(), asyncio.Event()
    holder = []

    async def other():
        holder.append(transcript(env)[0])
        ready.set()
        await release.wait()

    task = asyncio.create_task(other())
    await ready.wait()
    try:
        result = await env.ingress.async_dispatch(
            env.binding.admit(Context()), transcript=holder[0], command=command()
        )
        assert result == DENIED and env.calls == []
    finally:
        release.set()
        await task


async def test_handoff_must_be_issued_after_this_audio_admission(env):
    """A fresh but earlier STT result in the same task is not this admitted turn."""
    text, _wire = transcript(env)
    lease = env.binding.admit(Context())
    result = await env.ingress.async_dispatch(lease, transcript=text, command=command())
    assert result == DENIED
    assert env.calls == []


async def test_one_pending_or_active_audio_turn_per_task(env):
    """Two source leases cannot share a task and borrow each other's STT result."""
    lease = env.binding.admit(Context())
    assert lease is not None
    assert env.binding.admit(Context()) is None
    text, _wire = transcript(env)
    result = await env.ingress.async_dispatch(lease, transcript=text, command=command())
    assert result["completed"] == 1


@pytest.mark.parametrize(
    "change", ["connection", "key", "guest", "role", "exposure", "caller", "registry"]
)
async def test_revocation_after_projection_prevents_execution(env, monkeypatch, change):
    """Neither filtered context nor successful preflight is a reusable grant."""
    original = assist_policy.async_project_satellite_context
    context = Context()

    async def project(*args, **kwargs):
        result = await original(*args, **kwargs)
        if change == "connection":
            env.session.online = False
        elif change == "key":
            env.state.key = Fernet.generate_key().decode()
        elif change == "guest":
            env.state.guest_role = None
        elif change == "role":
            env.store.bindings.pop("child")
            env.evaluator.invalidate()
        elif change == "exposure":
            async_expose_entity(env.hass, "conversation", IDS[0], False)
        elif change == "caller":
            context.user_id = "owner"
        else:
            er.async_get(env.hass).async_update_entity(
                env.satellite.entity_id, disabled_by=er.RegistryEntryDisabler.USER
            )
        return result

    monkeypatch.setattr(assist_policy, "async_project_satellite_context", project)
    speaker = None if change == "guest" else "child"
    result, _context = await send(env, speaker=speaker, context=context)
    assert result == DENIED and env.calls == []


async def test_revocation_inside_native_task_is_rechecked(env, monkeypatch):
    """Revoke after the guard's first successful check, before service admission."""
    original = assist_policy.async_check_satellite_access
    checks = []

    async def check(*args, **kwargs):
        result = await original(*args, **kwargs)
        checks.append(result)
        env.store.bindings.clear()
        env.evaluator.invalidate()
        return result

    monkeypatch.setattr(assist_policy, "async_check_satellite_access", check)
    result, _context = await send(env)
    assert result == DENIED and env.calls == []
    assert len(checks) == 2


async def test_disconnect_cancels_and_awaits_native_child(env):
    """A disconnected pipeline cannot leave the native service task detached."""
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def slow(_call):
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    env.hass.services.async_register("light", "turn_on", slow)
    task = asyncio.create_task(send(env))
    await started.wait()
    await env.binding.async_close()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set() and not env.dispatcher._scopes


@pytest.mark.parametrize("failure", ["missing", "version", "exception"])
async def test_policy_unavailable_never_falls_back(env, monkeypatch, failure):
    """Provider failure cannot route to ordinary Assist, guest or raw services."""
    if failure == "missing":
        env.hass.data.pop(DATA_RBAC)
    elif failure == "version":
        monkeypatch.setattr(assist_policy, "SATELLITE_API_VERSION", True)
    else:

        async def broken(*args, **kwargs):
            raise RuntimeError("PRIVATE FAILURE")

        monkeypatch.setattr(assist_policy, "async_project_satellite_context", broken)
    result, _context = await send(env)
    assert result["status"] in {"denied", "unconfirmed"}
    assert env.calls == [] and "PRIVATE" not in str(result)


async def test_expired_admission_is_denied(env, monkeypatch):
    """Expired source authority is never renewed implicitly by execution."""
    monkeypatch.setattr(satellite_admission, "ADMISSION_TTL", -1)
    result, _context = await send(env)
    assert result == DENIED and env.calls == []


async def test_failure_is_unconfirmed_and_not_retried(env):
    """An admitted device error does not trigger another control route."""
    attempts = []

    async def broken(call):
        attempts.append(call)
        raise RuntimeError("PRIVATE DEVICE ERROR")

    env.hass.services.async_register("light", "turn_on", broken)
    result, _context = await send(env)
    assert result == {"status": "unconfirmed", "completed": 0}
    assert len(attempts) == 1 and "PRIVATE" not in str(result)


async def test_unbound_recognized_v1_packet_is_not_a_guest(env):
    """A legacy profile without an enrolled account cannot borrow the guest role."""
    lease = env.binding.admit(Context())
    wire = env.packets.encode(
        env.state.key, "Turn on the lamp", voice="profile", revision="a" * 32
    )
    text = env.runtime.handoffs.issue(env.state.key, wire)
    result = await env.ingress.async_dispatch(lease, transcript=text, command=command())
    assert result == DENIED and env.calls == []


async def test_invalid_pairing_result_is_not_guest_authority(env):
    """A bad packet remains denied instead of becoming an unmatched voice."""
    lease = env.binding.admit(Context())
    text, _wire = transcript(env, None)
    env.state.key = Fernet.generate_key().decode()
    result = await env.ingress.async_dispatch(lease, transcript=text, command=command())
    assert result == DENIED and env.calls == []


async def test_mixed_batch_does_not_execute_only_the_allowed_part(env):
    """The entire proposed target set must pass before any device is called."""
    result, _context = await send(env, payload=command(IDS[0], IDS[2]))
    assert result == DENIED and env.calls == []


async def test_role_revocation_between_targets_reports_partial(env):
    """Stop remaining targets without claiming an already admitted action was undone."""

    async def record(call):
        env.calls.append(call.data)
        env.store.bindings.clear()
        env.evaluator.invalidate()

    env.hass.services.async_register("light", "turn_on", record)
    result, _context = await send(env, payload=command(*IDS[:2]))
    assert result == {"status": "partial", "completed": 1}
    assert env.calls == [{"entity_id": IDS[0]}]


async def test_concurrent_guest_and_child_turns_do_not_share_authority(env):
    """Parallel pipeline tasks keep their own Context, admission and policy subject."""
    child_context, guest_context = Context(), Context()
    child, guest = await asyncio.gather(
        send(env, payload=command(IDS[1]), context=child_context),
        send(env, speaker=None, payload=command(IDS[1]), context=guest_context),
    )
    assert child[0] == {"status": "completed", "completed": 1}
    assert guest[0] == DENIED
    assert env.calls == [("light", "turn_on", {"entity_id": IDS[1]}, child_context)]


async def test_broadened_native_service_arguments_are_refused(env, monkeypatch):
    """The satellite guard keeps the exact service/data admission of its parent."""
    execution = pytest.importorskip("custom_components.codex_assist.rbac_execution")

    async def broaden(_handler, domain, service, intent_obj, _state):
        await intent_obj.hass.services.async_call(
            domain,
            service,
            {"entity_id": list(IDS)},
            context=intent_obj.context,
            blocking=True,
        )

    monkeypatch.setattr(execution._AwaitedHandler, "async_call_service", broaden)
    result, _context = await send(env)
    assert result == DENIED and env.calls == []


async def test_closed_registry_cannot_register_or_issue_new_authority(env):
    """Closing the entry is terminal; reopening requires a fresh registration."""
    await env.ingress.async_close()
    assert env.binding.admit(Context()) is None
    with pytest.raises(ValueError):
        env.ingress.register_transport(
            env.satellite.entity_id, object(), connection_is_current=lambda _: True
        )


async def test_capacity_does_not_evict_live_replay_protection(env, monkeypatch):
    """A full registry refuses another audio task instead of evicting its lease."""
    monkeypatch.setattr(satellite_admission, "MAX_ADMISSIONS", 1)
    ready, release = asyncio.Event(), asyncio.Event()

    async def holding():
        lease = env.binding.admit(Context())
        ready.set()
        await release.wait()
        text, _wire = transcript(env)
        return await env.ingress.async_dispatch(
            lease, transcript=text, command=command()
        )

    task = asyncio.create_task(holding())
    await ready.wait()
    try:
        assert env.binding.admit(Context()) is None
    finally:
        release.set()
    assert (await task)["completed"] == 1
