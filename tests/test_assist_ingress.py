"""Synthetic in-process ingress integration; no network routes/device commands."""

import asyncio
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from homeassistant.auth.permissions.const import POLICY_CONTROL, POLICY_READ
from homeassistant.auth.permissions.models import PermissionLookup
from homeassistant.components.homeassistant.exposed_entities import async_expose_entity
from homeassistant.core import Context
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component

from custom_components.ha_rbac import assist_ingress, assist_policy
from custom_components.ha_rbac.assist_ingress import ProtectedAssistIngress
from custom_components.ha_rbac.const import DATA_RBAC, TIER_USER
from custom_components.ha_rbac.policy import Permissions, compile_role


@pytest.fixture
async def env(hass, monkeypatch):
    """Connect real paired preparation, compiled policies and native local services."""
    consumer = pytest.importorskip("custom_components.codex_assist.rbac_dispatch")
    voices = pytest.importorskip("custom_components.codex_assist.voice_match")
    packets = pytest.importorskip("custom_components.codex_assist.speaker_packet")
    assert await async_setup_component(hass, "homeassistant", {})
    ids = ("light.allowed", "light.speaker_only", "light.denied", "light.read_only")
    for eid in ids:
        er.async_get(hass).async_get_or_create("light", "test", eid, suggested_object_id=eid[6:])
        hass.states.async_set(eid, "off", {"friendly_name": f"PRIVATE {eid}"})
        async_expose_entity(hass, "conversation", eid, True)

    def permissions(subject):
        grants = {"light.allowed": {POLICY_READ: True, POLICY_CONTROL: True},
                  "light.read_only": {POLICY_READ: True}}
        if subject.startswith("child"):
            grants["light.speaker_only"] = {POLICY_READ: True, POLICY_CONTROL: True}
        role = compile_role(
            hass, {"id": subject, "name": subject,
                   "allow": {"entities": {"entity_ids": grants}}, "deny": {}},
            PermissionLookup(er.async_get(hass), dr.async_get(hass)),
        )
        return Permissions(roles=[role])

    subjects = ("child", "child2", "kiosk", "kiosk2")
    users = {uid: SimpleNamespace(
        id=uid, is_active=True, is_owner=False, system_generated=False,
        permissions=SimpleNamespace(check_entity=lambda *args: True),
    ) for uid in subjects}
    roles = {uid: permissions(uid) for uid in subjects}
    bindings = {uid: [uid] for uid in subjects}

    async def get_user(uid):
        await asyncio.sleep(0)  # Exercise account-resolution scheduling boundaries.
        return users.get(uid)

    monkeypatch.setattr(hass.auth, "async_get_user", get_user)
    hass.data[DATA_RBAC] = SimpleNamespace(
        store=SimpleNamespace(bindings=bindings),
        evaluator=SimpleNamespace(async_permissions=lambda user: roles[user.id]),
    )
    runtime = voices.SpeakerRuntime()
    state = SimpleNamespace(key=Fernet.generate_key().decode())
    kiosks = frozenset({"kiosk", "kiosk2"})
    provider = consumer.ProtectedDispatcher(
        hass, runtime, key_provider=lambda: state.key, kiosk_user_ids=kiosks,
        candidate_entity_ids=ids,
    )
    ingress, source = ProtectedAssistIngress(hass), object()
    unregister = ingress.register("prototype", provider, kiosk_user_ids=kiosks,
                                  source_bindings=(source,))
    calls = []

    async def record(call):
        calls.append((dict(call.data), call.context))

    for operation in ("turn_on", "turn_off"):
        hass.services.async_register("light", operation, record)
    yield SimpleNamespace(hass=hass, ingress=ingress, provider=provider, source=source,
                          unregister=unregister, calls=calls, runtime=runtime, state=state,
                          packets=packets, users=users, roles=roles, bindings=bindings)
    ingress.close()
    runtime.handoffs.clear()


def command(*ids, operation="turn_on"):
    """Build an untrusted structured command, not identity evidence."""
    return {"operation": operation, "entity_ids": list(ids or ("light.allowed",))}


def carrier(env, *, speaker="child", text="Turn on the permitted lamp"):
    """Stand in for trusted STT on the actual owning pipeline task."""
    wire = env.packets.encode(
        env.state.key, text, voice="profile" if speaker else None,
        revision="c" * 32 if speaker else None, ha_user_id=speaker,
    )
    return env.runtime.handoffs.issue(env.state.key, wire), wire


async def send(env, *, payload=None, speaker="child", kiosk="kiosk"):
    """Simulate an already-authenticated server connection, not a network login."""
    context = Context(user_id=kiosk)
    admission = env.ingress.admit("prototype", context=context, source_binding=env.source)
    text, _ = carrier(env, speaker=speaker)
    result = await env.ingress.async_dispatch(
        admission, transcript=text, command=payload if payload is not None else command(),
    )
    return result, context


async def test_registered_chain_verifies_handoff_and_executes_exactly_once(env):
    """Exercise admission through real native execution with no user substitution."""
    result, context = await send(env)
    assert result == {"status": "completed", "completed": 1}
    assert env.calls == [({"entity_id": "light.allowed"}, context)]
    assert context.user_id == "kiosk"  # Speaker account is not impersonated.
    assert set(result) == {"status", "completed"} and "PRIVATE" not in str(result)
    assert not env.provider._scopes and not env.ingress._active


@pytest.mark.parametrize("ids", [
    ("light.denied",), ("light.allowed", "light.denied"), ("light.speaker_only",),
    ("light.read_only",), ("script.indirect",), ("light.allowed", "light.allowed"),
])
async def test_both_context_and_control_ceilings_deny_entire_forbidden_batch(env, ids):
    """Neither context readability nor speaker rights alone authorize a command."""
    result, _ = await send(env, payload=command(*ids))
    assert result == {"status": "denied", "completed": 0}
    assert env.calls == []


@pytest.mark.parametrize("extra", ["user_id", "ha_user_id", "prepared_request", "history", "device_id"])
async def test_payload_cannot_select_identity_provenance_or_history(env, extra):
    """Reject extra authority fields rather than silently using or ignoring them."""
    result, _ = await send(env, payload={**command(), extra: "owner"})
    assert result["status"] == "denied" and env.calls == []


@pytest.mark.parametrize("kind", ["raw_packet", "serialized", "prepared", "unknown", "unbound"])
async def test_no_client_serialization_or_identity_object_is_a_voice_handoff(env, kind):
    """Require the exact private handoff, verified owner and a recognized speaker."""
    context = Context(user_id="kiosk")
    admission = env.ingress.admit("prototype", context=context, source_binding=env.source)
    text, wire = carrier(env, speaker=None if kind == "unknown" else "child")
    if kind == "raw_packet":
        text = wire
    elif kind == "serialized":
        text = str(text)
    elif kind == "prepared":
        text = SimpleNamespace(verified=True, ha_user_id="child", voice="profile")
    elif kind == "unbound":
        wire = env.packets.encode(env.state.key, "Request", voice="profile", revision="d" * 32)
        text = env.runtime.handoffs.issue(env.state.key, wire)
    result = await env.ingress.async_dispatch(admission, transcript=text, command=command())
    assert result["status"] == "denied" and env.calls == []


async def test_source_caller_destination_and_forged_admission_cannot_select_provider(env):
    """Only registered server-held capabilities can enter protected dispatch."""
    for destination, context, source in (
        ("missing", Context(user_id="kiosk"), env.source),
        ("prototype", Context(user_id="owner"), env.source),
        ("prototype", Context(), env.source),
        ("prototype", Context(user_id="kiosk"), object()),
        ("prototype", Context(user_id="kiosk"), "client-device-id"),
    ):
        assert env.ingress.admit(destination, context=context, source_binding=source) is None
    forged = SimpleNamespace(context=Context(user_id="kiosk"), owner=asyncio.current_task())
    assert (await env.ingress.async_dispatch(forged, transcript="x", command=command()))["status"] == "denied"
    assert (await env.provider.async_dispatch(forged, transcript="x", command=command()))["status"] == "denied"
    assert env.calls == []


async def test_admission_and_nonce_replay_never_execute_twice(env):
    """Consume admission, transcript object and packet nonce independently."""
    context = Context(user_id="kiosk")
    admission = env.ingress.admit("prototype", context=context, source_binding=env.source)
    text, wire = carrier(env)
    assert (await env.ingress.async_dispatch(admission, transcript=text,
                                             command=command()))["completed"] == 1
    assert (await env.ingress.async_dispatch(admission, transcript=text,
                                             command=command()))["status"] == "denied"
    for replay in (text, env.runtime.handoffs.issue(env.state.key, wire)):
        fresh = env.ingress.admit("prototype", context=context, source_binding=env.source)
        assert (await env.ingress.async_dispatch(fresh, transcript=replay,
                                                 command=command()))["status"] == "denied"
    assert len(env.calls) == 1


async def test_handoff_must_belong_to_the_original_pipeline_task(env):
    """Matching text/key does not let a different pipeline borrow STT evidence."""
    issued, release = asyncio.Event(), asyncio.Event()
    holder = []

    async def other_stt_task():
        holder.append(carrier(env)[0])
        issued.set()
        await release.wait()

    task = asyncio.create_task(other_stt_task())
    await issued.wait()
    try:
        admission = env.ingress.admit("prototype", context=Context(user_id="kiosk"),
                                     source_binding=env.source)
        result = await env.ingress.async_dispatch(admission, transcript=holder[0], command=command())
        assert result["status"] == "denied" and env.calls == []
    finally:
        release.set()
        await task


async def test_admission_cannot_move_to_another_pipeline_task(env):
    """A live admission is still invalid on a different task."""
    admission = env.ingress.admit("prototype", context=Context(user_id="kiosk"),
                                 source_binding=env.source)
    text, _ = carrier(env)
    result = await asyncio.create_task(env.ingress.async_dispatch(
        admission, transcript=text, command=command(),
    ))
    assert result["status"] == "denied" and env.calls == []


@pytest.mark.parametrize("change", ["speaker", "kiosk", "native", "exposure", "key", "unregister"])
async def test_revocation_after_context_before_execution_has_no_fallback(env, monkeypatch, change):
    """Revoke after successful projection rather than merely testing initial denial."""
    original = assist_policy.async_project_context

    async def project(*args, **kwargs):
        result = await original(*args, **kwargs)
        if change in {"speaker", "kiosk"}:
            env.bindings.pop("child" if change == "speaker" else "kiosk")
        elif change == "native":
            env.users["kiosk"].permissions.check_entity = lambda *args: False
        elif change == "exposure":
            async_expose_entity(env.hass, "conversation", "light.allowed", False)
        elif change == "key":
            env.state.key = Fernet.generate_key().decode()
        else:
            env.unregister()
        return result

    monkeypatch.setattr(assist_policy, "async_project_context", project)
    result, _ = await send(env)
    assert result["status"] == "denied" and env.calls == []


async def test_revoke_after_guard_preflight_is_rechecked_inside_native_task(env, monkeypatch):
    """Carry the ingress binding through to the last native execution check."""
    original = assist_policy.async_check_access

    async def check(*args, **kwargs):
        result = await original(*args, **kwargs)
        env.bindings.pop("child", None)
        return result

    monkeypatch.setattr(assist_policy, "async_check_access", check)
    result, _ = await send(env)
    assert result["status"] == "denied" and env.calls == []


async def test_mutable_command_is_frozen_before_policy_awaits(env, monkeypatch):
    """Do not retarget an already selected proposal through a mutable JSON body."""
    payload = command()
    original = assist_policy.async_project_context

    async def project(*args, **kwargs):
        payload["entity_ids"][:] = ["light.denied"]
        payload["operation"] = "turn_off"
        return await original(*args, **kwargs)

    monkeypatch.setattr(assist_policy, "async_project_context", project)
    result, _ = await send(env, payload=payload)
    assert result["status"] == "completed"
    assert env.calls[0][0] == {"entity_id": "light.allowed"}


async def test_concurrent_kiosks_and_speakers_have_independent_scopes(env, monkeypatch):
    """Exercise concurrent users through the same registry, runtime and dispatcher."""
    seen = []
    original = assist_policy.async_check_access

    async def check(hass, subject, ids, **kwargs):
        seen.append((subject, kwargs["ceiling_user_id"]))
        return await original(hass, subject, ids, **kwargs)

    monkeypatch.setattr(assist_policy, "async_check_access", check)
    first, second = await asyncio.gather(send(env), send(env, kiosk="kiosk2", speaker="child2"))
    assert first[0]["completed"] == second[0]["completed"] == 1
    assert set(seen) == {("child", "kiosk"), ("child2", "kiosk2")}
    assert {context.user_id for _, context in env.calls} == {"kiosk", "kiosk2"}
    assert not env.provider._scopes and not env.ingress._active


async def test_unregister_cancels_inflight_pipeline_without_detaching_native_work(env, monkeypatch):
    """Teardown invalidates the registration and awaits parent cancellation."""
    started = asyncio.Event()

    async def slow(*args, **kwargs):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(assist_policy, "async_project_context", slow)
    task = asyncio.create_task(send(env))
    await started.wait()
    env.unregister()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert env.calls == [] and not env.ingress._active and not env.provider._scopes
    assert env.ingress.admit("prototype", context=Context(user_id="kiosk"),
                             source_binding=env.source) is None


@pytest.mark.parametrize("change", ["missing_policy", "inactive", "owner", "lost_binding"])
async def test_no_default_account_or_unavailable_policy_fallback(env, change):
    """Missing restricted authority never becomes an ordinary Assist request."""
    if change == "missing_policy":
        env.hass.data.pop(DATA_RBAC)
    elif change == "inactive":
        env.users["child"].is_active = False
    elif change == "owner":
        env.users["child"].is_owner = True
    else:
        env.bindings.clear()
    result, _ = await send(env)
    assert result["status"] == "denied" and env.calls == []


async def test_expiry_and_capacity_fail_closed(env, monkeypatch):
    """Bound pending admissions without evicting a still-live request."""
    monkeypatch.setattr(assist_ingress, "MAX_ADMISSIONS", 1)
    context = Context(user_id="kiosk")
    first = env.ingress.admit("prototype", context=context, source_binding=env.source)
    assert env.ingress.admit("prototype", context=context, source_binding=env.source) is None
    text, _ = carrier(env)
    assert (await env.ingress.async_dispatch(first, transcript=text, command=command()))["completed"] == 1
    monkeypatch.setattr(assist_ingress, "ADMISSION_TTL", -1)
    expired = env.ingress.admit("prototype", context=context, source_binding=env.source)
    text, _ = carrier(env)
    assert (await env.ingress.async_dispatch(expired, transcript=text, command=command()))["status"] == "denied"
    assert len(env.calls) == 1


@pytest.mark.parametrize("version", [True, 0, 2, None])
async def test_registration_rejects_incompatible_providers_without_installing_destination(hass, version):
    """Require the exact protocol version, not a truthy compatibility claim."""
    ingress = ProtectedAssistIngress(hass)
    provider = SimpleNamespace(hass=hass, INGRESS_API_VERSION=version)
    with pytest.raises(ValueError):
        ingress.register("prototype", provider, kiosk_user_ids=frozenset({"kiosk"}),
                         source_bindings=(object(),))
    assert ingress._providers == {}


async def test_registration_cannot_replace_live_provider_or_rebind_it(env):
    """Registration is explicit and cannot silently replace a provider binding."""
    with pytest.raises(ValueError):
        env.ingress.register("prototype", env.provider, kiosk_user_ids=frozenset({"kiosk"}),
                             source_bindings=(env.source,))
    with pytest.raises(ValueError):
        env.ingress.register("other", env.provider, kiosk_user_ids=frozenset({"kiosk"}),
                             source_bindings=(env.source,))
    assert (await send(env))[0]["completed"] == 1


async def test_concurrent_packet_replay_is_consumed_before_context_await(env):
    """Two real pipeline tasks cannot spend one paired packet nonce twice."""
    wire = env.packets.encode(env.state.key, "Request", voice="profile", revision="e" * 32,
                              ha_user_id="child")

    async def replay():
        context = Context(user_id="kiosk")
        admission = env.ingress.admit("prototype", context=context, source_binding=env.source)
        text = env.runtime.handoffs.issue(env.state.key, wire)
        return await env.ingress.async_dispatch(admission, transcript=text, command=command())

    results = await asyncio.gather(replay(), replay())
    assert sorted(result["status"] for result in results) == ["completed", "denied"]
    assert len(env.calls) == 1


@pytest.mark.parametrize("payload", [
    {}, {"operation": "toggle", "entity_ids": ["light.allowed"]},
    {"operation": "turn_on", "entity_ids": "light.allowed"},
    {"operation": "turn_on", "entity_ids": []},
    {"operation": "turn_on", "entity_ids": ["light.allowed"], "delay": 1},
])
async def test_structured_schema_has_no_free_text_or_delayed_action_escape(env, payload):
    """Reject unsupported shapes rather than handing them to ordinary Assist."""
    result, _ = await send(env, payload=payload)
    assert result["status"] == "denied" and env.calls == []


async def test_pairing_rotation_during_native_policy_check_invalidates_the_ingress_scope(
    env, monkeypatch,
):
    """A valid initial context does not survive a key revision during execution."""
    original = assist_policy.async_check_access

    async def check(*args, **kwargs):
        result = await original(*args, **kwargs)
        env.state.key = Fernet.generate_key().decode()
        return result

    monkeypatch.setattr(assist_policy, "async_check_access", check)
    result, _ = await send(env)
    assert result["status"] == "denied" and env.calls == []


async def test_caller_switch_during_context_await_cannot_borrow_new_account(env, monkeypatch):
    """Check the original authenticated identity after scheduling boundaries."""
    context = Context(user_id="kiosk")
    original = assist_policy.async_project_context

    async def project(*args, **kwargs):
        result = await original(*args, **kwargs)
        context.user_id = "kiosk2"
        return result

    monkeypatch.setattr(assist_policy, "async_project_context", project)
    admission = env.ingress.admit("prototype", context=context, source_binding=env.source)
    text, _ = carrier(env)
    result = await env.ingress.async_dispatch(admission, transcript=text, command=command())
    assert result["status"] == "denied" and env.calls == []


async def test_closed_registry_cannot_be_reopened_by_registration(env):
    """Teardown is terminal for an old registry instance."""
    env.ingress.close()
    with pytest.raises(ValueError):
        env.ingress.register("new", env.provider, kiosk_user_ids=frozenset({"kiosk"}),
                             source_bindings=(env.source,))
    assert env.ingress._providers == {}


async def test_active_prototype_registration_does_not_open_ordinary_assist_routes(env):
    """Registration coordinates only this chain, never a baseline-denial exception."""
    for route in ("conversation/process", "conversation.process", "assist_pipeline/run",
                  "assist_satellite/intercept_wake_word", "assist_satellite.announce"):
        assert env.roles["kiosk"].tier_allowed(route, TIER_USER) is False
    assert (await send(env))[0]["completed"] == 1
