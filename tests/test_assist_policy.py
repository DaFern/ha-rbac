"""The in-process oracle never opens Assist or executes an action."""

from types import SimpleNamespace

import pytest
from homeassistant.auth.permissions.const import POLICY_CONTROL, POLICY_READ
from homeassistant.auth.permissions.models import PermissionLookup
from homeassistant.components.homeassistant.exposed_entities import async_expose_entity
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component

from custom_components.ha_rbac.assist_policy import (
    async_check_access,
    async_project_context,
)
from custom_components.ha_rbac.const import DATA_RBAC
from custom_components.ha_rbac.policy import Permissions, compile_role


@pytest.fixture
def policy(hass, monkeypatch):
    """Use the actual RBAC compiler, not a hand-written allow/deny substitute."""
    role = compile_role(
        hass,
        {"id": "child", "name": "Child", "allow": {"entities": {"entity_ids": {
            "light.allowed": {POLICY_READ: True, POLICY_CONTROL: True},
            "light.read_only": {POLICY_READ: True},
            "script.indirect": {POLICY_READ: True, POLICY_CONTROL: True},
        }}}, "deny": {}},
        PermissionLookup(er.async_get(hass), dr.async_get(hass)),
    )
    permissions = Permissions(roles=[role])
    user = SimpleNamespace(id="child", is_active=True, system_generated=False, is_owner=False,
                           permissions=SimpleNamespace(check_entity=lambda *args: True))
    users = {"child": user}

    async def get_user(user_id):
        return users.get(user_id)

    monkeypatch.setattr(hass.auth, "async_get_user", get_user)
    store = SimpleNamespace(bindings={"child": ["child"]})
    evaluator = SimpleNamespace(async_permissions=lambda _user: permissions)
    hass.data[DATA_RBAC] = SimpleNamespace(store=store, evaluator=evaluator)
    for eid in ("light.allowed", "light.read_only", "script.indirect"):
        hass.states.async_set(eid, "off", {})
    return SimpleNamespace(user=user, users=users, store=store, permissions=permissions,
                           evaluator=evaluator)


@pytest.mark.parametrize("operation", ["read", "turn_on", "turn_off"])
async def test_allowed_light_and_hidden_light(hass, policy, operation):
    """Both direct entity reads and direct on/off controls obey compiled roles."""
    assert (await async_check_access(hass, "child", ("light.allowed",),
                                    operation=operation)).allowed
    assert not (await async_check_access(hass, "child", ("light.denied",),
                                        operation=operation)).allowed


async def test_read_only_mixed_and_indirect_targets(hass, policy):
    """No partial allow, read-to-control escalation or script forwarding."""
    assert (await async_check_access(hass, "child", ("light.read_only",))).allowed
    for targets in (("light.read_only",), ("light.allowed", "light.denied"),
                    ("script.indirect",)):
        assert not (await async_check_access(hass, "child", targets,
                                            operation="turn_on")).allowed
    hass.states.async_set("light.allowed", "off", {"entity_id": ["light.denied"]})
    assert not (await async_check_access(hass, "child", ("light.allowed",),
                                        operation="turn_on")).allowed


@pytest.mark.parametrize("field", ["is_active", "system_generated", "is_owner"])
async def test_inactive_system_or_owner_accounts_are_not_restricted_authority(hass, policy, field):
    """Owner/system pass-through cannot be borrowed by a voice adapter."""
    setattr(policy.user, field, field != "is_active")
    assert not (await async_check_access(hass, "child", ("light.allowed",))).allowed


async def test_no_binding_no_provider_and_revocation_fail_closed(hass, policy):
    """Native HA fallback groups are not a substitute for explicit RBAC assignment."""
    policy.store.bindings.clear()
    assert not (await async_check_access(hass, "child", ("light.allowed",))).allowed
    policy.store.bindings["child"] = ["child"]
    assert (await async_check_access(hass, "child", ("light.allowed",))).allowed
    policy.user.permissions.check_entity = lambda *args: False
    assert not (await async_check_access(hass, "child", ("light.allowed",))).allowed
    hass.data.pop(DATA_RBAC)
    assert not (await async_check_access(hass, "child", ("light.allowed",))).allowed


async def test_attribute_filter_and_ceiling_intersection(hass, policy):
    """Neither extra read attributes nor a missing ceiling grants extra access."""
    assert not (await async_check_access(hass, "child", ("light.allowed",),
                                        ceiling_user_id="missing")).allowed
    policy.users["ceiling"] = SimpleNamespace(
        id="ceiling", is_active=True, system_generated=False, is_owner=False,
        permissions=SimpleNamespace(check_entity=lambda *args: True),
    )
    policy.store.bindings["ceiling"] = ["ceiling"]
    deny = Permissions()
    policy.evaluator.async_permissions = lambda user: (
        deny if user.id == "ceiling" else policy.permissions
    )
    assert not (await async_check_access(hass, "child", ("light.allowed",),
                                        ceiling_user_id="ceiling")).allowed
    policy.evaluator.async_permissions = lambda user: SimpleNamespace(
        full_access=False, check_entity=lambda *args: True,
        attribute_hidden=lambda eid, name: name == "private_detail",
    )
    assert not (await async_check_access(hass, "child", ("light.allowed",),
                                        attributes=("private_detail",))).allowed


@pytest.mark.parametrize(("targets", "operation"), [
    ((), "read"), (("light.allowed",) * 33, "read"), (("not an entity",), "read"),
    (("light.allowed",), "arbitrary_service"), (["light.allowed"], "read"),
])
async def test_invalid_or_unbounded_requests_are_denied(hass, policy, targets, operation):
    """No free text, area expansion or service names cross this interface."""
    assert not (await async_check_access(hass, "child", targets, operation=operation)).allowed


async def _context_fixture(hass, policy):
    """Expose synthetic entities with different speaker/device permissions."""
    assert await async_setup_component(hass, "homeassistant", {})

    for eid, name in (("light.allowed", "Allowed lamp"),
                      ("light.read_only", "Speaker only secret"),
                      ("light.denied", "Forbidden secret")):
        hass.states.async_set(eid, "on", {"friendly_name": name, "brightness": 128,
                                         "password": "NEVER_EXPORT", "entity_id": ["lock.secret"]})
        async_expose_entity(hass, "conversation", eid, True)
    policy.users["kiosk"] = SimpleNamespace(
        id="kiosk", is_active=True, system_generated=False, is_owner=False,
        permissions=SimpleNamespace(check_entity=lambda *args: True),
    )
    policy.store.bindings["kiosk"] = ["kiosk"]
    base = policy.permissions
    kiosk_role = compile_role(
        hass, {"id": "kiosk", "name": "Kiosk", "allow": {"entities": {"entity_ids": {
            "light.allowed": {POLICY_READ: True},
        }}}, "deny": {}}, PermissionLookup(er.async_get(hass), dr.async_get(hass)),
    )
    ceiling = Permissions(roles=[kiosk_role])
    policy.evaluator.async_permissions = lambda user: SimpleNamespace(
        full_access=False,
        check_entity=ceiling.check_entity if user.id == "kiosk"
        else base.check_entity,
        attribute_hidden=lambda eid, key: False,
    )


async def test_context_intersects_speaker_kiosk_exposure_and_projects_no_private_metadata(hass, policy):
    """Read-only entities need no control right, but both actors must allow reads."""
    await _context_fixture(hass, policy)
    result = await async_project_context(
        hass, "child", ("light.allowed", "light.read_only", "light.denied"),
        attributes=("brightness", "password", "entity_id"), ceiling_user_id="kiosk",
    )
    assert result == {"available": True, "entities": [{
        "entity_id": "light.allowed", "state": "on", "name": "Allowed lamp",
        "attributes": {"brightness": 128},
    }]}
    async_expose_entity(hass, "conversation", "light.allowed", False)
    assert (await async_project_context(
        hass, "child", ("light.allowed",), ceiling_user_id="kiosk",
    )) == {"available": True, "entities": []}


async def test_context_honors_fields_hidden_by_either_actor_and_does_not_derive_name(hass, policy):
    """A hidden friendly name has no fallback through State.name or aliases."""
    await _context_fixture(hass, policy)
    previous = policy.evaluator.async_permissions

    def permission(user):
        result = previous(user)
        result.attribute_hidden = lambda eid, key: key == (
            "friendly_name" if user.id == "kiosk" else "brightness"
        )
        return result

    policy.evaluator.async_permissions = permission
    result = await async_project_context(
        hass, "child", ("light.allowed",), attributes=("brightness",), ceiling_user_id="kiosk",
    )
    assert result == {"available": True, "entities": [{
        "entity_id": "light.allowed", "state": "on", "attributes": {},
    }]}


@pytest.mark.parametrize("key", ["state", "entity_id"])
async def test_context_omits_whole_entity_when_identity_or_state_is_hidden(hass, policy, key):
    """No sideways reconstruction through a name or other attribute."""
    await _context_fixture(hass, policy)
    policy.evaluator.async_permissions = lambda user: SimpleNamespace(
        full_access=False, check_entity=lambda *args: True,
        attribute_hidden=lambda eid, name: name == key,
    )
    result = await async_project_context(hass, "child", ("light.allowed",),
                                         ceiling_user_id="kiosk")
    assert result == {"available": True, "entities": []}


async def test_context_policy_revocation_missing_account_and_provider_failure_discard_data(hass, policy):
    """No previous snapshot or partial rows survive an unavailable policy."""
    await _context_fixture(hass, policy)
    assert (await async_project_context(hass, "child", ("light.allowed",),
                                        ceiling_user_id="kiosk"))["entities"]
    policy.store.bindings.pop("kiosk")
    assert await async_project_context(hass, "child", ("light.allowed",),
                                       ceiling_user_id="kiosk") == {
        "available": False, "entities": [],
    }
    policy.store.bindings["kiosk"] = ["kiosk"]

    def broken(user):
        raise RuntimeError("PRIVATE_ERROR")

    policy.evaluator.async_permissions = broken
    assert await async_project_context(hass, "child", ("light.allowed",)) == {
        "available": False, "entities": [],
    }


@pytest.mark.parametrize("value", [{"secret": "x"}, ["lock.secret"], "PRIVATE_STRING", float("nan")])
async def test_context_rejects_nested_or_wrong_type_attributes(hass, policy, value):
    """Curated field names do not authorize arbitrary payloads under those names."""
    await _context_fixture(hass, policy)
    hass.states.async_set("light.allowed", "on", {"brightness": value})
    result = await async_project_context(hass, "child", ("light.allowed",),
                                         attributes=("brightness",), ceiling_user_id="kiosk")
    assert result["available"] and result["entities"][0]["attributes"] == {}


@pytest.mark.parametrize("revoke", [False, True])
async def test_real_codex_consumer_and_rbac_projection_contract(hass, policy, revoke):
    """Optional cross-checkout test: real paired preparation and both policy compilers.

    Supply the Codex source checkout on PYTHONPATH to run this contract. It does
    not claim the tablet ingress, model delivery or action execution is connected.
    """
    consumer = pytest.importorskip("custom_components.codex_assist.rbac_context")
    packet_module = pytest.importorskip("custom_components.codex_assist.speaker_packet")
    voice_module = pytest.importorskip("custom_components.codex_assist.voice_match")
    from cryptography.fernet import Fernet  # noqa: PLC0415
    from homeassistant.core import Context  # noqa: PLC0415

    await _context_fixture(hass, policy)
    key = Fernet.generate_key().decode()
    wire = packet_module.encode(key, "Which lights can I use?", voice="child-profile",
                                revision="a" * 32, ha_user_id="child")
    prepared = voice_module.SpeakerRuntime().prepare_request(
        key, wire, [SimpleNamespace(role="user", content=wire)], "chat", "agent",
    )
    context = Context(user_id="kiosk")
    kwargs = {"approved_kiosk_user_ids": frozenset({"kiosk"}), "attributes": ("brightness",)}
    snapshot = await consumer.async_build_shared_context(
        hass, context, prepared, ("light.allowed", "light.read_only", "light.denied"), **kwargs,
    )
    assert snapshot.available
    assert "Allowed lamp" in snapshot.text
    assert "Forbidden secret" not in snapshot.text
    assert "Speaker only secret" not in snapshot.text
    assert "NEVER_EXPORT" not in snapshot.text and "lock.secret" not in snapshot.text
    assert context.user_id == "kiosk"
    payload = consumer.protected_model_payload(
        snapshot, context=context, prepared_request=prepared,
        user_text="Which lights can I use?", personality="Be concise.",
    )
    assert payload["tools"] == []
    assert "Allowed lamp" in str(payload)
    assert "Forbidden secret" not in str(payload) and "Speaker only secret" not in str(payload)
    if revoke:
        policy.store.bindings.pop("child")
        denied = await consumer.async_build_shared_context(
            hass, context, prepared, ("light.allowed",), **kwargs,
        )
        assert not denied.available and denied.text == ""


@pytest.mark.parametrize("revocation", [
    None, "speaker", "kiosk", "native", "inactive", "hidden", "mixed", "exposure",
])
async def test_real_codex_native_execution_rechecks_both_compiled_policies(
    hass, policy, monkeypatch, revocation,
):
    """Cross-checkout native service admission, not deployed tablet acceptance."""
    consumer = pytest.importorskip("custom_components.codex_assist.rbac_execution")
    packets = pytest.importorskip("custom_components.codex_assist.speaker_packet")
    voices = pytest.importorskip("custom_components.codex_assist.voice_match")
    from cryptography.fernet import Fernet  # noqa: PLC0415
    from homeassistant.core import Context  # noqa: PLC0415

    hass.states.async_remove("light.allowed")
    hass.states.async_remove("light.denied")
    er.async_get(hass).async_get_or_create("light", "test", "allowed",
                                         suggested_object_id="allowed")
    er.async_get(hass).async_get_or_create("light", "test", "denied",
                                         suggested_object_id="denied")
    await _context_fixture(hass, policy)
    # The context fixture deliberately includes reference metadata; a direct
    # controllable fixture must not masquerade as a member-expanding entity.
    hass.states.async_set("light.allowed", "off", {"friendly_name": "Allowed lamp"})
    ceiling_role = compile_role(
        hass, {"id": "kiosk", "name": "Kiosk", "allow": {"entities": {"entity_ids": {
            "light.allowed": {POLICY_READ: True, POLICY_CONTROL: True},
        }}}, "deny": {}}, PermissionLookup(er.async_get(hass), dr.async_get(hass)),
    )
    ceiling = Permissions(roles=[ceiling_role])
    policy.evaluator.async_permissions = lambda user: (
        ceiling if user.id == "kiosk" else policy.permissions
    )
    key = Fernet.generate_key().decode()
    wire = packets.encode(key, "Turn on the permitted lamp", voice="profile",
                          revision="b" * 32, ha_user_id="child")
    prepared = voices.SpeakerRuntime().prepare_request(
        key, wire, [SimpleNamespace(role="user", content=wire)], "chat", "agent",
    )
    context = Context(user_id="kiosk")
    guard = consumer.SharedExecutionGuard(hass, approved_kiosk_user_ids=frozenset({"kiosk"}))
    targets = ("light.allowed", "light.denied") if revocation == "mixed" else ("light.allowed",)
    command = guard.prepare(context, prepared, targets, operation="turn_on")
    assert command is not None
    calls = []

    async def record(call):
        calls.append(call)

    hass.services.async_register("light", "turn_on", record)
    # Revoke AFTER successful preflight, so only the execution-task recheck can
    # prevent this command. Exercise the real provider, not a mocked allow bit.
    from custom_components.ha_rbac import assist_policy as provider  # noqa: PLC0415

    original = provider.async_check_access
    checked = 0

    async def check(*args, **kwargs):
        nonlocal checked
        decision = await original(*args, **kwargs)
        checked += 1
        if checked == 1:
            if revocation in {"speaker", "kiosk"}:
                policy.store.bindings.pop("child" if revocation == "speaker" else "kiosk")
            elif revocation == "native":
                policy.users["kiosk"].permissions.check_entity = lambda *args: False
            elif revocation == "inactive":
                policy.user.is_active = False
            elif revocation == "hidden":
                hidden_role = compile_role(
                    hass, {"id": "hidden", "name": "Hidden", "allow": {}, "deny": {},
                           "attributes": {"rules": [{"names": ["state"]}]}},
                    PermissionLookup(er.async_get(hass), dr.async_get(hass)),
                )
                policy.permissions = Permissions(roles=[ceiling_role, hidden_role])
            elif revocation == "exposure":
                async_expose_entity(hass, "conversation", "light.allowed", False)
        return decision

    monkeypatch.setattr(provider, "async_check_access", check)
    result = await guard.async_execute(command, context=context, prepared_request=prepared)
    if revocation is None:
        assert result.status == "completed" and result.completed == 1
        assert len(calls) == 1
        assert calls[0].data == {"entity_id": "light.allowed"}
        assert calls[0].context is context
    else:
        assert result.status == "denied" and calls == []
    assert (await guard.async_execute(command, context=context,
                                       prepared_request=prepared)).status == "denied"
