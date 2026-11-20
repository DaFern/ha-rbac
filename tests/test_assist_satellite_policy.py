"""Dormant satellite policy contracts, not voice/transport or device acceptance."""

import asyncio
from types import SimpleNamespace

import pytest
from homeassistant.auth.permissions.const import POLICY_CONTROL, POLICY_READ
from homeassistant.components.homeassistant.exposed_entities import async_expose_entity
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component

from custom_components.ha_rbac import assist_policy
from custom_components.ha_rbac.const import DATA_RBAC, ROLE_USER
from custom_components.ha_rbac.policy import Evaluator, default_roles

TARGETS = ("light.guest", "light.child", "light.adult")


def role(role_id, *entities, **extra):
    """Build explicit synthetic grants; no household configuration is used."""
    grants = {eid: {POLICY_READ: True, POLICY_CONTROL: True} for eid in entities}
    return {
        "id": role_id,
        "name": role_id,
        "allow": {"entities": {"entity_ids": grants}},
        "deny": {},
        **extra,
    }


async def allowed(hass, ids=TARGETS[:1], **kwargs):
    """Return the real oracle's decision without replacing policy evaluation."""
    return (
        await assist_policy.async_check_satellite_access(hass, ids, **kwargs)
    ).allowed


async def project(hass, ids=TARGETS, **kwargs):
    """Read the real bounded projection without admitting a satellite turn."""
    return await assist_policy.async_project_satellite_context(hass, ids, **kwargs)


@pytest.fixture
async def satellite(hass, monkeypatch):
    """Use real evaluator/compiled roles, but no live admission or service calls."""
    assert await async_setup_component(hass, "homeassistant", {})
    for eid in TARGETS:
        er.async_get(hass).async_get_or_create(
            "light", "test", eid, suggested_object_id=eid.partition(".")[2]
        )
        attributes = {
            "friendly_name": eid,
            "brightness": 128,
            "password": "DO_NOT_PROJECT",
        }
        hass.states.async_set(eid, "on", attributes)
        async_expose_entity(hass, "conversation", eid, True)
    store = SimpleNamespace(
        roles={
            **default_roles(),
            "guest": role("guest", TARGETS[0]),
            "child": role("child", *TARGETS[:2]),
            "adult": role("adult", *TARGETS),
        },
        bindings={"child": ["child"], "adult": ["adult"]},
        global_deny={},
    )
    users = {
        uid: SimpleNamespace(
            id=uid,
            is_active=True,
            system_generated=False,
            is_owner=uid == "owner",
            is_admin=uid in {"adult", "owner"},
            permissions=SimpleNamespace(check_entity=lambda *args: True),
        )
        for uid in ("child", "adult", "owner", "unbound")
    }

    async def get_user(uid):
        return users.get(uid)

    monkeypatch.setattr(hass.auth, "async_get_user", get_user)
    evaluator = Evaluator(hass, store)
    rbac = SimpleNamespace(store=store, evaluator=evaluator)
    hass.data[DATA_RBAC] = rbac
    return SimpleNamespace(store=store, users=users, evaluator=evaluator, rbac=rbac)


@pytest.mark.parametrize(
    ("subject", "permitted"),
    [
        ({"guest_role_id": "guest"}, TARGETS[:1]),
        ({"user_id": "child"}, TARGETS[:2]),
        ({"user_id": "adult"}, TARGETS),
        ({"user_id": "owner"}, TARGETS),
    ],
)
async def test_guest_child_adult_owner_read_and_control(
    hass, satellite, subject, permitted
):
    """Adults/owners do not inherit a child kiosk ceiling."""
    for eid in TARGETS:
        for operation in ("read", "turn_on", "turn_off"):
            result = await allowed(hass, (eid,), operation=operation, **subject)
            assert result is (eid in permitted)
    result = await project(hass, attributes=("brightness", "password"), **subject)
    assert result["available"]
    assert [row["entity_id"] for row in result["entities"]] == list(permitted)
    assert all(row["attributes"] == {"brightness": 128} for row in result["entities"])
    assert "DO_NOT_PROJECT" not in str(result)


@pytest.mark.parametrize(
    "subject",
    [
        {},
        {"user_id": ""},
        {"user_id": "missing"},
        {"guest_role_id": ""},
        {"guest_role_id": "missing"},
        {"user_id": "child", "guest_role_id": "guest"},
    ],
)
async def test_missing_or_conflicting_subject_never_falls_back(
    hass, satellite, subject
):
    """Unknown speakers do not silently become guests or owners."""
    assert not await allowed(hass, operation="turn_on", **subject)
    assert not (await project(hass, **subject))["entities"]


async def test_unbound_speaker_keeps_ordinary_browser_fallback(hass, satellite):
    """The new lookup denies unbound users without modifying browser behaviour."""
    satellite.store.roles[ROLE_USER] = role(ROLE_USER, *TARGETS)
    satellite.evaluator.invalidate()
    user = satellite.users["unbound"]
    browser = satellite.evaluator.async_permissions(user)
    voice = satellite.evaluator.async_satellite_permissions(user)
    assert browser.check_entity(TARGETS[0], POLICY_READ)
    assert not voice.check_entity(TARGETS[0], POLICY_READ)
    assert not await allowed(hass, user_id="unbound")


@pytest.mark.parametrize("uid", ["child", "adult", "owner"])
@pytest.mark.parametrize("field", ["is_active", "system_generated"])
async def test_inactive_or_system_subject_is_denied(hass, satellite, uid, field):
    """Even an owner cannot supply revoked/system-generated voice authority."""
    setattr(satellite.users[uid], field, field != "is_active")
    assert not await allowed(hass, user_id=uid)
    assert not (await project(hass, user_id=uid))["entities"]


@pytest.mark.parametrize("subject", [{"user_id": "child"}, {"guest_role_id": "guest"}])
async def test_role_revocation_is_not_cached_authority(hass, satellite, subject):
    """Rebuild role permissions after the ordinary store invalidation event."""
    assert await allowed(hass, operation="turn_on", **subject)
    if "user_id" in subject:
        satellite.store.bindings.pop("child")
    else:
        satellite.store.roles.pop("guest")
    satellite.evaluator.invalidate()
    assert not await allowed(hass, operation="turn_on", **subject)
    assert not (await project(hass, **subject))["entities"]


async def test_role_global_deny_and_native_permissions(hass, satellite):
    """An HA administrator with a limited adult role is not an automatic bypass."""
    satellite.store.roles["adult"] = role("adult", TARGETS[0])
    satellite.evaluator.invalidate()
    assert not await allowed(hass, TARGETS[1:2], user_id="adult", operation="turn_on")
    satellite.store.global_deny["adult"] = {
        "entities": {"entity_ids": {TARGETS[0]: True}}
    }
    satellite.evaluator.invalidate()
    assert not await allowed(hass, user_id="adult")
    satellite.users["child"].permissions.check_entity = lambda *args: False
    assert not await allowed(hass, user_id="child")


async def test_guest_role_and_owner_leave_old_kiosk_contract_unchanged(hass, satellite):
    """Owner/full-access rejection stays in place on the old dual-account API."""
    old = await assist_policy.async_check_access(hass, "owner", TARGETS[:1])
    assert not old.allowed
    assert await allowed(hass, user_id="owner")
    assert not await allowed(hass, guest_role_id="admin")


@pytest.mark.parametrize("subject", [{"user_id": "owner"}, {"guest_role_id": "guest"}])
async def test_exposure_availability_and_mixed_batch_denials(hass, satellite, subject):
    """Owner privileges cannot bypass exposure, availability or supported actions."""
    async_expose_entity(hass, "conversation", TARGETS[0], False)
    assert not await allowed(hass, operation="turn_on", **subject)
    async_expose_entity(hass, "conversation", TARGETS[0], True)
    hass.states.async_set(TARGETS[0], "unavailable")
    assert not (await project(hass, TARGETS[:1], **subject))["entities"]
    hass.states.async_set(TARGETS[0], "on")
    targets = (TARGETS[0], "light.missing")
    assert not await allowed(hass, targets, operation="turn_on", **subject)


@pytest.mark.parametrize("operation", ["toggle", "unlock", "restart", {}, None])
async def test_no_arbitrary_or_malformed_operations(hass, satellite, operation):
    """Owner means full supported access, not an arbitrary-service interface."""
    assert not await allowed(hass, user_id="owner", operation=operation)


async def test_hidden_fields_and_service_denial(hass, satellite):
    """Reading a light does not authorize hidden attributes or a forbidden action."""
    satellite.store.roles["child"] = role(
        "child",
        *TARGETS[:2],
        attributes={"deny": ["friendly_name", "brightness"]},
        tiers={"max": "user", "deny": ["light.turn_on"]},
    )
    satellite.evaluator.invalidate()
    result = await project(hass, user_id="child", attributes=("brightness",))
    assert len(result["entities"]) == 2
    assert all(
        "name" not in row and not row["attributes"] for row in result["entities"]
    )
    assert not await allowed(hass, user_id="child", operation="turn_on")
    assert await allowed(hass, user_id="child", operation="turn_off")


@pytest.mark.parametrize("subject", [{"user_id": "child"}, {"guest_role_id": "guest"}])
async def test_schedule_and_unplaced_location_deny(
    hass, satellite, monkeypatch, subject
):
    """Guest location is unknown; neither schedule nor location can widen access."""
    role_id = subject.get("guest_role_id", subject.get("user_id"))
    satellite.store.roles[role_id]["location"] = {
        "zones": ["zone.home"],
        "mode": "not_in",
    }
    satellite.evaluator.invalidate()
    assert not await allowed(hass, **subject)
    satellite.store.roles[role_id].pop("location")
    satellite.evaluator.invalidate()
    role_type = type(satellite.evaluator._compiled_role(role_id))
    monkeypatch.setattr(role_type, "active_at", lambda *args: False)
    assert not await allowed(hass, **subject)


async def test_provider_loss_during_account_await(hass, satellite, monkeypatch):
    """Replacing the provider while resolving a user is not a new implicit grant."""

    async def get_user(uid):
        hass.data.pop(DATA_RBAC)
        return satellite.users[uid]

    monkeypatch.setattr(hass.auth, "async_get_user", get_user)
    assert await project(hass, user_id="child") == {"available": False, "entities": []}


async def test_cancellation_propagates_without_fallback(hass, satellite, monkeypatch):
    """Cancelling authentication must not turn a matched request into a guest turn."""

    async def get_user(_uid):
        raise asyncio.CancelledError

    monkeypatch.setattr(hass.auth, "async_get_user", get_user)
    with pytest.raises(asyncio.CancelledError):
        await allowed(hass, user_id="child")


@pytest.mark.parametrize(
    "targets",
    [(), [], ("light.guest",) * 2, ("light.guest",) * 33, ({},), ("bad id",)],
)
async def test_malformed_targets_are_denied(hass, satellite, targets):
    """Duplicate, unbounded and structurally invalid requests cannot become grants."""
    assert not await allowed(hass, targets, user_id="owner")
    assert await project(hass, targets, user_id="owner") == {
        "available": False,
        "entities": [],
    }


@pytest.mark.parametrize("hidden", ["state", "entity_id"])
async def test_hidden_identity_does_not_leak_through_projection(
    hass, satellite, hidden
):
    """Hiding identity/state withholds the whole entity and control permission."""
    satellite.store.roles["child"] = role(
        "child", *TARGETS[:2], attributes={"deny": [hidden]}
    )
    satellite.evaluator.invalidate()
    assert not (await project(hass, user_id="child"))["entities"]
    assert not await allowed(hass, user_id="child", operation="turn_on")


@pytest.mark.parametrize("platform", ["group", "template"])
async def test_indirect_platforms_remain_denied_for_owner(hass, satellite, platform):
    """A broad owner policy cannot turn an indirect entity into a direct command."""
    entry = er.async_get(hass).async_get_or_create("light", platform, "indirect")
    hass.states.async_set(entry.entity_id, "on")
    async_expose_entity(hass, "conversation", entry.entity_id, True)
    assert not await allowed(
        hass, (entry.entity_id,), user_id="owner", operation="turn_on"
    )
