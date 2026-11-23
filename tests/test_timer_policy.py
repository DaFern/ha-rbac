"""Finite timer oracle: real HA registries, native timer registration and compiled roles."""

import asyncio
from types import SimpleNamespace

import pytest
from homeassistant.components.homeassistant.exposed_entities import async_expose_entity
from homeassistant.components.intent.const import TIMER_DATA
from homeassistant.components.intent.timers import TimerManager
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component
from homeassistant.util import dt as dt_util

from custom_components.ha_rbac import assist_policy
from custom_components.ha_rbac.const import DATA_RBAC
from custom_components.ha_rbac.policy import DAYS, Evaluator, default_roles
from testsupport.ha_test import MockConfigEntry


@pytest.fixture
async def timer_policy(hass, monkeypatch):
    """Build an exposed timer device with independent native and RBAC grants."""
    assert await async_setup_component(hass, "homeassistant", {})
    entry = MockConfigEntry(domain="esphome")
    entry.add_to_hass(hass)
    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={("esphome", "oracle-timer")},
    )
    satellite = er.async_get(hass).async_get_or_create(
        "assist_satellite", "esphome", "oracle-timer",
        config_entry=entry, device_id=device.id,
    )
    hass.states.async_set(satellite.entity_id, "idle")
    async_expose_entity(hass, "conversation", satellite.entity_id, True)
    manager = TimerManager(hass)
    hass.data[TIMER_DATA] = manager
    manager.register_handler(device.id, lambda *_: None)
    store = SimpleNamespace(
        roles={**default_roles(), "guest": {
            "id": "guest", "name": "Guest",
            "allow": {"entities": {"entity_ids": {
                satellite.entity_id: {"read": True, "control": True},
            }}},
        }},
        bindings={"speaker": ["guest"]}, global_deny={},
    )
    evaluator = Evaluator(hass, store)
    hass.data[DATA_RBAC] = SimpleNamespace(store=store, evaluator=evaluator)
    user = SimpleNamespace(
        id="speaker", is_active=True, is_owner=False, is_admin=False, system_generated=False,
        permissions=SimpleNamespace(check_entity=lambda *args: True),
    )

    async def get_user(uid):
        await asyncio.sleep(0)
        return user if uid == user.id else None

    monkeypatch.setattr(hass.auth, "async_get_user", get_user)
    return SimpleNamespace(
        satellite=satellite, device=device, manager=manager, store=store,
        evaluator=evaluator, user=user,
    )


@pytest.mark.parametrize("action", ["read", "cancel", "stop", "cancel_all"])
@pytest.mark.parametrize("subject", ["guest", "speaker"])
async def test_timer_oracle_uses_explicit_target_permissions(hass, timer_policy, action, subject):
    """Both selected guests and active enrolled accounts use target-specific rights."""
    e = timer_policy
    args = {"guest_role_id": "guest"} if subject == "guest" else {"user_id": "speaker"}
    result = await assist_policy.async_check_timer_access(
        hass, (e.satellite.entity_id,), action=action, **args,
    )
    assert result.allowed
    assert assist_policy.TIMER_POLICY_VERSION == 1


@pytest.mark.parametrize("action", ["cancel", "stop", "cancel_all"])
async def test_read_only_permission_is_not_a_cancellation_grant(hass, timer_policy, action):
    """Reading a timer never authorises cancelling it."""
    e = timer_policy
    e.store.roles["guest"]["allow"]["entities"]["entity_ids"][e.satellite.entity_id][
        "control"
    ] = False
    e.evaluator.invalidate()
    assert (await assist_policy.async_check_timer_access(
        hass, (e.satellite.entity_id,), guest_role_id="guest",
    )).allowed
    assert not (await assist_policy.async_check_timer_access(
        hass, (e.satellite.entity_id,), action=action, guest_role_id="guest",
    )).allowed


@pytest.mark.parametrize("change", [
    "permission", "unexposed", "disabled", "device", "no_handler", "unavailable",
    "missing_role", "full_access_guest", "closed_schedule", "hidden_name", "hidden_area",
    "hidden_timers", "inactive_account", "system_account", "native_denial", "unbound_account",
    "tier_denial",
    "hidden_area_label", "native_control_denial",
])
async def test_unavailable_hidden_revoked_or_inactive_targets_deny(hass, timer_policy, change):
    """Liveness, schedules, hidden metadata and both permission layers remain enforced."""
    e = timer_policy
    subject = {"guest_role_id": "guest"}
    if change == "permission":
        e.store.roles["guest"]["allow"] = {}
    elif change == "unexposed":
        async_expose_entity(hass, "conversation", e.satellite.entity_id, False)
    elif change == "disabled":
        er.async_get(hass).async_update_entity(
            e.satellite.entity_id, disabled_by=er.RegistryEntryDisabler.USER,
        )
    elif change == "device":
        er.async_get(hass).async_update_entity(e.satellite.entity_id, device_id=None)
    elif change == "no_handler":
        e.manager.handlers.clear()
    elif change == "unavailable":
        hass.states.async_set(e.satellite.entity_id, "unavailable")
    elif change == "missing_role":
        del e.store.roles["guest"]
    elif change == "full_access_guest":
        subject = {"guest_role_id": "admin"}
    elif change == "closed_schedule":
        e.store.roles["guest"]["schedule"] = {
            "days": [DAYS[(dt_util.now().weekday() + 1) % 7]],
        }
    elif change == "tier_denial":
        e.store.roles["guest"]["tiers"] = {"deny": ["timer.cancel"]}
    elif change.startswith("hidden_"):
        field = {"hidden_name": "friendly_name", "hidden_area": "area_id",
                 "hidden_area_label": "area",
                 "hidden_timers": "timers"}[change]
        e.store.roles["guest"]["attributes"] = {"deny": [field]}
    else:
        subject = {"user_id": "speaker"}
        if change == "inactive_account":
            e.user.is_active = False
        elif change == "system_account":
            e.user.system_generated = True
        elif change == "native_denial":
            e.user.permissions.check_entity = lambda *args: False
        elif change == "native_control_denial":
            e.user.permissions.check_entity = lambda eid, operation: operation == "read"
        else:
            e.store.bindings.clear()
    e.evaluator.invalidate()
    result = await assist_policy.async_check_timer_access(
        hass, (e.satellite.entity_id,), action="cancel", **subject,
    )
    assert not result.allowed


@pytest.mark.parametrize("ids", [
    (), [], ("light.test",), ("assist_satellite.bad/name",), ("assist_satellite.bad.name",),
    ({"invalid": "unhashable"},), (123,), ("assist_satellite.a",) * 2,
])
async def test_malformed_timer_target_requests_deny_without_raising(hass, timer_policy, ids):
    """Invalid and unhashable target input cannot reach an effect or raise."""
    result = await assist_policy.async_check_timer_access(hass, ids, guest_role_id="guest")
    assert not result.allowed


@pytest.mark.parametrize("kwargs", [
    {}, {"guest_role_id": "guest", "user_id": "speaker"},
    {"guest_role_id": "guest", "action": "execute_service"},
    {"guest_role_id": "guest", "action": "start"},
])
async def test_timer_contract_cannot_be_used_as_authentication_or_arbitrary_control(
    hass, timer_policy, kwargs,
):
    """Subject choice and operation vocabulary are finite and fail closed."""
    assert not (await assist_policy.async_check_timer_access(
        hass, (timer_policy.satellite.entity_id,), **kwargs,
    )).allowed


async def test_timer_contract_does_not_widen_legacy_satellite_actions(hass, timer_policy):
    """The separate timer API does not unlock the old generic satellite control API."""
    e = timer_policy
    assert (await assist_policy.async_check_timer_access(
        hass, (e.satellite.entity_id,), action="cancel", guest_role_id="guest",
    )).allowed
    assert not (await assist_policy.async_check_satellite_access(
        hass, (e.satellite.entity_id,), operation="turn_off", guest_role_id="guest",
    )).allowed


async def test_owner_still_needs_exposure_and_exact_supported_timer_target(hass, timer_policy):
    """An owner keeps native policy rights but cannot act on a non-timer target."""
    e = timer_policy
    e.user.is_owner = True
    e.store.bindings.clear()
    assert (await assist_policy.async_check_timer_access(
        hass, (e.satellite.entity_id,), action="cancel", user_id="speaker",
    )).allowed
    async_expose_entity(hass, "conversation", e.satellite.entity_id, False)
    assert not (await assist_policy.async_check_timer_access(
        hass, (e.satellite.entity_id,), action="cancel", user_id="speaker",
    )).allowed


@pytest.mark.parametrize("action", ["pause", "resume", "cancel", "add", "remove"])
async def test_exact_id_ui_contract_requires_current_target_control(hass, timer_policy, action):
    """The new UI contract is account-bound and does not widen the voice vocabulary."""
    e = timer_policy
    assert assist_policy.TIMER_CONTROL_POLICY_VERSION == 1
    assert (await assist_policy.async_check_timer_control_access(
        hass, (e.satellite.entity_id,), action=action, user_id="speaker",
    )).allowed
    e.store.roles["guest"]["allow"]["entities"]["entity_ids"][e.satellite.entity_id][
        "control"
    ] = False
    e.evaluator.invalidate()
    assert not (await assist_policy.async_check_timer_control_access(
        hass, (e.satellite.entity_id,), action=action, user_id="speaker",
    )).allowed
    if action != "cancel":
        assert not (await assist_policy.async_check_timer_access(
            hass, (e.satellite.entity_id,), action=action, user_id="speaker",
        )).allowed


@pytest.mark.parametrize("action", ["pause", "resume", "cancel", "add", "remove"])
async def test_exact_id_ui_operation_tier_denial_is_enforced(hass, timer_policy, action):
    """A specific timer operation denial remains stronger than entity control."""
    e = timer_policy
    e.store.roles["guest"]["tiers"] = {"deny": [f"timer.{action}"]}
    e.evaluator.invalidate()
    assert not (await assist_policy.async_check_timer_control_access(
        hass, (e.satellite.entity_id,), action=action, user_id="speaker",
    )).allowed


@pytest.mark.parametrize("action", ["start", "cancel_all", "execute_service", None, True, []])
async def test_exact_id_ui_contract_does_not_become_a_generic_timer_api(hass, timer_policy, action):
    """Only finite per-timer mutations can be admitted."""
    assert not (await assist_policy.async_check_timer_control_access(
        hass, (timer_policy.satellite.entity_id,), action=action, user_id="speaker",
    )).allowed
