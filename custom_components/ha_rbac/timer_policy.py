"""Finite cross-satellite timer permission oracle; never executes timer/device I/O."""

from homeassistant.auth.permissions.const import POLICY_CONTROL
from homeassistant.components.intent import async_device_supports_timers
from homeassistant.helpers import entity_registry as er

from .assist_policy import (
    ENTITY_ID,
    AccessDecision,
    _satellite_permissions,
    _satellite_readable,
)
from .const import DATA_RBAC, TIER_OPEN

VERSION = 1
ACTIONS = frozenset({"read", "cancel", "stop", "cancel_all"})
CONTROL_ACTIONS = frozenset({"pause", "resume", "cancel", "add", "remove"})
PRIVATE_FIELDS = (
    "friendly_name",
    "aliases",
    "area_id",
    "area",
    "area_name",
    "area_aliases",
    "timers",
    "name",
    "timer_names",
)


async def check(
    hass, satellite_ids, *, action="read", user_id=None, guest_role_id=None
):
    """Keep the existing read/cancel voice contract unchanged."""
    return await _check(
        hass,
        satellite_ids,
        action=action,
        user_id=user_id,
        guest_role_id=guest_role_id,
        actions=ACTIONS,
        command="timer.cancel",
    )


async def check_control(hass, satellite_ids, *, action, user_id):
    """Separate authenticated UI contract, with operation-specific tier denials."""
    return await _check(
        hass,
        satellite_ids,
        action=action,
        user_id=user_id,
        guest_role_id=None,
        actions=CONTROL_ACTIONS,
        command=f"timer.{action}" if type(action) is str else "",
    )


async def _check(
    hass, satellite_ids, *, action, user_id, guest_role_id, actions, command
):
    """Require exact exposed ESPHome satellites and fresh native/RBAC permissions.

    An entity read grant is not a cancellation grant. No domain or service outside
    this timer-specific contract is added to the older satellite/guest APIs.
    Trusted callers must separately prove transport provenance and target identity.
    """
    if (
        type(satellite_ids) is not tuple
        or not 0 < len(satellite_ids) <= 32
        or any(
            type(eid) is not str
            or len(eid) > 255
            or not eid.startswith("assist_satellite.")
            or not ENTITY_ID.fullmatch(eid)
            for eid in satellite_ids
        )
        or len(set(satellite_ids)) != len(satellite_ids)
        or type(action) is not str
        or action not in actions
    ):
        return AccessDecision(False, "invalid_request")
    rbac = hass.data.get(DATA_RBAC)
    if rbac is None:
        return AccessDecision(False, "policy_unavailable")
    try:
        resolved = await _satellite_permissions(hass, rbac, user_id, guest_role_id)
        if resolved is None or hass.data.get(DATA_RBAC) is not rbac:
            return AccessDecision(False, "invalid_subject")
        native, role = resolved
        registry = er.async_get(hass)
        for eid in satellite_ids:
            entry = registry.async_get(eid)
            state = hass.states.get(eid)
            if (
                entry is None
                or entry.platform != "esphome"
                or entry.disabled_by is not None
                or not entry.device_id
                or state is None
                or state.state in {"unknown", "unavailable"}
                or not async_device_supports_timers(hass, entry.device_id)
                or not _satellite_readable(hass, native, role, eid)
                or any(role.attribute_hidden(eid, key) for key in PRIVATE_FIELDS)
            ):
                return AccessDecision(False, "denied")
            if action != "read" and (
                not role.check_entity(eid, POLICY_CONTROL)
                or (native is not None and not native.check_entity(eid, POLICY_CONTROL))
                # Timer cancellation is a finite exact-target operation, not the
                # raw Assist conversation/pipeline services in BASELINE_DENY.
                or not role.tier_allowed(command, TIER_OPEN)
            ):
                return AccessDecision(False, "denied")
    except Exception:  # noqa: BLE001 -- uncertain policy must never grant timer access
        return AccessDecision(False, "policy_unavailable")
    return AccessDecision(True, "allowed")
