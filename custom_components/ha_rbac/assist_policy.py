"""Versioned in-process permission oracle for a future protected Assist adapter.

This does not authenticate a speaker, open an endpoint, or execute a command.
Callers must independently authenticate the request and constrain its transport.
Decisions are single-use checks, not reusable grants across network/model awaits.
"""

import math
import re
from dataclasses import dataclass

from homeassistant.auth.permissions.const import POLICY_CONTROL, POLICY_READ
from homeassistant.core import HomeAssistant

from .const import DATA_RBAC

API_VERSION = 1
CONTEXT_API_VERSION = 1
MAX_TARGETS = 32
ENTITY_ID = re.compile(r"[a-z_]+\.[a-z0-9_]+\Z")
# Initial proof supports only direct lighting/fan on/off, not arbitrary services.
CONTROL_DOMAINS = frozenset({"light", "fan"})


@dataclass(frozen=True, slots=True)
class AccessDecision:
    """A fixed-code decision without private policy or entity data."""

    allowed: bool
    reason: str


async def async_check_access(
    hass: HomeAssistant,
    user_id: str,
    entity_ids: tuple[str, ...],
    *,
    operation: str = "read",
    attributes: tuple[str, ...] = (),
    ceiling_user_id: str | None = None,
) -> AccessDecision:
    """Intersect explicitly assigned current RBAC roles with native permissions.

    Only trusted in-process code may choose identities. A ceiling account must
    itself have an explicit restricted role; owner/system pass-through is denied.
    Never call this with an identity taken from model text or tool arguments.
    """
    if (
        not isinstance(user_id, str)
        or not user_id
        or not isinstance(entity_ids, tuple)
        or not 0 < len(entity_ids) <= MAX_TARGETS
        or any(not isinstance(eid, str) or not ENTITY_ID.fullmatch(eid) for eid in entity_ids)
        or not isinstance(attributes, tuple)
        or len(attributes) > 16
        or any(not isinstance(name, str) or not name or len(name) > 64 for name in attributes)
        or operation not in {"read", "turn_on", "turn_off"}
        or (operation != "read" and attributes)
        or (ceiling_user_id is not None
            and (not isinstance(ceiling_user_id, str) or not ceiling_user_id))
    ):
        return AccessDecision(False, "invalid_request")
    rbac = hass.data.get(DATA_RBAC)
    if rbac is None:
        return AccessDecision(False, "policy_unavailable")
    identities = tuple(dict.fromkeys((user_id, ceiling_user_id or user_id)))
    try:
        users = [await hass.auth.async_get_user(uid) for uid in identities]
        # Resolve accounts before taking policy snapshots; recheck policy on
        # every invocation. No await is allowed after the policy checks below.
        if hass.data.get(DATA_RBAC) is not rbac:
            return AccessDecision(False, "policy_changed")
        for uid, user in zip(identities, users, strict=True):
            if (
                user is None
                or not user.is_active
                or user.system_generated
                or user.is_owner
                or not rbac.store.bindings.get(uid)
            ):
                return AccessDecision(False, "account_not_restricted")
            permissions = rbac.evaluator.async_permissions(user)
            if permissions.full_access:
                return AccessDecision(False, "account_not_restricted")
            for eid in entity_ids:
                if (
                    not permissions.check_entity(eid, POLICY_READ)
                    or not user.permissions.check_entity(eid, POLICY_READ)
                ):
                    return AccessDecision(False, "denied")
                if any(permissions.attribute_hidden(eid, name) for name in attributes):
                    return AccessDecision(False, "denied")
                if operation == "read":
                    continue
                state = hass.states.get(eid)
                if (
                    eid.partition(".")[0] not in CONTROL_DOMAINS
                    or state is None
                    or "entity_id" in state.attributes
                    or any(permissions.attribute_hidden(eid, name)
                           for name in ("entity_id", "state"))
                ):
                    return AccessDecision(False, "indirect_or_unsupported")
                if (
                    not permissions.check_entity(eid, POLICY_CONTROL)
                    or not user.permissions.check_entity(eid, POLICY_CONTROL)
                ):
                    return AccessDecision(False, "denied")
    except Exception:  # noqa: BLE001 -- failure must never become permission
        return AccessDecision(False, "policy_unavailable")
    return AccessDecision(True, "allowed")


def _context_value(value):
    """Allow bounded scalar data only, never nested objects or reference lists."""
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return math.isfinite(value) and abs(value) < 1e20
    return isinstance(value, str) and len(value) <= 256 and value.isprintable()


async def async_project_context(
    hass: HomeAssistant,
    user_id: str,
    entity_ids: tuple[str, ...],
    *,
    attributes: tuple[str, ...] = (),
    ceiling_user_id: str | None = None,
) -> dict:
    """Project permitted Assist data atomically after resolving both accounts.

    No caller-supplied template, history, registry data, aliases, area metadata or
    tool output is merged. No await occurs while policy and state are projected.
    The snapshot is not an execution grant or a cacheable permission decision.
    """
    from homeassistant.components.homeassistant.exposed_entities import (  # noqa: PLC0415
        async_should_expose,
    )

    unavailable = {"available": False, "entities": []}
    if (
        not isinstance(user_id, str) or not user_id
        or not isinstance(entity_ids, tuple) or not 0 < len(entity_ids) <= MAX_TARGETS
        or any(not isinstance(eid, str) or not ENTITY_ID.fullmatch(eid) for eid in entity_ids)
        or not isinstance(attributes, tuple) or len(attributes) > 16
        or any(not isinstance(name, str) or not name or len(name) > 64 for name in attributes)
        or (ceiling_user_id is not None
            and (not isinstance(ceiling_user_id, str) or not ceiling_user_id))
    ):
        return unavailable
    rbac = hass.data.get(DATA_RBAC)
    if rbac is None:
        return unavailable
    try:
        identities = tuple(dict.fromkeys((user_id, ceiling_user_id or user_id)))
        users = [await hass.auth.async_get_user(uid) for uid in identities]
        if hass.data.get(DATA_RBAC) is not rbac:
            return unavailable
        policies = []
        for uid, user in zip(identities, users, strict=True):
            if (user is None or not user.is_active or user.system_generated or user.is_owner
                    or not rbac.store.bindings.get(uid)):
                return unavailable
            permission = rbac.evaluator.async_permissions(user)
            if permission.full_access:
                return unavailable
            policies.append((user.permissions, permission))

        entities = []
        for eid in dict.fromkeys(entity_ids):
            if (not async_should_expose(hass, "conversation", eid)
                    or not all(native.check_entity(eid, POLICY_READ)
                               and role.check_entity(eid, POLICY_READ)
                               for native, role in policies)):
                continue
            # A hidden identifier or state must not leak through another field.
            if any(role.attribute_hidden(eid, key) for _, role in policies
                   for key in ("entity_id", "state")):
                continue
            state = hass.states.get(eid)
            if state is None or not _context_value(state.state):
                continue
            row = {"entity_id": eid, "state": state.state, "attributes": {}}
            if (not any(role.attribute_hidden(eid, "friendly_name") for _, role in policies)
                    and _context_value(state.name)):
                row["name"] = state.name
            for key in dict.fromkeys(attributes):
                # Identity/reference/credentials metadata is never context data.
                domain = eid.partition(".")[0]
                if key not in CONTEXT_ATTRIBUTES.get(domain, frozenset()) | {"assumed_state"}:
                    continue
                if any(role.attribute_hidden(eid, key) for _, role in policies):
                    continue
                value = state.attributes.get(key)
                typed = (isinstance(value, bool) if key == "assumed_state" else
                         isinstance(value, str) if key in {"temperature_unit", "unit_of_measurement"}
                         else isinstance(value, (int, float)) and not isinstance(value, bool))
                if key in state.attributes and typed and _context_value(value):
                    row["attributes"][key] = value
            entities.append(row)
    except Exception:  # noqa: BLE001 -- discard partial results on any failure
        return unavailable
    return {"available": True, "entities": entities}


# A small initial projection, not a general attribute/registry dump. Lists of
# options, media titles, locations, entity references and credentials are excluded.
CONTEXT_ATTRIBUTES = {
    "light": frozenset({"brightness"}),
    "fan": frozenset({"percentage"}),
    "climate": frozenset({"current_temperature", "temperature", "temperature_unit",
                          "humidity", "current_humidity"}),
    "humidifier": frozenset({"humidity", "current_humidity"}),
    "cover": frozenset({"current_position"}),
    "sensor": frozenset({"unit_of_measurement", "battery_level"}),
    "number": frozenset({"unit_of_measurement"}),
}
