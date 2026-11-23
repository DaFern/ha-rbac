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
# Additive contract: the existing dual-account kiosk API remains unchanged.
SATELLITE_API_VERSION = 1
# Separate additive contract: do not widen the legacy tablet/on-off interfaces.
GUEST_POLICY_VERSION = 1
VOICE_POLICY_VERSION = 1
GUEST_ACTIONS = {
    "light": frozenset({"turn_on", "turn_off"}),
    "switch": frozenset({"turn_on", "turn_off"}),
    "fan": frozenset({"turn_on", "turn_off"}),
    "media_player": frozenset({
        "media_play", "media_pause", "media_next_track", "media_previous_track",
        "volume_up", "volume_down", "volume_set", "clear_playlist", "play_media",
        "media_stop", "volume_mute", "media_seek", "shuffle_set", "repeat_set",
    }),
}
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


def _satellite_request_valid(entity_ids, attributes, operation):
    """Accept only a bounded exact read or the initial direct on/off vocabulary."""
    return (
        isinstance(entity_ids, tuple)
        and 0 < len(entity_ids) <= MAX_TARGETS
        and all(
            isinstance(eid, str) and len(eid) <= 255 and ENTITY_ID.fullmatch(eid)
            for eid in entity_ids
        )
        and len(set(entity_ids)) == len(entity_ids)
        and isinstance(attributes, tuple)
        and len(attributes) <= 16
        and all(isinstance(key, str) and 0 < len(key) <= 64 for key in attributes)
        and isinstance(operation, str)
        and operation in {"read", "turn_on", "turn_off"}
        and (operation == "read" or not attributes)
    )


async def _satellite_permissions(hass, rbac, user_id, guest_role_id):
    """Resolve exactly one server-selected subject, never a fallback identity."""
    if (user_id is None) == (guest_role_id is None):
        return None
    if guest_role_id is not None:
        if not isinstance(guest_role_id, str) or not 0 < len(guest_role_id) <= 128:
            return None
        return None, rbac.evaluator.async_guest_permissions(guest_role_id)
    if not isinstance(user_id, str) or not 0 < len(user_id) <= 128:
        return None
    user = await hass.auth.async_get_user(user_id)
    if (
        hass.data.get(DATA_RBAC) is not rbac
        or user is None
        or user.id != user_id
        or not user.is_active
        or user.system_generated
    ):
        return None
    return user.permissions, rbac.evaluator.async_satellite_permissions(user)


def _satellite_readable(hass, native, role, eid):
    """Check exposure, native/role read access and hidden identity/state together."""
    from homeassistant.components.homeassistant.exposed_entities import (  # noqa: PLC0415
        async_should_expose,
    )

    return (
        async_should_expose(hass, "conversation", eid)
        and role.check_entity(eid, POLICY_READ)
        and (native is None or native.check_entity(eid, POLICY_READ))
        and not any(role.attribute_hidden(eid, key) for key in ("entity_id", "state"))
    )


async def async_check_satellite_access(
    hass: HomeAssistant,
    entity_ids: tuple[str, ...],
    *,
    user_id: str | None = None,
    guest_role_id: str | None = None,
    operation: str = "read",
    attributes: tuple[str, ...] = (),
) -> AccessDecision:
    """Check a speaker's own policy OR an explicitly selected guest role.

    Trusted server code must first establish satellite provenance and fresh
    matched/unmatched voice evidence. These arguments are NOT authentication.
    No kiosk ceiling, Context replacement, transport registration or execution
    is performed. Missing matched accounts never downgrade to guest authority.
    Even an owner is limited to this contract's supported operations.
    """
    from homeassistant.helpers import entity_registry as er  # noqa: PLC0415

    from .const import TIER_OPEN  # noqa: PLC0415

    if not _satellite_request_valid(entity_ids, attributes, operation):
        return AccessDecision(False, "invalid_request")
    rbac = hass.data.get(DATA_RBAC)
    if rbac is None:
        return AccessDecision(False, "policy_unavailable")
    try:
        resolved = await _satellite_permissions(hass, rbac, user_id, guest_role_id)
        if resolved is None:
            return AccessDecision(False, "invalid_subject")
        native, role = resolved
        for eid in entity_ids:
            if not _satellite_readable(hass, native, role, eid) or any(
                role.attribute_hidden(eid, key) for key in attributes
            ):
                return AccessDecision(False, "denied")
            state = hass.states.get(eid)
            if state is None or state.state in {"unknown", "unavailable"}:
                return AccessDecision(False, "unavailable_target")
            if operation == "read":
                continue
            entry = er.async_get(hass).async_get(eid)
            domain = eid.partition(".")[0]
            if (
                domain not in CONTROL_DOMAINS
                or entry is None
                or entry.disabled_by is not None
                or entry.platform in {"group", "template"}
                or "entity_id" in state.attributes
            ):
                return AccessDecision(False, "indirect_or_unsupported")
            if (
                not role.check_entity(eid, POLICY_CONTROL)
                or not role.tier_allowed(f"{domain}.{operation}", TIER_OPEN)
                or (native is not None and not native.check_entity(eid, POLICY_CONTROL))
            ):
                return AccessDecision(False, "denied")
    except Exception:  # noqa: BLE001 -- never fall back to native/guest authority
        return AccessDecision(False, "policy_unavailable")
    return AccessDecision(True, "allowed")


async def async_project_satellite_context(
    hass: HomeAssistant,
    entity_ids: tuple[str, ...],
    *,
    user_id: str | None = None,
    guest_role_id: str | None = None,
    attributes: tuple[str, ...] = (),
) -> dict:
    """Project current readable state without kiosk identity or unfiltered data.

    Call only after trusted admission, and rebuild for every delivery. Returned
    data is not permission to execute or to append unfiltered history/templates.
    """
    unavailable = {"available": False, "entities": []}
    if not _satellite_request_valid(entity_ids, attributes, "read"):
        return unavailable
    rbac = hass.data.get(DATA_RBAC)
    if rbac is None:
        return unavailable
    try:
        resolved = await _satellite_permissions(hass, rbac, user_id, guest_role_id)
        if resolved is None:
            return unavailable
        native, role = resolved
        entities = []
        for eid in entity_ids:
            if not _satellite_readable(hass, native, role, eid):
                continue
            state = hass.states.get(eid)
            if (
                state is None
                or state.state in {"unknown", "unavailable"}
                or not _context_value(state.state)
            ):
                continue
            row = {"entity_id": eid, "state": state.state, "attributes": {}}
            if not role.attribute_hidden(eid, "friendly_name") and _context_value(
                state.name
            ):
                row["name"] = state.name
            for key in dict.fromkeys(attributes):
                if key not in CONTEXT_ATTRIBUTES.get(state.domain, frozenset()) | {
                    "assumed_state"
                } or role.attribute_hidden(eid, key):
                    continue
                value = state.attributes.get(key)
                typed = (
                    isinstance(value, bool)
                    if key == "assumed_state"
                    else isinstance(value, str)
                    if key in {"temperature_unit", "unit_of_measurement"}
                    else isinstance(value, (int, float)) and not isinstance(value, bool)
                )
                if key in state.attributes and typed and _context_value(value):
                    row["attributes"][key] = value
            entities.append(row)
    except Exception:  # noqa: BLE001 -- discard partial output on provider failures
        return unavailable
    return {"available": True, "entities": entities}


async def async_guest_role_choices(hass: HomeAssistant) -> dict:
    """Metadata for the administrator options flow, not an execution grant.

    No endpoint is registered. Role rules remain in RBAC's existing domain/entity
    editor; Codex stores only the selected role ID. Restricted scheduled roles
    remain selectable, but their schedule is checked on every actual request.
    """
    rbac = hass.data.get(DATA_RBAC)
    if rbac is None:
        return {"available": False, "roles": []}
    try:
        rows = []
        if len(rbac.store.roles) > 100:
            return {"available": False, "roles": []}
        for role_id, role in rbac.store.roles.items():
            if (
                not isinstance(role_id, str)
                or not 0 < len(role_id) <= 128
                or not role_id.isprintable()
                or rbac.evaluator._compiled_role(role_id).full_access  # noqa: SLF001
            ):
                continue
            name = role.get("name", role_id)
            if not isinstance(name, str) or not 0 < len(name) <= 128 or not name.isprintable():
                name = role_id
            rows.append({"id": role_id, "name": name})
        return {"available": True, "roles": sorted(rows, key=lambda row: row["id"])}
    except Exception:  # noqa: BLE001 -- never offer uncertain roles
        return {"available": False, "roles": []}


async def async_check_guest_action(
    hass: HomeAssistant, entity_ids: tuple[str, ...], *,
    guest_role_id: str, operation: str = "read",
) -> AccessDecision:
    """Check a guest role without resolving or borrowing an HA user."""
    return await async_check_voice_action(
        hass, entity_ids, guest_role_id=guest_role_id, operation=operation
    )


async def async_check_voice_action(
    hass: HomeAssistant, entity_ids: tuple[str, ...], *,
    guest_role_id: str | None = None, user_id: str | None = None,
    operation: str = "read",
) -> AccessDecision:
    """Check current role-domain/entity rules for a fixed guest capability.

    Trusted admission is still required by the caller. This does not open the
    ordinary conversation/pipeline surfaces, assign an HA user, or execute I/O.
    Selecting a domain never permits arbitrary services or indirect group targets.
    """
    from homeassistant.helpers import entity_registry as er  # noqa: PLC0415

    from .const import TIER_OPEN  # noqa: PLC0415

    if not _satellite_request_valid(
        entity_ids, (), "read" if isinstance(operation, str) else None
    ):
        return AccessDecision(False, "invalid_request")
    rbac = hass.data.get(DATA_RBAC)
    if rbac is None:
        return AccessDecision(False, "policy_unavailable")
    try:
        resolved = await _satellite_permissions(hass, rbac, user_id, guest_role_id)
        if resolved is None:
            return AccessDecision(False, "invalid_subject")
        native, role = resolved
        for eid in entity_ids:
            domain = eid.partition(".")[0]
            state = hass.states.get(eid)
            entry = er.async_get(hass).async_get(eid)
            if (
                domain not in GUEST_ACTIONS
                or state is None
                or state.state in {"unknown", "unavailable"}
                or entry is None
                or entry.disabled_by is not None
                or entry.platform in {"group", "template"}
                or "entity_id" in state.attributes
                or not _satellite_readable(hass, native, role, eid)
                or (domain == "media_player" and (
                    entry.platform != "music_assistant"
                    or state.attributes.get("mass_player_type", "player") != "player"
                    or state.attributes.get("group_members", []) not in ([], [eid])
                ))
            ):
                return AccessDecision(False, "denied")
            if operation == "read":
                continue
            if (
                operation not in GUEST_ACTIONS[domain]
                or not role.check_entity(eid, POLICY_CONTROL)
                or (native is not None and not native.check_entity(eid, POLICY_CONTROL))
                or not role.tier_allowed(f"{domain}.{operation}", TIER_OPEN)
                or (operation == "play_media" and not role.tier_allowed(
                    "music_assistant.play_media", TIER_OPEN
                ))
            ):
                return AccessDecision(False, "denied")
    except Exception:  # noqa: BLE001 -- provider/role failure never grants authority
        return AccessDecision(False, "policy_unavailable")
    return AccessDecision(True, "allowed")


async def async_project_guest_context(
    hass: HomeAssistant, entity_ids: tuple[str, ...], *, guest_role_id: str,
) -> dict:
    """Project names/states under the selected guest role only."""
    return await async_project_voice_context(hass, entity_ids, guest_role_id=guest_role_id)


async def async_project_voice_context(
    hass: HomeAssistant, entity_ids: tuple[str, ...], *,
    guest_role_id: str | None = None, user_id: str | None = None,
) -> dict:
    """Bounded, filtered names/states only; no role rules or private attributes."""
    unavailable = {"available": False, "entities": []}
    if not _satellite_request_valid(entity_ids, (), "read"):
        return unavailable
    try:
        permitted = tuple([
            eid for eid in entity_ids
            if (await async_check_voice_action(
                hass, (eid,), guest_role_id=guest_role_id, user_id=user_id,
            )).allowed
        ])
        if not permitted:
            return {"available": True, "entities": []}
        return await async_project_satellite_context(
            hass, permitted, guest_role_id=guest_role_id, user_id=user_id,
        )
    except Exception:  # noqa: BLE001 -- never return a partial projection on errors
        return unavailable


VOICE_REFERENCE_VERSION = 1
VOICE_CAPABILITY_VERSION = 1
TIMER_POLICY_VERSION = 1


async def async_check_timer_access(hass, satellite_ids, **kwargs):
    """Check exact cross-satellite timer read/cancel rights; never execute an action."""
    from .timer_policy import check  # noqa: PLC0415

    return await check(hass, satellite_ids, **kwargs)


async def async_check_voice_capability(hass, entity_ids, **kwargs):
    """Check a finite ordinary capability without widening legacy action interfaces."""
    from .voice_capabilities import check  # noqa: PLC0415

    return await check(hass, entity_ids, **kwargs)


async def async_project_voice_capabilities(hass, entity_ids, **kwargs):
    """Project curated ordinary-device state under current native/RBAC read policy."""
    from .voice_capabilities import project  # noqa: PLC0415

    return await project(hass, entity_ids, **kwargs)


async def async_project_voice_references(
    hass: HomeAssistant, entity_ids: tuple[str, ...], *,
    guest_role_id: str | None = None, user_id: str | None = None,
) -> dict:
    """Return permitted conversational references, never group execution authority."""
    from homeassistant.helpers import area_registry as ar  # noqa: PLC0415
    from homeassistant.helpers import device_registry as dr  # noqa: PLC0415
    from homeassistant.helpers import entity_registry as er  # noqa: PLC0415

    unavailable = {"available": False, "references": []}
    if (
        type(entity_ids) is not tuple or not 0 < len(entity_ids) <= 1024
        or any(type(eid) is not str or not ENTITY_ID.fullmatch(eid)
               or eid.partition(".")[0] not in set(GUEST_ACTIONS) | {"climate", "cover"}
               for eid in entity_ids)
        or len(set(entity_ids)) != len(entity_ids)
    ):
        return unavailable
    rbac = hass.data.get(DATA_RBAC)
    if rbac is None:
        return unavailable
    try:
        resolved = await _satellite_permissions(hass, rbac, user_id, guest_role_id)
        if resolved is None or hass.data.get(DATA_RBAC) is not rbac:
            return unavailable
        native, role = resolved
        entities, devices, areas = er.async_get(hass), dr.async_get(hass), ar.async_get(hass)

        def text(value):
            return type(value) is str and 0 < len(value) <= 128 and value.isprintable()

        def reference(eid):
            state, entry = hass.states.get(eid), entities.async_get(eid)
            if (
                state is None or state.state in {"unknown", "unavailable"}
                or entry is None or entry.disabled_by is not None
                or not _satellite_readable(hass, native, role, eid)
                or role.attribute_hidden(eid, "friendly_name") or not text(state.name)
            ):
                return None
            row = {"entity_id": eid, "name": state.name}
            if not role.attribute_hidden(eid, "aliases"):
                row["aliases"] = sorted(alias for alias in entry.aliases if text(alias))[:8]
            device = devices.async_get(entry.device_id) if entry.device_id else None
            area = areas.async_get_area(entry.area_id or (device.area_id if device else None))
            if area and not any(role.attribute_hidden(eid, key) for key in (
                "area", "area_id", "area_name",
            )) and text(area.name):
                row["area"] = area.name
                if not role.attribute_hidden(eid, "area_aliases"):
                    row["area_aliases"] = sorted(
                        alias for alias in area.aliases if text(alias)
                    )[:8]
            return row

        visible = {}
        for eid in entity_ids:
            state, entry = hass.states.get(eid), entities.async_get(eid)
            if (state is None or entry is None or entry.platform in {"group", "template"}
                    or "entity_id" in state.attributes
                    or (state.domain == "cover" and state.attributes.get("device_class")
                        not in {"blind", "shade", "curtain", "shutter", "awning"})):
                continue
            if row := reference(eid):
                visible[eid] = row
        references = [visible[eid] for eid in sorted(visible)]
        # A group is only a descriptive alias for exact individually readable
        # direct members. No nested/template/dynamic group is an executable target.
        groups = 0
        for state in sorted(hass.states.async_all(), key=lambda state: state.entity_id):
            members = state.attributes.get("entity_id")
            entry = entities.async_get(state.entity_id)
            if (
                state.domain not in {"light", "switch", "fan", "group"}
                or entry is None or entry.platform != "group"
                or type(members) is not list or not 0 < len(members) <= 32
                or any(type(eid) is not str or eid not in visible
                       or eid.partition(".")[0] not in {"light", "switch", "fan"}
                       or "entity_id" in hass.states.get(eid).attributes for eid in members)
                or len(set(members)) != len(members)
            ):
                continue
            if row := reference(state.entity_id):
                row["members"] = sorted(members)
                references.append(row)
                groups += 1
                if groups == 32:
                    break
    except Exception:  # noqa: BLE001 -- discard partial metadata on policy failure
        return unavailable
    else:
        return {"available": True, "references": references}
