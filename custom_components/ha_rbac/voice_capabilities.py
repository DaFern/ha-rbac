"""Finite ordinary-device capabilities; no generic service or security-device bridge."""

import math

from homeassistant.auth.permissions.const import POLICY_CONTROL
from homeassistant.components.climate.const import ClimateEntityFeature
from homeassistant.components.cover.const import CoverEntityFeature
from homeassistant.components.fan import FanEntityFeature
from homeassistant.components.media_player.const import MediaPlayerEntityFeature
from homeassistant.helpers import entity_registry as er

from .assist_policy import AccessDecision, _satellite_permissions, _satellite_readable
from .const import DATA_RBAC, TIER_OPEN

VERSION = 1
DOMAINS = frozenset({"light", "switch", "fan", "climate", "cover", "media_player"})
BLINDS = frozenset({"blind", "shade", "curtain", "shutter", "awning"})
MEDIA = {
    "stop": ("media_stop", MediaPlayerEntityFeature.STOP),
    "pause": ("media_pause", MediaPlayerEntityFeature.PAUSE),
    "resume": ("media_play", MediaPlayerEntityFeature.PLAY),
    "next": ("media_next_track", MediaPlayerEntityFeature.NEXT_TRACK),
    "previous": ("media_previous_track", MediaPlayerEntityFeature.PREVIOUS_TRACK),
    "volume": ("volume_set", MediaPlayerEntityFeature.VOLUME_SET),
    "volume_up": ("volume_up", MediaPlayerEntityFeature.VOLUME_STEP),
    "volume_down": ("volume_down", MediaPlayerEntityFeature.VOLUME_STEP),
    "mute": ("volume_mute", MediaPlayerEntityFeature.VOLUME_MUTE),
    "unmute": ("volume_mute", MediaPlayerEntityFeature.VOLUME_MUTE),
    "seek": ("media_seek", MediaPlayerEntityFeature.SEEK),
    "shuffle": ("shuffle_set", MediaPlayerEntityFeature.SHUFFLE_SET),
    "repeat": ("repeat_set", MediaPlayerEntityFeature.REPEAT_SET),
    "power_on": ("turn_on", MediaPlayerEntityFeature.TURN_ON),
    "power_off": ("turn_off", MediaPlayerEntityFeature.TURN_OFF),
    "source": ("select_source", MediaPlayerEntityFeature.SELECT_SOURCE),
}
ATTRIBUTES = {
    "light": {
        "brightness",
        "color_mode",
        "supported_color_modes",
        "rgb_color",
        "color_temp_kelvin",
        "min_color_temp_kelvin",
        "max_color_temp_kelvin",
    },
    "switch": set(),
    "fan": {"percentage", "oscillating", "direction"},
    "climate": {
        "temperature",
        "current_temperature",
        "min_temp",
        "max_temp",
        "temperature_unit",
        "hvac_modes",
        "preset_modes",
        "preset_mode",
    },
    "cover": {"device_class", "current_position"},
    "media_player": {
        "volume_level",
        "is_volume_muted",
        "media_position",
        "media_duration",
        "media_title",
        "media_artist",
        "shuffle",
        "repeat",
        "source",
        "source_list",
    },
}


def _number(value, minimum, maximum):
    return (
        type(value) in {int, float}
        and math.isfinite(value)
        and minimum <= value <= maximum
    )


def _context_value(value):
    if type(value) is bool or _number(value, -1e9, 1e9):
        return value
    if type(value) is str and value.isprintable() and len(value) <= 256:
        return value
    if isinstance(value, (list, tuple, set)) and len(value) <= 64:
        result = [_context_value(item) for item in value]
        if all(item is not None and not isinstance(item, list) for item in result):
            return sorted(result) if type(value) is set else result
    return None


def _light_plan(attrs, args):
    """Only supported brightness/RGB/colour-temperature settings become light arguments."""
    data = {}
    modes = attrs.get("supported_color_modes", [])
    if "level" in args:
        if not _number(args["level"], 0, 100) or not set(modes) - {"onoff"}:
            return None
        data["brightness_pct"] = args["level"]
    if "rgb" in args:
        rgb = args["rgb"]
        if (
            not isinstance(rgb, (list, tuple))
            or len(rgb) != 3
            or any(type(item) is not int or not 0 <= item <= 255 for item in rgb)
            or not set(modes) & {"rgb", "rgbw", "rgbww", "hs", "xy"}
        ):
            return None
        data["rgb_color"] = list(rgb)
    if "kelvin" in args:
        if (
            "rgb" in args
            or "color_temp" not in modes
            or not _number(
                args["kelvin"],
                attrs.get("min_color_temp_kelvin", 1000),
                attrs.get("max_color_temp_kelvin", 20000),
            )
        ):
            return None
        data["color_temp_kelvin"] = args["kelvin"]
    return ("turn_on", data) if data else None


def prepare(state, action, args):
    """Resolve a typed action to one fixed service and validated exact arguments."""
    domain, attrs = state.domain, state.attributes
    features = attrs.get("supported_features", 0)
    if type(features) is not int:
        features = int(features) if isinstance(features, int) else 0
    if action in {"turn_on", "turn_off"} and domain in {"light", "switch", "fan"}:
        return action, {}
    if domain == "light" and action == "set_light":
        return _light_plan(attrs, args)
    if domain == "fan" and action == "set_fan_speed":
        if features & FanEntityFeature.SET_SPEED and _number(args.get("level"), 0, 100):
            return "set_percentage", {"percentage": args["level"]}
    if domain == "climate":
        if (
            action == "set_temperature"
            and features & ClimateEntityFeature.TARGET_TEMPERATURE
        ):
            low, high = attrs.get("min_temp"), attrs.get("max_temp")
            if _number(low, -100, 1000) and _number(high, low, 1000):
                if _number(args.get("temperature"), low, high):
                    return "set_temperature", {"temperature": args["temperature"]}
        if action == "set_hvac_mode" and args.get("mode") in attrs.get(
            "hvac_modes", []
        ):
            return "set_hvac_mode", {"hvac_mode": args["mode"]}
        if (
            action == "set_preset"
            and features & ClimateEntityFeature.PRESET_MODE
            and args.get("mode") in attrs.get("preset_modes", [])
        ):
            return "set_preset_mode", {"preset_mode": args["mode"]}
    if domain == "cover" and attrs.get("device_class") in BLINDS:
        simple = {
            "open_blind": ("open_cover", CoverEntityFeature.OPEN),
            "close_blind": ("close_cover", CoverEntityFeature.CLOSE),
            "stop_blind": ("stop_cover", CoverEntityFeature.STOP),
        }
        if action in simple and features & simple[action][1]:
            return simple[action][0], {}
        if (
            action == "set_blind_position"
            and features & CoverEntityFeature.SET_POSITION
            and _number(args.get("level"), 0, 100)
        ):
            return "set_cover_position", {"position": args["level"]}
    if domain == "media_player" and action in MEDIA and features & MEDIA[action][1]:
        service, _feature = MEDIA[action]
        if action == "volume":
            return (
                (service, {"volume_level": args["level"] / 100})
                if _number(
                    args.get("level"),
                    0,
                    100,
                )
                else None
            )
        if action in {"mute", "unmute"}:
            return service, {"is_volume_muted": action == "mute"}
        if action == "seek":
            duration = attrs.get("media_duration")
            if _number(duration, 0, 86400) and _number(
                args.get("position"), 0, duration
            ):
                return service, {"seek_position": args["position"]}
            return None
        if action == "shuffle":
            return (
                (service, {"shuffle": args["enabled"]})
                if type(
                    args.get("enabled"),
                )
                is bool
                else None
            )
        if action == "repeat":
            return (
                (service, {"repeat": args["mode"]})
                if args.get("mode")
                in {
                    "off",
                    "one",
                    "all",
                }
                else None
            )
        if action == "source":
            return (
                (service, {"source": args["mode"]})
                if args.get("mode")
                in attrs.get(
                    "source_list",
                    [],
                )
                else None
            )
        return service, {}
    return None


def supported_actions(state, native, role):
    """Advertise only fixed actions currently supported by both device and policy."""
    attrs = state.attributes

    def first(key):
        values = attrs.get(key)
        return values[0] if isinstance(values, (list, tuple)) and values else None

    candidates = {
        **{
            name: {}
            for name in (
                "turn_on",
                "turn_off",
                "open_blind",
                "close_blind",
                "stop_blind",
                "stop",
                "pause",
                "resume",
                "next",
                "previous",
                "volume_up",
                "volume_down",
                "mute",
                "unmute",
                "power_on",
                "power_off",
            )
        },
        "set_light": {"level": 50},
        "set_fan_speed": {"level": 50},
        "set_temperature": {"temperature": attrs.get("min_temp")},
        "set_hvac_mode": {"mode": first("hvac_modes")},
        "set_preset": {"mode": first("preset_modes")},
        "set_blind_position": {"level": 50},
        "volume": {"level": 50},
        "seek": {"position": 0},
        "shuffle": {"enabled": True},
        "repeat": {"mode": "off"},
        "source": {"mode": first("source_list")},
    }
    result = []
    if not role.check_entity(state.entity_id, POLICY_CONTROL) or (
        native is not None and not native.check_entity(state.entity_id, POLICY_CONTROL)
    ):
        return result
    for action, args in candidates.items():
        try:
            plan = prepare(state, action, args)
            if (
                plan
                and role.tier_allowed(f"{state.domain}.{plan[0]}", TIER_OPEN)
                and not any(
                    role.attribute_hidden(state.entity_id, key) for key in plan[1]
                )
                and not (
                    "brightness_pct" in plan[1]
                    and role.attribute_hidden(state.entity_id, "brightness")
                )
            ):
                result.append(action)
        except (TypeError, ValueError, KeyError):
            continue  # Malformed device metadata is not an advertised capability.
    return result


async def check(
    hass, ids, *, user_id=None, guest_role_id=None, action="read", args=None
):
    """Check exact current capabilities and role/native permission before each effect."""
    if (
        type(ids) is not tuple
        or not 0 < len(ids) <= 32
        or any(type(eid) is not str or len(eid) > 255 for eid in ids)
        or len(set(ids)) != len(ids)
        or type(action) is not str
        or (args is not None and type(args) is not dict)
    ):
        return AccessDecision(False, "invalid_request")
    rbac = hass.data.get(DATA_RBAC)
    try:
        resolved = (
            await _satellite_permissions(hass, rbac, user_id, guest_role_id)
            if rbac
            else None
        )
        if resolved is None or hass.data.get(DATA_RBAC) is not rbac:
            return AccessDecision(False, "invalid_subject")
        native, role = resolved
        registry = er.async_get(hass)
        for eid in ids:
            state, entry = hass.states.get(eid), registry.async_get(eid)
            if (
                state is None
                or state.domain not in DOMAINS
                or state.state in {"unavailable", "unknown"}
                or entry is None
                or entry.disabled_by is not None
                or entry.platform in {"group", "template"}
                or "entity_id" in state.attributes
                or not _satellite_readable(hass, native, role, eid)
                or (
                    state.domain == "cover"
                    and (
                        state.attributes.get("device_class") not in BLINDS
                        or role.attribute_hidden(eid, "device_class")
                    )
                )
                or (
                    state.domain == "media_player"
                    and (
                        state.attributes.get("group_members", []) not in ([], [eid])
                        or state.attributes.get("mass_player_type", "player")
                        != "player"
                    )
                )
            ):
                return AccessDecision(False, "denied")
            if action == "read":
                continue
            plan = prepare(state, action, args or {})
            if (
                plan is None
                or not role.check_entity(eid, POLICY_CONTROL)
                or (native is not None and not native.check_entity(eid, POLICY_CONTROL))
                or not role.tier_allowed(f"{state.domain}.{plan[0]}", TIER_OPEN)
                or any(role.attribute_hidden(eid, key) for key in plan[1])
                or (
                    "brightness_pct" in plan[1]
                    and role.attribute_hidden(eid, "brightness")
                )
            ):
                return AccessDecision(False, "denied")
    except Exception:  # noqa: BLE001 -- unknown capability or policy fails closed
        return AccessDecision(False, "policy_unavailable")
    return AccessDecision(True, "allowed")


async def project(hass, ids, *, user_id=None, guest_role_id=None):
    """Project only curated readable scalar/device-option state, never raw attributes."""
    result = []
    if type(ids) is not tuple or not 0 < len(ids) <= 32:
        return {"available": False, "entities": []}
    try:
        for eid in ids:
            if not (
                await check(
                    hass,
                    (eid,),
                    user_id=user_id,
                    guest_role_id=guest_role_id,
                )
            ).allowed:
                continue
            rbac = hass.data.get(DATA_RBAC)
            resolved = await _satellite_permissions(hass, rbac, user_id, guest_role_id)
            if resolved is None:
                return {"available": False, "entities": []}
            native, role = resolved
            state = hass.states.get(eid)
            if not _satellite_readable(hass, native, role, eid):
                continue
            row = {"entity_id": eid, "state": state.state, "attributes": {}}
            if not role.attribute_hidden(eid, "friendly_name"):
                if name := _context_value(state.name):
                    row["name"] = name
            for key in ATTRIBUTES[state.domain]:
                if not role.attribute_hidden(eid, key):
                    raw = state.attributes.get(key)
                    if key == "temperature_unit" and raw is None:
                        raw = str(hass.config.units.temperature_unit)
                    value = _context_value(raw)
                    if value is not None:
                        row["attributes"][key] = value
            if not role.attribute_hidden(eid, "supported_actions"):
                row["attributes"]["supported_actions"] = supported_actions(
                    state, native, role
                )
            if not role.attribute_hidden(eid, "readable_fields"):
                row["attributes"]["readable_fields"] = sorted(
                    key
                    for key in ATTRIBUTES[state.domain] | {"supported_actions"}
                    if not role.attribute_hidden(eid, key)
                )
            result.append(row)
    except Exception:  # noqa: BLE001 -- never return a partially uncertain projection
        return {"available": False, "entities": []}
    return {"available": True, "entities": result}
