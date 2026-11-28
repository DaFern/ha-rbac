"""Guest domains use compiled RBAC rules; ordinary intent denials stay intact."""

from types import SimpleNamespace

import pytest
from homeassistant.components.homeassistant.exposed_entities import async_expose_entity
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component

from custom_components.ha_rbac import assist_policy
from custom_components.ha_rbac.const import DATA_RBAC, TIER_ADMIN, TIER_OPEN, TIER_USER
from custom_components.ha_rbac.policy import Evaluator, default_roles

DOMAINS = ("switch", "light", "fan", "media_player")


@pytest.fixture
async def guest(hass):
    """Build a real evaluator and exposed synthetic devices without live bindings."""
    assert await async_setup_component(hass, "homeassistant", {})
    for domain in (*DOMAINS, "lock", "script", "climate"):
        platform = "music_assistant" if domain == "media_player" else "test"
        entry = er.async_get(hass).async_get_or_create(
            domain,
            platform,
            f"guest-{domain}",
            suggested_object_id="guest",
        )
        hass.states.async_set(entry.entity_id, "off", {"friendly_name": "Guest device"})
        async_expose_entity(hass, "conversation", entry.entity_id, True)
    store = SimpleNamespace(
        roles={
            **default_roles(),
            "voice_guest": {
                "id": "voice_guest",
                "name": "Voice guest",
                "allow": {
                    "entities": {
                        "domains": {
                            domain: {"read": True, "control": True}
                            for domain in DOMAINS
                        }
                    }
                },
                "deny": {},
            },
        },
        bindings={},
        global_deny={},
    )
    evaluator = Evaluator(hass, store)
    hass.data[DATA_RBAC] = SimpleNamespace(store=store, evaluator=evaluator)
    return SimpleNamespace(store=store, evaluator=evaluator)


async def check(hass, ids, operation="read", role="voice_guest"):
    """Ask the real guest oracle for a single boolean decision."""
    return (
        await assist_policy.async_check_guest_action(
            hass,
            ids,
            guest_role_id=role,
            operation=operation,
        )
    ).allowed


@pytest.mark.parametrize("domain", DOMAINS)
async def test_selected_domains_and_current_rules_apply(hass, guest, domain):
    """Removing a domain immediately revokes both control and projected context."""
    eid = f"{domain}.guest"
    operation = "media_play" if domain == "media_player" else "turn_on"
    assert await check(hass, (eid,), operation)
    guest.store.roles["voice_guest"]["allow"]["entities"]["domains"].pop(domain)
    guest.evaluator.invalidate()
    assert not await check(hass, (eid,), operation)
    rows = await assist_policy.async_project_guest_context(
        hass,
        (eid,),
        guest_role_id="voice_guest",
    )
    assert rows["entities"] == []


async def test_domain_grants_include_future_entities_without_a_second_allowlist(
    hass, guest
):
    """A selected domain covers new devices through the existing compiler."""
    entry = er.async_get(hass).async_get_or_create(
        "switch",
        "test",
        "later-plug",
        suggested_object_id="later",
    )
    hass.states.async_set(entry.entity_id, "off")
    async_expose_entity(hass, "conversation", entry.entity_id, True)
    assert await check(hass, (entry.entity_id,), "turn_on")


@pytest.mark.parametrize(
    "operation",
    [
        "media_play",
        "media_pause",
        "media_next_track",
        "media_previous_track",
        "volume_up",
        "volume_down",
        "volume_set",
        "clear_playlist",
        "play_media",
    ],
)
async def test_only_fixed_music_capabilities(hass, guest, operation):
    """The music vocabulary is finite even when its domain is granted."""
    assert await check(hass, ("media_player.guest",), operation)


@pytest.mark.parametrize(
    ("domain", "operation"),
    [
        ("lock", "unlock"),
        ("script", "turn_on"),
        ("climate", "set_temperature"),
        ("switch", "toggle"),
        ("light", "volume_set"),
        ("media_player", "join"),
        ("media_player", "turn_on"),
        ("media_player", "browse_media"),
    ],
)
async def test_domain_selection_does_not_mean_arbitrary_service_access(
    hass,
    guest,
    domain,
    operation,
):
    """Unsupported domains and services stay closed despite broader role data."""
    guest.store.roles["voice_guest"]["allow"]["entities"]["domains"][domain] = {
        "read": True,
        "control": True,
    }
    guest.evaluator.invalidate()
    assert not await check(hass, (f"{domain}.guest",), operation)


@pytest.mark.parametrize(
    "change",
    [
        "removed_role",
        "read_only",
        "entity_deny",
        "unexposed",
        "unavailable",
        "group",
        "template",
        "members",
        "hidden_state",
    ],
)
async def test_deny_and_revocation_always_win(hass, guest, change):
    """A former grant is not a reusable guest capability."""
    eid = "switch.guest"
    assert await check(hass, (eid,), "turn_on")
    role = guest.store.roles["voice_guest"]
    if change == "removed_role":
        guest.store.roles.pop("voice_guest")
    elif change == "read_only":
        role["allow"]["entities"]["domains"]["switch"]["control"] = False
    elif change == "entity_deny":
        role["deny"] = {"entities": {"entity_ids": {eid: True}}}
    elif change == "hidden_state":
        role["attributes"] = {"deny": ["state"]}
    elif change == "unexposed":
        async_expose_entity(hass, "conversation", eid, False)
    elif change == "unavailable":
        hass.states.async_set(eid, "unavailable")
    elif change == "members":
        hass.states.async_set(eid, "off", {"entity_id": ["switch.other"]})
    else:
        registry = er.async_get(hass)
        registry.async_remove(eid)
        registry.async_get_or_create(
            "switch", change, "replacement", suggested_object_id="guest"
        )
    guest.evaluator.invalidate()
    assert not await check(hass, (eid,), "turn_on")


@pytest.mark.parametrize(
    "attributes",
    [
        {"mass_player_type": "group"},
        {"group_members": ["media_player.other"]},
        {"group_members": ["media_player.guest", "media_player.other"]},
    ],
)
async def test_music_groups_cannot_broaden_role_access(hass, guest, attributes):
    """Music controls cannot target a group containing other players."""
    hass.states.async_set("media_player.guest", "idle", attributes)
    assert not await check(hass, ("media_player.guest",), "media_play")


async def test_mixed_batch_and_missing_or_full_access_roles_are_denied(hass, guest):
    """A guest cannot borrow an admin role or partially execute a mixed batch."""
    assert not await check(hass, ("switch.guest", "lock.guest"), "turn_on")
    assert not await check(hass, ("switch.guest",), "turn_on", role="missing")
    assert not await check(hass, ("switch.guest",), "turn_on", role="admin")
    assert not await check(hass, ("switch.guest",), "turn_on", role="")


async def test_role_choices_contain_no_rules_and_exclude_full_access(hass, guest):
    """The options flow receives bounded restricted-role labels only."""
    result = await assist_policy.async_guest_role_choices(hass)
    assert result["available"]
    assert {"id": "voice_guest", "name": "Voice guest"} in result["roles"]
    assert all(set(row) == {"id", "name"} for row in result["roles"])
    assert "admin" not in {row["id"] for row in result["roles"]}


async def test_guest_projection_contains_only_current_supported_domain_grants(
    hass, guest
):
    """A positive context must not silently become an unavailable empty snapshot."""
    ids = tuple(f"{domain}.guest" for domain in (*DOMAINS, "lock", "script"))
    result = await assist_policy.async_project_guest_context(
        hass,
        ids,
        guest_role_id="voice_guest",
    )
    assert result["available"] is True
    assert {row["entity_id"] for row in result["entities"]} == {
        f"{domain}.guest" for domain in DOMAINS
    }
    assert all(row["attributes"] == {} for row in result["entities"])


@pytest.mark.parametrize("tier", [TIER_OPEN, TIER_USER, TIER_ADMIN])
@pytest.mark.parametrize(
    "command",
    [
        "conversation/process",
        "conversation.process",
        "assist_pipeline/run",
        "assist_satellite/intercept_wake_word",
    ],
)
async def test_guest_domains_never_relax_the_existing_intent_boundary(
    hass,
    guest,
    tier,
    command,
):
    """Domain grants never bypass the ordinary free-text intent denial."""
    permissions = guest.evaluator.async_guest_permissions("voice_guest")
    assert not permissions.tier_allowed(command, tier)
