"""Transport-owned satellite admission contract; no live transport is registered.

Only trusted integration code may register an authenticated connection. The
connection validator must derive liveness from that transport, not client JSON,
an entity ID, an event, or a user-supplied ``is_authenticated`` flag. This module
does not authenticate a network connection or intercept HA's default pipeline.
"""

import asyncio
import time
from dataclasses import dataclass

from homeassistant.core import Context
from homeassistant.helpers import entity_registry as er

SATELLITE_ADMISSION_VERSION = 1
ADMISSION_TTL = 30
MAX_CONNECTIONS = 32
MAX_ADMISSIONS = 256


@dataclass(eq=False, repr=False)
class _Connection:
    session: object
    satellite_id: str
    identity: tuple
    validator: object
    active: bool = True


@dataclass(frozen=True, eq=False, repr=False)
class _Admission:
    context: Context
    caller: str | None
    owner: object
    connection: _Connection
    issued: float
    expires: float


class SatelliteTransportBinding:
    """Server-held handle, never exposed to a device, model or serialized request."""

    def __init__(self, registry, connection):
        """Keep the exact registered connection, not a reconstructable device ID."""
        self._registry = registry
        self._connection = connection

    def admit(self, context):
        """Call on the actual audio pipeline task with its original HA Context."""
        return self._registry._admit(self._connection, context)  # noqa: SLF001

    def close(self):
        """Revoke this connection before cancelling its active pipeline tasks."""
        return self._registry._disconnect(self._connection)  # noqa: SLF001

    async def async_close(self):
        """Wait for cancellation, including awaited native child work."""
        tasks = self.close()
        await asyncio.gather(*tasks, return_exceptions=True)


class SatelliteAdmissionRegistry:
    """Entry-owned registry for a future authenticated, protected audio adapter.

    The adapter must enter here instead of HA's ordinary sentence-trigger/local
    intent pipeline. Registering a binding does not make that adapter exist.
    No anonymous public ingress, HA user substitution or baseline exception is
    installed. Device/user strings in ordinary conversation inputs confer nothing.
    """

    def __init__(self, hass, provider, *, approved_satellite_ids=frozenset()):
        """Bind one provider to administrator-owned satellite enrollment."""
        if (
            getattr(provider, "hass", None) is not hass
            or type(getattr(provider, "SATELLITE_DISPATCH_VERSION", None)) is not int
            or provider.SATELLITE_DISPATCH_VERSION != SATELLITE_ADMISSION_VERSION
            or not isinstance(approved_satellite_ids, frozenset)
            or len(approved_satellite_ids) > MAX_CONNECTIONS
            or any(not isinstance(eid, str) for eid in approved_satellite_ids)
        ):
            raise ValueError("Unsupported satellite provider")
        self.hass = hass
        self._provider = provider
        self._approved = approved_satellite_ids
        self._connections = {}
        self._pending = {}
        self._active = {}
        self._closed = False
        if provider.bind_satellite_ingress(self.is_current) is not True:
            raise ValueError("Satellite provider already bound")

    def _identity(self, satellite_id):
        entry = er.async_get(self.hass).async_get(satellite_id)
        if (
            entry is None
            or entry.domain != "assist_satellite"
            or entry.disabled_by is not None
            or not entry.device_id
        ):
            return None
        return (
            entry.id,
            entry.unique_id,
            entry.platform,
            entry.config_entry_id,
            entry.device_id,
        )

    def register_transport(self, satellite_id, session, *, connection_is_current):
        """Trusted transport code binds a verified session to an enrolled satellite.

        The callback must also check transport credentials/configuration revisions.
        It runs synchronously again at every final native service admission.
        Arbitrary Python integrations are trusted peers, not sandboxed clients.
        """
        if (
            self._closed
            or not isinstance(satellite_id, str)
            or satellite_id not in self._approved
            or session is None
            or id(session) in self._connections
            or len(self._connections) >= MAX_CONNECTIONS
            or not callable(connection_is_current)
            or (identity := self._identity(satellite_id)) is None
        ):
            raise ValueError("Unapproved satellite connection")
        connection = _Connection(session, satellite_id, identity, connection_is_current)
        self._connections[id(session)] = connection
        if not self._connected(connection):
            self._disconnect(connection)
            raise ValueError("Satellite connection is not current")
        return SatelliteTransportBinding(self, connection)

    def _connected(self, connection):
        try:
            return (
                not self._closed
                and connection.active
                and self._connections.get(id(connection.session)) is connection
                and connection.satellite_id in self._approved
                and self._identity(connection.satellite_id) == connection.identity
                and connection.validator(connection.session) is True
            )
        except Exception:  # noqa: BLE001 -- connection failure never broadens admission
            return False

    def _live(self, admission):
        return (
            self._connected(admission.connection)
            and admission.context.user_id == admission.caller
            and admission.expires > time.monotonic()
            and not admission.owner.done()
            and not admission.owner.cancelling()
        )

    def is_current(self, admission):
        """Validate active admission inside native child tasks, not just the parent."""
        return (
            isinstance(admission, _Admission)
            and self._active.get(id(admission)) is admission
            and self._live(admission)
        )

    def _admit(self, connection, context):
        now = time.monotonic()
        self._pending = {
            key: item for key, item in self._pending.items() if item.expires > now
        }
        owner = asyncio.current_task()
        if (
            not self._connected(connection)
            or not isinstance(context, Context)
            or (context.user_id is not None and not isinstance(context.user_id, str))
            or owner is None
            or owner.cancelling()
            or len(self._pending) + len(self._active) >= MAX_ADMISSIONS
            or any(item.owner is owner for item in self._pending.values())
            or any(item.owner is owner for item in self._active.values())
        ):
            return None
        admission = _Admission(
            context,
            context.user_id,
            owner,
            connection,
            now,
            now + ADMISSION_TTL,
        )
        self._pending[id(admission)] = admission
        return admission

    async def async_dispatch(self, admission, *, transcript, command):
        """Consume exact admission before awaits; never forward a denial elsewhere."""
        return await self._async_dispatch(
            admission, "async_dispatch", transcript=transcript, command=command
        )

    async def async_guest_turn(self, admission, *, transcript, handler):
        """Admit a trusted server-owned guest handler, never a client callback."""
        if not callable(handler):
            return {"status": "denied", "completed": 0}
        return await self._async_dispatch(
            admission, "async_guest_turn", transcript=transcript, handler=handler
        )

    async def async_voice_turn(self, admission, *, transcript, handler):
        """Protected matched/neutral turn; no changes to ordinary Assist ingress."""
        if not callable(handler):
            return {"status": "denied", "completed": 0}
        return await self._async_dispatch(
            admission, "async_voice_turn", transcript=transcript, handler=handler
        )

    def discard_pending(self, admission):
        """Release an unfinished STT turn without dispatching or renewing it."""
        if (
            isinstance(admission, _Admission)
            and admission.owner is asyncio.current_task()
            and self._pending.get(id(admission)) is admission
        ):
            self._pending.pop(id(admission))

    async def _async_dispatch(self, admission, method, **kwargs):
        """Share the exact one-use transport boundary between fixed capabilities."""
        denied = {"status": "denied", "completed": 0}
        if (
            not isinstance(admission, _Admission)
            or self._pending.pop(id(admission), None) is not admission
            or admission.owner is not asyncio.current_task()
            or not self._live(admission)
        ):
            return denied
        self._active[id(admission)] = admission
        try:
            result = await getattr(self._provider, method)(admission, **kwargs)
            if (
                type(result) is not dict
                or set(result) != {"status", "completed"}
                or result["status"]
                not in {"completed", "partial", "denied", "unconfirmed"}
                or type(result["completed"]) is not int
                or not 0 <= result["completed"] <= 32
            ):
                return {"status": "unconfirmed", "completed": 0}
            return dict(result)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 -- never expose policy/transport details
            return {"status": "unconfirmed", "completed": 0}
        finally:
            self._active.pop(id(admission), None)

    def _disconnect(self, connection):
        connection.active = False
        if self._connections.get(id(connection.session)) is connection:
            self._connections.pop(id(connection.session))
        tasks = {
            item.owner
            for item in (*self._pending.values(), *self._active.values())
            if item.connection is connection
            and item.owner is not asyncio.current_task()
        }
        self._pending = {
            key: item
            for key, item in self._pending.items()
            if item.connection is not connection
        }
        for task in tasks:
            task.cancel()
        return tasks

    def close(self):
        """Revoke all connections/leases before stopping the protected dispatcher."""
        self._closed = True
        tasks = set()
        for connection in tuple(self._connections.values()):
            tasks.update(self._disconnect(connection))
        self._pending.clear()
        self._provider.close()
        return tasks

    async def async_close(self):
        """Revoke first, then wait for all pipeline cancellation to finish."""
        await asyncio.gather(*self.close(), return_exceptions=True)
