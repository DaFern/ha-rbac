"""Dormant in-process protected Assist admission; NOT Supervisor add-on ingress.

Nothing registers this from setup or exempts a proxy/HTTP/WebSocket command.
Trusted server adapters must authenticate HA Context and establish a source
binding before calling admit(). Payload fields are never identity evidence.
Registration is coordination between trusted integrations, not a sandbox for
arbitrary Python providers or proof that a network endpoint is safe to expose.
"""

import asyncio
import time
from dataclasses import dataclass, field

from homeassistant.core import Context

INGRESS_API_VERSION = 1
ADMISSION_TTL = 30
MAX_ADMISSIONS = 256
MAX_PROVIDERS = 16


def _denied():
    return {"status": "denied", "completed": 0}


@dataclass(eq=False, repr=False)
class _Registration:
    destination: str
    provider: object
    kiosks: frozenset
    sources: tuple
    active: bool = True


@dataclass(frozen=True, eq=False, repr=False)
class _Admission:
    context: Context
    caller: str
    owner: object = field(repr=False)
    registration: _Registration = field(repr=False)
    expires: float


class ProtectedAssistIngress:
    """Entry-independent RBAC registry, explicitly instantiated by tests only.

    A future authenticated transport adapter must derive Context/source from its
    server connection, NEVER request JSON, a selected agent or a device_id string.
    The original pipeline task must own both admission and STT handoff consumption.
    """

    def __init__(self, hass):
        """Create an empty registry; do not attach any HA route."""
        self.hass = hass
        self._providers = {}
        self._pending = {}
        self._active = {}
        self._closed = False

    def register(self, destination, provider, *, kiosk_user_ids, source_bindings):
        """Explicit trusted-code handshake; return exact-registration teardown."""
        if (self._closed or not isinstance(destination, str) or not 0 < len(destination) <= 128
                or destination in self._providers or len(self._providers) >= MAX_PROVIDERS
                or not isinstance(kiosk_user_ids, frozenset) or not 0 < len(kiosk_user_ids) <= 32
                or any(not isinstance(uid, str) or not uid for uid in kiosk_user_ids)
                or not isinstance(source_bindings, tuple) or not 0 < len(source_bindings) <= 32
                or any(type(source) is not object for source in source_bindings)
                or getattr(provider, "hass", None) is not self.hass
                or type(getattr(provider, "INGRESS_API_VERSION", None)) is not int
                or provider.INGRESS_API_VERSION != INGRESS_API_VERSION):
            raise ValueError("Unsupported protected provider registration")
        registration = _Registration(destination, provider, kiosk_user_ids, source_bindings)

        def current(admission):
            return (isinstance(admission, _Admission)
                    and self._active.get(id(admission)) is admission
                    and admission.registration is registration and self._current(admission))

        if provider.bind_ingress(current) is not True:
            raise ValueError("Protected provider already bound or unavailable")
        self._providers[destination] = registration

        def unregister():
            if self._providers.get(destination) is not registration:
                return
            registration.active = False
            self._providers.pop(destination)
            self._pending = {key: item for key, item in self._pending.items()
                             if item.registration is not registration}
            provider.close()

        return unregister

    def _current(self, admission):
        registration = admission.registration
        return (registration.active
                and self._providers.get(registration.destination) is registration
                and admission.context.user_id == admission.caller
                and admission.caller in registration.kiosks
                and admission.expires > time.monotonic()
                and not admission.owner.done() and not admission.owner.cancelling())

    def admit(self, destination, *, context, source_binding):
        """Bind an authenticated server call, without granting policy access."""
        now = time.monotonic()
        self._pending = {key: item for key, item in self._pending.items() if item.expires > now}
        registration = self._providers.get(destination)
        owner = asyncio.current_task()
        if (registration is None or not registration.active
                or not isinstance(context, Context) or not context.user_id
                or context.user_id not in registration.kiosks
                or not any(source_binding is source for source in registration.sources)
                or owner is None or owner.cancelling()
                or len(self._pending) + len(self._active) >= MAX_ADMISSIONS):
            return None
        admission = _Admission(context, context.user_id, owner, registration, now + ADMISSION_TTL)
        self._pending[id(admission)] = admission
        return admission

    async def async_dispatch(self, admission, *, transcript, command):
        """Consume before awaits. No upstream forwarding/fallback on any failure."""
        if (not isinstance(admission, _Admission)
                or self._pending.pop(id(admission), None) is not admission
                or admission.owner is not asyncio.current_task() or not self._current(admission)):
            return _denied()
        self._active[id(admission)] = admission
        try:
            result = await admission.registration.provider.async_dispatch(
                admission, transcript=transcript, command=command,
            )
            if (not isinstance(result, dict) or set(result) != {"status", "completed"}
                    or result["status"] not in {"completed", "partial", "denied", "unconfirmed"}
                    or type(result["completed"]) is not int or not 0 <= result["completed"] <= 32):
                return {"status": "unconfirmed", "completed": 0}
            return dict(result)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 -- no policy/provider errors in public responses
            return {"status": "unconfirmed", "completed": 0}
        finally:
            self._active.pop(id(admission), None)

    def close(self):
        """Revoke every lease before closing providers; never open baseline routes."""
        self._closed = True
        registrations = list(self._providers.values())
        for registration in registrations:
            registration.active = False
        self._providers.clear()
        self._pending.clear()
        for registration in registrations:
            registration.provider.close()
