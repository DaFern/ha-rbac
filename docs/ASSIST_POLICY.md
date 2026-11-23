# Proposed in-process Assist policy interface

## Finite cross-satellite timer oracle — development only

`TIMER_POLICY_VERSION=1` adds `async_check_timer_access`, implemented in
`timer_policy.py`. It accepts exact `assist_satellite` IDs and only `read`,
`cancel`, `stop` or `cancel_all`. It has no transport, endpoint, state projection,
service registration or device I/O.

Targets must be enabled, available, exposed ESPHome timer devices. A selected
restricted guest role or active enrolled speaker supplies current native/RBAC
read rights; cancellation additionally needs target control rights and the
open-tier `timer.cancel` policy check. Hidden timer/name/area metadata denies.
Schedules, inactive/system/unbound accounts, disabled targets and unsupported
input fail closed. Read-only does not become cancellation authority.

This is a finite timer operation, not forwarding a raw `assist_satellite` service
or conversation. Existing `BASELINE_DENY` and legacy satellite/guest action
contracts remain unchanged. The consumer must prove live source admission, limit
candidates to administrator-owned enrollment, pin native target identity, recheck
immediately before effects and protect remote data in shared conversation history.
It may not treat this oracle's point-in-time answer as a persistent grant.

No household role, binding, exposure or policy was changed. This paired source is
not installed, published or physically accepted. RBAC remains local-only unless
the owner separately approves publication/deployment.

The 44 timer-oracle cases passed on current/minimum HA in the paired selections;
current cross-project policy/admission selection passed 246, minimum passed 113
with 122 unsupported-feature skips. Both source trees passed Ruff and whitespace
checks. Real roles/registries/timers are exercised with simulated external
transport, model and native ESPHome action boundaries, not physical kiosks.

## Handoff checkpoint — development only

The owner chose to keep this RBAC work **local only**. The repository still points
to `FezVrasta/ha-rbac`; no fork, upstream push, pull request, release, installation
or restart was authorized. A local commit preserves the five new policy/ingress/
test/documentation files. Codex's companion prototype is published separately;
installing Codex alone does not install this dependency or enable parental controls.

Resume with authenticated transport/source-provenance design, protected resolver/
model integration and lifecycle ownership. Keep baseline Assist denials, tools-free
model context and the service-admission/physical-completion limits intact. Obtain
separate approval before publishing RBAC, enabling routes or changing live accounts.

This is an **inactive development foundation**, not an enabled Assist exception.
`assist_policy.py` exposes API version 1 for trusted integrations to evaluate current
explicitly assigned RBAC policies without reading storage or copying role rules.
It has no HTTP/WebSocket registration and executes no actions. The existing baseline
conversation, pipeline and satellite denials remain unchanged.

`async_check_access` accepts an account ID from trusted server code, exact entity IDs,
an operation (`read`, `turn_on`, `turn_off`), optional requested attribute names and
an optional explicitly restricted ceiling account. It returns only a boolean and a
fixed reason, not policy content, state or credentials. IDs in model prompts or tool
arguments are not trustworthy identities; the consumer must authenticate transport
and caller independently before querying policy.

The check requires an active non-system/non-owner account with an explicit binding,
intersects native and RBAC read/control policy and both accounts where a ceiling is
supplied, and refuses full-access pass-through. It reevaluates on each invocation;
the result is not a durable token. Restricted attributes are denied. Initial control
scope is direct lights/fans on/off only. Other actions and compound targets such as
scripts/scenes/groups remain denied rather than trying to infer their reach.
Member metadata is denied even when empty. Either actor hiding state or entity
identity also denies control, not just context projection.

This does **not** authorize forwarding an unrestricted sentence or native tool after
a preflight check. A supported provider registration/ingress handshake, restricted
context and actual target-bound execution-time enforcement are still required.
No integration should remove `BASELINE_DENY` or treat this API as a broad Assist allow.
Shared-satellite ceiling configuration and voice evidence handling remain consumer
work and are not implemented by this module.

## Read-only context projection

`CONTEXT_API_VERSION=1` adds `async_project_context`: exact configured candidates
are intersected with HA Assist exposure, both actors' native read rights, and both
current RBAC policies. Accounts and bindings are checked before a synchronous
projection. Hidden state/identifier removes a row; hidden names have no fallback.
Only requested domain-curated, bounded scalar fields are exported. Reference lists,
aliases, registries, arbitrary metadata, credentials and nested structures are never
merged. Provider faults discard partial results. The response contains no role
details, denied names or denied counts. This is a point-in-time read snapshot, not
an action grant, confidential history store or broad Assist exception.

The Codex consumer separately validates schema/size/version, binds a snapshot to
one caller/voice turn and prepares a tools-disabled envelope without old history,
unrestricted prompts or rendered HA templates. This path is inactive until the
protected ingress and exact execution guards are complete.

The selected oracle/context/policy/intent/schedule/location run passed 132 tests,
including two cross-checkout cases using actual Codex preparation/projection/envelope
code. The existing intent-surface denials remained passing. The full RBAC suite was
not run for this development step; no live permissions or installed code changed.

Tests use the real RBAC policy compiler and cover allowed/denied/read-only targets,
mixed and indirect actions, missing/disabled/system/owner accounts, explicit binding,
native permission revocation, hidden attributes, ceiling denial and request bounds.
Existing intent-surface denial tests are run alongside them to check that adding the
oracle did not open an ingress route. No live policy was read or modified for tests.

## Inactive exact-target consumer

Codex's development `rbac_execution.py` now consumes this oracle inside a native
ServiceIntentHandler execution task before each sealed exact service admission.
It checks both current bindings and native/RBAC read/control rights for the whole
batch, then validates caller/turn, entity registry identity, exposure and state.
Proposals are bounded, expiring and single-use; concurrent replay is consumed before
awaiting policy. Group/template platforms and arbitrary/indirect actions are denied.
No live provider registration, ingress exception, tool enablement or policy edit was
added. Ordinary free-text/Assist denials remain mandatory.

This protects service admission, not later integration/firmware scheduling. Commands
already admitted cannot be undone; later revocation stops remaining targets and is
reported as partial completion. It is not a system-wide transaction or device lock.

The selected oracle/context/policy/intent/schedule/location suite passed 140 tests
on both current and minimum HA, including eight new cross-checkout execution cases
using real paired preparation, compiled speaker/kiosk policies and native HA service
handling. Allowed direct execution occurs once; mixed forbidden targets and policy
revocation after preflight execute zero commands. Full RBAC-suite and protected
tablet/satellite acceptance remain unverified. Existing ingress-denial tests passed.

## Dormant protected provider/admission prototype

`assist_ingress.py` (not the Supervisor add-on ingress guard) now provides an
explicit in-process `ProtectedAssistIngress` registry, version 1. `register()` binds
a trusted provider, restricted kiosk IDs and server-held source capability objects;
`admit()` seals the original server-authenticated Context and owning pipeline task;
`async_dispatch()` consumes admission before awaits and invokes only that exact
provider. Admissions expire after 30 seconds, with 256 combined pending/active
records; registrations are bounded to 16. Copies, wrong tasks, unknown destinations,
unapproved source objects/accounts and closed/expired registrations cannot dispatch.

Nothing instantiates/registers this from integration setup, HTTP, WebSocket or the
proxy. There is no route exception or change to `BASELINE_DENY`. This is trusted
Python integration coordination, not network authentication or a provider sandbox.
Future authenticated transports must derive Context/source from their server-side
connection, never a client user_id/device_id, and require separate security review.

The Codex provider consumes its existing exact-object, task-owned paired STT handoff,
verifies packet/account binding and nonce freshness, filters both actors' context,
freezes a strict exact-ID command, and invokes its entry-owned native guard. It
revalidates registration/caller/key liveness inside native execution after policy
awaits. Unregister closes guards and cancels active parent pipelines; cancellation
must be awaited by the embedding lifecycle. No free-text/native LLM/model path is
enabled, and responses contain only fixed status/count, never raw policy or state.

Fifty-one new ingress cases passed as part of a 191-case selected cross-checkout
suite on both current and minimum HA. These exercise actual paired preparation,
compiled policies, filtered context and synthetic native services with simulated
authenticated Contexts/sources. Authentication over a network, real STT/satellite
provenance, setup/unload hooks and working household parental controls are not
established. Integration fixtures intentionally skip without the Codex checkout;
that skipped run does not establish the connected chain.
