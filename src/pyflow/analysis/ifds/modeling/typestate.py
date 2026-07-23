"""Reusable typestate protocol model for IFDS clients."""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Iterable, Mapping

from .calls import (
    STATE_CLOSE as ACTION_CLOSE,
    STATE_OPEN as ACTION_OPEN,
    STATE_USE as ACTION_USE,
    CallModel,
    CallModelRegistry,
)


STATE_OPEN = "open"
STATE_CLOSED = "closed"
STATE_LOCKED = "locked"
STATE_UNLOCKED = "unlocked"
STATE_ACTIVE = "active"
STATE_COMPLETE = "complete"

ACTION_FILE_OPEN = "file.open"
ACTION_FILE_CLOSE = "file.close"
ACTION_FILE_USE = "file.use"
ACTION_SOCKET_OPEN = "socket.open"
ACTION_SOCKET_CLOSE = "socket.close"
ACTION_SOCKET_USE = "socket.use"
ACTION_LOCK_CREATE = "lock.create"
ACTION_LOCK_ACQUIRE = "lock.acquire"
ACTION_LOCK_RELEASE = "lock.release"
ACTION_TRANSACTION_BEGIN = "transaction.begin"
ACTION_TRANSACTION_COMPLETE = "transaction.complete"
ACTION_TRANSACTION_USE = "transaction.use"


@dataclass(frozen=True)
class TypestateTransition:
    """A named call action that transitions matching resources."""

    action: str
    from_states: FrozenSet[str]
    to_state: str | None


@dataclass(frozen=True)
class TypestateViolation:
    """A call action that is illegal for resources in matching states."""

    action: str
    states: FrozenSet[str]
    kind: str


@dataclass(frozen=True)
class TypestateExitObligation:
    """A state that must not remain at procedure exit."""

    states: FrozenSet[str]
    kind: str
    suppress_when_escaped: bool = True


@dataclass(frozen=True)
class TypestateActionModel:
    """Map symbolic call names to a protocol action."""

    names: FrozenSet[str]
    action: str
    resource_arg_positions: FrozenSet[int] = frozenset({0})
    track_method_receiver: bool = True
    creates_resource: bool = False


@dataclass(frozen=True)
class TypestateProtocol:
    """Declarative finite-state protocol used by IFDS typestate analyses."""

    name: str
    initial_state: str
    actions: tuple[TypestateActionModel, ...]
    transitions: tuple[TypestateTransition, ...]
    violations: tuple[TypestateViolation, ...]
    exit_obligations: tuple[TypestateExitObligation, ...] = ()

    def action_for_name(self, name: str | None) -> str | None:
        if name is None:
            return None
        for model in self.actions:
            if name in model.names:
                return model.action
        return None

    def action_model_for_name(self, name: str | None) -> TypestateActionModel | None:
        if name is None:
            return None
        for model in self.actions:
            if name in model.names:
                return model
        return None

    def transition(self, action: str, state: str) -> TypestateTransition | None:
        for transition in self.transitions:
            if transition.action == action and state in transition.from_states:
                return transition
        return None

    def violations_for(self, action: str, state: str) -> tuple[TypestateViolation, ...]:
        return tuple(
            violation
            for violation in self.violations
            if violation.action == action and state in violation.states
        )

    def exit_violations_for(self, state: str) -> tuple[TypestateExitObligation, ...]:
        return tuple(
            obligation
            for obligation in self.exit_obligations
            if state in obligation.states
        )

    def to_call_model_registry(self) -> CallModelRegistry:
        models: list[CallModel] = []
        for action_model in self.actions:
            for name in action_model.names:
                models.append(
                    CallModel(
                        name=name,
                        typestate_actions=frozenset({action_model.action}),
                        resource_arg_positions=action_model.resource_arg_positions,
                        track_method_receiver=action_model.track_method_receiver,
                        typestate_action_protocols=frozenset(
                            {(action_model.action, self.name)}
                        ),
                    )
                )
        return CallModelRegistry(models)


class TypestateEngine:
    """Rule evaluator for one or more finite-state protocols."""

    def __init__(self, protocols: Iterable[TypestateProtocol]) -> None:
        self.protocols = tuple(protocols)

    def protocol_for_action(self, action: str) -> TypestateProtocol | None:
        for protocol in self.protocols:
            if any(model.action == action for model in protocol.actions):
                return protocol
        return None

    def call_model_registry(self) -> CallModelRegistry:
        registries = [protocol.to_call_model_registry() for protocol in self.protocols]
        if not registries:
            return CallModelRegistry()
        head, *tail = registries
        return head.merged(*tail)

    def transition(self, action: str, state: str) -> TypestateTransition | None:
        protocol = self.protocol_for_action(action)
        if protocol is None:
            return None
        return protocol.transition(action, state)

    def violations_for(self, action: str, state: str) -> tuple[TypestateViolation, ...]:
        protocol = self.protocol_for_action(action)
        if protocol is None:
            return ()
        return protocol.violations_for(action, state)

    def exit_violations_for(
        self, protocol_name: str, state: str
    ) -> tuple[TypestateExitObligation, ...]:
        for protocol in self.protocols:
            if protocol.name == protocol_name:
                return protocol.exit_violations_for(state)
        return ()

    def protocol_name_for_action(self, action: str) -> str | None:
        protocol = self.protocol_for_action(action)
        return protocol.name if protocol is not None else None

    def initial_state_for_action(self, action: str) -> str | None:
        protocol = self.protocol_for_action(action)
        if protocol is None:
            return None
        for model in protocol.actions:
            if model.action == action and model.creates_resource:
                return protocol.initial_state
        return None

    def actions_by_name(self) -> Mapping[str, str]:
        return {
            name: action_model.action
            for protocol in self.protocols
            for action_model in protocol.actions
            for name in action_model.names
        }


def resource_lifecycle_protocol(
    *,
    open_names: Iterable[str],
    close_names: Iterable[str],
    use_names: Iterable[str],
    resource_arg_positions: FrozenSet[int],
    track_method_receiver: bool,
) -> TypestateProtocol:
    """Build the standard open/close/use protocol."""
    return TypestateProtocol(
        name="resource",
        initial_state=STATE_OPEN,
        actions=(
            TypestateActionModel(
                names=frozenset(open_names),
                action=ACTION_OPEN,
                resource_arg_positions=resource_arg_positions,
                track_method_receiver=track_method_receiver,
                creates_resource=True,
            ),
            TypestateActionModel(
                names=frozenset(close_names),
                action=ACTION_CLOSE,
                resource_arg_positions=resource_arg_positions,
                track_method_receiver=track_method_receiver,
            ),
            TypestateActionModel(
                names=frozenset(use_names),
                action=ACTION_USE,
                resource_arg_positions=resource_arg_positions,
                track_method_receiver=track_method_receiver,
            ),
        ),
        transitions=(
            TypestateTransition(
                action=ACTION_CLOSE,
                from_states=frozenset({STATE_OPEN}),
                to_state=STATE_CLOSED,
            ),
        ),
        violations=(
            TypestateViolation(
                action=ACTION_USE,
                states=frozenset({STATE_CLOSED}),
                kind="use_after_close",
            ),
            TypestateViolation(
                action=ACTION_CLOSE,
                states=frozenset({STATE_CLOSED}),
                kind="double_close",
            ),
        ),
        exit_obligations=(
            TypestateExitObligation(
                states=frozenset({STATE_OPEN}),
                kind="resource_leak",
            ),
        ),
    )


def file_descriptor_protocol() -> TypestateProtocol:
    """Protocol for files, temporary files, and raw file descriptors."""
    return _closable_protocol(
        name="file",
        open_action=ACTION_FILE_OPEN,
        close_action=ACTION_FILE_CLOSE,
        use_action=ACTION_FILE_USE,
        open_names={
            "open",
            "io.open",
            "os.open",
            "tempfile.NamedTemporaryFile",
            "tempfile.TemporaryFile",
            "tempfile.mkstemp",
            "pathlib.Path.open",
        },
        close_names={"close", "os.close", "__exit__", "cleanup"},
        use_names={
            "read",
            "readline",
            "readlines",
            "write",
            "writelines",
            "seek",
            "tell",
            "truncate",
            "flush",
            "os.read",
            "os.write",
        },
    )


def socket_protocol() -> TypestateProtocol:
    """Protocol for socket-like resources."""
    return _closable_protocol(
        name="socket",
        open_action=ACTION_SOCKET_OPEN,
        close_action=ACTION_SOCKET_CLOSE,
        use_action=ACTION_SOCKET_USE,
        open_names={"socket.socket", "socket.create_connection"},
        close_names={"close", "shutdown", "__exit__"},
        use_names={
            "send",
            "sendall",
            "sendto",
            "recv",
            "recvfrom",
            "connect",
            "bind",
            "listen",
            "accept",
        },
    )


def lock_protocol() -> TypestateProtocol:
    """Protocol for lock-like synchronization primitives."""
    return TypestateProtocol(
        name="lock",
        initial_state=STATE_UNLOCKED,
        actions=(
            TypestateActionModel(
                names=frozenset(
                    {
                        "threading.Lock",
                        "threading.RLock",
                        "threading.Semaphore",
                        "threading.BoundedSemaphore",
                        "multiprocessing.Lock",
                        "asyncio.Lock",
                    }
                ),
                action=ACTION_LOCK_CREATE,
                resource_arg_positions=frozenset(),
                track_method_receiver=False,
                creates_resource=True,
            ),
            TypestateActionModel(
                names=frozenset({"acquire", "__enter__"}),
                action=ACTION_LOCK_ACQUIRE,
                resource_arg_positions=frozenset(),
            ),
            TypestateActionModel(
                names=frozenset({"release", "__exit__"}),
                action=ACTION_LOCK_RELEASE,
                resource_arg_positions=frozenset(),
            ),
        ),
        transitions=(
            TypestateTransition(
                action=ACTION_LOCK_ACQUIRE,
                from_states=frozenset({STATE_UNLOCKED}),
                to_state=STATE_LOCKED,
            ),
            TypestateTransition(
                action=ACTION_LOCK_RELEASE,
                from_states=frozenset({STATE_LOCKED}),
                to_state=STATE_UNLOCKED,
            ),
        ),
        violations=(
            TypestateViolation(
                action=ACTION_LOCK_ACQUIRE,
                states=frozenset({STATE_LOCKED}),
                kind="double_acquire",
            ),
            TypestateViolation(
                action=ACTION_LOCK_RELEASE,
                states=frozenset({STATE_UNLOCKED}),
                kind="release_without_acquire",
            ),
        ),
        exit_obligations=(
            TypestateExitObligation(
                states=frozenset({STATE_LOCKED}),
                kind="lock_leak",
            ),
        ),
    )


def transaction_protocol() -> TypestateProtocol:
    """Protocol for explicit database transaction lifecycles."""
    return TypestateProtocol(
        name="transaction",
        initial_state=STATE_ACTIVE,
        actions=(
            TypestateActionModel(
                names=frozenset({"begin", "transaction", "begin_transaction"}),
                action=ACTION_TRANSACTION_BEGIN,
                resource_arg_positions=frozenset(),
                creates_resource=True,
            ),
            TypestateActionModel(
                names=frozenset({"commit", "rollback", "__exit__"}),
                action=ACTION_TRANSACTION_COMPLETE,
                resource_arg_positions=frozenset(),
            ),
            TypestateActionModel(
                names=frozenset({"execute", "executemany", "executescript"}),
                action=ACTION_TRANSACTION_USE,
                resource_arg_positions=frozenset(),
            ),
        ),
        transitions=(
            TypestateTransition(
                action=ACTION_TRANSACTION_COMPLETE,
                from_states=frozenset({STATE_ACTIVE}),
                to_state=STATE_COMPLETE,
            ),
        ),
        violations=(
            TypestateViolation(
                action=ACTION_TRANSACTION_USE,
                states=frozenset({STATE_COMPLETE}),
                kind="transaction_use_after_complete",
            ),
            TypestateViolation(
                action=ACTION_TRANSACTION_COMPLETE,
                states=frozenset({STATE_COMPLETE}),
                kind="transaction_double_complete",
            ),
        ),
        exit_obligations=(
            TypestateExitObligation(
                states=frozenset({STATE_ACTIVE}),
                kind="uncommitted_transaction",
            ),
        ),
    )


def built_in_python_protocols() -> tuple[TypestateProtocol, ...]:
    """Return practical built-in protocols for Python SAST."""
    return (
        file_descriptor_protocol(),
        socket_protocol(),
        lock_protocol(),
        transaction_protocol(),
    )


def typestate_action_for_protocol(protocol: str, action: str) -> str | None:
    """Return the engine action id for a registry protocol/action pair."""
    normalized_protocol = protocol.strip().lower()
    normalized_action = action.strip().lower()
    mapping = {
        ("resource", "open"): ACTION_OPEN,
        ("resource", "close"): ACTION_CLOSE,
        ("resource", "use"): ACTION_USE,
        ("file", "open"): ACTION_FILE_OPEN,
        ("file", "close"): ACTION_FILE_CLOSE,
        ("file", "use"): ACTION_FILE_USE,
        ("socket", "open"): ACTION_SOCKET_OPEN,
        ("socket", "close"): ACTION_SOCKET_CLOSE,
        ("socket", "use"): ACTION_SOCKET_USE,
        ("lock", "create"): ACTION_LOCK_CREATE,
        ("lock", "open"): ACTION_LOCK_CREATE,
        ("lock", "acquire"): ACTION_LOCK_ACQUIRE,
        ("lock", "use"): ACTION_LOCK_ACQUIRE,
        ("lock", "release"): ACTION_LOCK_RELEASE,
        ("lock", "close"): ACTION_LOCK_RELEASE,
        ("transaction", "begin"): ACTION_TRANSACTION_BEGIN,
        ("transaction", "open"): ACTION_TRANSACTION_BEGIN,
        ("transaction", "complete"): ACTION_TRANSACTION_COMPLETE,
        ("transaction", "commit"): ACTION_TRANSACTION_COMPLETE,
        ("transaction", "rollback"): ACTION_TRANSACTION_COMPLETE,
        ("transaction", "close"): ACTION_TRANSACTION_COMPLETE,
        ("transaction", "use"): ACTION_TRANSACTION_USE,
    }
    return mapping.get((normalized_protocol, normalized_action))


def _closable_protocol(
    *,
    name: str,
    open_action: str,
    close_action: str,
    use_action: str,
    open_names: Iterable[str],
    close_names: Iterable[str],
    use_names: Iterable[str],
) -> TypestateProtocol:
    return TypestateProtocol(
        name=name,
        initial_state=STATE_OPEN,
        actions=(
            TypestateActionModel(
                names=frozenset(open_names),
                action=open_action,
                resource_arg_positions=frozenset(),
                track_method_receiver=False,
                creates_resource=True,
            ),
            TypestateActionModel(
                names=frozenset(close_names),
                action=close_action,
                resource_arg_positions=frozenset(),
            ),
            TypestateActionModel(
                names=frozenset(use_names),
                action=use_action,
                resource_arg_positions=frozenset(),
            ),
        ),
        transitions=(
            TypestateTransition(
                action=close_action,
                from_states=frozenset({STATE_OPEN}),
                to_state=STATE_CLOSED,
            ),
        ),
        violations=(
            TypestateViolation(
                action=use_action,
                states=frozenset({STATE_CLOSED}),
                kind="use_after_close",
            ),
            TypestateViolation(
                action=close_action,
                states=frozenset({STATE_CLOSED}),
                kind="double_close",
            ),
        ),
        exit_obligations=(
            TypestateExitObligation(
                states=frozenset({STATE_OPEN}),
                kind=f"{name}_leak",
            ),
        ),
    )
