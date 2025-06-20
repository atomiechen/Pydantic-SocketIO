import functools
import inspect
import logging
from typing import Any, Callable, Optional, Type, overload

from pydantic import TypeAdapter, validate_call, ValidationError
from pydantic_core import to_jsonable_python
from socketio import (
    AsyncServer as OldAsyncServer,
    Server as OldServer,
    Client as OldClient,
    AsyncClient as OldAsyncClient,
)
from socketio.base_server import BaseServer as OldBaseServer
from socketio.base_client import BaseClient as OldBaseClient


# Save the original functions
_old_server_init = OldBaseServer.__init__
_old_server_on = OldBaseServer.on
_old_server_emit = OldServer.emit
_old_server_emit_async = OldAsyncServer.emit

_old_client_init = OldBaseClient.__init__
_old_client_on = OldBaseClient.on
_old_client_emit = OldClient.emit
_old_client_emit_async = OldAsyncClient.emit


module_logger = logging.getLogger(__name__)
module_logger.addHandler(logging.NullHandler())



def _wrapper(
    handler: Callable,
    old_on: Callable,
    self,
    event: str,
    *args,
    **kwargs,
):
    """Wrap the handler to validate the input using pydantic"""
    validated_handler = validate_call(handler)
    if event in ["connect", "disconnect"]:
        # For connect and disconnect events, convert ValidationError
        # to TypeError, so that socketio can handle it properly
        if inspect.iscoroutinefunction(validated_handler):

            @functools.wraps(validated_handler)
            async def wrapped_handler(*args, **kwargs):  # type: ignore
                try:
                    return await validated_handler(*args, **kwargs)
                except ValidationError as e:
                    raise TypeError from e
        else:

            @functools.wraps(validated_handler)
            def wrapped_handler(*args, **kwargs):
                try:
                    return validated_handler(*args, **kwargs)
                except ValidationError as e:
                    raise TypeError from e
    else:
        wrapped_handler = validated_handler  # type: ignore

    # Register the wrapped handler
    old_on(self, event, wrapped_handler, *args, **kwargs)
    return wrapped_handler


class PydanticSioToolset:
    """A toolset for pydantic validation and conversion for socketio."""

    def __init__(self, old_on: Callable):
        self._EMIT_EVENT_TYPES = {}
        self._old_on = old_on

    def register_emit(self, event: str, payload_type: Optional[Type] = None):
        """Decorator to register the payload type for an event."""

        def decorator(payload_type: Type):
            self._EMIT_EVENT_TYPES[event] = payload_type
            return payload_type

        if payload_type is None:
            # invoked as a decorator
            return decorator
        else:
            # not invoked as a decorator, but as a function
            return decorator(payload_type)

    def validate_emit(self, event: str, data: Any):
        """Validate the emit data type for the given event."""
        expected_type = self._EMIT_EVENT_TYPES.get(event)
        if expected_type is None:
            # If no type is registered, skip validation
            return

        TypeAdapter(expected_type).validate_python(data)

    def on(
        self,
        event: str,
        handler: Optional[Callable] = None,
        *args,
        **kwargs,
    ) -> Callable:
        if handler is None:
            # invoked as a decorator
            return functools.partial(
                _wrapper,
                old_on=self._old_on,
                self=self,
                event=event,
                *args,
                **kwargs,
            )
        else:
            # not invoked as a decorator, but as a function
            return _wrapper(handler, self._old_on, self, event, *args, **kwargs)

    def schema(self):
        """Return the event schema of the server."""
        # TODO
        pass


class BaseServer(PydanticSioToolset, OldBaseServer):
    """BaseServer with pydantic validation."""

    @overload
    def __init__(
        self,
        client_manager=None,
        logger=False,
        serializer="default",
        json=None,
        async_handlers=True,
        always_connect=False,
        namespaces=None,
        **kwargs,
    ): ...

    @overload
    def __init__(self, *args, **kwargs): ...

    def __init__(self, *args, **kwargs):
        _old_server_init(self, *args, **kwargs)
        PydanticSioToolset.__init__(self, _old_server_on)


class Server(BaseServer, OldServer):
    """Server with pydantic validation and data conversion."""

    def emit(
        self,
        event: str,
        data: Any = None,
        to: Optional[str] = None,
        *args,
        **kwargs,
    ):
        self.validate_emit(event, data)
        return _old_server_emit(
            self, event=event, data=to_jsonable_python(data), to=to, *args, **kwargs
        )


class AsyncServer(BaseServer, OldAsyncServer):
    """AsyncServer with pydantic validation and data conversion."""

    async def emit(
        self,
        event: str,
        data: Any = None,
        to: Optional[str] = None,
        *args,
        **kwargs,
    ):
        self.validate_emit(event, data)
        return await _old_server_emit_async(
            self, event=event, data=to_jsonable_python(data), to=to, *args, **kwargs
        )


class BaseClient(PydanticSioToolset, OldBaseClient):
    """BaseClient with pydantic validation."""

    @overload
    def __init__(
        self,
        reconnection=True,
        reconnection_attempts=0,
        reconnection_delay=1,
        reconnection_delay_max=5,
        randomization_factor=0.5,
        logger=False,
        serializer="default",
        json=None,
        handle_sigint=True,
        **kwargs,
    ): ...

    @overload
    def __init__(self, *args, **kwargs): ...

    def __init__(self, *args, **kwargs):
        _old_client_init(self, *args, **kwargs)
        PydanticSioToolset.__init__(self, _old_client_on)


class Client(BaseClient, OldClient):
    """Client with pydantic validation and data conversion."""

    def emit(self, event: str, data: Any = None, *args, **kwargs):
        self.validate_emit(event, data)
        return _old_client_emit(self, event, to_jsonable_python(data), *args, **kwargs)


class AsyncClient(BaseClient, OldAsyncClient):
    """AsyncClient with pydantic validation and data conversion."""

    async def emit(self, event: str, data: Any = None, *args, **kwargs):
        self.validate_emit(event, data)
        return await _old_client_emit_async(
            self, event, to_jsonable_python(data), *args, **kwargs
        )


def monkey_patch():
    module_logger.debug("Monkey patching")

    setattr(OldBaseServer, "__init__", BaseServer.__init__)
    setattr(OldBaseServer, "on", BaseServer.on)
    setattr(OldBaseServer, "register_emit", BaseServer.register_emit)
    setattr(OldBaseServer, "validate_emit", BaseServer.validate_emit)
    setattr(OldBaseServer, "schema", BaseServer.schema)

    setattr(OldServer, "emit", Server.emit)
    setattr(OldAsyncServer, "emit", AsyncServer.emit)

    setattr(OldBaseClient, "__init__", BaseClient.__init__)
    setattr(OldBaseClient, "on", BaseClient.on)
    setattr(OldBaseClient, "register_emit", BaseClient.register_emit)
    setattr(OldBaseClient, "validate_emit", BaseClient.validate_emit)
    setattr(OldBaseClient, "schema", BaseClient.schema)

    setattr(OldClient, "emit", Client.emit)
    setattr(OldAsyncClient, "emit", AsyncClient.emit)

    module_logger.debug("Monkey patched")
