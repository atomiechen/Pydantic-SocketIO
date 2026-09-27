# Change Log

All notable changes to Pydantic-SocketIO will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Export each server or client instance's current registrations with `asyncapi(title=..., version=...)`, while retaining `asyncapi_schema()`.

## [0.2.0] - 2026-09-27

### Added

- Validate and serialize `call()` request data, and optionally validate its acknowledgement with `response_model`.
- Validate event handler return annotations and serialize Pydantic model acknowledgements.
- Declare namespace-specific outgoing payloads and ACK types with `register_emit()`.
- Export registered event contracts as AsyncAPI 3.1 with `asyncapi_schema()`.

### Security

- Require `python-socketio>=5.16.2`, which also pulls in a patched Engine.IO version.
- On Python 3.8/3.9, some optional client and FastAPI dependencies cannot receive their latest security fixes because the patched upstream releases require newer Python. The base package continues to support Python 3.8+.

## [0.1.3] - 2025-10-08

### Added

- Support emit event data type validation
- Better type hint for IDE support

### Fixed

- Fix `Annotated` import issue for python 3.8



## [0.1.2] - 2025-06-19

### Fixed

- Check fastapi installation to avoid module not found error.



## [0.1.1] - 2025-03-18

### Added

- `SioDep` as `FastAPISocketIO` dependency injection in FastAPI applications.



## [0.1.0] - 2025-03-16

### Added

Initial features:

- Pydantic enhanced socketio server and client (both sync and async). They should be drop-in replacements for the original socketio server and client.
- Alternatively, monkey patching method `monkey_patch()` for the original socketio server and client.
- Integration with fastapi `FastAPISocketIO`.
