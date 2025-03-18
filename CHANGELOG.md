# Change Log

All notable changes to Pydantic-SocketIO will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).


## [0.1.1] - 2025-03-18

### Added

- `SioDep` as `FastAPISocketIO` dependency injection in FastAPI applications.



## [0.1.0] - 2025-03-16

### Added

Initial features:

- Pydantic enhanced socketio server and client (both sync and async). They should be drop-in replacements for the original socketio server and client.
- Alternatively, monkey patching method `monkey_patch()` for the original socketio server and client.
- Integration with fastapi `FastAPISocketIO`.
