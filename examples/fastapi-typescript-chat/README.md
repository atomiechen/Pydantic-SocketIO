# FastAPI + TypeScript chat example

This small app shows one contract moving from Python handlers and Pydantic models to AsyncAPI and then to types used by the official `socket.io-client`. The Python server validates the `ask` payload, returns an `Answer` ACK, and emits a `Notice` on `/chat`.

Requirements: Python 3.8+, Node.js 20.19+ or 22.12+, and npm. From the repository root:

```sh
uv sync --locked --all-extras
uv run --locked --no-sync python examples/fastapi-typescript-chat/export_contract.py
npm ci --prefix examples/fastapi-typescript-chat
npx @pydantic-socketio/codegen examples/fastapi-typescript-chat/asyncapi.json \
  -o examples/fastapi-typescript-chat/src/socketio.generated.ts
npm run typecheck --prefix examples/fastapi-typescript-chat
```

The `npx` command above uses the published codegen package. From the example directory, start two terminals:

```sh
# terminal 1: start the Python/FastAPI ASGI app
uv run --project ../.. --locked --no-sync uvicorn backend:app --host 127.0.0.1 --port 8000

# terminal 2: start the browser client
npm run dev
```

Open <http://127.0.0.1:5173>, enter a message, and observe both a server notice and an ACK. The [Python source](backend.py), [AsyncAPI document](asyncapi.json), [generated event types](src/socketio.generated.ts), and [browser client](src/main.ts) are checked in so you can inspect the full path without running it.

The event map rejects a wrong payload at compile time. For example, replacing the browser's emit call with `socket.emit("ask", { text: 123 })` causes `npm run typecheck` to fail because `Ask.text` is a string. Keep that invalid call out of the running app.

When changing the Python models or registrations, rerun the export and codegen commands, then type-check. Repository CI regenerates both checked-in outputs using the local codegen source and rejects drift.
