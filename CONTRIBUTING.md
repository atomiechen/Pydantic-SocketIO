# Contributing

Focused bug reports and pull requests are welcome. Describe the Python and Node versions you used, the event direction (Python server or client), and the expected Socket.IO behavior.

## Repository layout

- `src/pydantic_socketio/`: Python runtime and AsyncAPI exporter.
- `packages/codegen/`: TypeScript event interface generator and consumer tests.
- `examples/fastapi-typescript-chat/`: runnable Python → AsyncAPI → TypeScript example.
- `tests/`: Python tests, including typed contract checks.

## Local checks

Install [uv](https://docs.astral.sh/uv/) and Node.js 20.19+ or 22.12+:

```sh
uv sync --locked --all-extras
uv run --locked --no-sync bash scripts/lint.sh
uv run --locked --no-sync bash scripts/test.sh
npm ci --prefix packages/codegen
npm test --prefix packages/codegen
```

For codegen changes, regenerate the example's `asyncapi.json` from Python and `socketio.generated.ts` from the local codegen source. The example README has the commands; CI checks both files for drift and runs its TypeScript type check.

Python CI covers 3.8–3.13 on Linux, macOS, and Windows. Preserve the Python 3.8 minimum and existing Socket.IO behavior. Contract and codegen changes should keep event direction, namespaces, argument tuples, and ACK semantics accurate. Keep pull requests focused and document user-visible changes.

Release workflows use `workflow_dispatch` and are started by the project owner after review.
