# WhatsApp Rust Bridge - AI Coding Guidelines

Quick orientation for agents and contributors: despite the historical name, this repo is now a pure Node.js compatibility layer for the old Rust/WASM bridge API.

Core summary

- Runtime lives in `ts/index.ts` and is copied directly to `dist/`.
- Binary, Noise, app-state and group/session helpers are implemented with Node.js, Baileys and libsignal.
- Tests live in `test/` and run on Node's native test runner through the local `test/testkit.js` shim.
- Optional media helpers are intentionally disabled in this build: audio, image and sticker functions throw a clear unsupported error.

Key files to review

- `ts/index.ts` - Main runtime and public API surface.
- `ts/index.d.ts` - Hand-maintained public typings.
- `test/` - Compatibility and parity coverage for binary, crypto, Noise, sessions and migrations.
- `package.json` - Node-only build and test scripts.

Important patterns

- Encoding normalizes non-string attrs to strings and skips null, undefined and whitespace-only values.
- Decoded string payloads are still exposed as `Uint8Array` to preserve historical behavior.
- `InternalBinaryNode` remains mutable from JS and must continue to round-trip correctly after attr/content reassignment.
- Session and sender-key compatibility is lenient on input: `Uint8Array`, arrays and `{ type: 'Buffer', data: [...] }` should continue to work.
- Server-only JIDs decode without the leading `@`; re-encoding decoded nodes must preserve current parity expectations in `test/handshake-parity.test.ts`.

Build, test and release flow

- `npm run build` - copies `ts/index.ts` and `ts/index.d.ts` into `dist/`.
- `npm test` - rebuilds, transpiles tests into `.node-test/` and runs them with `node --test`.
- No Bun, Rust, wasm-pack or generated `pkg/` step remains in the active workflow.

Contributing guidance

- Keep the public API stable; consumers expect the old bridge export names.
- Prefer minimal fixes in `ts/index.ts` over new layers or abstractions.
- Add or update tests whenever behavior changes, especially around parity and migration edge cases.
- Preserve ESM-compatible imports with explicit `.js` suffixes where Node requires them.

Gotchas

- This repo still depends on Baileys and libsignal internals, so path changes in those packages can break imports.
- Some legacy migration tests intentionally accept degraded recovery behavior instead of full cryptographic state restoration.
- The build is copy-based, not bundled; syntax/runtime validity matters more than TypeScript-only cleanliness.
