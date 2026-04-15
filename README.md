# whatsapp-rust-bridge

Utilidades de WhatsApp para Node.js puro, sin WebAssembly ni Bun.

## Compatibility

- Runtime: Node.js 20+
- Build: `npm run build`
- Tests: `npm test`
- No requiere `wasm-pack`, `wasm-bindgen` ni Bun

## Features

| Feature                        | Status |
| ------------------------------ | ------ |
| Binary Protocol                | ✅     |
| Libsignal                      | ✅     |
| App State Sync                 | ✅     |
| Audio (waveform, duration)     | ✅     |
| Image (thumbnails, conversion) | ✅     |
| Sticker Metadata               | ✅     |

## Build

```bash
npm install
npm run build
npm test
```

## Baileys Integration

- [#1698](https://github.com/WhiskeySockets/Baileys/pull/1698) - Binary Protocol
- [#2067](https://github.com/WhiskeySockets/Baileys/pull/2067) - Libsignal
