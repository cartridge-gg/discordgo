# dave

Go bindings to [discord/libdave](https://github.com/discord/libdave), Discord's reference C/C++ implementation of the [DAVE protocol](https://daveprotocol.com) (Audio/Video E2EE for voice and video calls).

## Layout

- `libdave/` — vendored as a git submodule, pinned to an upstream commit. Pure C API lives at `libdave/cpp/includes/dave/dave.h`. Build output goes to `libdave/cpp/build/` (static library + headers).
- `session.go`, `decryptor.go`, etc. — Go types that wrap `DAVESessionHandle`, `DAVEDecryptorHandle`, and the rest of the libdave opaque handles. Written as thin passthroughs; protocol logic lives in libdave, Go owns lifecycle + channel plumbing.
- `dave.go` — CGO preamble, shared includes, error mapping.

## Build requirements

libdave needs OpenSSL 3 (default) and pulls mlspp via vcpkg. Our goclaw.Dockerfile installs the build toolchain in the builder stage and static-links `libstdc++` so the runtime image doesn't need a C++ runtime.

See `../docs/dave.md` (forthcoming) for the high-level architecture and the ordering of voice gateway opcodes 21-31.

## Status

Phase 0 scaffold. No CGO code yet.
