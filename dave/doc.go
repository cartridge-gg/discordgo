// Package dave provides Go bindings to Discord's libdave C library, which
// implements the DAVE (Distributed Audio/Video End-to-End Encryption) protocol
// used by Discord voice and video calls.
//
// # What DAVE actually does
//
// DAVE sits on top of Discord's existing RTP session encryption. Every voice
// frame Discord routes through its media server is already encrypted under a
// per-session key (xsalsa20_poly1305 today). DAVE adds a second layer: the
// frame *payload* is encrypted by the sender to a key that only other call
// participants hold, so Discord servers relay but cannot decrypt the audio.
//
// The key agreement under DAVE is MLS (RFC 9420). Discord acts as an external
// sender that delivers proposals/commits/welcomes to clients via voice-gateway
// opcodes 21-31. Clients derive per-sender AEAD keys via MLS-Exporter and wrap
// each RTP payload with AES-128-GCM using a ULEB128-encoded nonce and an
// 8-byte truncated auth tag. See https://daveprotocol.com for the wire format.
//
// # What this package does
//
// It's a thin wrapper over libdave's pure-C ABI (libdave/cpp/includes/dave/dave.h).
// libdave carries the cryptographic and protocol heavy lifting: MLS state,
// ratchet derivation, AEAD frame format, codec-aware cryptor selection. This
// package owns CGO lifecycle, callback plumbing, and Go-native ergonomics.
//
// # Build requirements
//
// libdave is vendored as a git submodule at discordgo/dave/libdave. Building
// this package requires:
//
//   - libdave.a (static lib) at dave/libdave/cpp/build/libdave.a
//   - OpenSSL 3 (or 1.1) development headers
//   - libstdc++ (linked for C++ runtime; static-linked in container builds)
//
// Run `make -C dave/libdave/cpp` (see libdave README) to build libdave.a before
// `go build ./...` in this fork. For container builds, the goclaw Dockerfile
// handles this in its builder stage.
//
// # Listen-only usage
//
// The cartridge bots are receive-only (no outbound encryption), so the
// surface we actually exercise is:
//
//	sess := dave.NewSession(authID, userID, onMLSFailure)
//	sess.Init(version, groupID)
//	sess.SetExternalSender(externalSenderBytes) // from voice opcode 25
//	sess.ProcessWelcome(welcomeBytes, rosterIDs) // from binary opcode 26
//	sess.ProcessCommit(commitBytes) // from binary opcode 27
//	ratchet := sess.GetKeyRatchet(remoteUserID)
//	dec := dave.NewDecryptor()
//	dec.TransitionToKeyRatchet(ratchet)
//	plain, err := dec.Decrypt(dave.MediaAudio, encryptedOpusFrame)
//
// Encryption paths exist but are not wired by this fork's voice receiver.
package dave
