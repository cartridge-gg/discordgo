// DAVE protocol (opcodes 21-31) types and constants.
//
// This file carries the wire-level shapes: opcode numbers, JSON payloads for
// the text opcodes, and a tiny binary-frame reader for the binary opcodes.
// The actual MLS / cryptography happens inside libdave via the dave package;
// discordgo is just the transport.

package discordgo

import (
	"encoding/binary"
	"errors"
)

// Voice gateway opcodes added by the DAVE protocol. Numbers come from the
// DAVE protocol whitepaper; see daveprotocol.com or
// https://github.com/discord/dave-protocol.
const (
	voiceOpDAVEPrepareTransition        = 21 // S→C JSON
	voiceOpDAVEExecuteTransition        = 22 // S→C JSON
	voiceOpDAVEReadyForTransition       = 23 // C→S JSON
	voiceOpDAVEPrepareEpoch             = 24 // S→C JSON
	voiceOpDAVEMLSExternalSenderPackage = 25 // S→C BINARY
	voiceOpDAVEMLSKeyPackage            = 26 // C→S BINARY
	voiceOpDAVEMLSProposals             = 27 // S→C BINARY
	voiceOpDAVEMLSCommitWelcome         = 28 // C→S BINARY
	voiceOpDAVEMLSAnnounceCommitTrans   = 29 // S→C BINARY
	voiceOpDAVEMLSWelcome               = 30 // S→C BINARY
	voiceOpDAVEMLSInvalidCommitWelcome  = 31 // C→S JSON
)

// voiceDAVEPrepareTransition is the payload body of opcode 21.
type voiceDAVEPrepareTransition struct {
	ProtocolVersion uint16 `json:"protocol_version"`
	TransitionID    uint16 `json:"transition_id"`
}

// voiceDAVEExecuteTransition is the payload body of opcode 22.
type voiceDAVEExecuteTransition struct {
	TransitionID uint16 `json:"transition_id"`
}

// voiceDAVEReadyForTransition is the payload body of opcode 23 (outbound).
type voiceDAVEReadyForTransition struct {
	TransitionID uint16 `json:"transition_id"`
}

// voiceDAVEPrepareEpoch is the payload body of opcode 24. Epoch=1 means
// a new MLS group is being (re)created.
type voiceDAVEPrepareEpoch struct {
	ProtocolVersion uint16 `json:"protocol_version"`
	Epoch           uint32 `json:"epoch"`
}

// voiceDAVEInvalidCommitWelcome is the payload body of opcode 31 (outbound).
type voiceDAVEInvalidCommitWelcome struct {
	TransitionID uint16 `json:"transition_id"`
}

// errDAVEFrameShort is returned by parseDAVEBinaryHeader when the frame is
// too short to contain the mandatory sequence_number + opcode byte.
var errDAVEFrameShort = errors.New("discordgo: DAVE binary frame shorter than header")

// parseDAVEBinaryHeader splits an inbound binary voice-gateway frame into
// its sequence number, opcode, and remaining payload.
//
// Per the DAVE whitepaper, every server→client binary opcode is framed as:
//
//	uint16 sequence_number (big-endian, per Discord convention)
//	uint8  opcode
//	...   opcode-specific payload
//
// Returns (seq, op, payload, nil) on success.
func parseDAVEBinaryHeader(frame []byte) (seq uint16, op uint8, payload []byte, err error) {
	if len(frame) < 3 {
		return 0, 0, nil, errDAVEFrameShort
	}
	seq = binary.BigEndian.Uint16(frame[0:2])
	op = frame[2]
	payload = frame[3:]
	return seq, op, payload, nil
}

// daveCommitWelcomeFrame assembles an outbound opcode-28 frame:
//
//	uint8 opcode = 28
//	opaque commit_welcome_bytes<...>   // produced by libdave
//
// libdave returns the serialized commit (and optional welcome) as a single
// byte slice via daveSessionProcessProposals; we just prepend the opcode byte.
func daveCommitWelcomeFrame(commitWelcomeBytes []byte) []byte {
	out := make([]byte, 1+len(commitWelcomeBytes))
	out[0] = voiceOpDAVEMLSCommitWelcome
	copy(out[1:], commitWelcomeBytes)
	return out
}

// daveKeyPackageFrame assembles an outbound opcode-26 frame:
//
//	uint8 opcode = 26
//	MLSMessage key_package_message
func daveKeyPackageFrame(keyPackageBytes []byte) []byte {
	out := make([]byte, 1+len(keyPackageBytes))
	out[0] = voiceOpDAVEMLSKeyPackage
	copy(out[1:], keyPackageBytes)
	return out
}
