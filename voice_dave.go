// DAVE protocol wiring for VoiceConnection. Keeps every DAVE-specific
// lifecycle hook in one file so voice.go stays close to upstream.

package discordgo

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/cartridge-gg/discordgo/dave"
	"github.com/gorilla/websocket"
)

// daveState carries the per-VoiceConnection DAVE session state. Created
// lazily when the voice gateway sends its first DAVE opcode (24, prepare
// epoch). Destroyed on VoiceConnection.Close.
type daveState struct {
	mu sync.Mutex

	session *dave.Session

	// Protocol version negotiated with the voice gateway. 0 means DAVE is
	// in passthrough mode for this session.
	protocolVersion uint16

	// Per-SSRC decryptors. Allocated lazily on VoiceSpeakingUpdate, one per
	// remote speaker. Keyed by SSRC.
	decryptors map[uint32]*daveStream

	// Per-user-ID key ratchet cache. The ratchet survives the decryptor and
	// is re-applied when MLS epoch changes.
	ratchets map[string]*dave.KeyRatchet
}

// daveStream ties a Decryptor to the KeyRatchet that feeds it. Both must be
// closed in the right order (decryptor first, then ratchet) to avoid libdave
// use-after-free.
type daveStream struct {
	decryptor *dave.Decryptor
	userID    string
}

// newDAVEState builds a daveState around a fresh dave.Session. authSessionID
// is used by libdave for persistent-key scoping; pass the voice-gateway
// session ID.
func (v *VoiceConnection) newDAVEState(authSessionID string) *daveState {
	onFailure := func(source, reason string) {
		v.log(LogError, "DAVE MLS failure in %s: %s", source, reason)
	}
	return &daveState{
		session:    dave.NewSession(authSessionID, onFailure),
		decryptors: make(map[uint32]*daveStream),
		ratchets:   make(map[string]*dave.KeyRatchet),
	}
}

// close releases every libdave handle owned by the daveState. Safe to call
// multiple times.
func (d *daveState) close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	for ssrc, s := range d.decryptors {
		if s.decryptor != nil {
			s.decryptor.Close()
		}
		delete(d.decryptors, ssrc)
	}
	for uid, kr := range d.ratchets {
		if kr != nil {
			kr.Close()
		}
		delete(d.ratchets, uid)
	}
	if d.session != nil {
		d.session.Destroy()
		d.session = nil
	}
}

// setProtocolVersion updates the negotiated version on both the daveState
// tracker and the underlying libdave session.
func (d *daveState) setProtocolVersion(v uint16) {
	d.mu.Lock()
	d.protocolVersion = v
	if d.session != nil {
		d.session.SetProtocolVersion(v)
	}
	d.mu.Unlock()
}

// ensureDecryptor returns (or creates) the Decryptor for a given SSRC, wiring
// it to the user's key ratchet if known.
func (d *daveState) ensureDecryptor(ssrc uint32, userID string) *dave.Decryptor {
	d.mu.Lock()
	defer d.mu.Unlock()

	if s, ok := d.decryptors[ssrc]; ok {
		return s.decryptor
	}

	dec := dave.NewDecryptor()
	if kr, ok := d.ratchets[userID]; ok {
		dec.TransitionToKeyRatchet(kr)
	}
	d.decryptors[ssrc] = &daveStream{
		decryptor: dec,
		userID:    userID,
	}
	return dec
}

// dropSSRC releases the decryptor for an SSRC (e.g. on speaker leave).
func (d *daveState) dropSSRC(ssrc uint32) {
	d.mu.Lock()
	s, ok := d.decryptors[ssrc]
	if ok {
		delete(d.decryptors, ssrc)
	}
	d.mu.Unlock()
	if ok && s.decryptor != nil {
		s.decryptor.Close()
	}
}

// installRatchetForUser caches a key ratchet for userID and re-points any
// decryptor already bound to that user to the new ratchet.
func (d *daveState) installRatchetForUser(userID string, kr *dave.KeyRatchet) {
	if kr == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	// Replace any prior ratchet for this user.
	if prev, ok := d.ratchets[userID]; ok && prev != nil {
		prev.Close()
	}
	d.ratchets[userID] = kr

	for _, s := range d.decryptors {
		if s.userID == userID && s.decryptor != nil {
			s.decryptor.TransitionToKeyRatchet(kr)
		}
	}
}

// refreshRatchetsForRoster queries libdave for a fresh KeyRatchet per roster
// member and applies them to their bound decryptors. Called after ProcessCommit
// or ProcessWelcome when the MLS epoch changes.
func (d *daveState) refreshRatchetsForRoster(rosterMemberIDs []uint64) {
	d.mu.Lock()
	sess := d.session
	d.mu.Unlock()
	if sess == nil {
		return
	}
	for _, id := range rosterMemberIDs {
		userID := strconv.FormatUint(id, 10)
		kr := sess.GetKeyRatchet(userID)
		if kr == nil {
			continue
		}
		d.installRatchetForUser(userID, kr)
	}
}

// handleDAVEJSONEvent dispatches the JSON-encoded DAVE opcodes (21, 22, 24,
// 31). Called from VoiceConnection.onEvent.
func (v *VoiceConnection) handleDAVEJSONEvent(op int, rawData json.RawMessage) {
	switch op {
	case voiceOpDAVEPrepareTransition:
		v.onDAVEPrepareTransition(rawData)
	case voiceOpDAVEExecuteTransition:
		v.onDAVEExecuteTransition(rawData)
	case voiceOpDAVEPrepareEpoch:
		v.onDAVEPrepareEpoch(rawData)
	default:
		v.log(LogWarning, "DAVE unknown JSON opcode %d", op)
	}
}

func (v *VoiceConnection) onDAVEPrepareTransition(raw json.RawMessage) {
	var p voiceDAVEPrepareTransition
	if err := json.Unmarshal(raw, &p); err != nil {
		v.log(LogError, "DAVE op21 unmarshal: %s", err)
		return
	}
	v.log(LogInformational, "DAVE op21 prepare_transition version=%d transition_id=%d",
		p.ProtocolVersion, p.TransitionID)

	// Downgrade to passthrough (version 0): flip every decryptor.
	if p.ProtocolVersion == 0 && v.dave != nil {
		v.dave.mu.Lock()
		for _, s := range v.dave.decryptors {
			if s.decryptor != nil {
				s.decryptor.TransitionToPassthroughMode(true)
			}
		}
		v.dave.mu.Unlock()
	}

	v.sendDAVEReadyForTransition(p.TransitionID)
}

func (v *VoiceConnection) onDAVEExecuteTransition(raw json.RawMessage) {
	var p voiceDAVEExecuteTransition
	if err := json.Unmarshal(raw, &p); err != nil {
		v.log(LogError, "DAVE op22 unmarshal: %s", err)
		return
	}
	v.log(LogInformational, "DAVE op22 execute_transition transition_id=%d", p.TransitionID)
	// No-op from discordgo's side: libdave handles the internal ratchet
	// rotation. The frame-level decrypt path will pick up the new key on
	// the next packet.
}

// ensureDAVEState lazy-creates v.dave + initializes the libdave session.
// Idempotent and serialized via v.Lock so concurrent OP4 / op25 handlers
// don't both call session.Init (which RESETS libdave state — second
// caller wipes the first caller's pending group + leaf node).
func (v *VoiceConnection) ensureDAVEState(protocolVersion uint16) (created bool) {
	v.Lock()
	defer v.Unlock()
	if v.dave != nil {
		return false
	}
	// authSessionID="" → libdave skips its persisted-key lookup and
	// generates a fresh ephemeral MLS signature key (session.cpp:597-599).
	// Passing v.sessionID makes signingKeyId_ non-empty, which forces the
	// GetPersistedKeyPair path; that fails because the Linux generic
	// implementation needs a writable key-storage dir and we don't ship
	// one. Result was: no leaf node, empty key package, op26 never sent,
	// MLS handshake never starts. Ephemeral keys are fine — each voice
	// connection is a fresh MLS group regardless.
	v.dave = v.newDAVEState("")
	groupID, _ := strconv.ParseUint(v.ChannelID, 10, 64)
	v.dave.session.Init(protocolVersion, groupID, v.UserID)
	v.dave.setProtocolVersion(protocolVersion)
	return true
}

// activateDAVEFromOP4 records the negotiated DAVE protocol version on the
// daveState. It also lazy-allocates the daveState + libdave session if
// they don't exist yet (OP4 may arrive before or after op25).
//
// What it intentionally does NOT do: marshal a key package or send op26.
// libdave can only produce a valid key package AFTER receiving op25
// (external_sender_package), which Discord sends on its own — usually
// before OP4. The op26 send lives in onDAVEExternalSenderPackage, where
// it has the data libdave needs.
func (v *VoiceConnection) activateDAVEFromOP4(protocolVersion uint16) {
	v.ensureDAVEState(protocolVersion)
	// If op25 lazy-inited with the default version (1) and OP4 reports
	// something different, update. setProtocolVersion is cheap + holds
	// daveState.mu, no v.Lock needed.
	v.dave.setProtocolVersion(protocolVersion)
	v.log(LogInformational, "DAVE: OP4 protocol_version=%d (awaiting op25 external_sender)", protocolVersion)
}

func (v *VoiceConnection) onDAVEPrepareEpoch(raw json.RawMessage) {
	var p voiceDAVEPrepareEpoch
	if err := json.Unmarshal(raw, &p); err != nil {
		v.log(LogError, "DAVE op24 unmarshal: %s", err)
		return
	}
	v.log(LogInformational, "DAVE op24 prepare_epoch version=%d epoch=%d",
		p.ProtocolVersion, p.Epoch)

	// ensureDAVEState is idempotent — covers the case where OP24 is the
	// first DAVE-related event we see (rare, but possible). When the
	// state was already created via op25's lazy-init OR via OP4, this
	// is a no-op. Critically, we DO NOT call session.Init again here:
	// libdave's Init resets MLS state, which would wipe the leaf node
	// + group membership we got from a prior op30 welcome. Discord
	// drives epoch transitions via op27/op28 (proposals + commits) and
	// op29/op30 (announces + welcomes); OP24 is purely informational
	// and just carries the protocol version + epoch number.
	v.ensureDAVEState(p.ProtocolVersion)
	v.dave.setProtocolVersion(p.ProtocolVersion)
}

// handleDAVEBinaryFrame dispatches the binary-encoded DAVE opcodes (25, 27,
// 29, 30). Called from wsListen when the websocket message type is binary.
func (v *VoiceConnection) handleDAVEBinaryFrame(frame []byte) {
	seq, op, payload, err := parseDAVEBinaryHeader(frame)
	if err != nil {
		v.log(LogError, "DAVE binary frame: %s", err)
		return
	}
	v.log(LogDebug, "DAVE binary op=%d seq=%d len=%d", op, seq, len(payload))

	// Discord sends op25 (external_sender_package) BEFORE op4 in practice
	// — that's the trigger for the DAVE handshake, not a post-init
	// message. Lazy-init with protocol version 1 (the only version
	// libdave supports today); op4's setProtocolVersion will update if
	// Discord advertises something else. Without this, op25 gets dropped
	// and libdave never gets the leaf node it needs to produce a key
	// package, so the MLS handshake stalls and inner-DAVE decrypt never
	// comes online.
	if v.ensureDAVEState(1) {
		v.log(LogInformational, "DAVE: lazy-init on first binary frame op=%d", op)
	}

	switch op {
	case voiceOpDAVEMLSExternalSenderPackage:
		v.onDAVEExternalSenderPackage(payload)
	case voiceOpDAVEMLSProposals:
		v.onDAVEProposals(payload)
	case voiceOpDAVEMLSAnnounceCommitTrans:
		v.onDAVEAnnounceCommitTransition(payload)
	case voiceOpDAVEMLSWelcome:
		v.onDAVEWelcome(payload)
	default:
		v.log(LogWarning, "DAVE unknown binary opcode %d", op)
	}
}

func (v *VoiceConnection) onDAVEExternalSenderPackage(payload []byte) {
	if v.dave.session == nil {
		return
	}
	v.dave.session.SetExternalSender(payload)
	v.log(LogInformational, "DAVE: op25 SetExternalSender done (len=%d)", len(payload))

	// The client responds to opcode 25 with its own opcode 26 (key package).
	kp := v.dave.session.MarshalledKeyPackage()
	if len(kp) == 0 {
		v.log(LogError, "DAVE: session returned empty key package")
		return
	}
	if err := v.sendDAVEBinaryFrame(daveKeyPackageFrame(kp)); err != nil {
		v.log(LogError, "DAVE: failed to send key package: %s", err)
		return
	}
	v.log(LogInformational, "DAVE: op26 key_package SENT (len=%d)", len(kp))
}

func (v *VoiceConnection) onDAVEProposals(payload []byte) {
	if v.dave.session == nil {
		return
	}
	recognized := v.daveRecognizedUserIDs()
	commitWelcome := v.dave.session.ProcessProposals(payload, recognized)
	if len(commitWelcome) == 0 {
		// Empty result means no commit was produced — either all proposals
		// were revoke-only or libdave rejected them. Nothing to send.
		return
	}
	if err := v.sendDAVEBinaryFrame(daveCommitWelcomeFrame(commitWelcome)); err != nil {
		v.log(LogError, "DAVE: failed to send commit/welcome: %s", err)
	}
}

func (v *VoiceConnection) onDAVEAnnounceCommitTransition(payload []byte) {
	if v.dave.session == nil || len(payload) < 2 {
		return
	}
	// Payload = uint16 transition_id || MLSMessage commit
	transitionID := uint16(payload[0])<<8 | uint16(payload[1])
	commitBytes := payload[2:]

	result := v.dave.session.ProcessCommit(commitBytes)
	if result == nil {
		v.log(LogError, "DAVE: ProcessCommit returned nil for transition_id=%d", transitionID)
		v.sendDAVEInvalidCommitWelcome(transitionID)
		return
	}
	defer result.Close()

	if result.Failed() {
		v.log(LogError, "DAVE: commit failed for transition_id=%d", transitionID)
		v.sendDAVEInvalidCommitWelcome(transitionID)
		return
	}
	if result.Ignored() {
		v.log(LogDebug, "DAVE: commit ignored for transition_id=%d", transitionID)
	} else {
		v.dave.refreshRatchetsForRoster(result.RosterMemberIDs())
	}
	v.sendDAVEReadyForTransition(transitionID)
}

func (v *VoiceConnection) onDAVEWelcome(payload []byte) {
	if v.dave.session == nil || len(payload) < 2 {
		return
	}
	// Payload = uint16 transition_id || Welcome
	transitionID := uint16(payload[0])<<8 | uint16(payload[1])
	welcomeBytes := payload[2:]

	recognized := v.daveRecognizedUserIDs()
	result := v.dave.session.ProcessWelcome(welcomeBytes, recognized)
	if result == nil {
		v.log(LogError, "DAVE: ProcessWelcome returned nil for transition_id=%d", transitionID)
		v.sendDAVEInvalidCommitWelcome(transitionID)
		return
	}
	defer result.Close()

	v.dave.refreshRatchetsForRoster(result.RosterMemberIDs())
	v.sendDAVEReadyForTransition(transitionID)
}

// sendDAVEReadyForTransition posts opcode 23 (JSON).
func (v *VoiceConnection) sendDAVEReadyForTransition(transitionID uint16) {
	msg := struct {
		Op   int                         `json:"op"`
		Data voiceDAVEReadyForTransition `json:"d"`
	}{
		Op:   voiceOpDAVEReadyForTransition,
		Data: voiceDAVEReadyForTransition{TransitionID: transitionID},
	}
	v.wsMutex.Lock()
	defer v.wsMutex.Unlock()
	if v.wsConn == nil {
		return
	}
	if err := v.wsConn.WriteJSON(msg); err != nil {
		v.log(LogError, "DAVE: failed to send ready_for_transition: %s", err)
	}
}

// sendDAVEInvalidCommitWelcome posts opcode 31 (JSON) to ask the gateway to
// re-add us to the group.
func (v *VoiceConnection) sendDAVEInvalidCommitWelcome(transitionID uint16) {
	msg := struct {
		Op   int                           `json:"op"`
		Data voiceDAVEInvalidCommitWelcome `json:"d"`
	}{
		Op:   voiceOpDAVEMLSInvalidCommitWelcome,
		Data: voiceDAVEInvalidCommitWelcome{TransitionID: transitionID},
	}
	v.wsMutex.Lock()
	defer v.wsMutex.Unlock()
	if v.wsConn == nil {
		return
	}
	if err := v.wsConn.WriteJSON(msg); err != nil {
		v.log(LogError, "DAVE: failed to send invalid_commit_welcome: %s", err)
	}
}

// sendDAVEBinaryFrame writes a raw binary frame to the voice gateway. Used
// for outbound opcodes 26 and 28.
func (v *VoiceConnection) sendDAVEBinaryFrame(frame []byte) error {
	v.wsMutex.Lock()
	defer v.wsMutex.Unlock()
	if v.wsConn == nil {
		return fmt.Errorf("no voice websocket")
	}
	return v.wsConn.WriteMessage(websocket.BinaryMessage, frame)
}

// daveRecognizedUserIDs returns the set of user IDs libdave should accept
// in MLS proposals + welcomes. The list is the trust anchor for MLS group
// membership: if Discord (the external sender) proposes adding a user
// outside this set, libdave rejects with "Unexpected user ID in add
// proposal" and the handshake stalls.
//
// Sources, in priority order:
//  1. Session state's voice-state cache for the guild — every user
//     currently in *any* voice channel of this guild. We don't filter to
//     the bot's channel because op27 can land before VOICE_STATE_UPDATE
//     events have fully populated, and Discord only proposes adding
//     users in our channel anyway.
//  2. Our own user ID + any SSRC-observed user IDs from completed
//     decryptors / ratchets, as a fallback if state caching is off.
func (v *VoiceConnection) daveRecognizedUserIDs() []string {
	seen := map[string]struct{}{v.UserID: {}}

	// Session state may be nil/empty if the consumer disabled state
	// tracking. Best-effort lookup; never block the DAVE handshake on
	// state being present.
	if v.session != nil && v.session.State != nil && v.GuildID != "" {
		if g, err := v.session.State.Guild(v.GuildID); err == nil && g != nil {
			for _, vs := range g.VoiceStates {
				if vs != nil && vs.UserID != "" {
					seen[vs.UserID] = struct{}{}
				}
			}
		}
	}

	if v.dave != nil {
		v.dave.mu.Lock()
		for _, s := range v.dave.decryptors {
			if s.userID != "" {
				seen[s.userID] = struct{}{}
			}
		}
		for uid := range v.dave.ratchets {
			seen[uid] = struct{}{}
		}
		v.dave.mu.Unlock()
	}

	out := make([]string, 0, len(seen))
	for uid := range seen {
		out = append(out, uid)
	}
	return out
}

// onDAVESpeakingUpdate is called from the opcode-5 (VoiceSpeakingUpdate)
// handler to register a fresh SSRC → userID mapping and prepare the matching
// Decryptor so the first audio frame can be decoded without blocking.
func (v *VoiceConnection) onDAVESpeakingUpdate(vs *VoiceSpeakingUpdate) {
	if v.dave == nil || vs.UserID == "" || vs.SSRC == 0 {
		return
	}
	// Convert SSRC to uint32. discordgo models it as int; Discord's real
	// range is uint32 but the Go struct uses int for backwards compatibility.
	ssrc := uint32(vs.SSRC)

	// If we don't have a ratchet for this user yet, ask libdave for one
	// (no-op if the group roster doesn't include them).
	v.dave.mu.Lock()
	_, haveRatchet := v.dave.ratchets[vs.UserID]
	sess := v.dave.session
	v.dave.mu.Unlock()

	if !haveRatchet && sess != nil {
		if kr := sess.GetKeyRatchet(vs.UserID); kr != nil {
			v.dave.installRatchetForUser(vs.UserID, kr)
		}
	}

	v.dave.ensureDecryptor(ssrc, vs.UserID)
}
