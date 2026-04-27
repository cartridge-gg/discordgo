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

// activateDAVEFromOP4 is the OP4-driven DAVE bring-up. The voice gateway
// signals DAVE is in effect for this call by setting dave_protocol_version
// in OP4 (session description); when that field is non-zero the client
// MUST proactively send its MLS key package to the gateway (opcode 26)
// — Discord does not initiate the MLS handshake on its own.
//
// This duplicates some of onDAVEPrepareEpoch's lazy-init path but fires
// EARLIER, before any OP21-31 traffic. If OP24 still arrives later, its
// handler is a no-op now (state already populated).
func (v *VoiceConnection) activateDAVEFromOP4(protocolVersion uint16) {
	if v.dave == nil {
		v.dave = v.newDAVEState(v.sessionID)
	}
	groupID, _ := strconv.ParseUint(v.ChannelID, 10, 64)
	v.dave.session.Init(protocolVersion, groupID, v.UserID)
	v.dave.setProtocolVersion(protocolVersion)

	kp := v.dave.session.MarshalledKeyPackage()
	if len(kp) == 0 {
		v.log(LogError, "DAVE: session returned empty key package on OP4 init")
		return
	}
	v.log(LogInformational, "DAVE: sending key package (op26) protocol=%d len=%d", protocolVersion, len(kp))
	if err := v.sendDAVEBinaryFrame(daveKeyPackageFrame(kp)); err != nil {
		v.log(LogError, "DAVE: failed to send key package: %s", err)
	}
}

func (v *VoiceConnection) onDAVEPrepareEpoch(raw json.RawMessage) {
	var p voiceDAVEPrepareEpoch
	if err := json.Unmarshal(raw, &p); err != nil {
		v.log(LogError, "DAVE op24 unmarshal: %s", err)
		return
	}
	v.log(LogInformational, "DAVE op24 prepare_epoch version=%d epoch=%d",
		p.ProtocolVersion, p.Epoch)

	if v.dave == nil {
		v.dave = v.newDAVEState(v.sessionID)
	}

	// Epoch=1 signals a new MLS group. Initialise the libdave session with
	// the negotiated protocol version and our snowflake ID.
	if p.Epoch == 1 {
		groupID, _ := strconv.ParseUint(v.ChannelID, 10, 64)
		v.dave.session.Init(p.ProtocolVersion, groupID, v.UserID)
	}
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

	if v.dave == nil {
		// Binary DAVE frames should only arrive after opcode 24 has set up
		// the session. If we see one first, log and drop.
		v.log(LogWarning, "DAVE binary op %d received before session init; dropping", op)
		return
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

	// The client responds to opcode 25 with its own opcode 26 (key package).
	kp := v.dave.session.MarshalledKeyPackage()
	if len(kp) == 0 {
		v.log(LogError, "DAVE: session returned empty key package")
		return
	}
	if err := v.sendDAVEBinaryFrame(daveKeyPackageFrame(kp)); err != nil {
		v.log(LogError, "DAVE: failed to send key package: %s", err)
	}
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

// daveRecognizedUserIDs returns the set of user IDs our client has seen via
// VoiceStateUpdate or VoiceSpeakingUpdate. libdave uses this list to decide
// whether to accept proposals and welcomes. For now we return just the local
// user ID plus any SSRC-observed userIDs; a fuller implementation tracks the
// guild voice state roster.
func (v *VoiceConnection) daveRecognizedUserIDs() []string {
	if v.dave == nil {
		return []string{v.UserID}
	}
	v.dave.mu.Lock()
	defer v.dave.mu.Unlock()

	seen := map[string]struct{}{v.UserID: {}}
	for _, s := range v.dave.decryptors {
		if s.userID != "" {
			seen[s.userID] = struct{}{}
		}
	}
	for uid := range v.dave.ratchets {
		seen[uid] = struct{}{}
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
