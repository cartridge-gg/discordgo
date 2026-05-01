package discordgo

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// DAVEHealth is a snapshot of the local DAVE/MLS handshake state, suitable
// for a supervisor to detect stuck handshakes (op26 sent but no op30 ever)
// or partial-roster failures (op30 received but ratchets_missing > 0).
//
// Fields are zero-valued when DAVE has not been initialized for this voice
// connection — check Initialized first.
type DAVEHealth struct {
	Initialized         bool      // true if a libdave session exists for this VC
	OP26SentAt          time.Time // last time we sent (or resent) the key_package
	OP30Received        bool      // true once any op30 (welcome) has been processed
	OP30LastReceived    time.Time // wall time of the most recent op30
	LastMissing         int       // ratchets_missing from the most recent op29/op30
	MissingFirstSeen    time.Time // wall time when LastMissing first became >0
	LastRosterSize      int       // roster size reported by the most recent op29/op30
	ProposalFailedSince time.Time // when op27 first started returning empty commits (epoch divergence)
}

// DAVEHealth returns a snapshot of the DAVE handshake state for this voice
// connection. Safe to call from any goroutine; returns zero value if DAVE
// is not active.
func (v *VoiceConnection) DAVEHealth() DAVEHealth {
	v.Lock()
	d := v.dave
	v.Unlock()
	if d == nil {
		return DAVEHealth{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return DAVEHealth{
		Initialized:         true,
		OP26SentAt:          d.op26SentAt,
		OP30Received:        d.op30Received,
		OP30LastReceived:    d.op30LastReceived,
		LastMissing:         d.lastMissing,
		MissingFirstSeen:    d.missingFirstSeen,
		LastRosterSize:      d.lastRosterSize,
		ProposalFailedSince: d.proposalFailedSince,
	}
}

// recordEpochUpdate is called from onDAVEAnnounceCommitTransition (op29)
// and onDAVEWelcome (op30) after refreshRatchetsForRoster, to update
// the supervisor-visible health counters. Holds daveState.mu briefly.
//
// A successful epoch update implicitly clears proposalFailedSince — if
// we just landed a fresh op30, libdave is back in sync with the group.
func (d *daveState) recordEpochUpdate(rosterSize, missing int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastRosterSize = rosterSize
	d.proposalFailedSince = time.Time{}
	switch {
	case missing == 0:
		d.lastMissing = 0
		d.missingFirstSeen = time.Time{}
	case d.lastMissing == 0:
		d.lastMissing = missing
		d.missingFirstSeen = time.Now()
	default:
		d.lastMissing = missing
		// keep missingFirstSeen unchanged so the watchdog can measure
		// how long missing has persisted.
	}
}

// ResendDAVEKeyPackage re-emits the bot's already-generated MLS key_package
// (op26) over the existing voice WS, without disturbing libdave state. Used
// when no op30 arrives within the watchdog timeout — the hope is that
// other clients in the channel haven't seen our proposal yet (e.g. they
// joined after we did and are on a stale roster) and re-emitting puts the
// proposal back in their queue.
//
// Cheaper than SoftResetDAVE because libdave state is preserved. If this
// doesn't trigger an op27 within another timeout window, the supervisor
// should escalate to SoftResetDAVE.
func (v *VoiceConnection) ResendDAVEKeyPackage() error {
	v.Lock()
	d := v.dave
	v.Unlock()
	if d == nil {
		return errors.New("DAVE: not initialized")
	}
	d.mu.Lock()
	sess := d.session
	d.mu.Unlock()
	if sess == nil {
		return errors.New("DAVE: session destroyed")
	}
	kp := sess.MarshalledKeyPackage()
	if len(kp) == 0 {
		return errors.New("DAVE: empty key package on resend")
	}
	if err := v.sendDAVEBinaryFrame(daveKeyPackageFrame(kp)); err != nil {
		return fmt.Errorf("DAVE: resend key package: %w", err)
	}
	d.mu.Lock()
	d.op26SentAt = time.Now()
	d.op30Received = false
	d.proposalFailedSince = time.Time{}
	d.mu.Unlock()
	v.log(LogInformational, "DAVE: op26 key_package RESENT (len=%d)", len(kp))
	return nil
}

// SoftResetDAVE tears down the libdave MLS session, re-initializes it with
// the same protocol version + group ID + cached external sender bytes,
// and emits a fresh op26 key_package. The voice connection (WS + UDP for
// SRTP) stays up — only the MLS layer recycles. Mid-flight audio that
// arrives during the reset window will fail to inner-decrypt until the
// new ratchets are installed via the next op30.
//
// Use when ResendDAVEKeyPackage doesn't trigger an op27 within the
// secondary timeout, or when op30 came back with persistent
// ratchets_missing > 0 (group is in a bad state, fresh handshake needed).
func (v *VoiceConnection) SoftResetDAVE() error {
	v.Lock()
	d := v.dave
	v.Unlock()
	if d == nil {
		return errors.New("DAVE: not initialized")
	}
	d.mu.Lock()
	sess := d.session
	pv := d.protocolVersion
	extSender := append([]byte(nil), d.externalSender...)
	d.mu.Unlock()
	if sess == nil {
		return errors.New("DAVE: session destroyed")
	}
	if len(extSender) == 0 {
		// Without the cached external sender we can't re-init libdave
		// to a state where MarshalledKeyPackage produces something
		// Discord will accept. Bail rather than send garbage.
		return errors.New("DAVE: no cached external sender; cannot soft-reset")
	}

	groupID, err := strconv.ParseUint(v.ChannelID, 10, 64)
	if err != nil {
		return fmt.Errorf("DAVE: parse channel id: %w", err)
	}

	// libdave Reset wipes leaf, group, ratchets — the next Init produces
	// a fresh leaf with a new ephemeral signature key.
	d.mu.Lock()
	sess.Reset()
	sess.Init(pv, groupID, v.UserID)
	sess.SetExternalSender(extSender)
	d.mu.Unlock()

	kp := sess.MarshalledKeyPackage()
	if len(kp) == 0 {
		return errors.New("DAVE: empty key package after soft-reset")
	}
	if err := v.sendDAVEBinaryFrame(daveKeyPackageFrame(kp)); err != nil {
		return fmt.Errorf("DAVE: send key package after reset: %w", err)
	}
	d.mu.Lock()
	d.op26SentAt = time.Now()
	d.op30Received = false
	d.lastMissing = 0
	d.missingFirstSeen = time.Time{}
	d.proposalFailedSince = time.Time{}
	d.mu.Unlock()
	v.log(LogInformational, "DAVE: SOFT-RESET complete + op26 sent (len=%d)", len(kp))
	return nil
}
