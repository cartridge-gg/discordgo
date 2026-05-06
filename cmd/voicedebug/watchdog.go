package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/cartridge-gg/discordgo"
)

// daveWatchdog polls vc.DAVEHealth every tickEvery and applies the recovery
// policy described in the design discussion:
//
//	if !op30Received && elapsed(op26) > stuckTimeout && humans > 0:
//	    resendOp26 (cap resendCap in resendWindow)
//	if op30Received && lastMissing > 0 && persisted > missingTimeout:
//	    softReset    (cap resetCap in resetWindow)
//
// "humans > 0" is approximated here by checking that any non-bot SSRC has
// produced at least one OpusRecv packet (tracked by the caller and passed
// in via humansActive). voicedebug's main loop sets that flag when the
// stats map gains a new SSRC.
type daveWatchdog struct {
	vc              *discordgo.VoiceConnection
	tickEvery       time.Duration
	stuckTimeout    time.Duration
	missingTimeout  time.Duration
	divergedTimeout time.Duration
	resendCap       int
	resendWindow    time.Duration
	resetCap        int
	resetWindow     time.Duration
	humansActive    func() bool
	log             func(format string, args ...any)

	mu      sync.Mutex
	resends []time.Time
	resets  []time.Time
}

func newDAVEWatchdog(vc *discordgo.VoiceConnection, humansActive func() bool, log func(string, ...any)) *daveWatchdog {
	return &daveWatchdog{
		vc:              vc,
		tickEvery:       2 * time.Second,
		stuckTimeout:    10 * time.Second,
		missingTimeout:  15 * time.Second,
		divergedTimeout: 5 * time.Second,
		resendCap:       3,
		resendWindow:    60 * time.Second,
		resetCap:        3,
		resetWindow:     120 * time.Second,
		humansActive:    humansActive,
		log:             log,
	}
}

// Run blocks, ticking until stopCh closes.
func (w *daveWatchdog) Run(stopCh <-chan struct{}) {
	t := time.NewTicker(w.tickEvery)
	defer t.Stop()
	for {
		select {
		case <-stopCh:
			return
		case now := <-t.C:
			w.tick(now)
		}
	}
}

func (w *daveWatchdog) tick(now time.Time) {
	if !w.humansActive() {
		return
	}
	h := w.vc.DAVEHealth()
	if !h.Initialized || h.OP26SentAt.IsZero() {
		return
	}

	switch {
	case !h.ProposalFailedSince.IsZero() && now.Sub(h.ProposalFailedSince) > w.divergedTimeout:
		// Highest priority: bot's MLS state diverged from the group's
		// epoch. ResendDAVEKeyPackage won't help here because libdave
		// will produce a key package for the wrong epoch — only a full
		// soft-reset (Reset + Init + fresh op26) recovers.
		w.tryReset(now, "epoch_diverged")
	case !h.OP30Received && now.Sub(h.OP26SentAt) > w.stuckTimeout:
		w.tryResend(now)
	case h.OP30Received && h.LastMissing > 0 && !h.MissingFirstSeen.IsZero() && now.Sub(h.MissingFirstSeen) > w.missingTimeout:
		w.tryReset(now, "missing_ratchets")
	}
}

func (w *daveWatchdog) tryResend(now time.Time) {
	w.mu.Lock()
	w.resends = pruneOlderThan(w.resends, now.Add(-w.resendWindow))
	if len(w.resends) >= w.resendCap {
		w.mu.Unlock()
		return
	}
	w.resends = append(w.resends, now)
	count := len(w.resends)
	w.mu.Unlock()

	if err := w.vc.ResendDAVEKeyPackage(); err != nil {
		w.log("|| WATCHDOG resend FAILED (%d/%d): %v", count, w.resendCap, err)
		return
	}
	w.log("|| WATCHDOG resend op26 (%d/%d in %s window)", count, w.resendCap, w.resendWindow)
}

func (w *daveWatchdog) tryReset(now time.Time, reason string) {
	w.mu.Lock()
	w.resets = pruneOlderThan(w.resets, now.Add(-w.resetWindow))
	if len(w.resets) >= w.resetCap {
		w.mu.Unlock()
		return
	}
	w.resets = append(w.resets, now)
	count := len(w.resets)
	w.mu.Unlock()

	if err := w.vc.SoftResetDAVE(); err != nil {
		w.log("|| WATCHDOG soft-reset FAILED reason=%s (%d/%d): %v", reason, count, w.resetCap, err)
		return
	}
	w.log("|| WATCHDOG soft-reset DAVE reason=%s (%d/%d in %s window)", reason, count, w.resetCap, w.resetWindow)
}

func pruneOlderThan(stamps []time.Time, cutoff time.Time) []time.Time {
	out := stamps[:0]
	for _, t := range stamps {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

// formatHealth renders a one-line snapshot for the periodic stats printer.
func formatHealth(h discordgo.DAVEHealth, now time.Time) string {
	if !h.Initialized {
		return "DAVE not initialized"
	}
	parts := []string{}
	if !h.OP26SentAt.IsZero() {
		parts = append(parts, fmt.Sprintf("op26-age=%s", now.Sub(h.OP26SentAt).Truncate(time.Second)))
	}
	if h.OP30Received {
		parts = append(parts, fmt.Sprintf("op30-age=%s", now.Sub(h.OP30LastReceived).Truncate(time.Second)))
	} else {
		parts = append(parts, "op30=NEVER")
	}
	parts = append(parts, fmt.Sprintf("roster=%d missing=%d", h.LastRosterSize, h.LastMissing))
	if !h.ProposalFailedSince.IsZero() {
		parts = append(parts, fmt.Sprintf("DIVERGED=%s", now.Sub(h.ProposalFailedSince).Truncate(time.Second)))
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return "DAVE " + out
}
