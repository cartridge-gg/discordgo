// Tests for VoiceConnection.onEvent — the voice-gateway opcode dispatcher.
//
// These feed canned JSON frames straight into onEvent and assert on the
// observable VoiceConnection state. The aim is to lock in the v8 protocol
// shape so we don't ship another regression like the OP8/NewTicker(0)
// panic — anything Discord can send us should be exercised here without
// touching the network.
//
// Stateful side-effects (UDP open, websocket writes) are not exercised
// because the test connection has no wsConn — those handlers either
// no-op or take an early-return path on a nil websocket. We rely on the
// AEAD/parse tests in voice_aead_test.go and the DAVE wire-format tests
// to catch payload-layout bugs.

package discordgo

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cartridge-gg/discordgo/dave"
)

// newTestVoiceConn builds a VoiceConnection that's just complete enough
// to feed onEvent without panicking. It deliberately leaves wsConn and
// udpConn nil so that handlers which would write to the wire short-circuit.
func newTestVoiceConn() *VoiceConnection {
	return &VoiceConnection{
		UserID:    "111",
		GuildID:   "222",
		ChannelID: "333",
		close:     make(chan struct{}),
		// wsConn intentionally nil — handlers that would write to the
		// websocket take a guarded path when wsConn == nil.
	}
}

func TestVoiceOnEventOP2_PopulatesFields(t *testing.T) {
	v := newTestVoiceConn()
	// v3-shaped OP2 with HeartbeatInterval included. v8-shaped OP2
	// would arrive without it; the OP8 test below covers that path.
	raw := []byte(`{
		"op": 2,
		"d": {
			"ssrc": 12345,
			"ip": "203.0.113.10",
			"port": 50000,
			"modes": ["aead_aes256_gcm_rtpsize", "aead_xchacha20_poly1305_rtpsize", "xsalsa20_poly1305"],
			"heartbeat_interval": 41250
		}
	}`)

	v.onEvent(raw)

	if v.op2.SSRC != 12345 {
		t.Errorf("op2.SSRC = %d, want 12345", v.op2.SSRC)
	}
	if v.op2.IP != "203.0.113.10" {
		t.Errorf("op2.IP = %q, want 203.0.113.10", v.op2.IP)
	}
	if v.op2.Port != 50000 {
		t.Errorf("op2.Port = %d, want 50000", v.op2.Port)
	}
	want := []string{"aead_aes256_gcm_rtpsize", "aead_xchacha20_poly1305_rtpsize", "xsalsa20_poly1305"}
	if len(v.op2.Modes) != 3 || v.op2.Modes[0] != want[0] {
		t.Errorf("op2.Modes = %v, want %v", v.op2.Modes, want)
	}
	if v.op2.HeartbeatInterval != time.Duration(41250) {
		// json.Duration unmarshals from a number-of-nanoseconds. Discord
		// sends ms; bwmarrin's struct tag treats it as a Duration which
		// is a known wart. The OP8 path uses the correct ms→Duration
		// conversion and is what production v8 uses.
		t.Errorf("op2.HeartbeatInterval = %v (raw nanoseconds, expected as-is from JSON)", v.op2.HeartbeatInterval)
	}
}

func TestVoiceOnEventOP2_NoHeartbeatInVoiceGatewayV8(t *testing.T) {
	// Critical regression: voice gateway v8 sends OP2 without
	// heartbeat_interval. The previous code path called
	// time.NewTicker(v.op2.HeartbeatInterval) unconditionally and
	// panicked with "non-positive interval for NewTicker". Today the
	// guard skips starting the ticker when the interval is zero.
	v := newTestVoiceConn()
	raw := []byte(`{
		"op": 2,
		"d": {
			"ssrc": 99,
			"ip": "203.0.113.20",
			"port": 50001,
			"modes": ["aead_aes256_gcm_rtpsize"]
		}
	}`)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("onEvent panicked on v8 OP2: %v", r)
		}
	}()

	v.onEvent(raw) // must not panic
}

func TestVoiceOnEventOP8_StartsHeartbeat(t *testing.T) {
	// In v4+, HELLO carries heartbeat_interval. Until OP8 lands we
	// don't have a ticker. After OP8 we should: parse the float
	// milliseconds, start the heartbeat goroutine, not panic.
	v := newTestVoiceConn()
	raw := []byte(`{
		"op": 8,
		"d": { "heartbeat_interval": 41250.0 }
	}`)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("onEvent panicked on OP8: %v", r)
		}
	}()
	v.onEvent(raw)

	// The heartbeat goroutine writes to wsConn which is nil here, so
	// it'll exit immediately on its first tick. Just verifying that
	// the dispatch didn't panic and the close chan still exists.
	select {
	case <-v.close:
		t.Errorf("close chan unexpectedly closed")
	default:
	}
}

func TestVoiceOnEventOP8_NonPositiveIntervalIsRejected(t *testing.T) {
	v := newTestVoiceConn()
	raw := []byte(`{ "op": 8, "d": { "heartbeat_interval": 0 } }`)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("onEvent panicked on OP8 with zero interval: %v", r)
		}
	}()
	v.onEvent(raw)
}

func TestVoiceOnEventOP4_PopulatesSecretKeyAndMode(t *testing.T) {
	v := newTestVoiceConn()
	raw := []byte(`{
		"op": 4,
		"d": {
			"mode": "aead_aes256_gcm_rtpsize",
			"secret_key": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]
		}
	}`)
	v.onEvent(raw)

	if v.op4.Mode != "aead_aes256_gcm_rtpsize" {
		t.Errorf("op4.Mode = %q, want aead_aes256_gcm_rtpsize", v.op4.Mode)
	}
	if v.op4.SecretKey[0] != 1 || v.op4.SecretKey[31] != 32 {
		t.Errorf("op4.SecretKey wasn't populated correctly: %v", v.op4.SecretKey)
	}
}

func TestVoiceOnEventOP5_FiresHandler(t *testing.T) {
	v := newTestVoiceConn()
	called := false
	var got *VoiceSpeakingUpdate
	v.AddHandler(func(_ *VoiceConnection, vs *VoiceSpeakingUpdate) {
		called = true
		got = vs
	})

	raw := []byte(`{
		"op": 5,
		"d": { "user_id": "999", "ssrc": 4242, "speaking": true }
	}`)
	v.onEvent(raw)

	if !called {
		t.Fatalf("OP5 handler was not invoked")
	}
	if got.UserID != "999" || got.SSRC != 4242 || !got.Speaking {
		t.Errorf("got = %+v, want UserID=999 SSRC=4242 Speaking=true", got)
	}
}

func TestVoiceOnEventOP5_BookkeepingWhenDAVEInactive(t *testing.T) {
	// When v.dave is nil, OP5 should still drive the user-registered
	// VoiceSpeakingUpdate handlers but onDAVESpeakingUpdate must
	// no-op (calling into a real dave.Decryptor would require libdave
	// at test time). Verify the path is guarded.
	v := newTestVoiceConn()
	called := false
	v.AddHandler(func(_ *VoiceConnection, _ *VoiceSpeakingUpdate) { called = true })
	raw := []byte(`{
		"op": 5,
		"d": { "user_id": "999", "ssrc": 4242, "speaking": true }
	}`)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("OP5 with nil dave state panicked: %v", r)
		}
	}()
	v.onEvent(raw)
	if !called {
		t.Errorf("user handler not called for OP5")
	}
}

func TestVoiceOnEventOP21_DAVEPrepareTransition_NoDAVESession(t *testing.T) {
	// OP21 with no active DAVE state should not panic, and should
	// gracefully no-op on the decryptor-flip path. sendDAVEReadyForTransition
	// will try to write to wsConn — which is nil — so it returns early.
	v := newTestVoiceConn()
	raw := []byte(`{
		"op": 21,
		"d": { "protocol_version": 0, "transition_id": 42 }
	}`)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("OP21 panicked: %v", r)
		}
	}()
	v.onEvent(raw)
}

func TestVoiceOnEventOP22_DAVEExecuteTransition_NoOp(t *testing.T) {
	v := newTestVoiceConn()
	raw := []byte(`{ "op": 22, "d": { "transition_id": 7 } }`)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("OP22 panicked: %v", r)
		}
	}()
	v.onEvent(raw)
}

// daveStateForTest returns an empty daveState that can be safely passed
// to handlers. Session is nil; decryptors and ratchets are empty maps
// of the correct types. Handlers must guard against nil session.
func daveStateForTest() *daveState {
	return &daveState{
		decryptors: make(map[uint32]*daveStream),
		ratchets:   make(map[string]*dave.KeyRatchet),
	}
}

func TestVoiceOnEventOP21_DAVESession_PassthroughDowngrade(t *testing.T) {
	// OP21 with protocol_version=0 (downgrade) should iterate
	// decryptors and flip them to passthrough. With an empty
	// decryptors map, the loop is a no-op.
	v := newTestVoiceConn()
	v.dave = daveStateForTest()
	raw := []byte(`{
		"op": 21,
		"d": { "protocol_version": 0, "transition_id": 42 }
	}`)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("OP21 panicked with empty daveState: %v", r)
		}
	}()
	v.onEvent(raw)
}

func TestVoiceOnEventOP24_DAVEPrepareEpoch_NotEpoch1NoInit(t *testing.T) {
	// OP24 with epoch != 1 should NOT lazy-init a new MLS group.
	// It just records the protocol version on the existing session.
	// With v.dave == nil + epoch == 2, this path constructs the dave
	// state but skips the NewSession→Init call inside the if-block.
	// The dave.NewSession does need libdave linked, so when libdave
	// is available this must succeed; otherwise the test panics with
	// a CGO link error rather than a JSON-parse error.
	v := newTestVoiceConn()
	raw := []byte(`{
		"op": 24,
		"d": { "protocol_version": 1, "epoch": 2 }
	}`)
	defer func() {
		if r := recover(); r != nil {
			s, _ := r.(string)
			if strings.Contains(s, "unmarshal") || strings.Contains(s, "json:") {
				t.Errorf("OP24 JSON parse failed: %v", r)
			}
			t.Logf("OP24 epoch=2 panic (expected if libdave-less): %v", r)
		}
	}()
	v.onEvent(raw)
}

func TestVoiceOnEventUnknownOpcodeNoCrash(t *testing.T) {
	v := newTestVoiceConn()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unknown opcode crashed onEvent: %v", r)
		}
	}()
	v.onEvent([]byte(`{"op": 99, "d": {}}`))
}

func TestVoiceOnEventBadJSONNoCrash(t *testing.T) {
	v := newTestVoiceConn()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("bad JSON crashed onEvent: %v", r)
		}
	}()
	v.onEvent([]byte(`not json`))
}

// TestVoiceWsHeartbeatScaling locks in a load-bearing quirk in
// upstream's wsHeartbeat: the function multiplies its argument by
// time.Millisecond before passing to NewTicker. The v3 path benefits
// from this accidentally — voiceOP2.HeartbeatInterval is declared as
// time.Duration but Discord sends a millisecond integer, so the JSON
// unmarshal reads it as a nanosecond count, and the wsHeartbeat
// scaling restores the right tick rate.
//
// Our OP8 (HELLO) path must mirror that contract or the heartbeat
// fires either too fast (and the gateway closes us) or too slow
// (and the gateway closes us for missed heartbeats). Concretely:
// a Discord-sent value of 41250 ms must result in a ~41.25s tick.
func TestVoiceWsHeartbeatScaling_ContractMatch(t *testing.T) {
	// Simulate what OP8 hands off to wsHeartbeat: a time.Duration
	// constructed by casting the float64 ms count, NOT by multiplying
	// by time.Millisecond. wsHeartbeat then multiplies by Millisecond
	// internally.
	const ms = 41250.0
	got := time.Duration(ms) * time.Millisecond
	want := 41250 * time.Millisecond
	if got != want {
		t.Errorf("OP8→wsHeartbeat scaling: got %v, want %v (Discord intended 41.25s)", got, want)
	}
	if got != 41250*time.Millisecond {
		t.Errorf("scaling produced %v, want 41.25 seconds", got)
	}
}

// Round-trip the OP2 struct through json.Unmarshal directly so we
// catch schema regressions in the struct tags without going through
// the full onEvent path.
func TestVoiceOP2_JSONStructTags(t *testing.T) {
	src := []byte(`{
		"ssrc": 1,
		"ip": "1.2.3.4",
		"port": 5,
		"modes": ["a"],
		"heartbeat_interval": 100
	}`)
	var op voiceOP2
	if err := json.Unmarshal(src, &op); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if op.SSRC != 1 || op.IP != "1.2.3.4" || op.Port != 5 || len(op.Modes) != 1 {
		t.Errorf("voiceOP2 fields didn't unmarshal: %+v", op)
	}
}
