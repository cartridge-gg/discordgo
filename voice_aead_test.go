// Tests for the voice gateway AEAD encryption helpers in voice_aead.go.
//
// These are pure-function unit tests — they encrypt a known plaintext
// with the same construction Discord uses (AES-256-GCM-RTPSize or
// XChaCha20-Poly1305-RTPSize), then verify our decrypt path returns
// the original. Anything that breaks here would also break against
// real Discord traffic, but the test loop is sub-second so we catch
// regressions before pushing.

package discordgo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestSelectVoiceEncryptionMode_Preference(t *testing.T) {
	cases := []struct {
		name       string
		advertised []string
		want       string
	}{
		{
			name:       "all three available, prefer AES-GCM",
			advertised: []string{encModeXSalsa20Poly1305, encModeAEADXChaChaPolyRTPSize, encModeAEADAESGCMRTPSize},
			want:       encModeAEADAESGCMRTPSize,
		},
		{
			name:       "no AES-GCM, fall back to XChaCha20",
			advertised: []string{encModeXSalsa20Poly1305, encModeAEADXChaChaPolyRTPSize},
			want:       encModeAEADXChaChaPolyRTPSize,
		},
		{
			name:       "only legacy",
			advertised: []string{encModeXSalsa20Poly1305},
			want:       encModeXSalsa20Poly1305,
		},
		{
			name:       "no supported modes",
			advertised: []string{"some_future_cipher"},
			want:       "",
		},
		{
			name:       "empty list defaults to AES-GCM",
			advertised: nil,
			want:       encModeAEADAESGCMRTPSize,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectVoiceEncryptionMode(tc.advertised)
			if got != tc.want {
				t.Errorf("selectVoiceEncryptionMode(%v) = %q, want %q", tc.advertised, got, tc.want)
			}
		})
	}
}

func TestVoiceModeUsesAEAD(t *testing.T) {
	cases := map[string]bool{
		encModeAEADAESGCMRTPSize:      true,
		encModeAEADXChaChaPolyRTPSize: true,
		encModeXSalsa20Poly1305:       false,
		"":                            false,
		"unknown_mode":                false,
	}
	for mode, want := range cases {
		if got := voiceModeUsesAEAD(mode); got != want {
			t.Errorf("voiceModeUsesAEAD(%q) = %v, want %v", mode, got, want)
		}
	}
}

// makeAEADAESGCMPacket encrypts plaintext under Discord's
// aead_aes256_gcm_rtpsize layout so we can round-trip through our
// decrypt path.
func makeAEADAESGCMPacket(t *testing.T, key *[32]byte, rtpHeader []byte, plaintext []byte, counter uint32) []byte {
	t.Helper()
	if len(rtpHeader) != 12 {
		t.Fatalf("makeAEADAESGCMPacket: rtpHeader must be 12 bytes, got %d", len(rtpHeader))
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[8:], counter)

	ciphertext := aead.Seal(nil, nonce[:], plaintext, rtpHeader)
	packet := make([]byte, 0, len(rtpHeader)+len(ciphertext)+4)
	packet = append(packet, rtpHeader...)
	packet = append(packet, ciphertext...)
	tail := make([]byte, 4)
	binary.BigEndian.PutUint32(tail, counter)
	packet = append(packet, tail...)
	return packet
}

func TestDecryptAEADAESGCMRTPSize_RoundTrip(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	rtpHeader := []byte{0x80, 0x78, 0x12, 0x34, 0x00, 0x00, 0x00, 0x10, 0xde, 0xad, 0xbe, 0xef}
	plaintext := []byte("hello opus frame")
	packet := makeAEADAESGCMPacket(t, &key, rtpHeader, plaintext, 0x01020304)

	got, err := decryptVoicePacket(encModeAEADAESGCMRTPSize, packet, &key)
	if err != nil {
		t.Fatalf("decryptVoicePacket(aes-gcm-rtpsize): %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestDecryptAEADAESGCMRTPSize_TamperedTagFails(t *testing.T) {
	var key [32]byte
	rtpHeader := make([]byte, 12)
	rtpHeader[0] = 0x80
	plaintext := []byte("hello")
	packet := makeAEADAESGCMPacket(t, &key, rtpHeader, plaintext, 1)

	// Flip a bit inside the AEAD tag region (last 16 bytes before the
	// trailing 4-byte counter).
	tagStart := len(packet) - 4 - 16
	packet[tagStart] ^= 0x01

	if _, err := decryptVoicePacket(encModeAEADAESGCMRTPSize, packet, &key); err == nil {
		t.Errorf("decrypt should reject tampered AEAD tag, got nil error")
	}
}

func TestDecryptAEADAESGCMRTPSize_TamperedAADFails(t *testing.T) {
	var key [32]byte
	rtpHeader := make([]byte, 12)
	rtpHeader[0] = 0x80
	plaintext := []byte("hello")
	packet := makeAEADAESGCMPacket(t, &key, rtpHeader, plaintext, 1)

	// Flip a bit inside the RTP header (used as AAD). AEAD must fail.
	packet[5] ^= 0x01
	if _, err := decryptVoicePacket(encModeAEADAESGCMRTPSize, packet, &key); err == nil {
		t.Errorf("decrypt should reject tampered AAD, got nil error")
	}
}

func makeAEADXChaChaPacket(t *testing.T, key *[32]byte, rtpHeader []byte, plaintext []byte, counter uint32) []byte {
	t.Helper()
	if len(rtpHeader) != 12 {
		t.Fatalf("makeAEADXChaChaPacket: rtpHeader must be 12 bytes, got %d", len(rtpHeader))
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		t.Fatalf("chacha20poly1305.NewX: %v", err)
	}
	var nonce [chacha20poly1305.NonceSizeX]byte
	binary.BigEndian.PutUint32(nonce[chacha20poly1305.NonceSizeX-4:], counter)

	ciphertext := aead.Seal(nil, nonce[:], plaintext, rtpHeader)
	packet := make([]byte, 0, len(rtpHeader)+len(ciphertext)+4)
	packet = append(packet, rtpHeader...)
	packet = append(packet, ciphertext...)
	tail := make([]byte, 4)
	binary.BigEndian.PutUint32(tail, counter)
	packet = append(packet, tail...)
	return packet
}

func TestDecryptAEADXChaChaPolyRTPSize_RoundTrip(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	rtpHeader := []byte{0x80, 0x78, 0x12, 0x34, 0x00, 0x00, 0x00, 0x10, 0xde, 0xad, 0xbe, 0xef}
	plaintext := []byte("hello chacha")
	packet := makeAEADXChaChaPacket(t, &key, rtpHeader, plaintext, 0x01020304)

	got, err := decryptVoicePacket(encModeAEADXChaChaPolyRTPSize, packet, &key)
	if err != nil {
		t.Fatalf("decryptVoicePacket(xchacha-rtpsize): %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestDecryptVoicePacket_TooShortFails(t *testing.T) {
	var key [32]byte
	short := []byte{1, 2, 3}
	if _, err := decryptVoicePacket(encModeAEADAESGCMRTPSize, short, &key); err == nil {
		t.Errorf("expected error on too-short packet, got nil")
	}
}

func TestDecryptVoicePacket_LegacyModeRoutedToCaller(t *testing.T) {
	// Legacy xsalsa20_poly1305 is handled inline by opusReceiver via
	// secretbox; decryptVoicePacket should refuse the call so the caller
	// knows to take the legacy path.
	var key [32]byte
	packet := make([]byte, 64)
	if _, err := decryptVoicePacket(encModeXSalsa20Poly1305, packet, &key); err == nil {
		t.Errorf("legacy mode should return an error directing the caller to handle it inline")
	}
}

func TestRTPSizeNonceCounterFromPacket(t *testing.T) {
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint32(pkt[16:], 0xdeadbeef)
	if got := rtpSizeNonceCounterFromPacket(pkt); got != 0xdeadbeef {
		t.Errorf("rtpSizeNonceCounterFromPacket = %#x, want 0xdeadbeef", got)
	}
	if got := rtpSizeNonceCounterFromPacket([]byte{1, 2}); got != 0 {
		t.Errorf("short packet should return 0, got %#x", got)
	}
}

func TestParseDAVEBinaryHeader(t *testing.T) {
	// Binary frame: uint16 seq || uint8 op || payload
	frame := []byte{0x12, 0x34, 25, 0xaa, 0xbb, 0xcc}
	seq, op, payload, err := parseDAVEBinaryHeader(frame)
	if err != nil {
		t.Fatalf("parseDAVEBinaryHeader: %v", err)
	}
	if seq != 0x1234 {
		t.Errorf("seq = %#x, want 0x1234", seq)
	}
	if op != 25 {
		t.Errorf("op = %d, want 25", op)
	}
	if !bytes.Equal(payload, []byte{0xaa, 0xbb, 0xcc}) {
		t.Errorf("payload = %v, want [0xaa 0xbb 0xcc]", payload)
	}
}

func TestParseDAVEBinaryHeader_TooShort(t *testing.T) {
	if _, _, _, err := parseDAVEBinaryHeader([]byte{0, 1}); err == nil {
		t.Errorf("expected error on 2-byte frame, got nil")
	}
}

func TestDAVECommitWelcomeFrame_Shape(t *testing.T) {
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	out := daveCommitWelcomeFrame(body)
	if len(out) != 1+len(body) {
		t.Fatalf("len(out) = %d, want %d", len(out), 1+len(body))
	}
	if out[0] != voiceOpDAVEMLSCommitWelcome {
		t.Errorf("out[0] = %d, want opcode %d", out[0], voiceOpDAVEMLSCommitWelcome)
	}
	if !bytes.Equal(out[1:], body) {
		t.Errorf("out[1:] = %v, want %v", out[1:], body)
	}
}

func TestDAVEKeyPackageFrame_Shape(t *testing.T) {
	body := []byte{0xca, 0xfe, 0xba, 0xbe}
	out := daveKeyPackageFrame(body)
	if len(out) != 1+len(body) {
		t.Fatalf("len(out) = %d", len(out))
	}
	if out[0] != voiceOpDAVEMLSKeyPackage {
		t.Errorf("out[0] = %d, want %d", out[0], voiceOpDAVEMLSKeyPackage)
	}
}
