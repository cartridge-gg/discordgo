// Discord voice-gateway AEAD encryption modes.
//
// As of voice gateway v8 (and DAVE rollout), Discord deprecated
// `xsalsa20_poly1305` and now only accepts the AEAD modes:
//   - aead_aes256_gcm_rtpsize       (preferred — hw-accelerated AES-NI)
//   - aead_xchacha20_poly1305_rtpsize
//
// In RTP-size mode, Discord packs the nonce as a 32-bit big-endian counter
// at the *end* of every UDP packet (NOT in the RTP header). The decryption
// flow per packet is:
//
//   1. Take the last 4 bytes of the packet as a 32-bit BE counter.
//   2. Pad to the AEAD's full nonce length (12 for AES-GCM, 24 for XChaCha20)
//      with leading zeros: nonce = [0...0 || counter_be32].
//   3. AAD = the RTP header (first 12 bytes of the packet).
//   4. Ciphertext (with appended 16-byte tag) = packet[12 : len-4].
//   5. Decrypt → plaintext is the inner DAVE-encrypted Opus frame.
//
// Upstream bwmarrin/discordgo v0.29.0 hardcodes xsalsa20_poly1305, so the
// gateway closes voice with code 4016 ("Unknown encryption mode") on
// servers that no longer offer the legacy cipher. This file adds the AEAD
// modes alongside the legacy path, and selectVoiceEncryptionMode picks
// whichever of the two AEAD options Discord advertises in its OP2 ready
// frame, falling back to xsalsa20_poly1305 only if neither is available.

package discordgo

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	encModeAEADAESGCMRTPSize     = "aead_aes256_gcm_rtpsize"
	encModeAEADXChaChaPolyRTPSize = "aead_xchacha20_poly1305_rtpsize"
	encModeXSalsa20Poly1305      = "xsalsa20_poly1305"
)

// preferredVoiceEncryptionModes lists Discord-supported voice cipher modes
// in the order this client prefers them. AEAD modes are required by the
// post-DAVE voice gateway; the xsalsa fallback exists only for the rare
// legacy-only server.
var preferredVoiceEncryptionModes = []string{
	encModeAEADAESGCMRTPSize,
	encModeAEADXChaChaPolyRTPSize,
	encModeXSalsa20Poly1305,
}

// selectVoiceEncryptionMode picks the strongest cipher from the list of
// modes Discord advertises in OP2. Returns the empty string if none of our
// supported modes appear, which signals to the caller to abort the UDP
// handshake instead of sending a mode Discord won't accept.
func selectVoiceEncryptionMode(advertised []string) string {
	if len(advertised) == 0 {
		// OP2 didn't carry a modes list (unusual). Send the strongest
		// AEAD; Discord will reject if it doesn't support it and we'll
		// observe the close code.
		return encModeAEADAESGCMRTPSize
	}
	have := make(map[string]struct{}, len(advertised))
	for _, m := range advertised {
		have[m] = struct{}{}
	}
	for _, want := range preferredVoiceEncryptionModes {
		if _, ok := have[want]; ok {
			return want
		}
	}
	return ""
}

// decryptVoicePacket strips Discord's outer per-session encryption from a
// raw UDP packet and returns the plaintext payload (which may itself be
// DAVE-encrypted; that layer is peeled later in opusReceiver).
//
// `packet` is the full UDP datagram. The first 12 bytes are the RTP header
// and remain plaintext; the rest of the layout depends on the mode.
func decryptVoicePacket(mode string, packet []byte, key *[32]byte) ([]byte, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("packet too short for RTP header (%d bytes)", len(packet))
	}
	switch mode {
	case encModeAEADAESGCMRTPSize:
		return decryptAEADAESGCMRTPSize(packet, key)
	case encModeAEADXChaChaPolyRTPSize:
		return decryptAEADXChaChaPolyRTPSize(packet, key)
	case encModeXSalsa20Poly1305, "":
		// Legacy. Caller (opusReceiver) handles this directly via
		// secretbox to keep the path identical to upstream discordgo.
		return nil, fmt.Errorf("legacy xsalsa20_poly1305 handled inline")
	default:
		return nil, fmt.Errorf("unsupported voice encryption mode: %q", mode)
	}
}

// rtpAADEnd returns the byte offset where the AEAD ciphertext starts —
// the AAD is the bytes BEFORE this offset, which for *_rtpsize Discord
// modes is: 12-byte fixed RTP header + (4*CC) CSRC list + (4 bytes
// extension preamble IF the X bit is set, NOT the extension payload).
//
// This is the subtle bit that took an hour of debugging:
// "rtpsize" does NOT mean "full RTP header is AAD". The extension data
// itself is encrypted along with the audio payload — only the 4-byte
// extension preamble (defined-by-profile + length-in-words) is in the
// clear and contributes to AAD. After decryption, the caller must skip
// `4 * extLengthWords` bytes from the start of the plaintext to reach
// the actual codec data.
func rtpAADEnd(packet []byte) int {
	const fixed = 12
	if len(packet) < fixed {
		return 0
	}
	cc := int(packet[0] & 0x0F)
	plainLen := fixed + 4*cc
	if (packet[0] & 0x10) != 0 {
		plainLen += 4 // extension preamble only — payload stays encrypted
	}
	return plainLen
}

// rtpExtPayloadBytes returns the size in bytes of the (encrypted)
// extension payload that the caller must strip from the decrypted
// plaintext to reach the audio codec data. Returns 0 when there is no
// extension. Must be called on the same packet that was decrypted.
func rtpExtPayloadBytes(packet []byte) int {
	if len(packet) < 12 {
		return 0
	}
	if (packet[0] & 0x10) == 0 {
		return 0
	}
	cc := int(packet[0] & 0x0F)
	extPreambleAt := 12 + 4*cc
	if len(packet) < extPreambleAt+4 {
		return 0
	}
	return 4 * int(binary.BigEndian.Uint16(packet[extPreambleAt+2:extPreambleAt+4]))
}

// decryptAEADAESGCMRTPSize implements AES-256-GCM where:
//   - the 32-bit nonce counter sits at the END of the packet (4 bytes)
//   - that counter is copied to the FIRST 4 bytes of the 12-byte nonce
//     (Discord's encoder uses LittleEndian.PutUint32 on nonce[0:4], and
//      the counter byte ordering in the packet matches that, so a verbatim
//      copy here is correct).
//   - the AAD is the unencrypted RTP header bytes (fixed header + CSRCs
//     + 4-byte extension preamble if X bit set), NOT the extension data.
//   - the encrypted region is everything between AAD and the counter,
//     including the extension payload (which the caller strips after
//     decrypting).
//   - the standard 16-byte AEAD tag is the last 16 bytes of the
//     encrypted region (right before the counter).
//
// Reference: bwmarrin/discordgo PR #1704 voice.go opusReceiver.
func decryptAEADAESGCMRTPSize(packet []byte, key *[32]byte) ([]byte, error) {
	if len(packet) < 12+16+4 {
		return nil, fmt.Errorf("packet too short for AES-GCM (%d)", len(packet))
	}
	aadEnd := rtpAADEnd(packet)
	if aadEnd <= 0 || aadEnd > len(packet)-16-4 {
		return nil, fmt.Errorf("invalid RTP AAD end (%d) for packet len %d", aadEnd, len(packet))
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	// Counter at the END of packet → FIRST 4 bytes of nonce. Verbatim
	// byte copy preserves whatever endianness the encoder used.
	var nonce [12]byte
	copy(nonce[:4], packet[len(packet)-4:])

	aad := packet[:aadEnd]
	ciphertext := packet[aadEnd : len(packet)-4]

	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm open: %w", err)
	}
	// Strip the now-decrypted extension payload — it sits at the start
	// of the plaintext and is not part of the codec data.
	if extBytes := rtpExtPayloadBytes(packet); extBytes > 0 && extBytes <= len(plaintext) {
		plaintext = plaintext[extBytes:]
	}
	return plaintext, nil
}

// decryptAEADXChaChaPolyRTPSize is the XChaCha20-Poly1305 sibling of
// decryptAEADAESGCMRTPSize. Same AAD/ciphertext/nonce-position contract;
// only the cipher and nonce length differ.
func decryptAEADXChaChaPolyRTPSize(packet []byte, key *[32]byte) ([]byte, error) {
	if len(packet) < 12+16+4 {
		return nil, fmt.Errorf("packet too short for XChaCha20 (%d)", len(packet))
	}
	aadEnd := rtpAADEnd(packet)
	if aadEnd <= 0 || aadEnd > len(packet)-16-4 {
		return nil, fmt.Errorf("invalid RTP AAD end (%d) for packet len %d", aadEnd, len(packet))
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305.NewX: %w", err)
	}

	var nonce [chacha20poly1305.NonceSizeX]byte
	copy(nonce[:4], packet[len(packet)-4:])

	aad := packet[:aadEnd]
	ciphertext := packet[aadEnd : len(packet)-4]

	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("xchacha20-poly1305 open: %w", err)
	}
	if extBytes := rtpExtPayloadBytes(packet); extBytes > 0 && extBytes <= len(plaintext) {
		plaintext = plaintext[extBytes:]
	}
	return plaintext, nil
}

// voiceModeUsesAEAD reports whether the negotiated mode is one of the
// AEAD-RTPSize ciphers (i.e. the inline xsalsa decrypt in opusReceiver
// must not be used).
func voiceModeUsesAEAD(mode string) bool {
	return mode == encModeAEADAESGCMRTPSize || mode == encModeAEADXChaChaPolyRTPSize
}

// rtpSizeNonceCounterFromPacket returns just the 32-bit nonce counter from
// the trailing bytes of an RTP-size AEAD packet. Useful for telemetry.
func rtpSizeNonceCounterFromPacket(packet []byte) uint32 {
	if len(packet) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(packet[len(packet)-4:])
}
