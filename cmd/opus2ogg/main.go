// opus2ogg — convert voicedebug's length-prefixed Opus packet dump into a
// playable OGG OPUS file. The .opus files written by cmd/voicedebug are
// raw Opus packets framed as [uint16 BE length][N bytes opus]; that's
// not playable by anything. This tool wraps each packet into an OGG
// page so you can drop the result into VLC/Audacity/ffplay and verify
// the bytes really are plaintext Opus speech.
//
// If the input was actually ciphertext, libopus will fail to decode
// during playback (silence, errors, or noise) — that's the e2e signal
// for whether DAVE inner decrypt produced real plaintext.
//
// Usage:
//
//	go run ./cmd/opus2ogg < /tmp/voicedebug-out/ssrc-453.opus > /tmp/voicedebug-out/ssrc-453.ogg
//	ffplay /tmp/voicedebug-out/ssrc-453.ogg
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"os"
)

// OGG CRC uses a non-standard polynomial. Build a table once.
var oggCRCTable = func() *crc32.Table {
	return crc32.MakeTable(0x04C11DB7) // Reflect=false, this is what OGG uses but the Go std uses reflected variants by default. Fall through to manual implementation below.
}()

// oggCRC32 implements RFC 3533 CRC32 (poly 0x04C11DB7, init 0, no
// reflection, no final xor). hash/crc32 only exposes reflected variants,
// so do it by hand. ~2µs per page in this tool's volume.
func oggCRC32(b []byte) uint32 {
	var crc uint32
	for _, x := range b {
		crc ^= uint32(x) << 24
		for i := 0; i < 8; i++ {
			if crc&0x80000000 != 0 {
				crc = (crc << 1) ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// writeOggPage writes a single OGG page wrapping `payload`. headerType:
// 0x02 first page, 0x04 last page, 0x00 normal, 0x01 continuation.
// granule is the absolute granule position (cumulative samples for
// audio pages, 0 for header pages).
func writeOggPage(w io.Writer, payload []byte, headerType byte, granule uint64, serial, seqNo uint32) error {
	// Segment table: split payload into 255-byte segments. A trailing
	// segment < 255 marks end of packet. If payload size is a multiple
	// of 255, append a zero-byte segment.
	var segs []byte
	rem := len(payload)
	for rem >= 255 {
		segs = append(segs, 255)
		rem -= 255
	}
	segs = append(segs, byte(rem))
	if len(segs) > 255 {
		return fmt.Errorf("payload too large for single OGG page (%d bytes)", len(payload))
	}

	header := make([]byte, 27+len(segs))
	copy(header[0:4], "OggS")
	header[4] = 0 // version
	header[5] = headerType
	binary.LittleEndian.PutUint64(header[6:14], granule)
	binary.LittleEndian.PutUint32(header[14:18], serial)
	binary.LittleEndian.PutUint32(header[18:22], seqNo)
	// CRC at [22:26] is computed over the entire page (header + payload)
	// with the CRC field zeroed. Already zeroed.
	header[26] = byte(len(segs))
	copy(header[27:], segs)

	page := append(header, payload...)
	crc := oggCRC32(page)
	binary.LittleEndian.PutUint32(page[22:26], crc)

	_, err := w.Write(page)
	return err
}

// opusHeadPacket builds the OPUS HEAD packet (page 1).
func opusHeadPacket(channels uint8, sampleRate uint32) []byte {
	pkt := make([]byte, 19)
	copy(pkt[0:8], "OpusHead")
	pkt[8] = 1 // version
	pkt[9] = channels
	binary.LittleEndian.PutUint16(pkt[10:12], 312) // preskip — 312 samples is the libopus default
	binary.LittleEndian.PutUint32(pkt[12:16], sampleRate)
	binary.LittleEndian.PutUint16(pkt[16:18], 0) // output gain
	pkt[18] = 0                                  // channel mapping family 0
	return pkt
}

// opusTagsPacket builds the OPUS TAGS packet (page 2). Empty comments.
func opusTagsPacket() []byte {
	vendor := "voicedebug-opus2ogg"
	pkt := make([]byte, 0, 16+len(vendor))
	pkt = append(pkt, []byte("OpusTags")...)
	var vlen [4]byte
	binary.LittleEndian.PutUint32(vlen[:], uint32(len(vendor)))
	pkt = append(pkt, vlen[:]...)
	pkt = append(pkt, []byte(vendor)...)
	var clen [4]byte
	binary.LittleEndian.PutUint32(clen[:], 0) // comment count
	pkt = append(pkt, clen[:]...)
	return pkt
}

func main() {
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	serial := rand.Uint32()
	var seq uint32

	// Page 1: OpusHead. headerType=0x02 means "beginning of stream".
	if err := writeOggPage(out, opusHeadPacket(1, 48000), 0x02, 0, serial, seq); err != nil {
		fmt.Fprintf(os.Stderr, "write head: %v\n", err)
		os.Exit(1)
	}
	seq++

	// Page 2: OpusTags. headerType=0x00.
	if err := writeOggPage(out, opusTagsPacket(), 0x00, 0, serial, seq); err != nil {
		fmt.Fprintf(os.Stderr, "write tags: %v\n", err)
		os.Exit(1)
	}
	seq++

	// Pages 3+: one Opus packet per page. Granule increments by samples
	// per packet — Discord uses 20ms frames at 48kHz = 960 samples.
	const samplesPerFrame = 960
	var granule uint64
	var packets int
	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(in, lenBuf[:]); err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "read length: %v\n", err)
			os.Exit(1)
		}
		size := int(binary.BigEndian.Uint16(lenBuf[:]))
		if size == 0 || size > 4000 {
			fmt.Fprintf(os.Stderr, "implausible packet length %d at packet %d\n", size, packets)
			os.Exit(1)
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(in, buf); err != nil {
			fmt.Fprintf(os.Stderr, "read packet body (%d bytes): %v\n", size, err)
			os.Exit(1)
		}
		granule += samplesPerFrame
		if err := writeOggPage(out, buf, 0x00, granule, serial, seq); err != nil {
			fmt.Fprintf(os.Stderr, "write page %d: %v\n", seq, err)
			os.Exit(1)
		}
		seq++
		packets++
	}

	fmt.Fprintf(os.Stderr, "wrote %d audio packets (%.2fs at 48kHz/20ms frames)\n",
		packets, float64(packets)*0.020)
}
