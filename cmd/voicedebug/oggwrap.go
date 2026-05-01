package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
)

// oggCRC32 implements RFC 3533 CRC32 (poly 0x04C11DB7, init 0, no
// reflection, no final xor). Vendored from cmd/opus2ogg so voicedebug
// can build OGG payloads in memory without a separate process.
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

func writeOggPage(w io.Writer, payload []byte, headerType byte, granule uint64, serial, seqNo uint32) error {
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
	header[4] = 0
	header[5] = headerType
	binary.LittleEndian.PutUint64(header[6:14], granule)
	binary.LittleEndian.PutUint32(header[14:18], serial)
	binary.LittleEndian.PutUint32(header[18:22], seqNo)
	header[26] = byte(len(segs))
	copy(header[27:], segs)

	page := append(header, payload...)
	crc := oggCRC32(page)
	binary.LittleEndian.PutUint32(page[22:26], crc)

	_, err := w.Write(page)
	return err
}

func opusHeadPacket() []byte {
	pkt := make([]byte, 19)
	copy(pkt[0:8], "OpusHead")
	pkt[8] = 1                                    // version
	pkt[9] = 1                                    // channels (mono)
	binary.LittleEndian.PutUint16(pkt[10:12], 312) // preskip
	binary.LittleEndian.PutUint32(pkt[12:16], 48000) // sample rate
	binary.LittleEndian.PutUint16(pkt[16:18], 0)
	pkt[18] = 0
	return pkt
}

func opusTagsPacket() []byte {
	vendor := "voicedebug"
	pkt := make([]byte, 0, 16+len(vendor))
	pkt = append(pkt, []byte("OpusTags")...)
	var vlen [4]byte
	binary.LittleEndian.PutUint32(vlen[:], uint32(len(vendor)))
	pkt = append(pkt, vlen[:]...)
	pkt = append(pkt, []byte(vendor)...)
	var clen [4]byte
	binary.LittleEndian.PutUint32(clen[:], 0)
	pkt = append(pkt, clen[:]...)
	return pkt
}

// opusFramesToOgg wraps a list of raw Opus packets (each one a 20ms
// 48kHz/mono frame) into a complete in-memory OGG OPUS bytestream
// suitable for posting to a STT API or playing in ffplay.
func opusFramesToOgg(frames [][]byte) []byte {
	var buf bytes.Buffer
	serial := rand.Uint32()
	var seq uint32
	_ = writeOggPage(&buf, opusHeadPacket(), 0x02, 0, serial, seq)
	seq++
	_ = writeOggPage(&buf, opusTagsPacket(), 0x00, 0, serial, seq)
	seq++
	const samplesPerFrame = 960
	var granule uint64
	for i, f := range frames {
		granule += samplesPerFrame
		ht := byte(0x00)
		if i == len(frames)-1 {
			ht = 0x04 // last page
		}
		_ = writeOggPage(&buf, f, ht, granule, serial, seq)
		seq++
	}
	return buf.Bytes()
}
