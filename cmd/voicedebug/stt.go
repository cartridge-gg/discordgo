package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// utteranceBuf accumulates Opus packets for a single SSRC's current
// utterance. Flushed by sttFlush when Speaking=false fires for that
// SSRC, or by the ceiling watchdog when first-packet age exceeds
// maxUtteranceAge.
type utteranceBuf struct {
	mu      sync.Mutex
	frames  [][]byte
	first   time.Time
	last    time.Time
	userID  string
	display string // resolved display name; empty until first GuildMember lookup
}

func (u *utteranceBuf) append(opus []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.frames) == 0 {
		u.first = time.Now()
	}
	u.last = time.Now()
	cp := make([]byte, len(opus))
	copy(cp, opus)
	u.frames = append(u.frames, cp)
}

// take returns the current frames and clears the buffer.
func (u *utteranceBuf) take() (frames [][]byte, first time.Time, userID, display string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	frames = u.frames
	first = u.first
	userID = u.userID
	display = u.display
	u.frames = nil
	u.first = time.Time{}
	return
}

// sttManager owns per-SSRC utterance buffers and dispatches completed
// utterances to ElevenLabs.
type sttManager struct {
	apiKey      string
	language    string
	utterDir    string
	gapMs       int
	maxAgeMs    int
	minMs       int
	resolveName func(userID string) string
	bufs        sync.Map // ssrc → *utteranceBuf
	httpClient  *http.Client
	log         func(format string, args ...any)
}

func newSTTManager(apiKey, language, utterDir string, resolveName func(string) string, log func(string, ...any)) *sttManager {
	return &sttManager{
		apiKey:      apiKey,
		language:    language,
		utterDir:    utterDir,
		gapMs:       1500,
		maxAgeMs:    10_000,
		minMs:       400,
		resolveName: resolveName,
		httpClient:  &http.Client{Timeout: 60 * time.Second},
		log:         log,
	}
}

func (m *sttManager) buf(ssrc uint32) *utteranceBuf {
	if v, ok := m.bufs.Load(ssrc); ok {
		return v.(*utteranceBuf)
	}
	v, _ := m.bufs.LoadOrStore(ssrc, &utteranceBuf{})
	return v.(*utteranceBuf)
}

// Append routes an opus packet into the right SSRC buffer.
func (m *sttManager) Append(ssrc uint32, opus []byte) {
	m.buf(ssrc).append(opus)
}

// NoteSpeaker records the userID for an SSRC (called from VoiceSpeakingUpdate).
// Resolves display name lazily on first flush.
func (m *sttManager) NoteSpeaker(ssrc uint32, userID string) {
	b := m.buf(ssrc)
	b.mu.Lock()
	b.userID = userID
	b.mu.Unlock()
}

// FlushSSRC ships the accumulated frames for one SSRC if there are any.
// Reason is purely for logging.
func (m *sttManager) FlushSSRC(ssrc uint32, reason string) {
	frames, first, userID, display := m.buf(ssrc).take()
	if len(frames) == 0 {
		return
	}
	durMs := len(frames) * 20
	if durMs < m.minMs {
		m.log("|| ssrc=%d skip-flush %s dur=%dms (<%dms min)", ssrc, reason, durMs, m.minMs)
		return
	}
	if display == "" && userID != "" && m.resolveName != nil {
		display = m.resolveName(userID)
		// cache for next utterance
		b := m.buf(ssrc)
		b.mu.Lock()
		b.display = display
		b.mu.Unlock()
	}
	if display == "" {
		display = fmt.Sprintf("ssrc-%d", ssrc)
	}
	go m.transcribeAndPrint(ssrc, frames, first, durMs, display, userID, reason)
}

// FlushAll iterates all known SSRCs.
func (m *sttManager) FlushAll(reason string) {
	m.bufs.Range(func(k, _ any) bool {
		m.FlushSSRC(k.(uint32), reason)
		return true
	})
}

// CeilingTick force-flushes any SSRC whose oldest packet is older than maxAgeMs,
// or whose last packet was longer than gapMs ago. Call every 200ms.
func (m *sttManager) CeilingTick(now time.Time) {
	m.bufs.Range(func(k, v any) bool {
		b := v.(*utteranceBuf)
		b.mu.Lock()
		empty := len(b.frames) == 0
		ageOldest := now.Sub(b.first)
		gap := now.Sub(b.last)
		b.mu.Unlock()
		if empty {
			return true
		}
		switch {
		case ageOldest > time.Duration(m.maxAgeMs)*time.Millisecond:
			m.FlushSSRC(k.(uint32), "max_age")
		case gap > time.Duration(m.gapMs)*time.Millisecond:
			m.FlushSSRC(k.(uint32), "silence_gap")
		}
		return true
	})
}

func (m *sttManager) transcribeAndPrint(ssrc uint32, frames [][]byte, first time.Time, durMs int, display, userID, reason string) {
	ogg := opusFramesToOgg(frames)

	// Save the .ogg file too — independently inspectable artifact.
	if m.utterDir != "" {
		_ = os.MkdirAll(m.utterDir, 0o755)
		ts := first.Format("20060102-150405.000")
		safeName := strings.ReplaceAll(display, " ", "_")
		fname := fmt.Sprintf("%s-ssrc%d-%s.ogg", ts, ssrc, safeName)
		if err := os.WriteFile(filepath.Join(m.utterDir, fname), ogg, 0o644); err != nil {
			m.log("|| ssrc=%d write utterance file: %v", ssrc, err)
		}
	}

	if m.apiKey == "" {
		// No STT key — just log the boundary.
		m.log("|| ssrc=%d utterance %s dur=%dms frames=%d (no STT)", ssrc, reason, durMs, len(frames))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	text, err := m.elevenLabsSTT(ctx, ogg)
	if err != nil {
		m.log("|| ssrc=%d STT error %s dur=%dms: %v", ssrc, reason, durMs, err)
		return
	}
	text = strings.TrimSpace(text)
	if text == "" {
		m.log("|| ssrc=%d STT empty %s dur=%dms", ssrc, reason, durMs)
		return
	}
	fmt.Printf(">>> [%s | ssrc=%d | %s | %dms]: %s\n",
		first.Format("15:04:05"), ssrc, display, durMs, text)
}

func (m *sttManager) elevenLabsSTT(ctx context.Context, ogg []byte) (string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("model_id", "scribe_v1"); err != nil {
		return "", err
	}
	if m.language != "" {
		if err := mw.WriteField("language_code", m.language); err != nil {
			return "", err
		}
	}
	fw, err := mw.CreateFormFile("file", "utterance.ogg")
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(ogg); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.elevenlabs.io/v1/speech-to-text", &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("xi-api-key", m.apiKey)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Text         string  `json:"text"`
		LanguageCode string  `json:"language_code"`
		Duration     float64 `json:"audio_duration_secs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Text, nil
}
