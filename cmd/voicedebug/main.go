// voicedebug — local repro tool for voice gateway / DAVE protocol bring-up.
//
// Connects with a bot token, joins a single voice channel, and dumps every
// gateway frame and every voice opcode at LogDebug. Designed to be run
// locally against the prod Cartridge bot (after scaling the prod replica
// to 0 so Discord doesn't reject the duplicate WS), so we can iterate on
// the DAVE handshake without a Cloud-Build round trip.
//
// In addition to gateway logging, this also writes one .opus raw file per
// observed SSRC into /tmp/voicedebug-out/ and prints a TOC-byte histogram
// every 5 seconds. The histogram is the cheapest signal for whether
// inner-DAVE decrypt is producing plaintext: real Opus packets have
// TOC bytes in a narrow set (~5-10 distinct values across thousands of
// packets), while ciphertext bytes are roughly uniform over 0-255.
//
// Usage:
//
//	go run ./cmd/voicedebug -token-file /tmp/discord-token -guild-id ... -voice-channel-id ...
//
// Ctrl-C cleanly disconnects and prints final per-SSRC stats.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cartridge-gg/discordgo"
)

type ssrcStat struct {
	mu        sync.Mutex
	count     int
	totalLen  int
	tocHist   map[byte]int
	firstSeen time.Time
	file      *os.File
}

func main() {
	verbose := flag.Bool("verbose", true, "log every dispatched event")
	outDir := flag.String("out", "/tmp/voicedebug-out", "directory to dump per-SSRC raw opus files")
	utterDir := flag.String("utterances", "", "directory to dump one OGG OPUS file per detected utterance (default: <out>/utterances)")
	sttKey := flag.String("stt-elevenlabs", os.Getenv("ELEVENLABS_API_KEY"),
		"if set, POST each utterance to ElevenLabs Scribe and print the transcript to stdout. Defaults to $ELEVENLABS_API_KEY.")
	sttLang := flag.String("stt-language", "", "ISO 639-1 language hint passed to ElevenLabs (e.g. 'en'). Empty = auto-detect.")
	tokenFile := flag.String("token-file", "", "file containing the Discord bot token; preferred over $DISCORD_TOKEN for local debugging")
	guildFlag := flag.String("guild-id", os.Getenv("GUILD_ID"), "Discord guild ID. Defaults to $GUILD_ID.")
	channelFlag := flag.String("voice-channel-id", os.Getenv("VOICE_CHANNEL_ID"), "Discord voice channel ID. Defaults to $VOICE_CHANNEL_ID.")
	handlerDelay := flag.Duration("handler-delay", 0,
		"sleep this long between ChannelVoiceJoin returning and registering the "+
			"VoiceSpeakingUpdate handler. Simulates goclaw's onJoinSuccess REST window "+
			"to repro the OP5-drop race the dave.16 fix targets.")
	flag.Parse()
	if *utterDir == "" {
		*utterDir = filepath.Join(*outDir, "utterances")
	}

	token := os.Getenv("DISCORD_TOKEN")
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatalf("read token file: %v", err)
		}
		token = strings.TrimSpace(string(data))
	}
	guildID := *guildFlag
	channelID := *channelFlag
	if token == "" || guildID == "" || channelID == "" {
		log.Fatal("set DISCORD_TOKEN or -token-file, plus GUILD_ID/-guild-id and VOICE_CHANNEL_ID/-voice-channel-id")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", *outDir, err)
	}

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Fatalf("New: %v", err)
	}
	dg.LogLevel = discordgo.LogDebug
	dg.Identify.Intents = discordgo.IntentsGuildMessages |
		discordgo.IntentsDirectMessages |
		discordgo.IntentsMessageContent |
		discordgo.IntentsGuilds |
		discordgo.IntentsGuildVoiceStates

	dg.AddHandler(func(_ *discordgo.Session, r *discordgo.Ready) {
		fmt.Printf(">>> READY user=%s id=%s session=%s shard=%v guilds=%d\n",
			r.User.Username, r.User.ID, r.SessionID, r.Shard, len(r.Guilds))
	})
	dg.AddHandler(func(_ *discordgo.Session, vs *discordgo.VoiceStateUpdate) {
		fmt.Printf(">>> VoiceStateUpdate user=%s guild=%s channel=%s session=%s\n",
			vs.UserID, vs.GuildID, vs.ChannelID, vs.SessionID)
	})
	if *verbose {
		dg.AddHandler(func(_ *discordgo.Session, gc *discordgo.GuildCreate) {
			fmt.Printf(">>> GuildCreate id=%s name=%q members=%d voiceStates=%d\n",
				gc.Guild.ID, gc.Guild.Name, len(gc.Guild.Members), len(gc.Guild.VoiceStates))
		})
	}

	if err := dg.Open(); err != nil {
		log.Fatalf("Open gateway: %v", err)
	}
	defer dg.Close()
	fmt.Println(">>> main gateway connected; waiting 3s for READY...")
	time.Sleep(3 * time.Second)

	// Pre-allocate a VoiceConnection in the session map with LogLevel
	// already cranked, so voice.open()'s logs (which check v.LogLevel,
	// not s.LogLevel) actually fire. ChannelVoiceJoin will reuse this
	// existing entry instead of creating a fresh one with LogLevel=0.
	vc := &discordgo.VoiceConnection{LogLevel: discordgo.LogDebug}
	dg.Lock()
	dg.VoiceConnections[guildID] = vc
	dg.Unlock()

	fmt.Printf(">>> joining voice: guild=%s channel=%s\n", guildID, channelID)
	vc, err = dg.ChannelVoiceJoin(guildID, channelID, false /*mute*/, false /*deaf*/)
	if err != nil {
		log.Fatalf("ChannelVoiceJoin: %v", err)
	}
	vc.LogLevel = discordgo.LogDebug
	if *handlerDelay > 0 {
		fmt.Printf(">>> simulating goclaw REST window: delaying VoiceSpeakingUpdate handler registration by %s\n", *handlerDelay)
		time.Sleep(*handlerDelay)
	}
	// Display name resolver — caches GuildMember lookups so we don't hit
	// Discord's REST API once per utterance for the same user.
	var nameMu sync.Mutex
	nameCache := map[string]string{}
	resolveName := func(userID string) string {
		nameMu.Lock()
		if n, ok := nameCache[userID]; ok {
			nameMu.Unlock()
			return n
		}
		nameMu.Unlock()
		gm, gerr := dg.GuildMember(guildID, userID)
		name := userID
		if gerr == nil && gm != nil {
			switch {
			case gm.Nick != "":
				name = gm.Nick
			case gm.User != nil && gm.User.GlobalName != "":
				name = gm.User.GlobalName
			case gm.User != nil:
				name = gm.User.Username
			}
		}
		nameMu.Lock()
		nameCache[userID] = name
		nameMu.Unlock()
		return name
	}

	stt := newSTTManager(*sttKey, *sttLang, *utterDir, resolveName,
		func(format string, args ...any) { fmt.Printf(format+"\n", args...) })
	if *sttKey != "" {
		fmt.Printf(">>> STT enabled: ElevenLabs Scribe; utterances → %s\n", *utterDir)
	} else {
		fmt.Printf(">>> STT disabled (no --stt-elevenlabs / $ELEVENLABS_API_KEY); utterances → %s\n", *utterDir)
	}

	vc.AddHandler(func(_ *discordgo.VoiceConnection, vsu *discordgo.VoiceSpeakingUpdate) {
		if *verbose {
			fmt.Printf(">>> VoiceSpeakingUpdate user=%s ssrc=%d speaking=%v\n",
				vsu.UserID, vsu.SSRC, vsu.Speaking)
		}
		ssrc := uint32(vsu.SSRC)
		if vsu.UserID != "" {
			stt.NoteSpeaker(ssrc, vsu.UserID)
		}
		if !vsu.Speaking {
			stt.FlushSSRC(ssrc, "speaking_false")
		}
	})

	// Ceiling watchdog — gap-flush at 1.5s silence, force-flush at 10s.
	stopCeiling := make(chan struct{})
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopCeiling:
				return
			case now := <-t.C:
				stt.CeilingTick(now)
			}
		}
	}()

	stats := struct {
		mu sync.Mutex
		m  map[uint32]*ssrcStat
	}{m: make(map[uint32]*ssrcStat)}

	// DAVE handshake watchdog — detects stuck handshakes (op26 sent but
	// no op30) and partial-roster failures (op30 with ratchets_missing > 0)
	// and applies the resend / soft-reset recovery policy.
	//
	// "human in channel" is sourced from discordgo's State, which tracks
	// VoiceStateUpdate events Discord pushes via the main gateway. We
	// count voice-state entries whose ChannelID matches ours and whose
	// UserID isn't the bot. This works whether the human joined before
	// or after the bot, and doesn't depend on them having spoken yet
	// (the original SSRC-based heuristic was chicken-and-egg: SSRC only
	// appears the moment the handshake completes, so the watchdog could
	// never fire pre-handshake).
	botID := dg.State.User.ID
	humansActive := func() bool {
		g, err := dg.State.Guild(guildID)
		if err != nil || g == nil {
			return false
		}
		for _, vs := range g.VoiceStates {
			if vs == nil {
				continue
			}
			if vs.ChannelID != channelID {
				continue
			}
			if vs.UserID == botID {
				continue
			}
			return true
		}
		return false
	}
	wd := newDAVEWatchdog(vc, humansActive,
		func(format string, args ...any) { fmt.Printf(format+"\n", args...) })
	stopWatchdog := make(chan struct{})
	go wd.Run(stopWatchdog)

	getOrCreate := func(ssrc uint32) *ssrcStat {
		stats.mu.Lock()
		defer stats.mu.Unlock()
		if s, ok := stats.m[ssrc]; ok {
			return s
		}
		path := filepath.Join(*outDir, fmt.Sprintf("ssrc-%d.opus", ssrc))
		f, ferr := os.Create(path)
		if ferr != nil {
			log.Printf("create %s: %v", path, ferr)
		}
		s := &ssrcStat{
			tocHist:   make(map[byte]int),
			firstSeen: time.Now(),
			file:      f,
		}
		stats.m[ssrc] = s
		fmt.Printf(">>> new ssrc=%d → dumping to %s\n", ssrc, path)
		return s
	}

	fmt.Printf(">>> voice connected; opus -> %s, stats every 5s. Ctrl-C to exit.\n", *outDir)
	go func() {
		for p := range vc.OpusRecv {
			if len(p.Opus) == 0 {
				continue
			}
			s := getOrCreate(p.SSRC)
			s.mu.Lock()
			s.count++
			s.totalLen += len(p.Opus)
			s.tocHist[p.Opus[0]]++
			if s.file != nil {
				// Length-prefixed framing: 2-byte BE length + bytes.
				_, _ = s.file.Write([]byte{byte(len(p.Opus) >> 8), byte(len(p.Opus) & 0xff)})
				_, _ = s.file.Write(p.Opus)
			}
			s.mu.Unlock()
			stt.Append(p.SSRC, p.Opus)
		}
	}()

	// Periodic stats printer. The TOC-byte histogram is the cheapest
	// signal for whether inner DAVE decrypt is producing plaintext:
	// real Opus uses a narrow set of TOC byte values; ciphertext is
	// uniformly distributed over 0-255.
	go func() {
		for {
			time.Sleep(5 * time.Second)
			stats.mu.Lock()
			ssrcs := make([]uint32, 0, len(stats.m))
			for k := range stats.m {
				ssrcs = append(ssrcs, k)
			}
			sort.Slice(ssrcs, func(i, j int) bool { return ssrcs[i] < ssrcs[j] })
			for _, ssrc := range ssrcs {
				s := stats.m[ssrc]
				s.mu.Lock()
				if s.count == 0 {
					s.mu.Unlock()
					continue
				}
				distinct := len(s.tocHist)
				avgLen := s.totalLen / s.count
				// Top-3 most common TOC values.
				type kv struct {
					b byte
					n int
				}
				kvs := make([]kv, 0, distinct)
				for b, n := range s.tocHist {
					kvs = append(kvs, kv{b, n})
				}
				sort.Slice(kvs, func(i, j int) bool { return kvs[i].n > kvs[j].n })
				top := ""
				for i := 0; i < 3 && i < len(kvs); i++ {
					if i > 0 {
						top += " "
					}
					top += fmt.Sprintf("%#02x:%d", kvs[i].b, kvs[i].n)
				}
				signal := "PLAINTEXT?"
				if distinct > 32 {
					signal = "CIPHERTEXT?"
				}
				fmt.Printf("|| ssrc=%d packets=%d distinct_toc=%d avg_len=%d top_toc=[%s] -> %s\n",
					ssrc, s.count, distinct, avgLen, top, signal)
				s.mu.Unlock()
			}
			stats.mu.Unlock()
			fmt.Printf("|| %s\n", formatHealth(vc.DAVEHealth(), time.Now()))
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n>>> shutdown signal; flushing in-flight utterances")
	close(stopCeiling)
	close(stopWatchdog)
	stt.FlushAll("shutdown")
	// Give in-flight goroutines a moment to finish their POSTs.
	time.Sleep(2 * time.Second)
	fmt.Println(">>> disconnecting voice + gateway")
	_ = vc.Disconnect()
	_ = dg.Close()

	// Flush + close raw files.
	stats.mu.Lock()
	for _, s := range stats.m {
		if s.file != nil {
			_ = s.file.Close()
		}
	}
	stats.mu.Unlock()
}
