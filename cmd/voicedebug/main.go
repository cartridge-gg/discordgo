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
//	export DISCORD_TOKEN="$(gcloud secrets versions access latest --secret=agent-discord-eng-token --project=c7e-prod)"
//	export GUILD_ID=954866867376357397
//	export VOICE_CHANNEL_ID=960655952116346931
//	go run ./cmd/voicedebug
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
	handlerDelay := flag.Duration("handler-delay", 0,
		"sleep this long between ChannelVoiceJoin returning and registering the "+
			"VoiceSpeakingUpdate handler. Simulates goclaw's onJoinSuccess REST window "+
			"to repro the OP5-drop race the dave.16 fix targets.")
	flag.Parse()

	token := os.Getenv("DISCORD_TOKEN")
	guildID := os.Getenv("GUILD_ID")
	channelID := os.Getenv("VOICE_CHANNEL_ID")
	if token == "" || guildID == "" || channelID == "" {
		log.Fatal("set DISCORD_TOKEN, GUILD_ID, VOICE_CHANNEL_ID")
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
	vc.AddHandler(func(_ *discordgo.VoiceConnection, vsu *discordgo.VoiceSpeakingUpdate) {
		fmt.Printf(">>> VoiceSpeakingUpdate user=%s ssrc=%d speaking=%v\n",
			vsu.UserID, vsu.SSRC, vsu.Speaking)
	})

	stats := struct {
		mu sync.Mutex
		m  map[uint32]*ssrcStat
	}{m: make(map[uint32]*ssrcStat)}

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
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n>>> shutdown signal; disconnecting voice + gateway")
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
