// voicedebug — local repro tool for voice gateway / DAVE protocol bring-up.
//
// Connects with a bot token, joins a single voice channel, and dumps every
// gateway frame and every voice opcode at LogDebug. Designed to be run
// locally against the prod Cartridge bot (after scaling the prod replica
// to 0 so Discord doesn't reject the duplicate WS), so we can iterate on
// the DAVE handshake without a Cloud-Build round trip.
//
// Usage:
//
//	export DISCORD_TOKEN="$(gcloud secrets versions access latest --secret=agent-discord-eng-token --project=c7e-prod)"
//	export GUILD_ID=954866867376357397
//	export VOICE_CHANNEL_ID=960655952116346931
//	go run ./cmd/voicedebug
//
// The binary prints every Op-* frame received and every state transition
// it makes on the voice connection. Ctrl-C cleanly disconnects.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cartridge-gg/discordgo"
)

func main() {
	verbose := flag.Bool("verbose", true, "log every dispatched event")
	flag.Parse()

	token := os.Getenv("DISCORD_TOKEN")
	guildID := os.Getenv("GUILD_ID")
	channelID := os.Getenv("VOICE_CHANNEL_ID")
	if token == "" || guildID == "" || channelID == "" {
		log.Fatal("set DISCORD_TOKEN, GUILD_ID, VOICE_CHANNEL_ID")
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
	vc.AddHandler(func(_ *discordgo.VoiceConnection, vsu *discordgo.VoiceSpeakingUpdate) {
		fmt.Printf(">>> VoiceSpeakingUpdate user=%s ssrc=%d speaking=%v\n",
			vsu.UserID, vsu.SSRC, vsu.Speaking)
	})

	fmt.Println(">>> voice connected; tailing OpusRecv. Ctrl-C to exit.")
	go func() {
		for p := range vc.OpusRecv {
			fmt.Printf(">>> opus packet ssrc=%d seq=%d ts=%d len=%d\n",
				p.SSRC, p.Sequence, p.Timestamp, len(p.Opus))
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n>>> shutdown signal; disconnecting voice + gateway")
	_ = vc.Disconnect()
	_ = dg.Close()
}
