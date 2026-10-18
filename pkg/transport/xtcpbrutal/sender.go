// Package xtcpbrutal implements an opt-in bounded rate-based QUIC congestion
// controller for XTCP Visitor traffic. The policy is inspired by Hysteria 2's
// Brutal controller but keeps an explicit configured pacing cap.
//
// It does not generate duplicate packets, disable QUIC loss recovery, alter
// XTCP NAT traversal, or create any new public UDP sockets.
package xtcpbrutal

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const (
	samplesSeconds  = 5
	minSamples      = 50
	minAckFraction  = 0.8
	minWindowBytes  = 16 * 1024
	maxWindowBytes  = 8 * 1024 * 1024
	maxBurstPackets = 10
	burstMillis     = 4
	bytesPerMbps    = int64(125_000)

	// MaxSafeMbps is an arithmetic guard, NOT an arbitrary 64 Mbps policy
	// limit. The token bucket multiplies bytes/sec by elapsed nanoseconds;
	// reject inputs that could overflow that multiplication on 64-bit Go.
	// This allows rates up to roughly 73 Gbps while retaining bounded
	// pacing, congestion windows, and QUIC backpressure.
	MaxSafeMbps = int((1<<63 - 1) / (bytesPerMbps * int64(time.Second)))
)

var (
	_ congestion.CongestionControl   = (*Sender)(nil)
	_ congestion.CongestionControlEx = (*Sender)(nil)
)

type packetSample struct {
	second int64
	acked  uint64
	lost   uint64
}

// Sender is owned by a single QUIC connection. quic-go serializes its packet,
// ACK and loss callbacks on that connection; callers must not share a Sender.
type Sender struct {
	targetBps int64
	maxBps    int64
	maxPacket congestion.ByteCount
	rtt       congestion.RTTStatsProvider

	samples      [samplesSeconds]packetSample
	ackRatio     float64
	pacer        pacingBucket
	diagEnabled  atomic.Bool
	diagSnapshot atomic.Pointer[DiagnosticSnapshot]
	diagAt       monotime.Time
	diagRawACK   float64
}

// NewSender configures a target rate and a strict *total wire pacing* ceiling,
// both expressed in decimal megabits per second. QUIC headers and retransmits
// use the same pacing budget, rather than being extra unbounded traffic.
func NewSender(targetMbps, maxMbps int) (*Sender, error) {
	if targetMbps < 1 || targetMbps > MaxSafeMbps ||
		maxMbps < targetMbps || maxMbps > MaxSafeMbps {
		return nil, fmt.Errorf("bounded Brutal requires 1 <= targetMbps <= maxMbps <= %d (arithmetic safety limit)", MaxSafeMbps)
	}
	s := &Sender{
		targetBps: int64(targetMbps) * bytesPerMbps,
		maxBps:    int64(maxMbps) * bytesPerMbps,
		maxPacket: congestion.InitialPacketSize,
		ackRatio:  1,
	}
	s.pacer = pacingBucket{
		maxPacket:  congestion.InitialPacketSize,
		lastBudget: maxBurstPackets * congestion.InitialPacketSize,
	}
	return s, nil
}

func (s *Sender) SetRTTStatsProvider(provider congestion.RTTStatsProvider) {
	s.rtt = provider
}

// pacedBytesPerSecond can compensate for loss but never exceed maxMbps.
// The min ACK fraction also makes compensation intentionally conservative.
func (s *Sender) pacedBytesPerSecond() int64 {
	ack := s.ackRatio
	if ack < minAckFraction {
		ack = minAckFraction
	}
	if ack > 1 {
		ack = 1
	}
	rate := int64(float64(s.targetBps) / ack)
	return min(rate, s.maxBps)
}

func (s *Sender) TimeUntilSend(_ congestion.ByteCount) monotime.Time {
	return s.pacer.timeUntilSend(s.pacedBytesPerSecond())
}

func (s *Sender) HasPacingBudget(now monotime.Time) bool {
	return s.pacer.budget(now, s.pacedBytesPerSecond()) >= int64(s.maxPacket)
}

func (s *Sender) OnPacketSent(now monotime.Time, _ congestion.ByteCount,
	_ congestion.PacketNumber, size congestion.ByteCount, _ bool,
) {
	s.pacer.sent(now, int64(size), s.pacedBytesPerSecond())
	s.publishDiagnostics(now)
}

func (s *Sender) CanSend(inFlight congestion.ByteCount) bool {
	return inFlight <= s.GetCongestionWindow()
}

func (s *Sender) GetCongestionWindow() congestion.ByteCount {
	if s.rtt == nil {
		return minWindowBytes
	}
	rtt := s.rtt.SmoothedRTT()
	if rtt <= 0 {
		return minWindowBytes
	}
	// Two RTTs of paced traffic give the fixed-rate pacer room to operate.
	// Never permit an unbounded in-flight queue.
	window := float64(s.pacedBytesPerSecond()) * rtt.Seconds() * 2
	if window >= float64(maxWindowBytes) {
		return maxWindowBytes
	}
	return congestion.ByteCount(max(minWindowBytes, int64(window)))
}

func (s *Sender) MaybeExitSlowStart() {}
func (s *Sender) InSlowStart() bool   { return false }
func (s *Sender) InRecovery() bool    { return false }

func (s *Sender) OnPacketAcked(_ congestion.PacketNumber, _ congestion.ByteCount,
	_ congestion.ByteCount, _ monotime.Time,
) {
}

func (s *Sender) OnCongestionEvent(_ congestion.PacketNumber, _ congestion.ByteCount,
	_ congestion.ByteCount,
) {
}

func (s *Sender) OnRetransmissionTimeout(_ bool) {}

func (s *Sender) SetMaxDatagramSize(size congestion.ByteCount) {
	if size > 0 {
		s.maxPacket = size
		s.pacer.maxPacket = size
	}
}

// OnCongestionEventEx samples packets confirmed/lost in five one-second slots.
// It does not assume every unacknowledged packet is lost. The sender can stay
// at its configured rate when loss is low; loss compensation is always capped.
func (s *Sender) OnCongestionEventEx(_ congestion.ByteCount, now monotime.Time,
	acked []congestion.AckedPacketInfo, lost []congestion.LostPacketInfo,
) {
	defer s.publishDiagnostics(now)
	second := int64(time.Duration(now) / time.Second)
	index := int(second % samplesSeconds)
	if index < 0 {
		index += samplesSeconds
	}
	entry := &s.samples[index]
	if entry.second != second {
		*entry = packetSample{second: second}
	}
	entry.acked += uint64(len(acked))
	entry.lost += uint64(len(lost))

	var confirmed, dropped uint64
	for _, slot := range s.samples {
		if slot.second <= second && second-slot.second < samplesSeconds {
			confirmed += slot.acked
			dropped += slot.lost
		}
	}
	total := confirmed + dropped
	if total > 0 {
		s.diagRawACK = float64(confirmed) / float64(total)
	}
	if total < minSamples {
		s.ackRatio = 1
		return
	}
	s.ackRatio = max(minAckFraction, float64(confirmed)/float64(total))
}

type pacingBucket struct {
	maxPacket  congestion.ByteCount
	lastAt     monotime.Time
	lastBudget congestion.ByteCount
}

func (b *pacingBucket) maxBurst(rate int64) int64 {
	return max(int64(b.maxPacket)*maxBurstPackets, rate*burstMillis/1000)
}

func (b *pacingBucket) budget(at monotime.Time, rate int64) int64 {
	burst := b.maxBurst(rate)
	if b.lastAt.IsZero() {
		return burst
	}
	age := at.Sub(b.lastAt)
	if age <= 0 {
		return min(int64(b.lastBudget), burst)
	}
	// A full second always refills this very small burst capacity; capping
	// avoids overflow for long idle connections and monotonic clock jumps.
	if age >= time.Second {
		return burst
	}
	earned := rate * age.Nanoseconds() / int64(time.Second)
	remaining := burst - min(burst, int64(b.lastBudget))
	if earned >= remaining {
		return burst
	}
	return min(burst, int64(b.lastBudget)+earned)
}

func (b *pacingBucket) sent(at monotime.Time, bytes, rate int64) {
	current := b.budget(at, rate)
	b.lastBudget = congestion.ByteCount(max(int64(0), current-bytes))
	b.lastAt = at
}

func (b *pacingBucket) timeUntilSend(rate int64) monotime.Time {
	if b.lastAt.IsZero() || int64(b.lastBudget) >= int64(b.maxPacket) {
		return 0
	}
	missing := int64(b.maxPacket) - int64(b.lastBudget)
	nanos := (missing*int64(time.Second) + rate - 1) / rate
	return b.lastAt.Add(max(congestion.MinPacingDelay, time.Duration(nanos)))
}
