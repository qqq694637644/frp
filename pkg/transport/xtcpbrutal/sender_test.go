package xtcpbrutal

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

type sampleRTT time.Duration

func (r sampleRTT) MinRTT() time.Duration                  { return time.Duration(r) }
func (r sampleRTT) LatestRTT() time.Duration               { return time.Duration(r) }
func (r sampleRTT) SmoothedRTT() time.Duration             { return time.Duration(r) }
func (r sampleRTT) MeanDeviation() time.Duration           { return 0 }
func (r sampleRTT) MaxAckDelay() time.Duration             { return 0 }
func (r sampleRTT) PTO(bool) time.Duration                 { return time.Duration(r) * 2 }
func (r sampleRTT) UpdateRTT(time.Duration, time.Duration) {}
func (r sampleRTT) SetMaxAckDelay(time.Duration)           {}
func (r sampleRTT) SetInitialRTT(time.Duration)            {}

func TestBrutalConfigStrictAndDefaultBounded(t *testing.T) {
	for _, v := range [][2]int{
		{0, 24},
		{-1, 20},
		{16, 0},
		{16, 15},
		{65, 65},
		{16, 65},
		{100000000, 100000000},
	} {
		if _, err := NewSender(v[0], v[1]); err == nil {
			t.Fatalf("invalid rate accepted: %+v", v)
		}
	}
	s, err := NewSender(16, 24)
	if err != nil {
		t.Fatal(err)
	}
	if s.pacedBytesPerSecond() != 2_000_000 {
		t.Fatalf("wrong 16 Mbps rate: %d", s.pacedBytesPerSecond())
	}
	s.ackRatio = 0.5
	if s.pacedBytesPerSecond() != 2_500_000 {
		t.Fatalf("loss compensation did not saturate minAckFraction: %d", s.pacedBytesPerSecond())
	}
	s.ackRatio = 0.9
	if s.pacedBytesPerSecond() != 2_222_222 {
		t.Fatalf("wrong loss compensation: %d", s.pacedBytesPerSecond())
	}
	s, _ = NewSender(16, 16)
	s.ackRatio = 0.2
	if s.pacedBytesPerSecond() != 2_000_000 {
		t.Fatal("total wire rate exceeded strict max cap")
	}
}

func TestBrutalPacingBudgetAndBurstRemainBounded(t *testing.T) {
	s, _ := NewSender(16, 24)
	now := monotime.Now()
	maxBurst := s.pacer.maxBurst(s.pacedBytesPerSecond())
	if maxBurst < 0 || maxBurst > 10*int64(s.maxPacket) {
		t.Fatalf("burst unexpectedly large: %d", maxBurst)
	}
	if !s.HasPacingBudget(now) {
		t.Fatal("first packet may not be sent")
	}
	for i := range 10 {
		s.OnPacketSent(now, 0, congestion.PacketNumber(i), s.maxPacket, true)
	}
	if s.pacer.lastBudget != 0 {
		t.Fatalf("ten-packet burst did not run out: %d", s.pacer.lastBudget)
	}
	if s.HasPacingBudget(now) {
		t.Fatal("controller ignored pacing exhaustion")
	}
	if deadline := s.TimeUntilSend(0); deadline.IsZero() || !deadline.After(now) {
		t.Fatalf("invalid pacing deadline %v", deadline)
	}
	if s.pacer.budget(now.Add(time.Second), s.pacedBytesPerSecond()) > maxBurst {
		t.Fatal("idle replenishment exceeded maximum burst")
	}
	// Reconfigure an MTU to a value higher than the initial size; the
	// controller must always respect the reported QUIC transport MTU.
	s.SetMaxDatagramSize(1350)
	if s.maxPacket != 1350 || s.pacer.maxPacket != 1350 {
		t.Fatal("packet size update not reflected by controller and pacer")
	}
}

func TestBrutalLossSamplingAndWindowBounds(t *testing.T) {
	s, _ := NewSender(16, 24)
	s.SetRTTStatsProvider(sampleRTT(400 * time.Millisecond))
	if s.GetCongestionWindow() < 1_000_000 || s.GetCongestionWindow() > maxWindowBytes {
		t.Fatalf("incorrect window at 400ms: %d", s.GetCongestionWindow())
	}
	second := monotime.Now()
	acks := make([]congestion.AckedPacketInfo, 80)
	lost := make([]congestion.LostPacketInfo, 20)
	s.OnCongestionEventEx(0, second, acks, lost)
	if s.ackRatio != 0.8 {
		t.Fatalf("unexpected ACK ratio: %f", s.ackRatio)
	}
	if s.pacedBytesPerSecond() > 3_000_000 {
		t.Fatal("wire pacing exceeded 24 Mbps")
	}
	s.OnCongestionEventEx(0, second.Add(10*time.Second), nil, nil)
	if s.ackRatio != 1 {
		t.Fatal("stale loss samples contaminated future traffic")
	}
	s.SetRTTStatsProvider(sampleRTT(100 * time.Millisecond))
	if s.GetCongestionWindow() < minWindowBytes {
		t.Fatal("window smaller than min")
	}
	s.SetRTTStatsProvider(sampleRTT(20 * time.Second))
	if s.GetCongestionWindow() > maxWindowBytes {
		t.Fatal("window exceeded hard memory cap")
	}
}

func TestBrutalLossSamplesNeedFiftyPackets(t *testing.T) {
	s, _ := NewSender(16, 24)
	s.OnCongestionEventEx(0, monotime.Now(),
		make([]congestion.AckedPacketInfo, 9),
		make([]congestion.LostPacketInfo, 30))
	if s.ackRatio != 1 {
		t.Fatalf("too few samples should not increase pacing: %f", s.ackRatio)
	}
}
