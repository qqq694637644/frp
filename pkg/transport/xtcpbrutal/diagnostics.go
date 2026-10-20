package xtcpbrutal

import (
	"time"

	"github.com/apernet/quic-go/monotime"
)

// DiagnosticSnapshot is published at most once per second by the QUIC sender
// goroutine. Readers never race the congestion controller or RTT provider.
type DiagnosticSnapshot struct {
	Updated              time.Time `json:"updated"`
	TargetMbps           float64   `json:"target_mbps"`
	MaxMbps              float64   `json:"max_mbps"`
	PacingBytesPerSecond int64     `json:"pacing_bytes_per_second"`
	CongestionWindow     int64     `json:"cwnd_bytes"`
	CompensationACKRatio float64   `json:"compensation_ack_ratio"`
	SampleACKRatio       float64   `json:"sample_ack_ratio"`
	BurstBytes           int64     `json:"burst_bytes"`
}

func (s *Sender) DiagnosticsSnapshot() *DiagnosticSnapshot {
	s.diagEnabled.Store(true)
	return s.diagSnapshot.Load()
}

func (s *Sender) publishDiagnostics(now monotime.Time) {
	if !s.diagEnabled.Load() || (!s.diagAt.IsZero() && now.Sub(s.diagAt) < time.Second) {
		return
	}
	s.diagAt = now
	s.diagSnapshot.Store(&DiagnosticSnapshot{
		Updated: time.Now().UTC(), TargetMbps: float64(s.targetBps) / 125000, MaxMbps: float64(s.maxBps) / 125000,
		PacingBytesPerSecond: s.pacedBytesPerSecond(), CongestionWindow: int64(s.GetCongestionWindow()),
		CompensationACKRatio: s.ackRatio, SampleACKRatio: s.diagRawACK,
		BurstBytes: s.pacer.maxBurst(s.pacedBytesPerSecond()),
	})
}
