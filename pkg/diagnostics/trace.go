package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"time"

	quic "github.com/apernet/quic-go"
	"github.com/apernet/quic-go/qlog"
	"github.com/apernet/quic-go/qlogwriter"
	"github.com/apernet/quic-go/qlogwriter/jsontext"
)

type ConnectionSnapshot struct {
	ID                       string            `json:"connection_id"`
	ODCID                    string            `json:"odcid"`
	Role                     string            `json:"role"`
	Tag                      string            `json:"tag"`
	Opened                   time.Time         `json:"opened"`
	Closed                   *time.Time        `json:"closed,omitempty"`
	CloseReason              string            `json:"close_reason,omitempty"`
	Local                    string            `json:"local"`
	Remote                   string            `json:"remote"`
	State                    string            `json:"state"`
	RTTMS                    *float64          `json:"rtt_ms"`
	MinRTTMS                 *float64          `json:"min_rtt_ms"`
	RTTVarianceMS            *float64          `json:"rtt_variance_ms"`
	Cwnd                     *int              `json:"cwnd_bytes"`
	InFlight                 *int              `json:"bytes_in_flight"`
	SentBytes                uint64            `json:"sent_bytes"`
	ReceivedBytes            uint64            `json:"received_bytes"`
	SentPackets              uint64            `json:"sent_packets"`
	ReceivedPackets          uint64            `json:"received_packets"`
	LossDeclarations         uint64            `json:"loss_declarations"`
	SpuriousLoss             uint64            `json:"spurious_loss"`
	StreamSentBytes          uint64            `json:"stream_sent_bytes"`
	StreamRetransmittedBytes *uint64           `json:"stream_retransmitted_bytes"`
	RetransmissionComplete   bool              `json:"retransmission_complete"`
	DatagramSent             uint64            `json:"datagram_sent"`
	DatagramReceived         uint64            `json:"datagram_received"`
	DatagramDrops            map[string]uint64 `json:"datagram_drops"`
	PTOCount                 uint32            `json:"pto_count"`
	Brutal                   any               `json:"brutal,omitempty"`
	Updated                  time.Time         `json:"updated"`
}
type (
	interval   struct{ lo, hi int64 }
	connection struct {
		mu                                                           sync.Mutex
		hub                                                          *Hub
		id, odcid, role, tag                                         string
		opened                                                       time.Time
		closed                                                       *time.Time
		reason, local, remote, state                                 string
		rtt, minRTT, rttVar                                          *float64
		cwnd, inFlight                                               *int
		sent, received, sentPackets, receivedPackets, lost, spurious uint64
		streamSent, retrans                                          uint64
		complete                                                     bool
		dgSent, dgReceived                                           uint64
		drops                                                        map[string]uint64
		ranges                                                       map[uint64][]interval
		pto                                                          uint32
		updated                                                      time.Time
		q                                                            *quic.Conn
		brutal                                                       func() any
		pendingMu                                                    sync.Mutex
		pending                                                      map[string]*probeWait
		producers                                                    int
	}
)

//go:fix inline
func ptr[T any](x T) *T { return new(x) }

func (c *connection) snapshot() ConnectionSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := ConnectionSnapshot{
		ID: c.id, ODCID: c.odcid, Role: c.role, Tag: c.tag, Opened: c.opened,
		Closed: c.closed, CloseReason: c.reason, Local: c.local, Remote: c.remote, State: c.state,
		RTTMS: c.rtt, MinRTTMS: c.minRTT, RTTVarianceMS: c.rttVar, Cwnd: c.cwnd, InFlight: c.inFlight,
		SentBytes: c.sent, ReceivedBytes: c.received, SentPackets: c.sentPackets, ReceivedPackets: c.receivedPackets,
		LossDeclarations: c.lost, SpuriousLoss: c.spurious, StreamSentBytes: c.streamSent,
		RetransmissionComplete: c.complete, DatagramSent: c.dgSent, DatagramReceived: c.dgReceived,
		DatagramDrops: make(map[string]uint64), PTOCount: c.pto, Updated: c.updated,
	}
	if c.complete {
		v.StreamRetransmittedBytes = new(c.retrans)
	}
	maps.Copy(v.DatagramDrops, c.drops)
	if c.brutal != nil {
		v.Brutal = c.brutal()
	}
	return v
}

// Scope binds an XTCP listener/dial to its actual qlog connection. No assumption
// is made that multiple handshakes on one listener are the same connection.
type Scope struct {
	role, tag string
	hub       *Hub
	mu        sync.Mutex
	traces    []*connection
}

func NewScope(role, tag string) *Scope { return &Scope{role: role, tag: tag, hub: Current()} }
func (s *Scope) Tracer(ctx context.Context, client bool, id quic.ConnectionID) qlogwriter.Trace {
	base := qlog.DefaultConnectionTracer(ctx, client, id)
	h := s.hub
	if h == nil || !h.enabled.Load() {
		return base
	}
	c := &connection{
		hub: h, id: s.role + ":" + id.String(), odcid: id.String(), role: s.role, tag: s.tag,
		opened: time.Now().UTC(), state: "handshaking", updated: time.Now().UTC(), complete: true,
		drops: make(map[string]uint64), ranges: make(map[uint64][]interval), pending: make(map[string]*probeWait),
	}
	h.mu.Lock()
	if len(h.conns) >= maxConnections {
		var oldest string
		var t time.Time
		for k, v := range h.conns {
			v.mu.Lock()
			closed := v.closed
			v.mu.Unlock()
			if closed != nil && (oldest == "" || closed.Before(t)) {
				oldest = k
				t = *closed
			}
		}
		if oldest != "" {
			delete(h.conns, oldest)
		} else {
			h.mu.Unlock()
			return base
		}
	}
	h.conns[c.id] = c
	h.mu.Unlock()
	s.mu.Lock()
	s.traces = append(s.traces, c)
	s.mu.Unlock()
	return &trace{c: c, base: base}
}

func (s *Scope) Attach(q *quic.Conn, brutal func() any) {
	if q == nil {
		return
	}
	h := s.hub
	if h == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var found *connection
	for _, c := range s.traces {
		c.mu.Lock()
		match := c.closed == nil && (c.remote == q.RemoteAddr().String() || len(s.traces) == 1)
		c.mu.Unlock()
		if match {
			if found != nil {
				return
			}
			found = c
		}
	}
	if found == nil {
		return
	}
	found.mu.Lock()
	found.q = q
	found.state = "ready"
	found.brutal = brutal
	found.local = q.LocalAddr().String()
	found.remote = q.RemoteAddr().String()
	found.mu.Unlock()
	h.mu.Lock()
	h.byConn[q] = found
	h.mu.Unlock()
	go found.acceptDiagnostics()
	go func() {
		<-q.Context().Done()
		found.mu.Lock()
		now := time.Now().UTC()
		found.closed = &now
		found.state = "closed"
		found.mu.Unlock()
		h.mu.Lock()
		delete(h.byConn, q)
		h.mu.Unlock()
	}()
}

type trace struct {
	c    *connection
	base qlogwriter.Trace
}
type recorder struct {
	c    *connection
	base qlogwriter.Recorder
	once sync.Once
}

func (t *trace) SupportsSchemas(schema string) bool {
	return schema == qlog.EventSchema || (t.base != nil && t.base.SupportsSchemas(schema))
}

func (t *trace) AddProducer() qlogwriter.Recorder {
	t.c.mu.Lock()
	t.c.producers++
	t.c.mu.Unlock()
	r := &recorder{c: t.c}
	if t.base != nil {
		r.base = t.base.AddProducer()
	}
	return r
}

func (r *recorder) Close() error {
	var err error
	r.once.Do(func() {
		if r.base != nil {
			err = r.base.Close()
		}
		r.c.mu.Lock()
		r.c.producers--
		r.c.mu.Unlock()
	})
	return err
}

func endpoint(p qlog.PathEndpointInfo) string {
	if p.IPv4.IsValid() {
		return p.IPv4.String()
	}
	if p.IPv6.IsValid() {
		return p.IPv6.String()
	}
	return ""
}

func (r *recorder) RecordEvent(e qlogwriter.Event) {
	c := r.c
	if c.hub.enabled.Load() {
		c.mu.Lock()
		c.updated = time.Now().UTC()
		switch v := e.(type) {
		case qlog.StartedConnection:
			c.local = endpoint(v.Local)
			c.remote = endpoint(v.Remote)
		case qlog.MetricsUpdated:
			if v.SmoothedRTT > 0 {
				c.rtt = new(float64(v.SmoothedRTT) / float64(time.Millisecond))
			}
			if v.MinRTT > 0 {
				c.minRTT = new(float64(v.MinRTT) / float64(time.Millisecond))
			}
			c.rttVar = new(float64(v.RTTVariance) / float64(time.Millisecond))
			c.cwnd = new(v.CongestionWindow)
			c.inFlight = new(v.BytesInFlight)
		case qlog.PacketSent:
			c.sent += uint64(v.Raw.Length)
			c.sentPackets++
			for _, f := range v.Frames {
				switch sf := f.Frame.(type) {
				case *qlog.StreamFrame:
					c.observeRange(uint64(sf.StreamID), sf.Offset, sf.Length)
				case qlog.StreamFrame:
					c.observeRange(uint64(sf.StreamID), sf.Offset, sf.Length)
				case *qlog.DatagramFrame:
					c.dgSent++
				case qlog.DatagramFrame:
					c.dgSent++
				}
			}
		case qlog.PacketReceived:
			c.received += uint64(v.Raw.Length)
			c.receivedPackets++
			for _, f := range v.Frames {
				switch f.Frame.(type) {
				case *qlog.DatagramFrame, qlog.DatagramFrame:
					c.dgReceived++
				}
			}
		case qlog.PacketLost:
			c.lost++
		case qlog.SpuriousLoss:
			c.spurious++
		case qlog.PTOCountUpdated:
			c.pto = v.PTOCount
		case qlog.ConnectionClosed:
			now := time.Now().UTC()
			c.closed = &now
			c.reason = fmt.Sprintf("%s: %s", v.Initiator, v.Reason)
			c.state = "closed"
		}
		c.mu.Unlock()
		c.captureEvent(e)
	}
	if r.base != nil {
		r.base.RecordEvent(e)
	}
}

// Record repeated STREAM offset ranges rather than mislabelling packet loss as
// retransmission. Bounded state: once capacity is exceeded the metric becomes
// unavailable, NOT a silently incorrect zero.
func (c *connection) observeRange(id uint64, off, n int64) {
	if n <= 0 || off < 0 {
		return
	}
	c.streamSent += uint64(n)
	if !c.complete {
		return
	}
	ranges, ok := c.ranges[id]
	if !ok && len(c.ranges) >= 4096 {
		c.complete = false
		c.ranges = nil
		return
	}
	end := off + n
	// Common contiguous progress/retransmission requires no allocation.
	if len(ranges) == 1 && off >= ranges[0].lo && off <= ranges[0].hi {
		c.retrans += uint64(min(end, ranges[0].hi) - off)
		if end > ranges[0].hi {
			ranges[0].hi = end
		}
		return
	}
	var repeated int64
	for _, r := range ranges {
		if lo, hi := max(off, r.lo), min(end, r.hi); lo < hi {
			repeated += hi - lo
		}
	}
	c.retrans += uint64(repeated)
	// At most 128 disjoint ranges per stream; most streams have one range.
	merged := make([]interval, 0, len(ranges)+1)
	cur := interval{off, end}
	inserted := false
	for _, r := range ranges {
		switch {
		case r.hi < cur.lo:
			merged = append(merged, r)
		case cur.hi < r.lo:
			if !inserted {
				merged = append(merged, cur)
				inserted = true
			}
			merged = append(merged, r)
		default:
			cur.lo = min(cur.lo, r.lo)
			cur.hi = max(cur.hi, r.hi)
		}
	}
	if !inserted {
		merged = append(merged, cur)
	}
	if len(merged) > 128 {
		c.complete = false
		c.ranges = nil
		return
	}
	c.ranges[id] = merged
}

func Drop(q any, reason string) {
	h := Current()
	if h == nil {
		return
	}
	conn, ok := q.(*quic.Conn)
	if !ok {
		return
	}
	h.mu.RLock()
	c := h.byConn[conn]
	h.mu.RUnlock()
	if c != nil {
		c.mu.Lock()
		if len(c.drops) < 32 || c.drops[reason] > 0 {
			c.drops[reason]++
		}
		c.mu.Unlock()
	}
}

// Captures serialize native qlog event data without redaction. They are bounded
// in memory, stop on size/time limit, and do no disk I/O in the packet callback.
type CaptureStatus struct {
	ID            string    `json:"id"`
	Started       time.Time `json:"started"`
	Ends          time.Time `json:"ends"`
	State         string    `json:"state"`
	Bytes         int       `json:"bytes"`
	Dropped       uint64    `json:"dropped_events"`
	Complete      bool      `json:"complete"`
	MidConnection bool      `json:"mid_connection"`
}
type capture struct {
	mu      sync.Mutex
	status  CaptureStatus
	files   map[string]*bytes.Buffer
	dropped atomicCounter
}
type atomicCounter struct {
	mu sync.Mutex
	n  uint64
}

func (a *atomicCounter) add()         { a.mu.Lock(); a.n++; a.mu.Unlock() }
func (a *atomicCounter) load() uint64 { a.mu.Lock(); defer a.mu.Unlock(); return a.n }
func (h *Hub) StartCapture(seconds int) error {
	if seconds != 30 && seconds != 60 && seconds != 300 {
		return fmt.Errorf("capture seconds must be 30, 60 or 300")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if prev := h.capture.Load(); prev != nil {
		prev.mu.Lock()
		active := prev.status.State == "recording" && time.Now().Before(prev.status.Ends)
		prev.mu.Unlock()
		if active {
			return fmt.Errorf("capture already running")
		}
	}
	now := time.Now().UTC()
	c := &capture{
		status: CaptureStatus{
			ID: newID(), Started: now, Ends: now.Add(time.Duration(seconds) * time.Second),
			State: "recording", Complete: true, MidConnection: true,
		},
		files: make(map[string]*bytes.Buffer),
	}
	h.capture.Store(c)
	return nil
}

func (h *Hub) StopCapture() {
	if c := h.capture.Load(); c != nil {
		c.mu.Lock()
		if c.status.State == "recording" {
			c.status.State = "stopped"
		}
		c.mu.Unlock()
	}
}

func (h *Hub) CaptureStatus() *CaptureStatus {
	c := h.capture.Load()
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.State == "recording" && time.Now().After(c.status.Ends) {
		c.status.State = "finished"
	}
	v := c.status
	v.Dropped = c.dropped.load()
	v.Complete = v.Complete && v.Dropped == 0
	return &v
}

func (h *Hub) CaptureData() (map[string]string, *CaptureStatus) {
	status := h.CaptureStatus()
	c := h.capture.Load()
	if c == nil {
		return nil, status
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]string, len(c.files))
	for k, v := range c.files {
		out[k] = v.String()
	}
	return out, status
}

func (c *connection) captureEvent(e qlogwriter.Event) {
	recording := c.hub.capture.Load()
	if recording == nil {
		return
	}
	if !recording.mu.TryLock() {
		recording.dropped.add()
		return
	}
	defer recording.mu.Unlock()
	now := time.Now().UTC()
	if recording.status.State != "recording" {
		return
	}
	if now.After(recording.status.Ends) {
		recording.status.State = "finished"
		return
	}
	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	if err := e.Encode(enc, now); err != nil {
		recording.status.Complete = false
		return
	}
	if buf.Len() > 64<<10 {
		recording.dropped.add()
		return
	}
	file := recording.files[c.id]
	if file == nil {
		if len(recording.files) >= maxConnections {
			recording.dropped.add()
			return
		}
		file = &bytes.Buffer{}
		header, _ := json.Marshal(map[string]any{
			"qlog_version": "0.3", "qlog_format": "JSON-SEQ",
			"file_schema":          "urn:ietf:params:qlog:file:sequential",
			"serialization_format": "application/qlog+json-seq",
			"trace": map[string]any{
				"event_schemas": []string{qlog.EventSchema},
				"vantage_point": map[string]string{"type": map[bool]string{true: "client", false: "server"}[c.role == "visitor"]},
				"common_fields": map[string]any{
					"group_id": c.odcid,
					"reference_time": map[string]any{
						"clock_type": "monotonic", "epoch": "unknown",
						"wall_clock_time": recording.status.Started.Format(time.RFC3339Nano),
					},
				},
			},
			"capture_note": "Started on an existing connection; handshake events before capture are unavailable",
		})
		file.WriteByte(0x1e)
		file.Write(header)
		file.WriteByte('\n')
		recording.status.Bytes += len(header) + 2
		recording.files[c.id] = file
	}
	event, _ := json.Marshal(map[string]any{
		"time": float64(now.Sub(recording.status.Started)) / float64(time.Millisecond),
		"name": e.Name(), "data": json.RawMessage(bytes.TrimSpace(buf.Bytes())),
	})
	if recording.status.Bytes+len(event)+2 > MaxCaptureBytes {
		recording.status.State = "size_limit"
		recording.status.Complete = false
		return
	}
	file.WriteByte(0x1e)
	file.Write(event)
	file.WriteByte('\n')
	recording.status.Bytes += len(event) + 2
}
