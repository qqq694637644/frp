// Package diagnostics exposes opt-in, authenticated loopback-only XTCP telemetry.
// It never opens a public listener, dials a target, or changes frps messages.
package diagnostics

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/apernet/quic-go"
)

const (
	Schema          = "rsx-diagnostics/1"
	MaxCaptureBytes = 16 << 20
	maxConnections  = 64
	maxLinks        = 4096
	maxEvents       = 512
)

type Config struct {
	Enabled    bool   `json:"enabled,omitempty"`
	ListenAddr string `json:"listenAddr,omitempty"`
	Token      string `json:"token,omitempty"`
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	host, port, err := net.SplitHostPort(c.ListenAddr)
	if err != nil || host != "127.0.0.1" {
		return errors.New("diagnostics.listenAddr must be 127.0.0.1:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("diagnostics.listenAddr has invalid port")
	}
	if len(c.Token) < 32 || len(c.Token) > 512 {
		return errors.New("diagnostics.token must contain 32..512 bytes")
	}
	return nil
}

// LocalToken is domain-separated from the RSX3 authentication protocol.
func LocalToken(secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write([]byte("rsx3-diagnostics-local-v1"))
	return hex.EncodeToString(m.Sum(nil))
}

type Event struct {
	Time       time.Time `json:"time"`
	Component  string    `json:"component"`
	Stage      string    `json:"stage"`
	State      string    `json:"state"`
	Detail     string    `json:"detail,omitempty"`
	DurationMS float64   `json:"duration_ms,omitempty"`
}
type StageState struct {
	State      string    `json:"state"`
	Updated    time.Time `json:"updated"`
	Detail     string    `json:"detail,omitempty"`
	DurationMS float64   `json:"duration_ms,omitempty"`
	Attempts   uint64    `json:"attempts"`
	Failures   uint64    `json:"failures"`
}
type Link struct {
	ConnectionID string     `json:"connection_id"`
	StreamID     uint64     `json:"stream_id"`
	Local        string     `json:"local"`
	Remote       string     `json:"remote"`
	Opened       time.Time  `json:"opened"`
	Closed       *time.Time `json:"closed,omitempty"`
}
type Snapshot struct {
	Schema      string                `json:"schema"`
	ProcessID   string                `json:"process_id"`
	Time        time.Time             `json:"time"`
	Started     time.Time             `json:"started"`
	Enabled     bool                  `json:"enabled"`
	Build       map[string]string     `json:"build"`
	Connections []ConnectionSnapshot  `json:"connections"`
	Stages      map[string]StageState `json:"stages"`
	Events      []Event               `json:"events"`
	Links       []Link                `json:"links"`
	HeapBytes   uint64                `json:"heap_bytes"`
	Goroutines  int                   `json:"goroutines"`
	Capture     *CaptureStatus        `json:"capture,omitempty"`
}

type Hub struct {
	mu          sync.RWMutex
	cfg         Config
	id          string
	started     time.Time
	conns       map[string]*connection
	byConn      map[*quic.Conn]*connection
	stages      map[string]StageState
	events      []Event
	links       map[string]Link
	enabled     atomic.Bool
	capture     atomic.Pointer[capture]
	probeMu     sync.Mutex
	probeActive bool
	probeCancel context.CancelFunc
	udpMu       sync.Mutex
	udpPending  map[string]chan udpReply
	udpSecond   int64
	udpRequests int
}

var current atomic.Pointer[Hub]

func Current() *Hub { return current.Load() }
func newID() string { var b [16]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func New(c Config) *Hub {
	h := &Hub{
		cfg: c, id: newID(), started: time.Now().UTC(),
		conns: make(map[string]*connection), byConn: make(map[*quic.Conn]*connection),
		stages: make(map[string]StageState), links: make(map[string]Link),
		udpPending: make(map[string]chan udpReply),
	}
	h.enabled.Store(true)
	return h
}

func Start(ctx context.Context, c Config) (func(), error) {
	if !c.Enabled {
		return func() {}, nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp4", c.ListenAddr)
	if err != nil {
		return nil, err
	}
	h := New(c)
	if !current.CompareAndSwap(nil, h) {
		_ = ln.Close()
		return nil, errors.New("diagnostics already started")
	}
	srv := &http.Server{
		Handler: h.Handler(), ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 130 * time.Second,
		IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192,
	}
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			current.CompareAndSwap(h, nil)
			h.enabled.Store(false)
			h.StopCapture()
			_ = srv.Close()
			close(done)
		})
	}
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-done:
		}
	}()
	go func() { _ = srv.Serve(ln) }()
	return stop, nil
}

func (h *Hub) Event(component, stage, state, detail string, duration time.Duration) {
	if h == nil {
		return
	}
	now := time.Now().UTC()
	h.mu.Lock()
	defer h.mu.Unlock()
	key := component + "/" + stage
	s := h.stages[key]
	s.State = state
	s.Updated = now
	s.Detail = detail
	s.DurationMS = float64(duration) / float64(time.Millisecond)
	if state == "starting" {
		s.Attempts++
	}
	if state == "failed" {
		s.Failures++
	}
	if len(h.stages) < 128 || h.stages[key].State != "" {
		h.stages[key] = s
	}
	if len(h.events) >= maxEvents {
		copy(h.events, h.events[1:])
		h.events = h.events[:len(h.events)-1]
	}
	h.events = append(h.events, Event{now, component, stage, state, detail, s.DurationMS})
}

func Record(component, stage, state, detail string, duration time.Duration) {
	if h := Current(); h != nil {
		h.Event(component, stage, state, detail, duration)
	}
}

func (h *Hub) Snapshot() Snapshot {
	h.mu.RLock()
	cs := make([]*connection, 0, len(h.conns))
	for _, c := range h.conns {
		cs = append(cs, c)
	}
	out := Snapshot{
		Schema: Schema, ProcessID: h.id, Time: time.Now().UTC(), Started: h.started,
		Enabled: h.enabled.Load(), Stages: make(map[string]StageState),
		Connections: []ConnectionSnapshot{}, Links: []Link{},
	}
	maps.Copy(out.Stages, h.stages)
	out.Events = append([]Event(nil), h.events...)
	for _, l := range h.links {
		out.Links = append(out.Links, l)
	}
	h.mu.RUnlock()
	for _, c := range cs {
		out.Connections = append(out.Connections, c.snapshot())
	}
	sort.Slice(out.Connections, func(i, j int) bool { return out.Connections[i].Opened.Before(out.Connections[j].Opened) })
	sort.Slice(out.Links, func(i, j int) bool { return out.Links[i].Opened.Before(out.Links[j].Opened) })
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	out.HeapBytes = mem.HeapAlloc
	out.Goroutines = runtime.NumGoroutine()
	out.Build = map[string]string{"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH}
	if b, ok := debug.ReadBuildInfo(); ok {
		for _, s := range b.Settings {
			if s.Key == "vcs.revision" || s.Key == "vcs.modified" {
				out.Build[s.Key] = s.Value
			}
		}
		for _, d := range b.Deps {
			if strings.Contains(d.Path, "quic-go") {
				out.Build["quic_go"] = d.Version
			}
		}
	}
	out.Capture = h.CaptureStatus()
	return out
}
func linkKey(local, remote string) string { return local + "|" + remote }

// LinkTCP records exact socket tuples; lookups only match live entries. It
// neither guesses session IDs nor parses encrypted user traffic.
func LinkTCP(raw any, app net.Conn) func() {
	h := Current()
	if h == nil || !h.enabled.Load() {
		return func() {}
	}
	v, ok := raw.(interface{ DiagnosticQUIC() (*quic.Conn, uint64) })
	if !ok {
		return func() {}
	}
	q, sid := v.DiagnosticQUIC()
	h.mu.Lock()
	c := h.byConn[q]
	if c == nil {
		h.mu.Unlock()
		return func() {}
	}
	// Store both orientations; callers specify their actual local/remote tuple.
	now := time.Now().UTC()
	a, b := app.LocalAddr().String(), app.RemoteAddr().String()
	for len(h.links) >= maxLinks {
		var oldest string
		var t time.Time
		for k, l := range h.links {
			if l.Closed != nil && (oldest == "" || l.Opened.Before(t)) {
				oldest = k
				t = l.Opened
			}
		}
		if oldest == "" {
			h.mu.Unlock()
			return func() {}
		}
		delete(h.links, oldest)
	}
	for _, p := range [][2]string{{a, b}, {b, a}} {
		h.links[linkKey(p[0], p[1])] = Link{ConnectionID: c.id, StreamID: sid, Local: p[0], Remote: p[1], Opened: now}
	}
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		end := time.Now().UTC()
		for _, p := range [][2]string{{a, b}, {b, a}} {
			k := linkKey(p[0], p[1])
			l := h.links[k]
			if l.ConnectionID == c.id && l.StreamID == sid {
				l.Closed = &end
				h.links[k] = l
			}
		}
	}
}

func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/v1/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		v := h.Snapshot()
		if r.URL.Query().Get("compact") == "1" {
			v.Links = nil
			if len(v.Events) > 16 {
				v.Events = v.Events[len(v.Events)-16:]
			}
			if len(v.Connections) > 4 {
				v.Connections = v.Connections[len(v.Connections)-4:]
			}
		}
		write(w, v)
	})
	mux.HandleFunc("/v1/lookup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		h.mu.RLock()
		l, ok := h.links[linkKey(r.URL.Query().Get("local"), r.URL.Query().Get("remote"))]
		h.mu.RUnlock()
		matches := ok && l.Closed == nil
		if rawAt := r.URL.Query().Get("at"); rawAt != "" {
			at, err := time.Parse(time.RFC3339Nano, rawAt)
			if err != nil {
				http.Error(w, "invalid tuple observation timestamp", 400)
				return
			}
			matches = ok && !at.Before(l.Opened) && (l.Closed == nil || !at.After(*l.Closed))
		}
		if !matches {
			write(w, map[string]any{"linked": false})
			return
		}
		write(w, map[string]any{"linked": true, "link": l})
	})
	mux.HandleFunc("/v1/capture", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			write(w, h.CaptureStatus())
		case "POST":
			var in struct {
				Seconds int `json:"seconds"`
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in) != nil {
				http.Error(w, "invalid JSON", 400)
				return
			}
			if err := h.StartCapture(in.Seconds); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			write(w, h.CaptureStatus())
		case "DELETE":
			h.StopCapture()
			write(w, h.CaptureStatus())
		default:
			w.WriteHeader(405)
		}
	})
	mux.HandleFunc("/v1/capture/data", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		data, status := h.CaptureData()
		write(w, map[string]any{"status": status, "qlogs": data})
	})
	mux.HandleFunc("/v1/benchmark", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var in struct {
			Bytes     int64  `json:"bytes"`
			Direction string `json:"direction"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in) != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		result, err := h.Benchmark(r.Context(), in.Bytes, in.Direction)
		if err != nil {
			write(w, map[string]any{"state": "failed", "error": err.Error()})
			return
		}
		write(w, result)
	})
	mux.HandleFunc("/v1/udp-probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		result, err := h.UDPProbe(r.Context())
		if err != nil {
			write(w, map[string]any{"state": "failed", "error": err.Error()})
			return
		}
		write(w, result)
	})
	mux.HandleFunc("/v1/cancel-test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		h.probeMu.Lock()
		cancel := h.probeCancel
		h.probeMu.Unlock()
		if cancel != nil {
			cancel()
		}
		write(w, map[string]bool{"cancel_requested": cancel != nil})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			w.WriteHeader(403)
			return
		}
		want := "Bearer " + h.cfg.Token
		if !hmac.Equal([]byte(r.Header.Get("Authorization")), []byte(want)) {
			w.WriteHeader(401)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (h *Hub) exclusive() (func(), error) {
	h.probeMu.Lock()
	defer h.probeMu.Unlock()
	if h.probeActive {
		return nil, errors.New("another QUIC diagnostic test is running")
	}
	h.probeActive = true
	return func() { h.probeMu.Lock(); h.probeActive = false; h.probeMu.Unlock() }, nil
}

func (h *Hub) activeConnection() (*connection, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var found *connection
	for _, c := range h.byConn {
		if c.q != nil && c.q.Context().Err() == nil {
			if found != nil {
				return nil, errors.New("multiple XTCP connections; select a single active node")
			}
			found = c
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no connected XTCP QUIC endpoint")
	}
	return found, nil
}
