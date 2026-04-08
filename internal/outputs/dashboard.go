package outputs

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/config"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/mitre"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/snapshot"
)

//go:embed all:web
var dashboardEmbed embed.FS

// DashboardOutput serves the MITRE dashboard, REST detail JSON, and the live /ws stream.
type DashboardOutput struct {
	port     int
	store    *mitre.Store
	server   *http.Server
	upgrader websocket.Upgrader
	mu       sync.RWMutex
	clients  map[*websocket.Conn]bool
	snap     *snapshot.SnapshotJSON
	tmplOnce sync.Once
	tmpl     *template.Template
	tmplErr  error
}

// NewDashboardOutput builds the HTTP/WebSocket server on cfg.Port using store for /log/{id}.
func NewDashboardOutput(cfg *config.WebsocketConfig, store *mitre.Store) *DashboardOutput {
	return &DashboardOutput{
		port:    cfg.Port,
		store:   store,
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (d *DashboardOutput) loadLogTemplate() error {
	d.tmplOnce.Do(func() {
		d.tmpl, d.tmplErr = template.ParseFS(dashboardEmbed, "web/log.html")
	})
	return d.tmplErr
}

type logPageView struct {
	ID          string
	ObservedAt  string
	Severity    string
	DataSource  string
	UnmappedMsg string
	EventJSON   string
	Matches     []mitre.Match
}

func (d *DashboardOutput) Init() error {
	if err := d.loadLogTemplate(); err != nil {
		return err
	}

	staticRoot, err := fs.Sub(dashboardEmbed, "web")
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot))))

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, err := dashboardEmbed.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})

	mux.HandleFunc("GET /log/{id}", d.handleLogPage)
	mux.HandleFunc("GET /api/events/{id}", d.handleEventJSON)

	mux.HandleFunc("/ws", d.handleConnection)

	d.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", d.port),
		Handler: mux,
	}

	go func() {
		log.Printf("Dashboard at http://127.0.0.1:%d/ (WebSocket /ws)", d.port)
		if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("dashboard server error: %v", err)
		}
	}()

	return nil
}

func (d *DashboardOutput) handleLogPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || d.store == nil {
		http.NotFound(w, r)
		return
	}
	ev, ok := d.store.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	raw, err := json.MarshalIndent(ev.Event, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := logPageView{
		ID:          ev.ID,
		ObservedAt:  ev.ObservedAt.Format(time.RFC3339),
		Severity:    string(ev.Severity),
		DataSource:  ev.DataSource,
		UnmappedMsg: ev.UnmappedMsg,
		EventJSON:   string(raw),
		Matches:     ev.Matches,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.tmpl.Execute(w, data); err != nil {
		log.Printf("template execute: %v", err)
	}
}

func (d *DashboardOutput) handleEventJSON(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || d.store == nil {
		http.NotFound(w, r)
		return
	}
	ev, ok := d.store.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(ev)
}

func (d *DashboardOutput) handleConnection(rw http.ResponseWriter, r *http.Request) {
	conn, err := d.upgrader.Upgrade(rw, r, nil)
	if err != nil {
		log.Printf("websocket upgrade error: %v", err)
		return
	}

	d.mu.Lock()
	d.clients[conn] = true
	currentSnap := d.snap
	d.mu.Unlock()

	if currentSnap != nil {
		data, _ := json.Marshal(currentSnap)
		_ = conn.WriteMessage(websocket.TextMessage, data)
	}

	go func() {
		defer func() {
			d.mu.Lock()
			delete(d.clients, conn)
			d.mu.Unlock()
			_ = conn.Close()
		}()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}()
}

func (d *DashboardOutput) SendSnapshot(snap *snapshot.SnapshotJSON) error {
	d.mu.Lock()
	d.snap = snap
	d.mu.Unlock()
	return nil
}

func (d *DashboardOutput) SendEvent(ev *mitre.EnrichedEvent) error {
	if ev == nil {
		return nil
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	for conn := range d.clients {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("websocket write error: %v", err)
			_ = conn.Close()
			delete(d.clients, conn)
		}
	}
	return nil
}

func (d *DashboardOutput) Close() error {
	d.mu.Lock()
	for conn := range d.clients {
		_ = conn.Close()
	}
	d.clients = make(map[*websocket.Conn]bool)
	d.mu.Unlock()

	if d.server != nil {
		return d.server.Close()
	}
	return nil
}
