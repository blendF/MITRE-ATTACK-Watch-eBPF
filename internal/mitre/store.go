package mitre

import (
	"sync"
)

// Store retains recent enriched events for dashboard detail pages.
type Store struct {
	mu   sync.RWMutex
	cap  int
	ids  []string
	byID map[string]*EnrichedEvent
}

func NewStore(capacity int) *Store {
	if capacity < 1 {
		capacity = 4096
	}
	return &Store{
		cap:  capacity,
		byID: make(map[string]*EnrichedEvent),
	}
}

// Add stores a copy pointer; ev must not be mutated afterward by caller.
func (s *Store) Add(ev *EnrichedEvent) {
	if s == nil || ev == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[ev.ID] = ev
	s.ids = append(s.ids, ev.ID)
	for len(s.ids) > s.cap {
		old := s.ids[0]
		s.ids = s.ids[1:]
		delete(s.byID, old)
	}
}

// Get returns a stored event by id.
func (s *Store) Get(id string) (*EnrichedEvent, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ev, ok := s.byID[id]
	return ev, ok
}
