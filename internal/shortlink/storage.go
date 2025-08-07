package shortlink

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/paragor/shortlink/internal/log"
)

type Storage struct {
	links      map[string]*Link
	linksMutex *sync.RWMutex

	config *storageConfig
}

type storageConfig struct {
	gcPeriod        time.Duration
	ttlExpiredLinks time.Duration
}

func newStorageConfig() *storageConfig {
	return &storageConfig{
		gcPeriod:        time.Hour,
		ttlExpiredLinks: 24 * time.Hour,
	}
}

type StorageOption func(config *storageConfig)

func StorageWithGcPeriod(period time.Duration) StorageOption {
	return func(config *storageConfig) {
		config.gcPeriod = period
	}
}
func StorageWithTtlExpiredLinks(ttl time.Duration) StorageOption {
	return func(config *storageConfig) {
		config.ttlExpiredLinks = ttl
	}
}

func NewStorage(options ...StorageOption) *Storage {
	storage := &Storage{
		config:     newStorageConfig(),
		links:      map[string]*Link{},
		linksMutex: &sync.RWMutex{},
	}
	for _, option := range options {
		option(storage.config)
	}

	go storage.gcLoop()
	return storage
}

func (s *Storage) gcLoop() {
	ticker := time.NewTicker(s.config.gcPeriod)
	for range ticker.C {
		start := time.Now()
		deleted := s.gc()
		log.GetLogger().Info(
			"gc iteration",
			slog.Float64("seconds", time.Now().Sub(start).Seconds()),
			slog.Int("deleted", deleted),
		)
	}
}

func (s *Storage) gc() int {
	expiredLinks := make([]*Link, 0, 256)
	now := time.Now()
	s.linksMutex.RLock()
	for _, link := range s.links {
		lastClick := link.lastSuccessClick.Load()

		deletedByClicksOverload := link.clicks.Load() >= link.maxClicks && lastClick != nil && now.Sub(*lastClick) > s.config.ttlExpiredLinks
		deletedByTtt := !link.expireAt.IsZero() && now.Sub(link.expireAt) >= s.config.ttlExpiredLinks
		deletedByHand := link.deleted.Load()

		isDeleted := deletedByClicksOverload || deletedByHand || deletedByTtt
		if isDeleted {
			expiredLinks = append(expiredLinks, link)
		}
	}
	s.linksMutex.RUnlock()
	s.linksMutex.Lock()
	for _, link := range expiredLinks {
		delete(s.links, link.id)
	}
	s.linksMutex.Unlock()
	return len(expiredLinks)
}

func (s *Storage) GetLink(id string) *Link {
	s.linksMutex.RLock()
	defer s.linksMutex.RUnlock()
	link, ok := s.links[id]
	if !ok {
		return nil
	}
	return link
}

func (s *Storage) SaveLink(link *Link) error {
	s.linksMutex.Lock()
	defer s.linksMutex.Unlock()
	if link == nil {
		return fmt.Errorf("empty link")
	}
	if link.id == "" {
		return fmt.Errorf("empty link id")
	}
	if _, alreadyExists := s.links[link.id]; alreadyExists {
		return fmt.Errorf("link with id '%s' already exists", link.id)
	}
	s.links[link.id] = link
	return nil
}
