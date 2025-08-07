package shortlink

import (
	"crypto/rand"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

type Link struct {
	id               string
	long             *url.URL
	createdAt        time.Time
	expireAt         time.Time
	lastSuccessClick *atomic.Pointer[time.Time]
	clicks           *atomic.Int64
	maxClicks        int64
	deleted          *atomic.Bool
	author           string
}

type LinkOption func(link *Link)

func LinkWithExpire(at time.Time) LinkOption {
	return func(link *Link) {
		link.expireAt = at
	}
}

func LinkWithMaxClicks(clicks int) LinkOption {
	return func(link *Link) {
		link.maxClicks = int64(clicks)
	}
}

func LinkWithAuthor(author string) LinkOption {
	return func(link *Link) {
		link.author = author
	}
}

func generateShortName() string {
	return strings.ToLower(rand.Text()[0:5])
}

func NewLink(target *url.URL, options ...LinkOption) *Link {
	link := &Link{
		id:        generateShortName(),
		long:      target,
		createdAt: time.Now(),
	}
	link.deleted = &atomic.Bool{}
	link.clicks = &atomic.Int64{}
	link.lastSuccessClick = &atomic.Pointer[time.Time]{}
	for _, option := range options {
		option(link)
	}
	return link
}

func (l *Link) TryClick() bool {
	if l.deleted.Load() {
		return false
	}
	if !l.expireAt.IsZero() && time.Now().After(l.expireAt) {
		return false
	}
	// race condition, but there is no requirements for such consistency
	if l.maxClicks != 0 && l.clicks.Load() >= l.maxClicks {
		return false
	}
	now := time.Now()
	l.clicks.Add(1)
	l.lastSuccessClick.Store(&now)

	return true
}

func (l *Link) GetTarget() *url.URL {
	return l.long
}

func (l *Link) GetId() string {
	return l.id
}

func (l *Link) Delete() {
	l.deleted.Store(true)
}
