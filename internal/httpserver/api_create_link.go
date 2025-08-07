package httpserver

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/paragor/shortlink/internal/log"
	"github.com/paragor/shortlink/internal/shortlink"
)

func (s *httpServer) apiCreateLink(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpError(r.Context(), w, "cant parse html form", err, http.StatusBadRequest)
		return
	}

	targetRaw := r.Form.Get("target")
	target, err := url.Parse(targetRaw)
	if err != nil {
		httpError(r.Context(), w, "cant parse target", err, http.StatusBadRequest)
		return
	}

	email, err := s.extractEmail(r)
	if err != nil {
		httpError(r.Context(), w, "cant extract email from request", err, http.StatusInternalServerError)
		return
	}

	timezone := r.Form.Get("timezone")
	if len(timezone) == 0 {
		httpError(r.Context(), w, "timezone cant not be empty", err, http.StatusBadRequest)
		return
	}

	expiration := time.Duration(0)
	expireAtRaw := r.Form.Get("expire_at")
	if expireAtRaw != "" {
		expireAt, err := parseBrowserTime(expireAtRaw, timezone)
		if err != nil {
			httpError(r.Context(), w, "cant parse expire_at", err, http.StatusBadRequest)
			return
		}
		expiration = expireAt.Sub(time.Now())
		if expiration < 0 {
			httpError(r.Context(), w, "invalid expire_at", err, http.StatusBadRequest)
			return
		}
	}
	maxClicks := 0
	maxClicksRaw := r.Form.Get("max_clicks")
	if maxClicksRaw != "" {
		maxClicks, err = strconv.Atoi(maxClicksRaw)
		if err != nil {
			httpError(r.Context(), w, "cant parse max_clicks", err, http.StatusInternalServerError)
			return
		}
	}

	options := []shortlink.LinkOption{
		shortlink.LinkWithAuthor(email),
	}
	if expiration != 0 {
		options = append(options, shortlink.LinkWithExpire(time.Now().Add(expiration)))
	}
	if maxClicks != 0 {
		options = append(options, shortlink.LinkWithMaxClicks(maxClicks))
	}
	link := shortlink.NewLink(target, options...)
	if err := s.storage.SaveLink(link); err != nil {
		httpError(r.Context(), w, "cant save link", err, http.StatusInternalServerError)
		return
	}
	shorturl := s.serverPublicUrl + "/" + link.GetId()
	//goland:noinspection GoDfaNilDereference
	log.FromContext(r.Context()).Info(
		"create new link",
		slog.Float64("ttl", expiration.Seconds()),
		slog.Int("max_clicks", maxClicks),
		slog.String("target", target.String()),
		slog.String("short_url", shorturl),
	)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(shorturl))
}

func parseBrowserTime(browserDatetime string, timezone string) (*time.Time, error) {
	if len(browserDatetime) == 0 {
		return nil, fmt.Errorf("browser date time is empty")
	}
	zone, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, fmt.Errorf("cant load timezone: %w", err)
	}
	result, err := time.ParseInLocation("2006-01-02T15:04", browserDatetime, zone)
	if err != nil {
		return nil, fmt.Errorf("cant parse timestamp: %w", err)
	}
	return &result, nil
}
