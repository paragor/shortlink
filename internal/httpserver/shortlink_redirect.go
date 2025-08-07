package httpserver

import (
	"log/slog"
	"net/http"
	"path"

	"github.com/paragor/shortlink/internal/log"
)

func (s *httpServer) shortlinkRedirect(w http.ResponseWriter, r *http.Request) {
	id := path.Base(r.URL.Path)
	link := s.storage.GetLink(id)
	if link == nil {
		http.NotFound(w, r)
		return
	}

	if !link.TryClick() {
		http.NotFound(w, r)
		return
	}
	log.FromContext(r.Context()).Info("success redirect", slog.String("target", link.GetTarget().String()))
	http.Redirect(w, r, link.GetTarget().String(), http.StatusFound)
}
