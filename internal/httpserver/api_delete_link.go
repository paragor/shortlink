package httpserver

import (
	"fmt"
	"net/http"
)

func (s *httpServer) apiDeleteLink(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		httpError(r.Context(), w, "query param 'id' is empty", fmt.Errorf("no id in query"), http.StatusBadRequest)
	}
	link := s.storage.GetLink(id)
	if link == nil {
		httpError(r.Context(), w, "link not found", fmt.Errorf("link not found"), http.StatusBadRequest)
		return
	}
	link.Delete()

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(""))
}
