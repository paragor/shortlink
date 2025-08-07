package httpserver

import (
	"html/template"
	"net/http"
)

type mainContext struct {
	AuthCompleted bool
	Email         string

	ChildComponent any
}

func (s *httpServer) htmxPrepareMainContext(r *http.Request) *mainContext {
	auth, err := s.extractAuthContext(r)
	if err != nil {
		return &mainContext{
			AuthCompleted: false,
			Email:         "",
		}
	}
	return &mainContext{
		AuthCompleted:  true,
		Email:          auth.Email,
		ChildComponent: nil,
	}
}
func (s *httpServer) htmxPageMain(w http.ResponseWriter, r *http.Request) {
	uploadForm, err := renderHtmx("component/create_link_form", nil)
	if err != nil {
		httpError(r.Context(), w, "error on render upload form", err, http.StatusInternalServerError)
		return
	}

	renderContext := s.htmxPrepareMainContext(r)
	renderContext.ChildComponent = template.HTML(uploadForm.String())

	writeHtmx(w, r, "page/index", renderContext, 200)
}

func (s *httpServer) htmxPageLogin(w http.ResponseWriter, r *http.Request) {
	oidcHtmx, err := renderHtmx("component/auth_oidc_challenge", "")
	if err != nil {
		httpError(r.Context(), w, "error on render oidc auth", err, http.StatusInternalServerError)
		return
	}
	renderContext := s.htmxPrepareMainContext(r)
	renderContext.ChildComponent = template.HTML(oidcHtmx.String())

	writeHtmx(w, r, "page/index", renderContext, http.StatusUnauthorized)
}
