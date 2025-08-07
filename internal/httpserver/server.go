package httpserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/paragor/shortlink/internal/httpserver/public"
	"github.com/paragor/shortlink/internal/log"
	"github.com/paragor/shortlink/internal/shortlink"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server interface {
	ListenAndServe() error
	Shutdown(ctx context.Context) error
}

type httpServer struct {
	storage         *shortlink.Storage
	oidc            *authOidcContext
	serverPublicUrl string

	mux    *mux.Router
	server *http.Server
}

func httpError(ctx context.Context, w http.ResponseWriter, publicMsg string, err error, code int) {
	log.FromContext(ctx).With(log.Error(err), slog.Int("response_code", code)).Error(publicMsg)
	http.Error(w, publicMsg, code)
}

func restartEtag(handler http.Handler) http.Handler {
	start := time.Now()
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		etag := start.String() + "@" + path.Clean(request.URL.Path)
		if requestEtag := request.Header.Get("If-None-Match"); requestEtag == etag {
			writer.WriteHeader(304)
			return
		}
		writer.Header().Set("ETag", etag)
		handler.ServeHTTP(writer, request)
	})
}

func cacheMiddleware(handler http.Handler, duration time.Duration) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "max-age="+strconv.Itoa(int(duration.Seconds())))
		handler.ServeHTTP(writer, request)
	})
}

func (s *httpServer) apiPing(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(200)
}
func (s *httpServer) ListenAndServe() error {
	return s.server.ListenAndServe()
}

func (s *httpServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func NewHttpServer(
	listen string,
	storage *shortlink.Storage,
	authConfig *AuthOidcConfig,
	serverPublicUrl string,
	diagnosticEndpointsEnabled bool,
) (Server, error) {
	oidc, err := newOidcContext(authConfig, serverPublicUrl+"/oidc/callback", "/")
	if err != nil {
		return nil, fmt.Errorf("cant init oidc: %w", err)
	}
	router := mux.NewRouter()
	srv := &http.Server{
		Addr:    listen,
		Handler: router,
	}
	server := &httpServer{
		server:          srv,
		mux:             router,
		storage:         storage,
		oidc:            oidc,
		serverPublicUrl: serverPublicUrl,
	}

	server.mux.Use(
		func(handler http.Handler) http.Handler {
			return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				defer func() {
					if err := recover(); err != nil {
						log.FromContext(request.Context()).
							With(log.Error(fmt.Errorf("%s", err))).
							Error("PANIC")
						writer.WriteHeader(http.StatusInternalServerError)
					}
				}()

				handler.ServeHTTP(writer, request)
			})
		},
		logsMiddleware,
		handlers.CompressHandler,
	)
	server.mux.Name("static").PathPrefix("/static/").Handler(
		restartEtag(
			cacheMiddleware(
				http.FileServer(
					http.FS(
						public.Static,
					),
				),
				5*time.Minute,
			),
		),
	)

	if diagnosticEndpointsEnabled {
		diags := server.mux.Name("diags").Subrouter()
		diags.Path("/metrics").Handler(promhttp.Handler())
		diags.Path("/healthz").HandlerFunc(server.apiPing)
		diags.Path("/readyz").HandlerFunc(server.apiPing)
	}

	htmx := server.mux.Name("htmx").Subrouter()
	htmx.Use(server.AuthMiddleware())
	htmx.Path("/admin").HandlerFunc(server.htmxPageMain)
	htmx.Path("/whoami").HandlerFunc(server.htmxPageWhoami)

	pub := server.mux.Name("public").Subrouter()
	pub.Path("/login").HandlerFunc(server.htmxPageLogin)
	pub.Path("/oidc/callback").Handler(server.oidc.AuthCallbackHandler())
	pub.Path("/oidc/login").Handler(server.oidc.AuthLoginHandler())
	pub.Path("/{short_link:[a-zA-Z0-9]+}").HandlerFunc(server.shortlinkRedirect)
	pub.Path("/").HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "/admin", http.StatusFound)
	})

	api := server.mux.Name("api").PathPrefix("/api/").Subrouter()
	api.Use(server.AuthMiddleware())
	api.Path("/create").Methods(http.MethodPost).HandlerFunc(server.apiCreateLink)
	api.Path("/delete").Methods(http.MethodDelete).HandlerFunc(server.apiDeleteLink)
	api.Path("/logout").Methods(http.MethodGet).HandlerFunc(server.apiLogout)

	return server, nil
}

func logsMiddleware(handler http.Handler) http.Handler {
	return handlers.CustomLoggingHandler(io.Discard, handler, func(_ io.Writer, params handlers.LogFormatterParams) {
		log.FromContext(params.Request.Context()).
			With(slog.Int("status_code", params.StatusCode)).
			With(slog.Int("size", params.Size)).
			With(slog.Float64("duration_seconds", time.Now().Sub(params.TimeStamp).Seconds())).
			With(slog.String("request_uri", params.Request.RequestURI)).
			With(slog.String("remote_addr", params.Request.RemoteAddr)).
			With(slog.String("request_id", params.Request.Header.Get("X-Request-ID"))).
			Info("request processed")
	})
}
