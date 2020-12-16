package oauth2

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/unrolled/secure"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/config"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/net"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/net/limit"
)

// NewRouter returns a new mux.router with oauth endpoints registered
func NewRouter(server *Server, limiter *limit.Limiter) *mux.Router {
	router := mux.NewRouter()

	router.Use(logAllRequestsMiddleware)
	router.Use(limitRequestMiddleware(limiter))
	router.Use(getSecureMiddleware().Handler)
	router.Use(noCacheMiddleware)
	router.Use(contentLengthMiddleware)

	dir := http.Dir("ui/static")
	fs := http.FileServer(dir)
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static", fs))

	router.HandleFunc("/.well-known/openid-configuration", server.GetOpenIDConfiguration).Methods("GET")
	router.HandleFunc("/v1/authorize", server.GetLoginRoute).Methods("GET", "POST")
	router.HandleFunc("/v1/authorize/handle", server.PostLoginRoute).Methods("POST")
	router.HandleFunc("/v1/clients", server.PostClientsRoute).Methods("POST")
	router.HandleFunc("/v1/clients/{id}", server.DeleteClientsRoute).Methods("DELETE")
	router.HandleFunc("/v1/keys", server.GetJwksRoute).Methods("GET")
	router.HandleFunc("/v1/token", server.PostTokenRoute).Methods("POST")
	router.HandleFunc("/v1/userinfo", server.GetUserInfoRoute).Methods("GET", "POST")
	router.HandleFunc("/v1/service-documentation", server.GetServiceDocumentationRoute).Methods("GET")

	return router
}

// log method and uri for each request
func logAllRequestsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("%s %s", r.Method, r.URL.Path)

		next.ServeHTTP(w, r)
	})
}

func limitRequestMiddleware(limiter *limit.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, err := net.GetIPAddress(r)
			if err != nil {
				logger.Error(err.Error())
				net.SendErrorResponse(w, r, errorServer, errorServerDescription, http.StatusInternalServerError)
				return
			}

			requestID := ip + r.URL.Path
			visitor := limiter.GetVisitor(requestID)
			if !visitor.IsAllowed() {
				logger.Debug("Too many requests for %q", requestID)
				net.SendErrorResponse(w, r, "rate_limit", "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			logger.Debug("Visitor %q can proceed", requestID)

			next.ServeHTTP(w, r)
		})
	}
}

// Secure middleware should be included as close to the top as possible, but
// after logging.
func getSecureMiddleware() *secure.Secure {
	// Set secure headers, there are more headers that can be set, but these are
	// the ones that are relevant to our case.
	// See https://owasp.org/www-project-secure-headers/
	secureMiddleware := secure.New(secure.Options{
		// Use Strict-Transport-Security to mitigate protocol downgrade and cookie
		// hijacking.
		STSSeconds:           31536000, // 1 year
		STSIncludeSubdomains: true,

		// Block rendering content in frames to mitigate clickjacking.
		FrameDeny: true,

		// frame-ancestors block content in frames similar to FrameDeny.
		ContentSecurityPolicy: "frame-ancestors 'none';default-src 'self';font-src 'self' data:;",

		// Prevent browser from MIME-sniffing to mitigate attacks based on
		// MIME-confusion.
		ContentTypeNosniff: true,

		// Mitigate leakage of credentials or other secrets via Referer headers by
		// suppressing the headers completely.
		ReferrerPolicy: "no-referrer",
	})

	return secureMiddleware
}

func noCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// contentLengthMiddleware will check the Content-Length header for post
// requests and return an error if the body is too large or the header is
// missing.
func contentLengthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			next.ServeHTTP(w, r)
			return
		}

		if r.ContentLength == -1 {
			net.SendErrorResponse(w, r, "missing-header", "Missing Content-Length header", http.StatusBadRequest)
			return
		}

		if r.ContentLength > config.MaxContentLength {
			logger.Info("Request has too large content length (%.2f kB, max is %.2f kB).", float64(r.ContentLength)/1024, float64(config.MaxContentLength)/1024)
			net.SendErrorResponse(w, r, "too_large_request_body", "Request body is too large", http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
	})
}
