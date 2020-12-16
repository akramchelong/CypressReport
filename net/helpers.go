package net

import (
	"encoding/json"
	"fmt"
	netHttp "net"
	"net/http"
	"runtime/debug"
	"strings"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"
)

type authMethod string

const (
	AuthMethodBasic  authMethod = "Basic"
	AuthMethodBearer authMethod = "Bearer"
)

type jsonError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// SendJSON encodes the response as JSON and sends it. If it fails to encode the
// JSON, a server_error will be returned instead.
func SendJSON(w http.ResponseWriter, content interface{}, statusCode int) {
	jsonValue, err := json.Marshal(content)
	if err != nil {
		logger.Error("Failed to encode JSON, stacktrace:\n" + string(debug.Stack()))
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	_, err = w.Write(jsonValue)
	if err != nil {
		logger.Error("Failed to write response, stacktrace:\n" + string(debug.Stack()))
		http.Error(w, "server_error", http.StatusInternalServerError)
	}
}

// SendUnauthorizedJSON formats an unauthorized response appending a
// WWW-Authenticate header with the appropriate authentication method.
func SendUnauthorizedJSON(w http.ResponseWriter, content interface{}, method authMethod) {
	realm := "IAM on-prem"
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`%s realm="%s"`, method, realm))
	SendJSON(w, content, http.StatusUnauthorized)
}

// SendErrorResponse sends response back to client based on the accept header.
// If accept header is application/json then json will be returned. Otherwise
// text/plain.
// error and error_description should follow rfc7591#section-3.2.2, which in
// short defines that:
// error must be a single ASCII error code string. Example: invalid_redirect_uri
// error_description is a human-readable ASCII text description of the error
// used for debugging. Optional, and if omitted it will be not be included in
// the error response.
func SendErrorResponse(w http.ResponseWriter, r *http.Request, error, errorDescription string, statusCode int) {
	if clientsAcceptsJson(r.Header["Accept"]) {
		SendJSON(w, jsonError{
			error,
			errorDescription,
		}, statusCode)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, "Error: %q, description: %q", error, errorDescription)
}

// GetIPAddress will return the IP address from the request object.
func GetIPAddress(r *http.Request) (string, error) {
	ip, _, err := netHttp.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}

	return ip, nil
}

// clientsAcceptsJson checks the request for an accept header and returns true
// if it contains application/json.
func clientsAcceptsJson(acceptHeader []string) bool {
	if len(acceptHeader) == 1 {
		// Split on comma to check for multiple types, i.e. accept header could
		// be:
		// "application/json, text/html, application/xhtml+xml, application/xml"
		types := strings.Split(acceptHeader[0], ",")

		// remove space before and after
		types = util.MapStringArray(types, func(s string) string {
			return strings.TrimSpace(s)
		})

		if util.Contains(types, "application/json") {
			return true
		}
	} else if len(acceptHeader) > 1 {
		// If multiple accept headers, assume that each contain a single type.
		if util.Contains(acceptHeader, "application/json") {
			return true
		}
	}

	return false
}
