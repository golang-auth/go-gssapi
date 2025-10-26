// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/golang-auth/go-gssapi/v3"
)

type ContextKey int

const (
	ctxInitiatorlName ContextKey = iota
)

// InitiatorName is the name of the initiator of the GSSAPI context.
// LocalName is set if the provider has the Localname extension
type InitiatorName struct {
	// PrincipalName is the fully qualified name of the initiator
	PrincipalName string

	// LocalName is the local name of the initiator if available
	LocalName string
}

func setInitiatorName(r *http.Request, initiatorName *InitiatorName) *http.Request {
	newCtx := context.WithValue(r.Context(), ctxInitiatorlName, initiatorName)
	return r.WithContext(newCtx)
}

// GetInitiatorName returns the initiator name from the request context if available
// This can be used by the 'next' http handler called by [Handler.ServeHTTP]
func GetInitiatorName(r *http.Request) (*InitiatorName, bool) {
	initiatorName, ok := r.Context().Value(ctxInitiatorlName).(*InitiatorName)
	return initiatorName, ok
}

// Handler is a http.Handler that performs GSSAPI authentication and passes the initiator name to the next handler
type Handler struct {
	provider   gssapi.Provider
	credential gssapi.Credential
	next       http.Handler
}

// HandlerOption is a function that can be used to configure the Handler
type HandlerOption func(s *Handler)

// WithAcceptorCredential sets the acceptor credential for the Handler
func WithAcceptorCredential(credential gssapi.Credential) HandlerOption {
	return func(s *Handler) {
		s.credential = credential
	}
}

// NewHandler creates a new Handler with the given GSSAPI provider and next handler
func NewHandler(provider gssapi.Provider, next http.Handler, options ...HandlerOption) *Handler {
	h := &Handler{
		provider: provider,
		next:     next,
	}
	for _, option := range options {
		option(h)
	}
	return h
}

// ServeHTTP performs the GSSAPI authentication and passes the initiator name to the next handler
// It doesn't seem possible to support any more than one GSSAPI round trip per request with
// the Go [http.Server] implementation without hijacking the connection.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authzType, authzToken := parseAuthzHeader(&r.Header)
	if authzType == "negotiate" && len(authzToken) > 0 {
		outToken, in, err := h.NegotiateOnce(authzToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if outToken != "" {
			w.Header().Set("Authorization", "Negotiate "+outToken)
		}
		r = setInitiatorName(r, in)
	} else {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	h.next.ServeHTTP(w, r)
}

// NegotiateOnce performs a single GSSAPI round trip to establish the context
// and returns the output token and initiator name.
func (h *Handler) NegotiateOnce(negotiateToken string) (string, *InitiatorName, error) {
	outToken := ""
	in := InitiatorName{}

	rawToken, err := base64.StdEncoding.DecodeString(negotiateToken)
	if err != nil {
		return "", nil, err
	}

	opts := []gssapi.AcceptSecContextOption{}
	if h.credential != nil {
		opts = append(opts, gssapi.WithAcceptorCredential(h.credential))
	}
	secCtx, err := h.provider.AcceptSecContext(opts...)
	if err != nil {
		return "", nil, err
	}
	defer secCtx.Delete() //nolint:errcheck
	respToken, info, err := secCtx.Continue(rawToken)
	if err != nil {
		return "", nil, err
	}
	if len(respToken) > 0 {
		outToken = base64.StdEncoding.EncodeToString(respToken)
	}

	if info.InitiatorName != nil {
		principalName, _, err := info.InitiatorName.Display()
		if err == nil {
			in.PrincipalName = principalName
		}

		if h.provider.HasExtension(gssapi.HasExtLocalname) {
			initatorNameLocal := info.InitiatorName.(gssapi.GssNameExtLocalname)
			in.LocalName, _ = initatorNameLocal.Localname(info.Mech)
		}
	}

	return outToken, &in, nil
}
