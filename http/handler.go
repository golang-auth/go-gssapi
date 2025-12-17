// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/golang-auth/go-gssapi/v3"
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
	newCtx := stashInitiatorName(r.Context(), initiatorName)
	return r.WithContext(newCtx)
}

func setHasChannelBindings(r *http.Request, has bool) *http.Request {
	newCtx := stashHasChannelBindings(r.Context(), has)
	return r.WithContext(newCtx)
}

// GetInitiatorName returns the initiator name from the request context if available
// This can be used by the 'next' http handler called by [Handler.ServeHTTP]
func GetInitiatorName(r *http.Request) (*InitiatorName, bool) {
	i := getInitiatorNameContext(r.Context())
	if i == nil {
		return nil, false
	}
	return i, true
}

// HasChannelBindings can be used by a [Handler] to verify whether the initiator
// supplied matching channel bindings.  The function will only ever return true
// if the underlying provider supports the Channel Bound extension.
func HasChannelBindings(r *http.Request) bool {
	return getHasCBContext(r.Context())
}

// Handler is a http.Handler that performs GSSAPI authentication and passes the initiator name to the next handler
type Handler struct {
	provider                  gssapi.Provider
	credential                gssapi.Credential
	channelBindingDisposition ChannelBindingDisposition
	channelBindingPresent     bool
	next                      http.Handler
}

// HandlerOption is a function that can be used to configure the Handler
type HandlerOption func(s *Handler)

// WithAcceptorCredential sets the acceptor credential for the Handler
func WithAcceptorCredential(credential gssapi.Credential) HandlerOption {
	return func(s *Handler) {
		s.credential = credential
	}
}

// WithAcceptorChannelBindingDisposition sets the channel binding type for the Handler.
//
// The disposition can be one of:
//   - ChannelBindingDispositionIgnore: ignore channel bindings
//   - ChannelBindingDispositionRequire: require channel bindings
//   - ChannelBindingDispositionIfAvailable: use channel bindings if supplied by the initiator
//
// Note that TLS channel bindings need access to the server certifficate presented to the client.
// For that we need to stash the connection information in the connection's context so that
// it can be retreieved by the handler.  This can be achieved by using [ServerWithStashConn]
// to create the http.Server.
func WithAcceptorChannelBindingDisposition(disposition ChannelBindingDisposition) HandlerOption {
	return func(s *Handler) {
		s.channelBindingDisposition = disposition
	}
}

// NewHandler creates a new Handler with the given GSSAPI provider and next handler
func NewHandler(provider gssapi.Provider, next http.Handler, options ...HandlerOption) (*Handler, error) {
	h := &Handler{
		provider: provider,
		next:     next,
	}
	for _, option := range options {
		option(h)
	}

	// It is only possible to tell the difference between no channel binndings and a successful match
	// when the GCC_C_CHANNEL_BOUND_FLAG is available.
	if h.channelBindingDisposition == ChannelBindingDispositionRequire &&
		!provider.HasExtension(gssapi.HasExtChannelBindingSignalling) {
		return nil, errors.New("channel bound GGSSAPI signalling extension unavailable: cannot require channel bindings")
	}

	return h, nil
}

// ServeHTTP performs the GSSAPI authentication and passes the initiator name to the next handler
// It doesn't seem possible to support any more than one GSSAPI round trip per request with
// the Go [http.Server] implementation without hijacking the connection.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authzType, authzToken := parseAuthzHeader(&r.Header)
	if authzType == "negotiate" && len(authzToken) > 0 {
		outToken, in, err := h.negotiateOnce(authzToken, r)
		if err != nil {
			h.log(r.Context(), "Error negotiating GSSAPI context: %s", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if outToken != "" {
			w.Header().Set("WWW-Authenticate", "Negotiate "+outToken)
		}
		r = setInitiatorName(r, in)
		r = setHasChannelBindings(r, h.channelBindingPresent)
	} else {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	h.next.ServeHTTP(w, r)
}

// negotiateOnce performs a single GSSAPI round trip to establish the context
// and returns the output token and initiator name.
func (h *Handler) negotiateOnce(negotiateToken string, r *http.Request) (string, *InitiatorName, error) {
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

	// Enable channel binnding if requested and we have a TLS connection
	if h.channelBindingDisposition != ChannelBindingDispositionIgnore {
		conn := getConnContext(r.Context())
		if tlsConn, ok := conn.(*tls.Conn); ok {
			serverCert, err := h.getServerCertificate(r.Context())
			if err != nil {
				return "", nil, fmt.Errorf("get server certificate: %w", err)
			}
			tlsState := tlsConn.ConnectionState()
			binding, err := krbEndpointBinding(&tlsState, serverCert)
			if err != nil {
				return "", nil, fmt.Errorf("acceptor channel binding: %w", err)
			}
			opts = append(opts, gssapi.WithAcceptorChannelBinding(binding))
		}
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

	h.channelBindingPresent = (info.Flags & gssapi.ContextFlagChannelBound) > 0

	// Verify that channel binding requirements are ment
	if h.channelBindingDisposition == ChannelBindingDispositionRequire && !h.channelBindingPresent {
		return "", nil, fmt.Errorf("%w (required but not supplied by initiator)", gssapi.ErrBadBindings)
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

func (h *Handler) log(ctx context.Context, format string, args ...interface{}) {
	logger := log.Default()

	if server := getServerContext(ctx); server != nil {
		if server.ErrorLog != nil {
			logger = server.ErrorLog
		}
	}

	logger.Printf(format, args...)
}

// ServerWithStashConn returns a new http.Server with a [http.Server.ConnContext] function that
// stashes the net.Conn in the connection's context.  The original ConnContext function
// is then called if it is not nil.
//
// This is intended to be be used when channel bindings are enabled.  The connection information
// is required by the handler to determine the server certificate used for the TLS connection.
func ServerWithStashConn(s *http.Server) *http.Server {
	oldConnContext := s.ConnContext
	s.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		ctx = stashConnContext(ctx, c)
		if oldConnContext != nil {
			return oldConnContext(ctx, c)
		}
		return ctx
	}
	return s
}

// GetServerCertificate extracts the http.Server from the request context and determines
// which server certificate was used for the TLS connection, using the same algorithm
// as http.Server. This replicates the certificate selection logic in order:
//  1. If tls.Config.GetCertificate is set, it attempts to determine the certificate
//     that would be selected (though the exact certificate chosen during handshake
//     may not be determinable without ClientHelloInfo)
//  2. If tls.Config.NameToCertificate is set (deprecated), it looks up the
//     certificate by server name from the connection state
//  3. Otherwise, tls.Config.Certificates[0] is used (the default behavior)
func (h *Handler) getServerCertificate(ctx context.Context) (*x509.Certificate, error) {
	server := getServerContext(ctx)
	if server == nil {
		return nil, fmt.Errorf("no http.Server found in context")
	}

	if server.TLSConfig == nil {
		return nil, fmt.Errorf("server has no TLS configuration")
	}

	conn := getConnContext(ctx)
	if conn == nil {
		return nil, fmt.Errorf("no connection found in context, forgot to use ServerWithStashConn?")
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("connection is not a TLS connection")
	}

	tlsState := tlsConn.ConnectionState()

	// Replicate the same algorithm as http.Server uses during TLS handshake
	config := server.TLSConfig

	// Step 1: If GetCertificate is set, we need to call it with ClientHelloInfo
	// However, we don't have the original ClientHelloInfo after the handshake.
	// We can reconstruct a minimal ClientHelloInfo from the connection state.
	if config.GetCertificate != nil {
		// Reconstruct ClientHelloInfo from connection state
		helloInfo := &tls.ClientHelloInfo{
			ServerName:        tlsState.ServerName,
			SupportedVersions: []uint16{tlsState.Version},
			CipherSuites:      []uint16{tlsState.CipherSuite},

			// TODO: un-comment after Go 1.24 is deprecated
			//SupportedCurves:   []tls.CurveID{tlsState.CurveID},
		}

		cert, err := config.GetCertificate(helloInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate from GetCertificate callback: %w", err)
		}
		if cert == nil {
			return nil, fmt.Errorf("GetCertificate callback returned nil certificate")
		}
		if cert.Leaf == nil {
			// Parse the certificate if it hasn't been parsed yet
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate from GetCertificate: %w", err)
			}
			cert.Leaf = leaf
		}
		return cert.Leaf, nil
	}

	// Step 2: Check the deprecated NameToCertificate map if available
	if config.NameToCertificate != nil && tlsState.ServerName != "" {
		if cert, ok := config.NameToCertificate[tlsState.ServerName]; ok && cert != nil {
			if cert.Leaf == nil {
				// Parse the certificate if it hasn't been parsed yet
				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					return nil, fmt.Errorf("failed to parse certificate from NameToCertificate: %w", err)
				}
				cert.Leaf = leaf
			}
			return cert.Leaf, nil
		}
	}

	// Step 3: Default behavior: use the first certificate in Certificates
	if len(config.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates configured in server TLS config")
	}

	cert := &config.Certificates[0]
	if cert.Leaf == nil {
		// Parse the certificate if it hasn't been parsed yet
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse server certificate: %w", err)
		}
		cert.Leaf = leaf
	}

	return cert.Leaf, nil
}
