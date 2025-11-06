// SPDX-License-Identifier: Apache-2.0

package http

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang-auth/go-gssapi/v3"
)

// SpnFunc is a function that returns the Service Principal Name (SPN) for a given URL.
type SpnFunc func(url url.URL) string

func defaultSpnFunc(url url.URL) string {
	return "HTTP@" + url.Host
}

// DefaultSpnFunc is the default SPN function used for new clients.
var DefaultSpnFunc SpnFunc = defaultSpnFunc

// GSSAPITransport is a http.RoundTripper implementation that includes GSSAPI
// (HTTP Negotiate) authentication.
type GSSAPITransport struct {
	transport http.RoundTripper

	provider           gssapi.Provider
	credential         gssapi.Credential
	spnFunc            SpnFunc
	opportunistic      bool
	mutual             bool
	expect100Threshold uint32

	httpLogging bool
	logFunc     func(format string, args ...interface{})
}

// ClientOption is a function that configures a Client
type ClientOption func(c *GSSAPITransport)

// WithOpportunistic configures the client to opportunisticly authenticate
//
// Opportunistic authentication means that the client does not wait for the server to
// respond with a 401 status code before sending an authentication token.  This
// is a performance optimization that can be used to reduce the number of round trips
// between the client and server, at the cost of initializing the GSSAPI context and
// potentially exposing authentcation credentials to the server unnecessarily.
func WithOpportunistic() ClientOption {
	return func(c *GSSAPITransport) {
		c.opportunistic = true
	}
}

// WithMutual configures the client to request mutual authentication
//
// Mutual authentication means that the client and server both authenticate each other.
// It causes the server to respond with a GSSAPI authentication token in the Authorization header
// that the client can use to complete the context establishment and verify the server's identity.
func WithMutual() ClientOption {
	return func(c *GSSAPITransport) {
		c.mutual = true
	}
}

// WithCredential configures the client to use a specific credential
func WithCredential(cred gssapi.Credential) ClientOption {
	return func(c *GSSAPITransport) {
		c.credential = cred
	}
}

// WithSpnFunc provides a custom function to provide the Service Principal Name (SPN) for a given URL.
//
// The default uses "HTTP@" + the host name of the URL.
func WithSpnFunc(spnFunc SpnFunc) ClientOption {
	return func(c *GSSAPITransport) {
		c.spnFunc = spnFunc
	}
}

// WithExpect100Threshold configures the client to use the Expect: Continue header
// if the request body is larger than the threshold.
//
// The default threshold is 4kb.  Setting the threshold to 0 means that the client will not use the
// Expect: Continue header.
func WithExpect100Threshold(threshold uint32) ClientOption {
	return func(c *GSSAPITransport) {
		c.expect100Threshold = threshold
	}
}

// WithRoundTripper configures the client to use a custom round tripper
func WithRoundTripper(transport http.RoundTripper) ClientOption {
	return func(c *GSSAPITransport) {
		c.transport = transport
	}
}

// WithHttpLogging configures the client to log the HTTP requests and responses
// Does nothing without a log function
func WithHttpLogging() ClientOption {
	return func(c *GSSAPITransport) {
		c.httpLogging = true
	}
}

// WithLogFunc configures the client to use a custom log function
func WithLogFunc(logFunc func(format string, args ...interface{})) ClientOption {
	return func(c *GSSAPITransport) {
		c.logFunc = logFunc
	}
}

func NewTransport(provider gssapi.Provider, options ...ClientOption) http.RoundTripper {
	dt := http.DefaultTransport.(*http.Transport)
	dt.MaxConnsPerHost = 1
	t := &GSSAPITransport{
		transport:          http.DefaultTransport,
		provider:           provider,
		expect100Threshold: 4096,
	}
	for _, option := range options {
		option(t)
	}
	if t.httpLogging && t.logFunc == nil {
		t.httpLogging = false
	}
	return t
}

func NewClient(provider gssapi.Provider, client *http.Client, options ...ClientOption) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}

	if client.Transport != nil {
		options = append(options, WithRoundTripper(client.Transport))
	}

	// Copy the client to avoid modifying the original
	newClient := *client
	newClient.Transport = NewTransport(provider, options...)
	return &newClient
}

func (t *GSSAPITransport) setInitialToken(req *http.Request) (gssapi.SecContext, error) {
	spn := t.spnFunc(*req.URL)
	spnName, err := t.provider.ImportName(spn, gssapi.GSS_NT_HOSTBASED_SERVICE)
	if err != nil {
		return nil, err
	}
	defer spnName.Release()

	// always request integrity
	flags := gssapi.ContextFlagInteg
	if t.mutual {
		// optionally request mutual authentication
		flags |= gssapi.ContextFlagMutual
	}

	opts := []gssapi.InitSecContextOption{
		gssapi.WithInitiatorFlags(flags),
	}

	secCtx, err := t.provider.InitSecContext(spnName, opts...)
	if err != nil {
		return nil, err
	}
	token, _, err := secCtx.Continue(nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))

	return secCtx, nil
}

// Use the underlying transport's RoundTripper wrapped in HTTP logging
// if enabled.
func (t *GSSAPITransport) roundTrip(req *http.Request) (*http.Response, error) {
	if t.httpLogging {
		err := t.requestLogging(req)
		if err != nil {
			return nil, err
		}
	}

	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if t.httpLogging {
		err := t.responseLogging(resp)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (t *GSSAPITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.httpLogging {
		req = t.setupLogging(req)
	}

	var secCtx gssapi.SecContext
	var err error

	// We are not meant to modify the request, so we need to create a new one
	req = req.Clone(req.Context())

	defer func() {
		if secCtx != nil {
			secCtx.Delete() //nolint:errcheck
		}
	}()

	// Preemptively set the initial token if opportunistic authentication is requested
	if t.opportunistic {
		secCtx, err = t.setInitialToken(req)
		if err != nil {
			return nil, err
		}
	}

	// use Expect: Continue for large requests or if we can't rewind the body
	// This causes the server to close the connection if it needs to send a 401 response, so we don't want to
	// always use this.
	if t.expect100Threshold > 0 && !t.opportunistic {
		useExpect100 := false
		if req.ContentLength > int64(t.expect100Threshold) {
			t.logFunc("Using Expect: Continue header because request body is larger than %d bytes", t.expect100Threshold)
			useExpect100 = true
		}
		if req.GetBody == nil && !t.opportunistic {
			t.logFunc("Using Expect: Continue header because request body is not rewindable and opportunistic authentication is not requested")
			useExpect100 = true
		}
		if useExpect100 {
			req.Header.Set("Expect", "100-continue")
		}
	}

	// Send the request / get a response
	resp, err := t.roundTrip(req)
	if err != nil {
		return nil, err
	}

	// Redo the request with an initial token if we didn't already send one opportunistically
	if resp.StatusCode == 401 && !t.opportunistic {
		negotiateChallenge, err := FindOneWwwAuthenticateChallenge(&resp.Header, "Negotiate")
		if err != nil {
			return nil, err
		}

		// the challenge must not have a token or parameters
		if negotiateChallenge.Token68 != "" || len(negotiateChallenge.Parameters) > 0 {
			return nil, fmt.Errorf("negotiate challenge must not have a token or parameters")
		}

		secCtx, err = t.setInitialToken(req)
		if err != nil {
			return nil, err
		}

		resp, err = t.roundTrip(req)
		if err != nil {
			return nil, err
		}
	}

	// If we are doing mutual auth (which is of dubious value for HTTP), we need to
	// validate the response token.  At least we can catch a trojan server even if we
	// will have sent it the request body already.
	if resp.StatusCode != 401 && t.mutual {
		negotiateChallenge, err := FindOneWwwAuthenticateChallenge(&resp.Header, "Negotiate")
		if err != nil {
			return nil, err
		}

		// the challenge must have a token
		if negotiateChallenge.Token68 == "" {
			return nil, fmt.Errorf("no response token - required for mutual authentication: %+v / %+v", negotiateChallenge, resp.Header)
		}

		rawToken, err := base64.StdEncoding.DecodeString(negotiateChallenge.Token68)
		if err != nil {
			return nil, err
		}
		_, info, err := secCtx.Continue(rawToken)
		if err != nil {
			return nil, err
		}

		// verify that we have the flags we requested
		if info.Flags&gssapi.ContextFlagMutual == 0 {
			return nil, fmt.Errorf("mutual authentication requested but not available")
		}
	}

	return resp, nil
}
